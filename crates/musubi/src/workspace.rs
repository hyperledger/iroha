//! Cargo-style workspace discovery and deterministic Musubi V1 metadata.
//!
//! Workspace loading is deliberately filesystem-aware. On qualified Unix, every manifest final
//! component is opened as one bounded, singly linked regular file beneath a canonically validated
//! root; other targets return an unsupported error before reading. Every local dependency is
//! normalized before it becomes part of the effective package graph. Ancestor validation remains
//! path-based and does not claim protection from a deliberately timed ABA.
use crate::{
    local_file::read_bounded_single_link_regular_file_v1,
    manifest::{
        ConcreteDependency, DependencyPath, DependencySpec, MANIFEST_FILE_NAME, Manifest,
        ManifestError, PortablePath, ResolvedPackageManifest, WorkspaceManifest, parse_manifest,
    },
};
use iroha_data_model::musubi::{MusubiPackageSelectorV1, MusubiVersionReqV1};
use iroha_model_base::name::Name;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs, io,
    path::{Component, Path, PathBuf},
};
/// Maximum local bytes accepted for one first-release manifest.
pub(crate) const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
type MemberSeed = (PathBuf, PathBuf, Manifest);
/// Stable category of a workspace discovery or validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceErrorKind {
    /// Filesystem access failed.
    Io,
    /// A manifest failed strict V1 parsing or inheritance.
    Manifest,
    /// No ancestor `Musubi.toml` exists.
    NotFound,
    /// A path escaped the owning workspace.
    Escape,
    /// A symlink or non-regular filesystem object was encountered.
    UnsafeFilesystem,
    /// Workspace membership or defaults are inconsistent.
    Membership,
    /// A local dependency does not match its declared registry identity.
    Dependency,
    /// Two packages or portable paths collide.
    Collision,
}
/// Structured workspace error with a stable category and implicated path.
#[derive(Debug)]
pub struct WorkspaceError {
    kind: WorkspaceErrorKind,
    path: Option<PathBuf>,
    message: String,
}
impl WorkspaceError {
    fn new(kind: WorkspaceErrorKind, path: Option<PathBuf>, message: impl Into<String>) -> Self {
        Self {
            kind,
            path,
            message: message.into(),
        }
    }
    fn io(operation: &str, path: &Path, error: &io::Error) -> Self {
        Self::new(
            WorkspaceErrorKind::Io,
            Some(path.to_path_buf()),
            format!("failed to {operation}: {error}"),
        )
    }
    fn manifest(path: &Path, error: &ManifestError) -> Self {
        Self::new(
            WorkspaceErrorKind::Manifest,
            Some(path.to_path_buf()),
            error.to_string(),
        )
    }
    /// Return the stable error category.
    #[must_use]
    pub const fn kind(&self) -> WorkspaceErrorKind {
        self.kind
    }
    /// Return the implicated filesystem path, when one exists.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
    /// Return the human-readable reason without its path prefix.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}
impl fmt::Display for WorkspaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(formatter, "{}: {}", path.display(), self.message),
            None => formatter.write_str(&self.message),
        }
    }
}
impl Error for WorkspaceError {}
/// Whether an effective dependency participates in publication or only a root-local test graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyKind {
    /// Published, transitively resolved dependency.
    Normal,
    /// Selected-root-only development dependency.
    Development,
}
/// Concrete dependency after workspace inheritance, including path provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveDependency {
    /// Parent-local import alias.
    pub alias: Name,
    /// Normal or development semantics.
    pub kind: DependencyKind,
    /// Concrete registry/path declaration.
    pub dependency: ConcreteDependency,
    /// Canonical directory against which a local dependency path is resolved.
    pub defined_in: PathBuf,
    /// Canonical local manifest path for a path dependency.
    pub local_manifest: Option<PathBuf>,
}
/// One loaded package member with fully applied package/dependency inheritance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceMember {
    /// Portable member path relative to the workspace root (`.` for the root package).
    pub workspace_path: PortablePath,
    /// Canonical package directory.
    pub package_root: PathBuf,
    /// Canonical package manifest path.
    pub manifest_path: PathBuf,
    /// Strict raw manifest syntax tree.
    pub manifest: Manifest,
    /// Package metadata after `[workspace.package]` inheritance.
    pub package: ResolvedPackageManifest,
    /// Effective normal dependencies in alias order.
    pub dependencies: BTreeMap<Name, EffectiveDependency>,
    /// Effective development dependencies in alias order.
    pub dev_dependencies: BTreeMap<Name, EffectiveDependency>,
}
/// Deterministic metadata for one dependency edge.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DependencyMetadata {
    /// Parent-local import alias.
    pub alias: String,
    /// Dependency kind.
    pub kind: DependencyKind,
    /// Registry selector, if declared.
    pub package: Option<String>,
    /// Canonical range, if declared.
    pub requirement: Option<String>,
    /// Portable local path, if present.
    pub path: Option<String>,
}
/// Deterministic metadata for one workspace member.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemberMetadata {
    /// Portable workspace-relative package path.
    pub path: String,
    /// Canonical namespaced package selector.
    pub package: String,
    /// Exact package version.
    pub version: String,
    /// Effective dependencies sorted by kind and alias.
    pub dependencies: Vec<DependencyMetadata>,
}
/// Stable semantic workspace metadata without timestamps or cache/network state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceMetadata {
    /// Canonical root manifest path.
    pub root_manifest: PathBuf,
    /// Members sorted by portable path.
    pub members: Vec<MemberMetadata>,
    /// Default-member portable paths in sorted order.
    pub default_members: Vec<String>,
}
/// Fully loaded owning workspace, or a synthetic one-package workspace for a standalone package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workspace {
    root: PathBuf,
    root_manifest_path: PathBuf,
    root_manifest: Manifest,
    members: BTreeMap<PortablePath, WorkspaceMember>,
    default_members: BTreeSet<PortablePath>,
    synthetic: bool,
    manifest_overlays: BTreeMap<PathBuf, String>,
}
impl Workspace {
    /// Return the canonical workspace root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Return the canonical root manifest path.
    #[must_use]
    pub fn root_manifest_path(&self) -> &Path {
        &self.root_manifest_path
    }
    /// Return the parsed root manifest.
    #[must_use]
    pub const fn root_manifest(&self) -> &Manifest {
        &self.root_manifest
    }
    /// Return all members in deterministic portable-path order.
    #[must_use]
    pub const fn members(&self) -> &BTreeMap<PortablePath, WorkspaceMember> {
        &self.members
    }
    /// Return default members in deterministic portable-path order.
    #[must_use]
    pub const fn default_members(&self) -> &BTreeSet<PortablePath> {
        &self.default_members
    }
    /// Return whether this is the implicit workspace of a standalone package.
    #[must_use]
    pub const fn is_synthetic(&self) -> bool {
        self.synthetic
    }
    /// Select members using Cargo-style default/all/package/exclude semantics.
    ///
    /// `packages` contains canonical namespaced package selectors. Exclusions always apply last.
    /// With neither `all` nor explicit packages, the root's default-member set is selected.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown package or exclusion selector.
    pub fn select_members(
        &self,
        all: bool,
        packages: &[MusubiPackageSelectorV1],
        excludes: &[MusubiPackageSelectorV1],
    ) -> Result<Vec<&WorkspaceMember>, WorkspaceError> {
        let by_package = self
            .members
            .iter()
            .map(|(path, member)| (member.package.selector.clone(), path))
            .collect::<BTreeMap<_, _>>();
        let mut selected = if all {
            self.members.keys().cloned().collect::<BTreeSet<_>>()
        } else if packages.is_empty() {
            self.default_members.clone()
        } else {
            packages
                .iter()
                .map(|package| {
                    by_package
                        .get(package)
                        .map(|path| (*path).clone())
                        .ok_or_else(|| {
                            WorkspaceError::new(
                                WorkspaceErrorKind::Membership,
                                Some(self.root_manifest_path.clone()),
                                format!("package `{package}` is not a workspace member"),
                            )
                        })
                })
                .collect::<Result<BTreeSet<_>, _>>()?
        };
        for package in excludes {
            let path = by_package.get(package).ok_or_else(|| {
                WorkspaceError::new(
                    WorkspaceErrorKind::Membership,
                    Some(self.root_manifest_path.clone()),
                    format!("excluded package `{package}` is not a workspace member"),
                )
            })?;
            selected.remove(*path);
        }
        Ok(selected
            .iter()
            .map(|path| {
                self.members
                    .get(path)
                    .expect("selected paths originate from members")
            })
            .collect())
    }
    /// Build deterministic semantic metadata for `metadata` and JSON rendering.
    #[must_use]
    pub fn metadata(&self) -> WorkspaceMetadata {
        let members = self
            .members
            .values()
            .map(|member| {
                let mut dependencies = member
                    .dependencies
                    .values()
                    .chain(member.dev_dependencies.values())
                    .map(dependency_metadata)
                    .collect::<Vec<_>>();
                dependencies.sort();
                MemberMetadata {
                    path: member.workspace_path.to_string(),
                    package: member.package.selector.to_string(),
                    version: member.package.version.to_string(),
                    dependencies,
                }
            })
            .collect();
        WorkspaceMetadata {
            root_manifest: self.root_manifest_path.clone(),
            members,
            default_members: self
                .default_members
                .iter()
                .map(ToString::to_string)
                .collect(),
        }
    }
    /// Load a validated local path package below this workspace root.
    ///
    /// Active workspace members are returned from the already materialized member set, preserving
    /// workspace inheritance. A non-member path package is parsed as a standalone package: it may
    /// refer to other packages below the same workspace root, but it may not inherit workspace
    /// fields or dependencies. This gives graph construction a single filesystem-safe entry point
    /// for recursively reachable path dependencies.
    ///
    /// # Errors
    ///
    /// Returns an error if `manifest_path` is outside the workspace root, is not the canonical
    /// `Musubi.toml` of a non-symlink directory, declares a nested workspace, uses unavailable
    /// workspace inheritance, or contains an invalid dependency.
    pub fn load_path_package(
        &self,
        manifest_path: &Path,
    ) -> Result<WorkspaceMember, WorkspaceError> {
        if let Some(member) = self
            .members
            .values()
            .find(|member| member.manifest_path == manifest_path)
        {
            return Ok(member.clone());
        }
        let package_root = manifest_path.parent().ok_or_else(|| {
            WorkspaceError::new(
                WorkspaceErrorKind::Dependency,
                Some(manifest_path.to_path_buf()),
                "path dependency manifest has no package directory",
            )
        })?;
        let package_root = confined_directory(&self.root, &self.root, package_root)?;
        let expected_manifest = package_root.join(MANIFEST_FILE_NAME);
        if expected_manifest != manifest_path {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::Dependency,
                Some(manifest_path.to_path_buf()),
                format!(
                    "path dependency manifest must be `{}`",
                    expected_manifest.display()
                ),
            ));
        }
        let manifest = read_manifest_overlay(&expected_manifest, None, &self.manifest_overlays)?;
        if manifest.workspace.is_some() {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::Membership,
                Some(expected_manifest),
                "a reachable non-member path package must not declare a nested workspace",
            ));
        }
        let package = manifest
            .resolve_package(None)
            .map_err(|error| WorkspaceError::manifest(manifest_path, &error))?;
        let local_packages = self
            .members
            .iter()
            .map(|(path, member)| (member.manifest_path.clone(), path.clone()))
            .collect::<BTreeMap<_, _>>();
        let resolved_packages = self
            .members
            .iter()
            .map(|(path, member)| (path.clone(), member.package.clone()))
            .collect::<BTreeMap<_, _>>();
        let no_workspace_dependencies = BTreeMap::new();
        let dependencies = resolve_dependencies(
            &self.root,
            &package_root,
            manifest_path,
            &manifest.dependencies,
            DependencyKind::Normal,
            &no_workspace_dependencies,
            &local_packages,
            &resolved_packages,
            None,
            &self.manifest_overlays,
        )?;
        let dev_dependencies = resolve_dependencies(
            &self.root,
            &package_root,
            manifest_path,
            &manifest.dev_dependencies,
            DependencyKind::Development,
            &no_workspace_dependencies,
            &local_packages,
            &resolved_packages,
            None,
            &self.manifest_overlays,
        )?;
        let relative = package_root.strip_prefix(&self.root).map_err(|_| {
            WorkspaceError::new(
                WorkspaceErrorKind::Escape,
                Some(package_root.clone()),
                "path dependency package is outside the workspace root",
            )
        })?;
        let workspace_path = portable_from_relative_path(relative)?;
        Ok(WorkspaceMember {
            workspace_path,
            package_root,
            manifest_path: manifest_path.to_path_buf(),
            manifest,
            package,
            dependencies,
            dev_dependencies,
        })
    }
}
/// Discover the nearest ancestor `Musubi.toml` without following symlinks.
///
/// `start` may name a directory, an ordinary file within a package, or the manifest itself.
///
/// # Errors
///
/// Returns an error if `start` is missing/unsafe, filesystem access fails, or
/// no ancestor manifest exists.
pub fn discover_manifest(start: &Path) -> Result<PathBuf, WorkspaceError> {
    let start_metadata = fs::symlink_metadata(start)
        .map_err(|error| WorkspaceError::io("inspect discovery start", start, &error))?;
    if start_metadata.file_type().is_symlink() {
        return Err(unsafe_path(start, "discovery start must not be a symlink"));
    }
    verify_discovery_ancestors(start)?;
    let canonical_start = fs::canonicalize(start)
        .map_err(|error| WorkspaceError::io("canonicalize discovery start", start, &error))?;
    if start_metadata.is_file()
        && start.file_name().and_then(|name| name.to_str()) == Some(MANIFEST_FILE_NAME)
    {
        validate_manifest_file(&canonical_start)?;
        return Ok(canonical_start);
    }
    let mut directory = if start_metadata.is_dir() {
        canonical_start
    } else {
        canonical_start
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                WorkspaceError::new(
                    WorkspaceErrorKind::NotFound,
                    Some(canonical_start.clone()),
                    "discovery start has no parent directory",
                )
            })?
    };
    loop {
        let candidate = directory.join(MANIFEST_FILE_NAME);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(unsafe_path(
                        &candidate,
                        "ancestor manifest must be a regular non-symlink file",
                    ));
                }
                validate_manifest_file(&candidate)?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(WorkspaceError::io(
                    "inspect ancestor manifest",
                    &candidate,
                    &error,
                ));
            }
        }
        let Some(parent) = directory.parent() else {
            break;
        };
        directory = parent.to_path_buf();
    }
    Err(WorkspaceError::new(
        WorkspaceErrorKind::NotFound,
        Some(start.to_path_buf()),
        format!("no ancestor `{MANIFEST_FILE_NAME}` was found"),
    ))
}
/// Discover the root manifest of the workspace owning `start`.
///
/// A package with no ancestor workspace is its own synthetic workspace. A manifest nested beneath a
/// workspace must be an explicit, non-excluded member; it is never silently treated as standalone.
///
/// # Errors
///
/// Returns an error for discovery, strict manifest parsing, unsafe member
/// paths, or an unlisted package nested beneath a workspace root.
pub fn discover_workspace_manifest(start: &Path) -> Result<PathBuf, WorkspaceError> {
    discover_workspace_manifest_selected(start, None, &BTreeMap::new())
}

fn discover_workspace_manifest_selected(
    start: &Path,
    selected: Option<&iroha_fs::SelectedRegularFile>,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<PathBuf, WorkspaceError> {
    let nearest = discover_manifest(start)?;
    require_selected_manifest_path(&nearest, selected)?;
    let nearest_root = nearest
        .parent()
        .expect("a manifest path has a parent")
        .to_path_buf();
    let nearest_manifest = read_manifest_overlay(&nearest, selected, overlays)?;
    if nearest_manifest.workspace.is_some() {
        return Ok(nearest);
    }
    let mut directory = nearest_root
        .parent()
        .map_or_else(|| nearest_root.clone(), Path::to_path_buf);
    loop {
        let candidate = directory.join(MANIFEST_FILE_NAME);
        if candidate != nearest {
            match fs::symlink_metadata(&candidate) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        return Err(unsafe_path(
                            &candidate,
                            "ancestor manifest must be a regular non-symlink file",
                        ));
                    }
                    let candidate_manifest = read_manifest_overlay(&candidate, selected, overlays)?;
                    if let Some(workspace) = &candidate_manifest.workspace {
                        let relative = nearest_root.strip_prefix(&directory).map_err(|_| {
                            WorkspaceError::new(
                                WorkspaceErrorKind::Escape,
                                Some(nearest.clone()),
                                "candidate workspace does not contain the package",
                            )
                        })?;
                        let relative = portable_from_relative_path(relative)?;
                        if path_is_excluded(&relative, &workspace.exclude) {
                            return Ok(nearest);
                        }
                        if workspace.members.contains(&relative) {
                            return Ok(candidate);
                        }
                        return Err(WorkspaceError::new(
                            WorkspaceErrorKind::Membership,
                            Some(nearest.clone()),
                            format!(
                                "package `{relative}` is nested beneath {}, but is not listed in `workspace.members`",
                                candidate.display()
                            ),
                        ));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(WorkspaceError::io(
                        "inspect ancestor manifest",
                        &candidate,
                        &error,
                    ));
                }
            }
        }
        let Some(parent) = directory.parent() else {
            break;
        };
        directory = parent.to_path_buf();
    }
    Ok(nearest)
}
/// Load the workspace owning `start`, apply inheritance, and validate every
/// local dependency manifest.
///
/// # Errors
///
/// Returns an error for discovery, strict parsing, missing/default membership, path escape,
/// symlinks, package collisions, or mismatched path-dependency identity/ranges.
pub fn load_workspace(start: &Path) -> Result<Workspace, WorkspaceError> {
    load_workspace_selected(start, None, &BTreeMap::new())
}

/// Load the original selected manifest through its native descriptor, preserving every
/// independent ancestor, member and dependency selection in the canonical workspace owner.
/// # Errors
/// Returns the same workspace diagnostics or a changed selected-file refusal.
pub(crate) fn load_workspace_from_selected(
    selected: &iroha_fs::SelectedRegularFile,
) -> Result<Workspace, WorkspaceError> {
    selected
        .revalidate()
        .map_err(|error| WorkspaceError::io("retain selected manifest", selected.path(), &error))?;
    let workspace = load_workspace_selected(selected.path(), Some(selected), &BTreeMap::new())?;
    selected.revalidate().map_err(|error| {
        WorkspaceError::io(
            "retain selected workspace manifest",
            selected.path(),
            &error,
        )
    })?;
    Ok(workspace)
}

fn load_workspace_selected(
    start: &Path,
    selected: Option<&iroha_fs::SelectedRegularFile>,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<Workspace, WorkspaceError> {
    let nearest_manifest_path = discover_manifest(start)?;
    require_selected_manifest_path(&nearest_manifest_path, selected)?;
    let root_manifest_path = discover_workspace_manifest_selected(start, selected, overlays)?;
    let root = root_manifest_path
        .parent()
        .expect("manifest path has parent")
        .to_path_buf();
    let root_manifest = read_manifest_overlay(&root_manifest_path, selected, overlays)?;
    let synthetic = root_manifest.workspace.is_none();
    let workspace_declaration = root_manifest.workspace.as_ref();
    let seeds = collect_member_seeds(
        &root,
        &root_manifest_path,
        &root_manifest,
        workspace_declaration,
        selected,
        overlays,
    )?;
    validate_nearest_member(&nearest_manifest_path, &root_manifest_path, &seeds)?;
    let package_defaults = workspace_declaration.map(|workspace| &workspace.package);
    let resolved_packages = resolve_member_packages(&seeds, package_defaults)?;
    let workspace_dependencies = workspace_declaration
        .map(|workspace| &workspace.dependencies)
        .cloned()
        .unwrap_or_default();
    let members = materialize_members(
        &root,
        seeds,
        &resolved_packages,
        &workspace_dependencies,
        selected,
        overlays,
    )?;
    let default_members = default_member_set(workspace_declaration, &members, &root_manifest_path)?;
    Ok(Workspace {
        root,
        root_manifest_path,
        root_manifest,
        members,
        default_members,
        synthetic,
        manifest_overlays: overlays.clone(),
    })
}
fn collect_member_seeds(
    root: &Path,
    root_manifest_path: &Path,
    root_manifest: &Manifest,
    workspace: Option<&WorkspaceManifest>,
    selected: Option<&iroha_fs::SelectedRegularFile>,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<BTreeMap<PortablePath, MemberSeed>, WorkspaceError> {
    let mut seeds = BTreeMap::new();
    if root_manifest.package.is_some() {
        let dot = PortablePath::new(".")
            .map_err(|error| WorkspaceError::manifest(root_manifest_path, &error))?;
        seeds.insert(
            dot,
            (
                root.to_path_buf(),
                root_manifest_path.to_path_buf(),
                root_manifest.clone(),
            ),
        );
    }
    if let Some(workspace) = workspace {
        let excluded = workspace.exclude.iter().cloned().collect::<BTreeSet<_>>();
        if excluded.contains(&PortablePath::new(".").expect("dot is valid")) {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::Membership,
                Some(root_manifest_path.to_path_buf()),
                "`workspace.exclude` cannot exclude the workspace root",
            ));
        }
        let mut collision_paths = BTreeMap::<String, PortablePath>::new();
        for member_path in &workspace.members {
            if member_path.as_str() == "." {
                return Err(WorkspaceError::new(
                    WorkspaceErrorKind::Membership,
                    Some(root_manifest_path.to_path_buf()),
                    "the root package is implicit and must not appear in `workspace.members`",
                ));
            }
            if path_is_excluded(member_path, &workspace.exclude) {
                continue;
            }
            if let Some(previous) =
                collision_paths.insert(member_path.collision_key(), member_path.clone())
            {
                return Err(WorkspaceError::new(
                    WorkspaceErrorKind::Collision,
                    Some(root_manifest_path.to_path_buf()),
                    format!("portable member collision between `{previous}` and `{member_path}`"),
                ));
            }
            let member_root = confined_directory(root, root, &member_path.to_path_buf())?;
            let member_manifest_path = member_root.join(MANIFEST_FILE_NAME);
            let member_manifest = read_manifest_overlay(&member_manifest_path, selected, overlays)?;
            if member_manifest.package.is_none() {
                return Err(WorkspaceError::new(
                    WorkspaceErrorKind::Membership,
                    Some(member_manifest_path),
                    "workspace members must define `[package]`",
                ));
            }
            if member_manifest.workspace.is_some() {
                return Err(WorkspaceError::new(
                    WorkspaceErrorKind::Membership,
                    Some(member_manifest_path),
                    "nested workspace declarations are not allowed in a member",
                ));
            }
            seeds.insert(
                member_path.clone(),
                (member_root, member_manifest_path, member_manifest),
            );
        }
    }
    if seeds.is_empty() {
        return Err(WorkspaceError::new(
            WorkspaceErrorKind::Membership,
            Some(root_manifest_path.to_path_buf()),
            "workspace contains no package members",
        ));
    }
    Ok(seeds)
}
fn validate_nearest_member(
    nearest_manifest_path: &Path,
    root_manifest_path: &Path,
    seeds: &BTreeMap<PortablePath, MemberSeed>,
) -> Result<(), WorkspaceError> {
    if nearest_manifest_path != root_manifest_path
        && !seeds
            .values()
            .any(|(_, manifest_path, _)| manifest_path == nearest_manifest_path)
    {
        return Err(WorkspaceError::new(
            WorkspaceErrorKind::Membership,
            Some(nearest_manifest_path.to_path_buf()),
            "nearest package manifest is not an active member of the owning workspace",
        ));
    }
    Ok(())
}
fn resolve_member_packages(
    seeds: &BTreeMap<PortablePath, MemberSeed>,
    package_defaults: Option<&crate::manifest::WorkspacePackageDefaults>,
) -> Result<BTreeMap<PortablePath, ResolvedPackageManifest>, WorkspaceError> {
    let mut resolved_packages = BTreeMap::new();
    let mut package_paths = BTreeMap::new();
    for (path, (_, manifest_path, manifest)) in seeds {
        let package = manifest
            .resolve_package(package_defaults)
            .map_err(|error| WorkspaceError::manifest(manifest_path, &error))?;
        if let Some(previous) = package_paths.insert(package.selector.clone(), path.clone()) {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::Collision,
                Some(manifest_path.clone()),
                format!(
                    "package `{}` is declared by both `{previous}` and `{path}`",
                    package.selector
                ),
            ));
        }
        resolved_packages.insert(path.clone(), package);
    }
    Ok(resolved_packages)
}
fn materialize_members(
    root: &Path,
    seeds: BTreeMap<PortablePath, MemberSeed>,
    resolved_packages: &BTreeMap<PortablePath, ResolvedPackageManifest>,
    workspace_dependencies: &BTreeMap<Name, ConcreteDependency>,
    selected: Option<&iroha_fs::SelectedRegularFile>,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<BTreeMap<PortablePath, WorkspaceMember>, WorkspaceError> {
    let local_packages = seeds
        .iter()
        .map(|(path, (_, manifest_path, _))| (manifest_path.clone(), path.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut members = BTreeMap::new();
    for (path, (package_root, manifest_path, manifest)) in seeds {
        let package = resolved_packages
            .get(&path)
            .expect("all member packages were resolved")
            .clone();
        let dependencies = resolve_dependencies(
            root,
            &package_root,
            &manifest_path,
            &manifest.dependencies,
            DependencyKind::Normal,
            workspace_dependencies,
            &local_packages,
            resolved_packages,
            selected,
            overlays,
        )?;
        let dev_dependencies = resolve_dependencies(
            root,
            &package_root,
            &manifest_path,
            &manifest.dev_dependencies,
            DependencyKind::Development,
            workspace_dependencies,
            &local_packages,
            resolved_packages,
            selected,
            overlays,
        )?;
        members.insert(
            path.clone(),
            WorkspaceMember {
                workspace_path: path,
                package_root,
                manifest_path,
                manifest,
                package,
                dependencies,
                dev_dependencies,
            },
        );
    }
    Ok(members)
}
#[allow(clippy::too_many_arguments)]
fn resolve_dependencies(
    workspace_root: &Path,
    package_root: &Path,
    manifest_path: &Path,
    dependencies: &BTreeMap<Name, DependencySpec>,
    kind: DependencyKind,
    workspace_dependencies: &BTreeMap<Name, ConcreteDependency>,
    local_packages: &BTreeMap<PathBuf, PortablePath>,
    resolved_packages: &BTreeMap<PortablePath, ResolvedPackageManifest>,
    selected: Option<&iroha_fs::SelectedRegularFile>,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<BTreeMap<Name, EffectiveDependency>, WorkspaceError> {
    let mut result = BTreeMap::new();
    for (alias, dependency) in dependencies {
        let (dependency, defined_in) = match dependency {
            DependencySpec::Concrete(dependency) => (dependency.clone(), package_root.to_path_buf()),
            DependencySpec::Workspace => (
                workspace_dependencies.get(alias).cloned().ok_or_else(|| {
                    WorkspaceError::new(
                        WorkspaceErrorKind::Dependency,
                        Some(manifest_path.to_path_buf()),
                        format!(
                            "dependency `{alias}` inherits from `[workspace.dependencies]`, but no entry exists"
                        ),
                    )
                })?,
                workspace_root.to_path_buf(),
            ),
        };
        let local_manifest = match &dependency {
            ConcreteDependency::Registry { .. } => None,
            ConcreteDependency::Path {
                path,
                package,
                requirement,
            } => {
                let dependency_root = resolve_dependency_root(workspace_root, &defined_in, path)?;
                let dependency_manifest_path = dependency_root.join(MANIFEST_FILE_NAME);
                let dependency_manifest =
                    read_manifest_overlay(&dependency_manifest_path, selected, overlays)?;
                if dependency_manifest.package.is_none() {
                    return Err(WorkspaceError::new(
                        WorkspaceErrorKind::Dependency,
                        Some(dependency_manifest_path),
                        format!("path dependency `{alias}` points to a virtual workspace"),
                    ));
                }
                if dependency_manifest.library.is_none() {
                    return Err(WorkspaceError::new(
                        WorkspaceErrorKind::Dependency,
                        Some(dependency_manifest_path),
                        format!(
                            "path dependency `{alias}` is a contract-only package; dependencies must declare a `[lib]` interface"
                        ),
                    ));
                }
                let local_package = match local_packages.get(&dependency_manifest_path) {
                    Some(member_path) => resolved_packages
                        .get(member_path)
                        .expect("member package resolution is complete")
                        .clone(),
                    None => dependency_manifest.resolve_package(None).map_err(|error| {
                        WorkspaceError::manifest(&dependency_manifest_path, &error)
                    })?,
                };
                validate_declared_path_identity(
                    alias,
                    &dependency_manifest_path,
                    package.as_ref(),
                    requirement.as_ref(),
                    &local_package,
                )?;
                Some(dependency_manifest_path)
            }
        };
        result.insert(
            alias.clone(),
            EffectiveDependency {
                alias: alias.clone(),
                kind,
                dependency,
                defined_in,
                local_manifest,
            },
        );
    }
    Ok(result)
}
fn validate_declared_path_identity(
    alias: &Name,
    manifest_path: &Path,
    declared_package: Option<&MusubiPackageSelectorV1>,
    declared_requirement: Option<&MusubiVersionReqV1>,
    local_package: &ResolvedPackageManifest,
) -> Result<(), WorkspaceError> {
    let (Some(package), Some(requirement)) = (declared_package, declared_requirement) else {
        return Ok(());
    };
    if package != &local_package.selector {
        return Err(WorkspaceError::new(
            WorkspaceErrorKind::Dependency,
            Some(manifest_path.to_path_buf()),
            format!(
                "path dependency `{alias}` declares `{package}`, but its local manifest is `{}`",
                local_package.selector
            ),
        ));
    }
    if !requirement.matches(&local_package.version) {
        return Err(WorkspaceError::new(
            WorkspaceErrorKind::Dependency,
            Some(manifest_path.to_path_buf()),
            format!(
                "path dependency `{alias}` requirement `{requirement}` does not match local version `{}`",
                local_package.version
            ),
        ));
    }
    Ok(())
}
fn resolve_dependency_root(
    workspace_root: &Path,
    defined_in: &Path,
    path: &DependencyPath,
) -> Result<PathBuf, WorkspaceError> {
    confined_directory(workspace_root, defined_in, &path.to_path_buf())
}
fn default_member_set(
    workspace: Option<&WorkspaceManifest>,
    members: &BTreeMap<PortablePath, WorkspaceMember>,
    root_manifest_path: &Path,
) -> Result<BTreeSet<PortablePath>, WorkspaceError> {
    let Some(defaults) = workspace.and_then(|workspace| workspace.default_members.as_ref()) else {
        return Ok(members.keys().cloned().collect());
    };
    let mut result = BTreeSet::new();
    for path in defaults {
        if !members.contains_key(path) {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::Membership,
                Some(root_manifest_path.to_path_buf()),
                format!("default member `{path}` is not an active workspace member"),
            ));
        }
        result.insert(path.clone());
    }
    Ok(result)
}
fn dependency_metadata(dependency: &EffectiveDependency) -> DependencyMetadata {
    match &dependency.dependency {
        ConcreteDependency::Registry {
            package,
            requirement,
        } => DependencyMetadata {
            alias: dependency.alias.to_string(),
            kind: dependency.kind,
            package: Some(package.to_string()),
            requirement: Some(requirement.to_string()),
            path: None,
        },
        ConcreteDependency::Path {
            path,
            package,
            requirement,
        } => DependencyMetadata {
            alias: dependency.alias.to_string(),
            kind: dependency.kind,
            package: package.as_ref().map(ToString::to_string),
            requirement: requirement.as_ref().map(ToString::to_string),
            path: Some(path.to_string()),
        },
    }
}
/// Load the canonical workspace contract with bounded unsaved manifest text.
///
/// Filesystem identity, containment, dependency resolution and strict TOML validation are
/// identical to ordinary builds. Overlays never create an alternate on-disk manifest.
///
/// # Errors
/// Returns an error for unsafe filesystem identities, unreadable files, oversized
/// overlays, invalid manifests, or inconsistent workspace and dependency bindings.
pub fn load_workspace_with_overlays(
    start: &Path,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<Workspace, WorkspaceError> {
    load_workspace_selected(start, None, overlays)
}
fn read_manifest_overlay(
    path: &Path,
    selected: Option<&iroha_fs::SelectedRegularFile>,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<Manifest, WorkspaceError> {
    overlays.get(path).map_or_else(
        || read_manifest_selected(path, selected),
        |text| {
            read_manifest_with_reader(path, |_, maximum| {
                if text.len() as u64 > maximum {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "manifest overlay exceeds its byte limit",
                    ));
                }
                Ok(text.as_bytes().to_vec())
            })
        },
    )
}
fn read_manifest(path: &Path) -> Result<Manifest, WorkspaceError> {
    read_manifest_with_reader(path, read_bounded_single_link_regular_file_v1)
}
fn require_selected_manifest_path(
    path: &Path,
    selected: Option<&iroha_fs::SelectedRegularFile>,
) -> Result<(), WorkspaceError> {
    if let Some(selected) = selected {
        selected.revalidate().map_err(|error| {
            WorkspaceError::io("retain selected manifest path", selected.path(), &error)
        })?;
        if path != selected.path() {
            return Err(unsafe_path(
                path,
                "discovery differs from the original selected manifest",
            ));
        }
    }
    Ok(())
}
pub(crate) fn read_manifest_selected(
    path: &Path,
    selected: Option<&iroha_fs::SelectedRegularFile>,
) -> Result<Manifest, WorkspaceError> {
    selected
        .filter(|selected| selected.path() == path)
        .map_or_else(
            || read_manifest(path),
            |selected| {
                read_manifest_with_reader(path, |_, maximum| {
                    let maximum = usize::try_from(maximum).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "manifest byte limit exceeds this host",
                        )
                    })?;
                    selected.read(maximum)
                })
            },
        )
}
fn read_manifest_with_reader<F>(path: &Path, read_file: F) -> Result<Manifest, WorkspaceError>
where
    F: FnOnce(&Path, u64) -> io::Result<Vec<u8>>,
{
    validate_manifest_file(path)?;
    let bytes = read_file(path, MAX_MANIFEST_BYTES)
        .map_err(|error| WorkspaceError::io("read bounded manifest", path, &error))?;
    let source = String::from_utf8(bytes).map_err(|error| {
        WorkspaceError::io(
            "read manifest as UTF-8",
            path,
            &io::Error::new(io::ErrorKind::InvalidData, error),
        )
    })?;
    parse_manifest(&source).map_err(|error| WorkspaceError::manifest(path, &error))
}
fn validate_manifest_file(path: &Path) -> Result<(), WorkspaceError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| WorkspaceError::io("inspect manifest", path, &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(unsafe_path(
            path,
            "manifest must be a regular non-symlink file",
        ));
    }
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(WorkspaceError::new(
            WorkspaceErrorKind::Manifest,
            Some(path.to_path_buf()),
            format!("manifest exceeds the {MAX_MANIFEST_BYTES}-byte local safety bound"),
        ));
    }
    Ok(())
}
fn confined_directory(
    root: &Path,
    base: &Path,
    relative: &Path,
) -> Result<PathBuf, WorkspaceError> {
    let root = fs::canonicalize(root)
        .map_err(|error| WorkspaceError::io("canonicalize workspace root", root, &error))?;
    let base = fs::canonicalize(base)
        .map_err(|error| WorkspaceError::io("canonicalize path base", base, &error))?;
    if !base.starts_with(&root) {
        return Err(WorkspaceError::new(
            WorkspaceErrorKind::Escape,
            Some(base),
            "path base is outside the workspace root",
        ));
    }
    let candidate = lexical_normalize(&base.join(relative))?;
    if !candidate.starts_with(&root) {
        return Err(WorkspaceError::new(
            WorkspaceErrorKind::Escape,
            Some(candidate),
            "relative path escapes the workspace root",
        ));
    }
    verify_no_symlink_descendant(&root, &candidate)?;
    let metadata = fs::symlink_metadata(&candidate)
        .map_err(|error| WorkspaceError::io("inspect directory", &candidate, &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unsafe_path(
            &candidate,
            "workspace path must resolve to a non-symlink directory",
        ));
    }
    let canonical = fs::canonicalize(&candidate)
        .map_err(|error| WorkspaceError::io("canonicalize directory", &candidate, &error))?;
    if canonical != candidate {
        return Err(unsafe_path(
            &candidate,
            "workspace path resolves through a filesystem alias",
        ));
    }
    Ok(canonical)
}
fn verify_no_symlink_descendant(root: &Path, target: &Path) -> Result<(), WorkspaceError> {
    let relative = target.strip_prefix(root).map_err(|_| {
        WorkspaceError::new(
            WorkspaceErrorKind::Escape,
            Some(target.to_path_buf()),
            "path is outside the workspace root",
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::Escape,
                Some(target.to_path_buf()),
                "normalized workspace path contains a non-normal component",
            ));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            WorkspaceError::io("inspect workspace path component", &current, &error)
        })?;
        if metadata.file_type().is_symlink() {
            return Err(unsafe_path(
                &current,
                "workspace paths must not traverse symlinks",
            ));
        }
    }
    Ok(())
}
fn verify_discovery_ancestors(path: &Path) -> Result<(), WorkspaceError> {
    let absolute = if path.is_absolute() {
        lexical_normalize(path)?
    } else {
        let current = std::env::current_dir()
            .map_err(|error| WorkspaceError::io("read current directory", path, &error))?;
        lexical_normalize(&current.join(path))?
    };
    let mut current = PathBuf::new();
    let mut normal_depth = 0_usize;
    for component in absolute.components() {
        current.push(component.as_os_str());
        if !matches!(component, Component::Normal(_)) {
            continue;
        }
        normal_depth += 1;
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            WorkspaceError::io("inspect discovery path component", &current, &error)
        })?;
        // macOS exposes stable top-level aliases such as `/var` -> `/private/var`.
        // Treat that platform root mapping as an anchor, but reject every
        // project-level symlink below it.
        if metadata.file_type().is_symlink() && normal_depth > 1 {
            return Err(unsafe_path(
                &current,
                "discovery paths must not traverse project-level symlinks",
            ));
        }
    }
    Ok(())
}
fn lexical_normalize(path: &Path) -> Result<PathBuf, WorkspaceError> {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => output.push(prefix.as_os_str()),
            Component::RootDir => output.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                if !output.pop() {
                    return Err(WorkspaceError::new(
                        WorkspaceErrorKind::Escape,
                        Some(path.to_path_buf()),
                        "path traversal underflows the filesystem root",
                    ));
                }
            }
            Component::Normal(component) => output.push(component),
        }
    }
    Ok(output)
}
fn portable_from_relative_path(path: &Path) -> Result<PortablePath, WorkspaceError> {
    if path.as_os_str().is_empty() {
        return PortablePath::new(".").map_err(|error| {
            WorkspaceError::new(WorkspaceErrorKind::Membership, None, error.to_string())
        });
    }
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::Membership,
                Some(path.to_path_buf()),
                "workspace-relative path is not portable",
            ));
        };
        components.push(component.to_str().ok_or_else(|| {
            WorkspaceError::new(
                WorkspaceErrorKind::Membership,
                Some(path.to_path_buf()),
                "workspace-relative path is not UTF-8",
            )
        })?);
    }
    PortablePath::new(&components.join("/")).map_err(|error| {
        WorkspaceError::new(
            WorkspaceErrorKind::Membership,
            Some(path.to_path_buf()),
            error.to_string(),
        )
    })
}
fn path_is_excluded(path: &PortablePath, excludes: &[PortablePath]) -> bool {
    excludes.iter().any(|excluded| {
        path == excluded
            || (excluded.as_str() != "."
                && path
                    .as_str()
                    .strip_prefix(excluded.as_str())
                    .is_some_and(|suffix| suffix.starts_with('/')))
    })
}
fn unsafe_path(path: &Path, message: impl Into<String>) -> WorkspaceError {
    WorkspaceError::new(
        WorkspaceErrorKind::UnsafeFilesystem,
        Some(path.to_path_buf()),
        message,
    )
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write as _;
    #[cfg(unix)]
    use std::process::Command;
    use tempfile::TempDir;
    const ROOT: &str = r#"manifest-version = 1
[workspace]
members = ["packages/app", "packages/lib"]
default-members = ["packages/app"]

[workspace.package]
namespace = "apps.sora"
version = "1.2.0"
edition = "1"
abi-version = 1
license = "Apache-2.0"

[workspace.dependencies]
lib = { path = "packages/lib", package = "apps.sora/lib", version = "^1.0.0" }
"#;
    const APP: &str = r#"manifest-version = 1
[package]
namespace = { workspace = true }
name = "app"
version = { workspace = true }
edition = { workspace = true }
abi-version = { workspace = true }
license = { workspace = true }
[lib]
source-dir = "src"
exports = ["run"]
[dependencies]
lib = { workspace = true }
[dev-dependencies]
fixture = { path = "../lib" }
"#;
    const LIB: &str = r#"manifest-version = 1
[package]
namespace = { workspace = true }
name = "lib"
version = "1.1.0"
edition = { workspace = true }
abi-version = { workspace = true }
[lib]
exports = ["value"]
"#;
    const STANDALONE: &str = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "standalone"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
exports = []
"#;
    fn write_file(path: &Path, body: &str) {
        fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        let mut file = fs::File::create(path).expect("create file");
        file.write_all(body.as_bytes()).expect("write file");
        file.sync_all().expect("sync file");
    }
    fn fixture() -> TempDir {
        let temp = TempDir::new().expect("temporary directory");
        write_file(&temp.path().join(MANIFEST_FILE_NAME), ROOT);
        write_file(
            &temp.path().join("packages/app").join(MANIFEST_FILE_NAME),
            APP,
        );
        write_file(
            &temp.path().join("packages/lib").join(MANIFEST_FILE_NAME),
            LIB,
        );
        fs::create_dir_all(temp.path().join("packages/app/src")).expect("app source");
        temp
    }
    #[test]
    fn discovers_ancestor_and_owning_workspace() {
        let temp = fixture();
        let nested = temp.path().join("packages/app/src");
        let canonical_root = fs::canonicalize(temp.path()).expect("canonical fixture root");
        assert_eq!(
            discover_manifest(&nested).expect("nearest"),
            canonical_root.join("packages/app/Musubi.toml")
        );
        assert_eq!(
            discover_workspace_manifest(&nested).expect("workspace"),
            canonical_root.join(MANIFEST_FILE_NAME)
        );
    }
    #[test]
    fn selected_root_and_member_use_the_same_workspace_inheritance_and_selection() {
        let temp = fixture();
        let ordinary = load_workspace(temp.path()).expect("ordinary workspace");
        for path in ["Musubi.toml", "packages/app/Musubi.toml"] {
            let selected = iroha_fs::SelectedRegularFile::capture(temp.path().join(path))
                .expect("native selected manifest");
            for _ in 0..2 {
                let workspace =
                    load_workspace_from_selected(&selected).expect("selected workspace");
                assert_eq!(
                    workspace.root_manifest_path(),
                    ordinary.root_manifest_path()
                );
                assert_eq!(workspace.metadata(), ordinary.metadata());
                assert_eq!(workspace.default_members(), ordinary.default_members());
                assert!(!workspace.is_synthetic());
                selected
                    .revalidate()
                    .expect("original selected manifest retained");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn selected_member_retains_its_original_and_reads_other_dependency_manifests_fresh() {
        let temp = fixture();
        let path = temp.path().join("packages/app/Musubi.toml");
        let selected =
            iroha_fs::SelectedRegularFile::capture(&path).expect("native selected member");
        let original = load_workspace_from_selected(&selected).expect("original workspace");
        let library = PortablePath::new("packages/lib").expect("library path");
        assert_eq!(
            original.members()[&library].package.version.to_string(),
            "1.1.0"
        );
        write_file(
            &temp.path().join("packages/lib/Musubi.toml"),
            &LIB.replace("1.1.0", "1.2.0"),
        );
        let fresh = load_workspace_from_selected(&selected).expect("fresh independent dependency");
        assert_eq!(
            fresh.members()[&library].package.version.to_string(),
            "1.2.0"
        );
        selected.revalidate().expect("original member unchanged");
        write_file(&path, &APP.replace("name = \"app\"", "name = \"changed\""));
        let error =
            load_workspace_from_selected(&selected).expect_err("changed original member refuses");
        assert_eq!(error.kind(), WorkspaceErrorKind::Io);
        assert!(selected.revalidate().is_err());
    }

    #[test]
    fn loads_inheritance_and_keeps_dev_dependencies_nontransitive() {
        let temp = fixture();
        let workspace = load_workspace(&temp.path().join("packages/app/src")).expect("workspace");
        assert!(!workspace.is_synthetic());
        assert_eq!(workspace.members().len(), 2);
        assert_eq!(
            workspace
                .default_members()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["packages/app"]
        );
        let app = workspace
            .members()
            .get(&PortablePath::new("packages/app").expect("path"))
            .expect("app");
        let canonical_root = fs::canonicalize(temp.path()).expect("canonical fixture root");
        assert_eq!(app.package.selector.to_string(), "apps.sora/app");
        assert_eq!(app.package.version.to_string(), "1.2.0");
        assert_eq!(app.package.license.as_deref(), Some("Apache-2.0"));
        assert_eq!(app.dependencies["lib"].defined_in, canonical_root);
        assert_eq!(
            app.dependencies["lib"].local_manifest.as_deref(),
            Some(canonical_root.join("packages/lib/Musubi.toml").as_path())
        );
        assert_eq!(
            app.dev_dependencies["fixture"].kind,
            DependencyKind::Development
        );
        assert!(
            workspace.members()[&PortablePath::new("packages/lib").expect("path")]
                .dev_dependencies
                .is_empty()
        );
    }
    #[test]
    fn loads_reachable_nonmember_path_package_without_workspace_inheritance() {
        let temp = fixture();
        let helper = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "helper"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
exports = ["help"]
[dependencies]
lib = { path = "../lib", package = "apps.sora/lib", version = "^1.0.0" }
"#;
        write_file(&temp.path().join("packages/helper/Musubi.toml"), helper);
        let workspace = load_workspace(temp.path()).expect("workspace");
        let root = fs::canonicalize(temp.path()).expect("canonical root");
        let package = workspace
            .load_path_package(&root.join("packages/helper/Musubi.toml"))
            .expect("reachable standalone path package");
        assert_eq!(package.package.selector.to_string(), "apps.sora/helper");
        assert_eq!(
            package.dependencies["lib"].local_manifest.as_deref(),
            Some(root.join("packages/lib/Musubi.toml").as_path())
        );
        let inherited = helper.replace("version = \"1.0.0\"", "version = { workspace = true }");
        write_file(&temp.path().join("packages/helper/Musubi.toml"), &inherited);
        assert_eq!(
            workspace
                .load_path_package(&root.join("packages/helper/Musubi.toml"))
                .expect_err("nonmember inheritance must fail")
                .kind(),
            WorkspaceErrorKind::Manifest
        );
    }
    #[test]
    fn metadata_and_selection_are_deterministic() {
        let temp = fixture();
        let workspace = load_workspace(temp.path()).expect("workspace");
        let metadata = workspace.metadata();
        assert_eq!(
            metadata
                .members
                .iter()
                .map(|member| member.path.as_str())
                .collect::<Vec<_>>(),
            ["packages/app", "packages/lib"]
        );
        let defaults = workspace.select_members(false, &[], &[]).expect("defaults");
        assert_eq!(defaults.len(), 1);
        assert_eq!(defaults[0].package.selector.to_string(), "apps.sora/app");
        let all = workspace.select_members(true, &[], &[]).expect("all");
        assert_eq!(all.len(), 2);
        let exclude = ["apps.sora/lib".parse().expect("selector")];
        assert_eq!(
            workspace
                .select_members(true, &[], &exclude)
                .expect("exclude")
                .len(),
            1
        );
    }
    #[test]
    fn rejects_path_escape_and_declared_identity_mismatch() {
        let temp = fixture();
        let escaped = APP.replace("../lib", "../../../outside");
        write_file(&temp.path().join("packages/app/Musubi.toml"), &escaped);
        assert_eq!(
            load_workspace(temp.path()).expect_err("escape").kind(),
            WorkspaceErrorKind::Escape
        );
        write_file(&temp.path().join("packages/app/Musubi.toml"), APP);
        let mismatch = ROOT.replace("apps.sora/lib", "apps.sora/other");
        write_file(&temp.path().join(MANIFEST_FILE_NAME), &mismatch);
        assert_eq!(
            load_workspace(temp.path())
                .expect_err("identity mismatch")
                .kind(),
            WorkspaceErrorKind::Dependency
        );
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_members_and_manifests() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::new().expect("temporary directory");
        write_file(&temp.path().join(MANIFEST_FILE_NAME), ROOT);
        let outside = TempDir::new().expect("outside");
        write_file(&outside.path().join(MANIFEST_FILE_NAME), APP);
        fs::create_dir_all(temp.path().join("packages")).expect("packages");
        symlink(outside.path(), temp.path().join("packages/app")).expect("member symlink");
        fs::create_dir_all(temp.path().join("packages/lib")).expect("lib dir");
        write_file(&temp.path().join("packages/lib/Musubi.toml"), LIB);
        assert_eq!(
            load_workspace(temp.path())
                .expect_err("symlinked member")
                .kind(),
            WorkspaceErrorKind::UnsafeFilesystem
        );
    }
    #[test]
    fn manifest_reader_accepts_a_bounded_regular_leaf() {
        let temp = TempDir::new().expect("temporary directory");
        let manifest = temp.path().join(MANIFEST_FILE_NAME);
        write_file(&manifest, STANDALONE);
        let parsed = read_manifest(&manifest).expect("bounded regular manifest");
        assert_eq!(parsed.schema_version, 1);
        assert!(parsed.package.is_some());
    }
    #[cfg(unix)]
    #[test]
    fn manifest_reader_rejects_a_raced_regular_replacement() {
        let temp = TempDir::new().expect("temporary directory");
        let manifest = temp.path().join(MANIFEST_FILE_NAME);
        let replacement = temp.path().join("replacement.toml");
        write_file(&manifest, STANDALONE);
        write_file(&replacement, STANDALONE);
        let error = read_manifest_with_reader(&manifest, |path, maximum| {
            crate::local_file::read_bounded_single_link_regular_file_with_hook_v1(
                path,
                maximum,
                |path| {
                    fs::remove_file(path)?;
                    fs::rename(&replacement, path)
                },
            )
        })
        .expect_err("raced manifest replacement must fail");
        assert_eq!(error.kind(), WorkspaceErrorKind::Io);
    }
    #[cfg(unix)]
    #[test]
    fn manifest_reader_rejects_a_raced_fifo_without_blocking() {
        let temp = TempDir::new().expect("temporary directory");
        let manifest = temp.path().join(MANIFEST_FILE_NAME);
        write_file(&manifest, STANDALONE);
        let error = read_manifest_with_reader(&manifest, |path, maximum| {
            crate::local_file::read_bounded_single_link_regular_file_with_hook_v1(
                path,
                maximum,
                |path| {
                    fs::remove_file(path)?;
                    let status = Command::new("mkfifo").arg(path).status()?;
                    if !status.success() {
                        return Err(io::Error::other("mkfifo failed"));
                    }
                    Ok(())
                },
            )
        })
        .expect_err("raced FIFO manifest must fail without hanging");
        assert_eq!(error.kind(), WorkspaceErrorKind::Io);
    }
    #[test]
    fn manifest_reader_rejects_hardlinked_and_oversized_leaves() {
        let temp = TempDir::new().expect("temporary directory");
        let manifest = temp.path().join(MANIFEST_FILE_NAME);
        let alias = temp.path().join("Musubi.alias.toml");
        write_file(&manifest, STANDALONE);
        fs::hard_link(&manifest, &alias).expect("create manifest hard link");
        assert_eq!(
            read_manifest(&manifest)
                .expect_err("hardlinked manifest must fail")
                .kind(),
            WorkspaceErrorKind::Io
        );
        fs::remove_file(&alias).expect("remove hard link");
        fs::File::create(&manifest)
            .expect("replace manifest")
            .set_len(MAX_MANIFEST_BYTES + 1)
            .expect("extend sparse manifest");
        assert_eq!(
            read_manifest(&manifest)
                .expect_err("oversized manifest must fail")
                .kind(),
            WorkspaceErrorKind::Manifest
        );
    }
    #[test]
    fn excluded_nested_package_is_standalone() {
        let temp = TempDir::new().expect("temporary directory");
        let root = ROOT
            .replace(
                "members = [\"packages/app\", \"packages/lib\"]",
                "members = []\nexclude = [\"vendor\"]",
            )
            .replace("default-members = [\"packages/app\"]\n", "");
        write_file(&temp.path().join(MANIFEST_FILE_NAME), &root);
        write_file(&temp.path().join("vendor/tool/Musubi.toml"), LIB);
        assert_eq!(
            discover_workspace_manifest(&temp.path().join("vendor/tool"))
                .expect("excluded package"),
            fs::canonicalize(temp.path())
                .expect("canonical fixture root")
                .join("vendor/tool/Musubi.toml")
        );
    }
    #[test]
    fn standalone_package_gets_synthetic_workspace() {
        let temp = TempDir::new().expect("temporary directory");
        write_file(&temp.path().join(MANIFEST_FILE_NAME), STANDALONE);
        let workspace = load_workspace(temp.path()).expect("standalone");
        assert!(workspace.is_synthetic());
        assert_eq!(workspace.members().len(), 1);
        assert!(
            workspace
                .members()
                .contains_key(&PortablePath::new(".").expect("dot"))
        );
    }

    #[test]
    fn contract_only_roots_load_but_cannot_be_imported_as_path_libraries() {
        let temp = TempDir::new().expect("workspace directory");
        let contract = include_str!("../../../examples/coffee-club/Musubi.toml");
        write_file(&temp.path().join("app/Musubi.toml"), contract);
        assert!(load_workspace(&temp.path().join("app")).is_ok());
        write_file(
            &temp.path().join("Musubi.toml"),
            &format!("{STANDALONE}\n[dependencies]\napp = {{ path = \"app\" }}\n"),
        );
        let error = load_workspace(temp.path()).expect_err("contract is not an importable library");
        assert_eq!(error.kind(), WorkspaceErrorKind::Dependency);
        assert!(error.message().contains("contract-only package"));
        assert!(error.message().contains("app"));
    }
}
