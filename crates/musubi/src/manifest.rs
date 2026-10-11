//! Strict parsing and focused editing for the Musubi V1 package manifest.
//!
//! The parser intentionally has no compatibility mode. Every table is closed,
//! `manifest-version = 1` is mandatory, and values are converted immediately
//! into the structured Musubi data-model types used by resolution and
//! publication.
use iroha_data_model::musubi::{
    MUSUBI_IVM_ABI_VERSION_V1, MUSUBI_MAX_DEPENDENCIES_V1, MUSUBI_MAX_EXPORTS_V1,
    MUSUBI_MAX_KEYWORDS_V1, MusubiKotodamaEditionV1, MusubiNamespaceV1, MusubiPackageNameV1,
    MusubiPackageSelectorV1, MusubiVersionReqV1, MusubiVersionV1,
};
use iroha_model_base::name::Name;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::PathBuf,
    str::FromStr,
};
/// Filename of a first-release Musubi manifest.
pub const MANIFEST_FILE_NAME: &str = "Musubi.toml";
/// Only manifest schema accepted by this implementation.
pub const MANIFEST_VERSION_V1: u32 = 1;
const MAX_DESCRIPTION_BYTES: usize = 4_096;
const MAX_LICENSE_BYTES: usize = 256;
const MAX_REPOSITORY_BYTES: usize = 2_048;
const MAX_KEYWORD_BYTES: usize = 64;
const MAX_INCLUDE_PATHS: usize = 256;
const MAX_LOCAL_TARGETS: usize = 256;
const MAX_PORTABLE_PATH_BYTES: usize = 4_096;
const MAX_PORTABLE_COMPONENT_BYTES: usize = 255;
const MAX_PORTABLE_COMPONENTS: usize = 64;
/// Broad category of a manifest validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestErrorKind {
    /// The TOML document is malformed, including duplicate keys.
    Toml,
    /// The manifest schema marker is absent or unsupported.
    Version,
    /// A closed table contains an unknown or deliberately unsupported field.
    UnknownField,
    /// A required field is absent.
    MissingField,
    /// A field has the wrong type or a noncanonical value.
    InvalidField,
    /// A first-release collection or string bound was exceeded.
    Limit,
    /// A focused text edit could not be performed safely.
    Edit,
}
/// Structured error produced while parsing or editing `Musubi.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestError {
    kind: ManifestErrorKind,
    location: String,
    message: String,
}
impl ManifestError {
    fn new(
        kind: ManifestErrorKind,
        location: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            location: location.into(),
            message: message.into(),
        }
    }
    /// Return the stable error category.
    #[must_use]
    pub const fn kind(&self) -> ManifestErrorKind {
        self.kind
    }
    /// Return the dotted manifest location associated with the error.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }
    /// Return the human-readable reason without a path prefix.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}
impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.location.is_empty() {
            formatter.write_str(&self.message)
        } else {
            write!(formatter, "{}: {}", self.location, self.message)
        }
    }
}
impl Error for ManifestError {}
/// A normalized relative path whose spelling is safe on supported platforms.
///
/// Paths use `/`, contain no traversal components, drive prefixes, or portable
/// reserved names, and are compared byte-for-byte. The single spelling `.` is
/// retained for APIs that explicitly select a package or include root.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortablePath(String);
impl PortablePath {
    /// Parse and validate one canonical portable path.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when `raw` is not a canonical portable package path.
    pub fn new(raw: &str) -> Result<Self, ManifestError> {
        validate_portable_path(raw, false).map(Self)
    }
    /// Return the canonical slash-separated spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Convert to a platform path without changing its semantics.
    #[must_use]
    pub fn to_path_buf(&self) -> PathBuf {
        if self.0 == "." {
            return PathBuf::from(".");
        }
        self.0.split('/').collect()
    }
    /// Return a deterministic ASCII case-folded collision key.
    #[must_use]
    pub fn collision_key(&self) -> String {
        self.0.chars().flat_map(char::to_lowercase).collect()
    }
}
impl fmt::Display for PortablePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl FromStr for PortablePath {
    type Err = ManifestError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::new(raw)
    }
}
/// A portable relative dependency path.
///
/// Unlike package-content paths, dependency paths may contain `..` so a member
/// can refer to a sibling. Workspace loading normalizes the path and proves it
/// remains beneath the workspace root before any manifest is read.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DependencyPath(String);
impl DependencyPath {
    /// Parse a portable relative dependency path.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when `raw` is not a valid portable relative dependency path.
    pub fn new(raw: &str) -> Result<Self, ManifestError> {
        validate_portable_path(raw, true).map(Self)
    }
    /// Return the slash-separated source spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Convert to a platform-relative path.
    #[must_use]
    pub fn to_path_buf(&self) -> PathBuf {
        if self.0 == "." {
            return PathBuf::from(".");
        }
        self.0.split('/').collect()
    }
}
impl fmt::Display for DependencyPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl FromStr for DependencyPath {
    type Err = ManifestError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::new(raw)
    }
}
/// A value either written locally or explicitly inherited from the workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inheritable<T> {
    /// Concrete value written in this package manifest.
    Value(T),
    /// `{ workspace = true }` marker.
    Workspace,
}
impl<T> Inheritable<T> {
    /// Return the concrete local value, if this field is not inherited.
    #[must_use]
    pub const fn local(&self) -> Option<&T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Workspace => None,
        }
    }
    /// Return whether the field explicitly inherits from its workspace.
    #[must_use]
    pub const fn is_workspace(&self) -> bool {
        matches!(self, Self::Workspace)
    }
}
/// Package identity, compiler binding, and immutable descriptive metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageManifest {
    /// Namespace or an explicit workspace inheritance marker.
    pub namespace: Inheritable<MusubiNamespaceV1>,
    /// Canonical package-name segment. Names are never inherited.
    pub name: MusubiPackageNameV1,
    /// Structured package version or workspace inheritance marker.
    pub version: Inheritable<MusubiVersionV1>,
    /// Kotodama source edition. V1 is the sole accepted value.
    pub edition: Inheritable<MusubiKotodamaEditionV1>,
    /// IVM ABI version. V1 is the sole accepted value.
    pub abi_version: Inheritable<u16>,
    /// Optional bounded description.
    pub description: Option<Inheritable<String>>,
    /// Optional readme file selected into a package.
    pub readme: Option<Inheritable<PortablePath>>,
    /// Optional SPDX-like license metadata.
    pub license: Option<Inheritable<String>>,
    /// Optional license file selected into a package.
    pub license_file: Option<Inheritable<PortablePath>>,
    /// Optional canonical HTTP(S) source repository URL.
    pub repository: Option<Inheritable<String>>,
    /// Optional canonical keyword set.
    pub keywords: Option<Inheritable<Vec<String>>>,
    /// Optional positive additions to the package file set.
    pub include: Option<Inheritable<Vec<PortablePath>>>,
}
/// Concrete package metadata after workspace inheritance is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPackageManifest {
    /// Canonical user-facing package selector.
    pub selector: MusubiPackageSelectorV1,
    /// Structured exact package version.
    pub version: MusubiVersionV1,
    /// Kotodama source edition.
    pub edition: MusubiKotodamaEditionV1,
    /// IVM ABI version.
    pub abi_version: u16,
    /// Optional bounded description.
    pub description: Option<String>,
    /// Optional readme file.
    pub readme: Option<PortablePath>,
    /// Optional license metadata.
    pub license: Option<String>,
    /// Optional license file.
    pub license_file: Option<PortablePath>,
    /// Optional source repository URL.
    pub repository: Option<String>,
    /// Sorted package keywords.
    pub keywords: Vec<String>,
    /// Sorted positive include additions.
    pub include: Vec<PortablePath>,
}
/// Shared concrete values available to package manifests in a workspace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkspacePackageDefaults {
    /// Shared namespace.
    pub namespace: Option<MusubiNamespaceV1>,
    /// Shared structured version.
    pub version: Option<MusubiVersionV1>,
    /// Shared Kotodama edition.
    pub edition: Option<MusubiKotodamaEditionV1>,
    /// Shared IVM ABI version.
    pub abi_version: Option<u16>,
    /// Shared description.
    pub description: Option<String>,
    /// Shared readme path, relative to the workspace root.
    pub readme: Option<PortablePath>,
    /// Shared license metadata.
    pub license: Option<String>,
    /// Shared license-file path, relative to the workspace root.
    pub license_file: Option<PortablePath>,
    /// Shared source repository URL.
    pub repository: Option<String>,
    /// Shared canonical keyword set.
    pub keywords: Option<Vec<String>>,
    /// Shared positive include additions, relative to the workspace root.
    pub include: Option<Vec<PortablePath>>,
}
/// Local Kotodama library configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryManifest {
    /// Directory containing library sources, relative to the package root.
    pub source_dir: PortablePath,
    /// Sorted, explicit exported interface names.
    pub exports: Vec<Name>,
}
/// One local contract or test target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalTarget {
    /// Parent-local target name.
    pub name: Name,
    /// One `.ko` contract source, or a test source/directory, relative to the package root.
    pub path: PortablePath,
}
/// Concrete registry or local path dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConcreteDependency {
    /// Registry range for one canonical namespaced package.
    Registry {
        /// Canonical package selector. The parent table key remains the import alias.
        package: MusubiPackageSelectorV1,
        /// Canonical structured `SemVer` requirement.
        requirement: MusubiVersionReqV1,
    },
    /// Validated local package path, optionally paired with its publish-time registry identity.
    Path {
        /// Relative path to a directory containing `Musubi.toml`.
        path: DependencyPath,
        /// Canonical registry identity required when publishing a normal dependency.
        package: Option<MusubiPackageSelectorV1>,
        /// Registry requirement paired with `package`.
        requirement: Option<MusubiVersionReqV1>,
    },
}
impl ConcreteDependency {
    /// Return the registry package and range usable in a published normal dependency.
    ///
    /// # Errors
    ///
    /// Returns an error when a local-only path dependency has no registry identity.
    pub fn publication_requirement(
        &self,
    ) -> Result<(&MusubiPackageSelectorV1, &MusubiVersionReqV1), ManifestError> {
        match self {
            Self::Registry {
                package,
                requirement,
            }
            | Self::Path {
                package: Some(package),
                requirement: Some(requirement),
                ..
            } => Ok((package, requirement)),
            Self::Path { .. } => Err(ManifestError::new(
                ManifestErrorKind::InvalidField,
                "dependencies",
                "a publishable normal path dependency must declare both `package` and `version`",
            )),
        }
    }
}
/// Dependency declaration before workspace inheritance is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DependencySpec {
    /// A concrete registry or path dependency.
    Concrete(ConcreteDependency),
    /// Exact `{ workspace = true }` inheritance marker.
    Workspace,
}
/// Which dependency table a focused edit should modify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencySection {
    /// `[dependencies]`.
    Normal,
    /// `[dev-dependencies]`.
    Development,
    /// `[workspace.dependencies]`.
    Workspace,
}
impl DependencySection {
    fn header(self) -> &'static str {
        match self {
            Self::Normal => "dependencies",
            Self::Development => "dev-dependencies",
            Self::Workspace => "workspace.dependencies",
        }
    }
}
/// Workspace membership and shared package/dependency declarations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceManifest {
    /// Explicit member directories relative to the workspace root.
    pub members: Vec<PortablePath>,
    /// Optional explicit default-member set.
    pub default_members: Option<Vec<PortablePath>>,
    /// Member paths omitted from the workspace.
    pub exclude: Vec<PortablePath>,
    /// Concrete values inherited by member package sections.
    pub package: WorkspacePackageDefaults,
    /// Concrete dependencies inherited by alias.
    pub dependencies: BTreeMap<Name, ConcreteDependency>,
}
/// Fully validated syntax tree for a first-release `Musubi.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// Always [`MANIFEST_VERSION_V1`].
    pub schema_version: u32,
    /// Package section, absent only for virtual workspace roots.
    pub package: Option<PackageManifest>,
    /// Library configuration, absent only for virtual workspace roots.
    pub library: Option<LibraryManifest>,
    /// Sorted local contract targets.
    pub contracts: Vec<LocalTarget>,
    /// Sorted local test targets.
    pub tests: Vec<LocalTarget>,
    /// Normal dependency declarations keyed by parent-local alias.
    pub dependencies: BTreeMap<Name, DependencySpec>,
    /// Root-local development dependencies keyed by parent-local alias.
    pub dev_dependencies: BTreeMap<Name, DependencySpec>,
    /// Optional workspace declaration.
    pub workspace: Option<WorkspaceManifest>,
    /// Lint levels from `[lints]`: lint slugs mapped to `"allow"`, `"warn"` or `"deny"`, plus the
    /// optional `deny-warnings = true`. A package without `[lints]` uses its workspace root's.
    pub lints: Option<kotodama_lang::session::LintConfig>,
}
impl Manifest {
    /// Return whether this document is a virtual workspace root.
    #[must_use]
    pub fn is_virtual_workspace(&self) -> bool {
        self.package.is_none() && self.workspace.is_some()
    }
    /// Resolve all package fields against optional workspace defaults.
    ///
    /// # Errors
    ///
    /// Returns an error for a virtual manifest or an inheritance marker whose
    /// corresponding workspace value is absent.
    pub fn resolve_package(
        &self,
        defaults: Option<&WorkspacePackageDefaults>,
    ) -> Result<ResolvedPackageManifest, ManifestError> {
        let package = self.package.as_ref().ok_or_else(|| {
            ManifestError::new(
                ManifestErrorKind::MissingField,
                "package",
                "virtual workspace roots do not define a package",
            )
        })?;
        let namespace = resolve_required(
            "package.namespace",
            &package.namespace,
            defaults.and_then(|value| value.namespace.as_ref()),
        )?;
        let version = resolve_required(
            "package.version",
            &package.version,
            defaults.and_then(|value| value.version.as_ref()),
        )?;
        let edition = resolve_required(
            "package.edition",
            &package.edition,
            defaults.and_then(|value| value.edition.as_ref()),
        )?;
        let abi_version = resolve_required(
            "package.abi-version",
            &package.abi_version,
            defaults.and_then(|value| value.abi_version.as_ref()),
        )?;
        Ok(ResolvedPackageManifest {
            selector: MusubiPackageSelectorV1 {
                namespace,
                name: package.name.clone(),
            },
            version,
            edition,
            abi_version,
            description: resolve_optional(
                "package.description",
                package.description.as_ref(),
                defaults.and_then(|value| value.description.as_ref()),
            )?,
            readme: resolve_optional(
                "package.readme",
                package.readme.as_ref(),
                defaults.and_then(|value| value.readme.as_ref()),
            )?,
            license: resolve_optional(
                "package.license",
                package.license.as_ref(),
                defaults.and_then(|value| value.license.as_ref()),
            )?,
            license_file: resolve_optional(
                "package.license-file",
                package.license_file.as_ref(),
                defaults.and_then(|value| value.license_file.as_ref()),
            )?,
            repository: resolve_optional(
                "package.repository",
                package.repository.as_ref(),
                defaults.and_then(|value| value.repository.as_ref()),
            )?,
            keywords: resolve_optional(
                "package.keywords",
                package.keywords.as_ref(),
                defaults.and_then(|value| value.keywords.as_ref()),
            )?
            .unwrap_or_default(),
            include: resolve_optional(
                "package.include",
                package.include.as_ref(),
                defaults.and_then(|value| value.include.as_ref()),
            )?
            .unwrap_or_default(),
        })
    }
}
/// Parse and fully validate one Musubi V1 manifest document.
///
/// The TOML parser rejects duplicate keys before semantic validation. Every
/// table is subsequently checked against a closed field set.
///
/// # Errors
///
/// Returns a structured error for malformed TOML, duplicates, unknown fields,
/// unsupported V1 constructs, type mismatches, noncanonical values, or bounds.
pub fn parse_manifest(source: &str) -> Result<Manifest, ManifestError> {
    let root = source.parse::<toml::Table>().map_err(|error| {
        ManifestError::new(
            ManifestErrorKind::Toml,
            "Musubi.toml",
            format!("invalid or duplicate TOML: {error}"),
        )
    })?;
    reject_unsupported_root_fields(&root)?;
    reject_unknown(
        &root,
        &[
            "manifest-version",
            "package",
            "lib",
            "contract",
            "test",
            "dependencies",
            "dev-dependencies",
            "workspace",
            "lints",
        ],
        "",
    )?;
    let manifest_version = required_integer(&root, "manifest-version", "manifest-version")?;
    if manifest_version != i64::from(MANIFEST_VERSION_V1) {
        return Err(ManifestError::new(
            ManifestErrorKind::Version,
            "manifest-version",
            "`manifest-version = 1` is required; pre-release manifests are not supported",
        ));
    }
    let package = root
        .get("package")
        .map(|value| parse_package(required_value_table(value, "package")?))
        .transpose()?;
    let library = root
        .get("lib")
        .map(|value| parse_library(required_value_table(value, "lib")?))
        .transpose()?;
    let contracts = parse_targets(root.get("contract"), "contract")?;
    let tests = parse_targets(root.get("test"), "test")?;
    let dependencies = parse_dependency_table(root.get("dependencies"), "dependencies", true)?;
    let dev_dependencies =
        parse_dependency_table(root.get("dev-dependencies"), "dev-dependencies", true)?;
    let workspace = root
        .get("workspace")
        .map(|value| parse_workspace(required_value_table(value, "workspace")?))
        .transpose()?;
    let lints = root
        .get("lints")
        .map(|value| parse_lints(required_value_table(value, "lints")?))
        .transpose()?;
    match (&package, &workspace) {
        (None, None) => {
            return Err(ManifestError::new(
                ManifestErrorKind::MissingField,
                "package",
                "a manifest must define `[package]` or `[workspace]`",
            ));
        }
        (None, Some(_)) => {
            if library.is_some()
                || !contracts.is_empty()
                || !tests.is_empty()
                || !dependencies.is_empty()
                || !dev_dependencies.is_empty()
            {
                return Err(ManifestError::new(
                    ManifestErrorKind::InvalidField,
                    "Musubi.toml",
                    "a virtual workspace root cannot define library, targets, or package dependencies",
                ));
            }
        }
        (Some(_), _) if library.is_none() && contracts.is_empty() => {
            return Err(ManifestError::new(
                ManifestErrorKind::MissingField,
                "package",
                "package manifests require a `[lib]` or at least one `[[contract]]` target",
            ));
        }
        (Some(_), _) => {}
    }
    Ok(Manifest {
        schema_version: MANIFEST_VERSION_V1,
        package,
        library,
        contracts,
        tests,
        dependencies,
        dev_dependencies,
        workspace,
        lints,
    })
}
/// Parse `[lints]`: every key is a registered lint slug (or `deny-warnings`), so a misspelled
/// lint fails closed with the closest known name instead of being ignored.
fn parse_lints(table: &toml::Table) -> Result<kotodama_lang::session::LintConfig, ManifestError> {
    let mut config = kotodama_lang::session::LintConfig::new();
    for (key, value) in table {
        let location = format!("lints.{key}");
        if key == "deny-warnings" {
            let deny = value.as_bool().ok_or_else(|| {
                ManifestError::new(
                    ManifestErrorKind::InvalidField,
                    &location,
                    "`deny-warnings` must be `true` or `false`",
                )
            })?;
            config.set_deny_warnings(deny);
            continue;
        }
        let level = value
            .as_str()
            .and_then(kotodama_lang::lint::LintLevel::parse)
            .ok_or_else(|| {
                ManifestError::new(
                    ManifestErrorKind::InvalidField,
                    &location,
                    "a lint level must be \"allow\", \"warn\", or \"deny\"",
                )
            })?;
        config.set_level(key, level).map_err(|unknown| {
            ManifestError::new(
                ManifestErrorKind::UnknownField,
                &location,
                unknown.to_string(),
            )
        })?;
    }
    Ok(config)
}
/// Add or replace one dependency through a span-focused text edit.
///
/// Existing comments and all unrelated bytes are preserved. A missing table is
/// appended without serializing the rest of the document.
///
/// # Errors
///
/// Returns an error if the input manifest is invalid, the alias is invalid, an inherited dependency
/// is requested in `[workspace.dependencies]`, or a targeted entry uses a multiline/table form that
/// cannot be replaced without touching unrelated text.
pub fn upsert_dependency(
    source: &str,
    section: DependencySection,
    alias: &str,
    dependency: &DependencySpec,
) -> Result<String, ManifestError> {
    parse_manifest(source)?;
    let alias = parse_alias(alias, "dependency alias")?;
    if section == DependencySection::Workspace && matches!(dependency, DependencySpec::Workspace) {
        return Err(ManifestError::new(
            ManifestErrorKind::Edit,
            "workspace.dependencies",
            "workspace dependencies must be concrete",
        ));
    }
    let rendered = render_dependency(dependency);
    let edited = edit_dependency_line(source, section, alias.as_ref(), Some(&rendered))?;
    parse_manifest(&edited)?;
    Ok(edited)
}
/// Remove one dependency through a span-focused text edit.
///
/// # Errors
///
/// Returns an error if the manifest or alias is invalid, the selected table is absent, the alias is
/// absent, or the entry cannot be removed as one focused assignment line.
pub fn remove_dependency(
    source: &str,
    section: DependencySection,
    alias: &str,
) -> Result<String, ManifestError> {
    parse_manifest(source)?;
    let alias = parse_alias(alias, "dependency alias")?;
    let edited = edit_dependency_line(source, section, alias.as_ref(), None)?;
    parse_manifest(&edited)?;
    Ok(edited)
}
fn parse_package(table: &toml::Table) -> Result<PackageManifest, ManifestError> {
    reject_unknown(
        table,
        &[
            "namespace",
            "name",
            "version",
            "edition",
            "abi-version",
            "description",
            "readme",
            "license",
            "license-file",
            "repository",
            "keywords",
            "include",
        ],
        "package",
    )?;
    Ok(PackageManifest {
        namespace: parse_required_inheritable(table, "namespace", "package.namespace", |value| {
            parse_string(value, "package.namespace")?
                .parse()
                .map_err(|error| invalid("package.namespace", error))
        })?,
        name: parse_string(
            required_value(table, "name", "package.name")?,
            "package.name",
        )?
        .parse()
        .map_err(|error| invalid("package.name", error))?,
        version: parse_required_inheritable(table, "version", "package.version", |value| {
            parse_string(value, "package.version")?
                .parse()
                .map_err(|error| invalid("package.version", error))
        })?,
        edition: parse_required_inheritable(table, "edition", "package.edition", |value| {
            parse_edition(value, "package.edition")
        })?,
        abi_version: parse_required_inheritable(
            table,
            "abi-version",
            "package.abi-version",
            |value| parse_abi_version(value, "package.abi-version"),
        )?,
        description: parse_optional_inheritable(
            table,
            "description",
            "package.description",
            |value| parse_bounded_text(value, "package.description", MAX_DESCRIPTION_BYTES),
        )?,
        readme: parse_optional_inheritable(table, "readme", "package.readme", |value| {
            parse_portable_path(value, "package.readme")
        })?,
        license: parse_optional_inheritable(table, "license", "package.license", |value| {
            parse_bounded_text(value, "package.license", MAX_LICENSE_BYTES)
        })?,
        license_file: parse_optional_inheritable(
            table,
            "license-file",
            "package.license-file",
            |value| parse_portable_path(value, "package.license-file"),
        )?,
        repository: parse_optional_inheritable(
            table,
            "repository",
            "package.repository",
            parse_repository,
        )?,
        keywords: parse_optional_inheritable(
            table,
            "keywords",
            "package.keywords",
            parse_keywords,
        )?,
        include: parse_optional_inheritable(table, "include", "package.include", |value| {
            parse_path_array(value, "package.include", MAX_INCLUDE_PATHS)
        })?,
    })
}
fn parse_library(table: &toml::Table) -> Result<LibraryManifest, ManifestError> {
    reject_unknown(table, &["source-dir", "exports"], "lib")?;
    let source_dir = match table.get("source-dir") {
        Some(value) => parse_portable_path(value, "lib.source-dir")?,
        None => PortablePath::new("src")?,
    };
    let exports_value = required_value(table, "exports", "lib.exports")?;
    let mut exports = parse_name_array(exports_value, "lib.exports", MUSUBI_MAX_EXPORTS_V1)?;
    ensure_unique_names(&exports, "lib.exports")?;
    exports.sort();
    Ok(LibraryManifest {
        source_dir,
        exports,
    })
}
fn parse_targets(
    value: Option<&toml::Value>,
    field: &'static str,
) -> Result<Vec<LocalTarget>, ManifestError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| {
        ManifestError::new(
            ManifestErrorKind::InvalidField,
            field,
            "must be an array of tables",
        )
    })?;
    if values.len() > MAX_LOCAL_TARGETS {
        return Err(limit(field, MAX_LOCAL_TARGETS));
    }
    let mut targets = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let location = format!("{field}[{index}]");
        let table = required_value_table(value, &location)?;
        reject_unknown(table, &["name", "path"], &location)?;
        let name_location = format!("{location}.name");
        let path_location = format!("{location}.path");
        let name = parse_alias(
            parse_string(
                required_value(table, "name", &name_location)?,
                &name_location,
            )?,
            &name_location,
        )?;
        let path = parse_portable_path(
            required_value(table, "path", &path_location)?,
            &path_location,
        )?;
        #[expect(
            clippy::case_sensitive_file_extension_comparisons,
            reason = "portable Musubi contract targets require the canonical lowercase .ko suffix"
        )]
        if field == "contract" && !path.as_str().ends_with(".ko") {
            return Err(ManifestError::new(
                ManifestErrorKind::InvalidField,
                &path_location,
                "each named contract target must identify one `.ko` source file; directory targets are supported only for tests",
            ));
        }
        targets.push(LocalTarget { name, path });
    }
    ensure_unique_names(
        &targets
            .iter()
            .map(|target| target.name.clone())
            .collect::<Vec<_>>(),
        field,
    )?;
    targets.sort_by(|left, right| left.name.cmp(&right.name).then(left.path.cmp(&right.path)));
    Ok(targets)
}
fn parse_workspace(table: &toml::Table) -> Result<WorkspaceManifest, ManifestError> {
    reject_unknown(
        table,
        &[
            "members",
            "default-members",
            "exclude",
            "package",
            "dependencies",
        ],
        "workspace",
    )?;
    let members = table
        .get("members")
        .map(|value| parse_path_array(value, "workspace.members", MAX_INCLUDE_PATHS))
        .transpose()?
        .unwrap_or_default();
    let default_members = table
        .get("default-members")
        .map(|value| parse_path_array(value, "workspace.default-members", MAX_INCLUDE_PATHS))
        .transpose()?;
    let exclude = table
        .get("exclude")
        .map(|value| parse_path_array(value, "workspace.exclude", MAX_INCLUDE_PATHS))
        .transpose()?
        .unwrap_or_default();
    let package = table
        .get("package")
        .map(|value| parse_workspace_package(required_value_table(value, "workspace.package")?))
        .transpose()?
        .unwrap_or_default();
    let dependencies =
        parse_concrete_dependency_table(table.get("dependencies"), "workspace.dependencies")?;
    Ok(WorkspaceManifest {
        members,
        default_members,
        exclude,
        package,
        dependencies,
    })
}
fn parse_workspace_package(table: &toml::Table) -> Result<WorkspacePackageDefaults, ManifestError> {
    reject_unknown(
        table,
        &[
            "namespace",
            "version",
            "edition",
            "abi-version",
            "description",
            "readme",
            "license",
            "license-file",
            "repository",
            "keywords",
            "include",
        ],
        "workspace.package",
    )?;
    Ok(WorkspacePackageDefaults {
        namespace: parse_optional_string_value(table, "namespace", "workspace.package.namespace")?
            .map(|raw| {
                raw.parse()
                    .map_err(|error| invalid("workspace.package.namespace", error))
            })
            .transpose()?,
        version: parse_optional_string_value(table, "version", "workspace.package.version")?
            .map(|raw| {
                raw.parse()
                    .map_err(|error| invalid("workspace.package.version", error))
            })
            .transpose()?,
        edition: table
            .get("edition")
            .map(|value| parse_edition(value, "workspace.package.edition"))
            .transpose()?,
        abi_version: table
            .get("abi-version")
            .map(|value| parse_abi_version(value, "workspace.package.abi-version"))
            .transpose()?,
        description: table
            .get("description")
            .map(|value| {
                parse_bounded_text(
                    value,
                    "workspace.package.description",
                    MAX_DESCRIPTION_BYTES,
                )
            })
            .transpose()?,
        readme: table
            .get("readme")
            .map(|value| parse_portable_path(value, "workspace.package.readme"))
            .transpose()?,
        license: table
            .get("license")
            .map(|value| parse_bounded_text(value, "workspace.package.license", MAX_LICENSE_BYTES))
            .transpose()?,
        license_file: table
            .get("license-file")
            .map(|value| parse_portable_path(value, "workspace.package.license-file"))
            .transpose()?,
        repository: table
            .get("repository")
            .map(|value| parse_repository_at(value, "workspace.package.repository"))
            .transpose()?,
        keywords: table
            .get("keywords")
            .map(|value| parse_keywords_at(value, "workspace.package.keywords"))
            .transpose()?,
        include: table
            .get("include")
            .map(|value| parse_path_array(value, "workspace.package.include", MAX_INCLUDE_PATHS))
            .transpose()?,
    })
}
fn parse_dependency_table(
    value: Option<&toml::Value>,
    location: &'static str,
    allow_workspace: bool,
) -> Result<BTreeMap<Name, DependencySpec>, ManifestError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let table = required_value_table(value, location)?;
    if table.len() > MUSUBI_MAX_DEPENDENCIES_V1 {
        return Err(limit(location, MUSUBI_MAX_DEPENDENCIES_V1));
    }
    let mut result = BTreeMap::new();
    for (raw_alias, value) in table {
        let alias_location = format!("{location}.{raw_alias}");
        let alias = parse_alias(raw_alias, &alias_location)?;
        let dependency = parse_dependency(value, &alias_location, allow_workspace)?;
        result.insert(alias, dependency);
    }
    Ok(result)
}
fn parse_concrete_dependency_table(
    value: Option<&toml::Value>,
    location: &'static str,
) -> Result<BTreeMap<Name, ConcreteDependency>, ManifestError> {
    parse_dependency_table(value, location, false)?
        .into_iter()
        .map(|(alias, dependency)| match dependency {
            DependencySpec::Concrete(dependency) => Ok((alias, dependency)),
            DependencySpec::Workspace => Err(ManifestError::new(
                ManifestErrorKind::InvalidField,
                location,
                "workspace dependencies cannot inherit from themselves",
            )),
        })
        .collect()
}
fn parse_dependency(
    value: &toml::Value,
    location: &str,
    allow_workspace: bool,
) -> Result<DependencySpec, ManifestError> {
    let table = required_value_table(value, location)?;
    for unsupported in [
        "git",
        "optional",
        "features",
        "default-features",
        "build",
        "target",
    ] {
        if table.contains_key(unsupported) {
            return Err(ManifestError::new(
                ManifestErrorKind::UnknownField,
                format!("{location}.{unsupported}"),
                format!("`{unsupported}` dependencies are not supported in Musubi V1"),
            ));
        }
    }
    reject_unknown(
        table,
        &["workspace", "package", "version", "path"],
        location,
    )?;
    if table.contains_key("workspace") {
        if !allow_workspace {
            return Err(ManifestError::new(
                ManifestErrorKind::InvalidField,
                location,
                "workspace dependencies must be concrete",
            ));
        }
        if table.len() != 1 || table.get("workspace").and_then(toml::Value::as_bool) != Some(true) {
            return Err(ManifestError::new(
                ManifestErrorKind::InvalidField,
                location,
                "workspace inheritance must be exactly `{ workspace = true }`",
            ));
        }
        return Ok(DependencySpec::Workspace);
    }
    let package = table
        .get("package")
        .map(|value| {
            parse_string(value, &format!("{location}.package"))?
                .parse()
                .map_err(|error| invalid(format!("{location}.package"), error))
        })
        .transpose()?;
    let requirement = table
        .get("version")
        .map(|value| {
            parse_string(value, &format!("{location}.version"))?
                .parse()
                .map_err(|error| invalid(format!("{location}.version"), error))
        })
        .transpose()?;
    match table.get("path") {
        Some(value) => {
            if package.is_some() != requirement.is_some() {
                return Err(ManifestError::new(
                    ManifestErrorKind::InvalidField,
                    location,
                    "a path dependency must declare both `package` and `version`, or neither",
                ));
            }
            let path = parse_string(value, &format!("{location}.path"))?
                .parse()
                .map_err(|error: ManifestError| {
                    ManifestError::new(
                        error.kind(),
                        format!("{location}.path"),
                        error.message().to_owned(),
                    )
                })?;
            Ok(DependencySpec::Concrete(ConcreteDependency::Path {
                path,
                package,
                requirement,
            }))
        }
        None => match (package, requirement) {
            (Some(package), Some(requirement)) => {
                Ok(DependencySpec::Concrete(ConcreteDependency::Registry {
                    package,
                    requirement,
                }))
            }
            _ => Err(ManifestError::new(
                ManifestErrorKind::MissingField,
                location,
                "a registry dependency requires `package` and `version`",
            )),
        },
    }
}
fn parse_required_inheritable<T>(
    table: &toml::Table,
    key: &str,
    location: &str,
    parse: impl FnOnce(&toml::Value) -> Result<T, ManifestError>,
) -> Result<Inheritable<T>, ManifestError> {
    parse_inheritable(required_value(table, key, location)?, location, parse)
}
fn parse_optional_inheritable<T>(
    table: &toml::Table,
    key: &str,
    location: &str,
    parse: impl FnOnce(&toml::Value) -> Result<T, ManifestError>,
) -> Result<Option<Inheritable<T>>, ManifestError> {
    table
        .get(key)
        .map(|value| parse_inheritable(value, location, parse))
        .transpose()
}
fn parse_inheritable<T>(
    value: &toml::Value,
    location: &str,
    parse: impl FnOnce(&toml::Value) -> Result<T, ManifestError>,
) -> Result<Inheritable<T>, ManifestError> {
    if let Some(table) = value.as_table() {
        if table.len() == 1 && table.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
            return Ok(Inheritable::Workspace);
        }
        return Err(ManifestError::new(
            ManifestErrorKind::InvalidField,
            location,
            "workspace inheritance must be exactly `{ workspace = true }`",
        ));
    }
    parse(value).map(Inheritable::Value)
}
fn resolve_required<T: Clone>(
    location: &str,
    value: &Inheritable<T>,
    workspace: Option<&T>,
) -> Result<T, ManifestError> {
    match value {
        Inheritable::Value(value) => Ok(value.clone()),
        Inheritable::Workspace => workspace.cloned().ok_or_else(|| {
            ManifestError::new(
                ManifestErrorKind::MissingField,
                location,
                "field inherits from `[workspace.package]`, but the workspace value is absent",
            )
        }),
    }
}
fn resolve_optional<T: Clone>(
    location: &str,
    value: Option<&Inheritable<T>>,
    workspace: Option<&T>,
) -> Result<Option<T>, ManifestError> {
    match value {
        None => Ok(None),
        Some(Inheritable::Value(value)) => Ok(Some(value.clone())),
        Some(Inheritable::Workspace) => workspace.cloned().map(Some).ok_or_else(|| {
            ManifestError::new(
                ManifestErrorKind::MissingField,
                location,
                "field inherits from `[workspace.package]`, but the workspace value is absent",
            )
        }),
    }
}
fn parse_edition(
    value: &toml::Value,
    location: &str,
) -> Result<MusubiKotodamaEditionV1, ManifestError> {
    if parse_string(value, location)? == "1" {
        Ok(MusubiKotodamaEditionV1::V1)
    } else {
        Err(ManifestError::new(
            ManifestErrorKind::InvalidField,
            location,
            "Musubi V1 requires Kotodama `edition = \"1\"`",
        ))
    }
}
fn parse_abi_version(value: &toml::Value, location: &str) -> Result<u16, ManifestError> {
    let version = value.as_integer().ok_or_else(|| {
        ManifestError::new(
            ManifestErrorKind::InvalidField,
            location,
            "must be the integer 1",
        )
    })?;
    if version != i64::from(MUSUBI_IVM_ABI_VERSION_V1) {
        return Err(ManifestError::new(
            ManifestErrorKind::InvalidField,
            location,
            "Musubi V1 requires `abi-version = 1`",
        ));
    }
    Ok(MUSUBI_IVM_ABI_VERSION_V1)
}
fn parse_repository(value: &toml::Value) -> Result<String, ManifestError> {
    parse_repository_at(value, "package.repository")
}
fn parse_repository_at(value: &toml::Value, location: &str) -> Result<String, ManifestError> {
    let raw = parse_bounded_text(value, location, MAX_REPOSITORY_BYTES)?;
    let parsed = url::Url::parse(&raw).map_err(|error| invalid(location, error))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(ManifestError::new(
            ManifestErrorKind::InvalidField,
            location,
            "repository must be an absolute HTTP(S) URL without credentials",
        ));
    }
    if parsed.as_str() != raw {
        return Err(ManifestError::new(
            ManifestErrorKind::InvalidField,
            location,
            format!("repository URL is not canonical; use `{parsed}`"),
        ));
    }
    Ok(raw)
}
fn parse_keywords(value: &toml::Value) -> Result<Vec<String>, ManifestError> {
    parse_keywords_at(value, "package.keywords")
}
fn parse_keywords_at(value: &toml::Value, location: &str) -> Result<Vec<String>, ManifestError> {
    let array = value.as_array().ok_or_else(|| {
        ManifestError::new(
            ManifestErrorKind::InvalidField,
            location,
            "must be an array of lowercase ASCII kebab keywords",
        )
    })?;
    if array.len() > MUSUBI_MAX_KEYWORDS_V1 {
        return Err(limit(location, MUSUBI_MAX_KEYWORDS_V1));
    }
    let mut keywords = Vec::with_capacity(array.len());
    for (index, value) in array.iter().enumerate() {
        let item_location = format!("{location}[{index}]");
        let keyword = parse_bounded_text(value, &item_location, MAX_KEYWORD_BYTES)?;
        if keyword.starts_with('-')
            || keyword.ends_with('-')
            || keyword.contains("--")
            || !keyword
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ManifestError::new(
                ManifestErrorKind::InvalidField,
                item_location,
                "keyword must be canonical lowercase ASCII kebab text",
            ));
        }
        keywords.push(keyword);
    }
    ensure_unique_strings(&keywords, location)?;
    keywords.sort();
    Ok(keywords)
}
fn parse_path_array(
    value: &toml::Value,
    location: &str,
    maximum: usize,
) -> Result<Vec<PortablePath>, ManifestError> {
    let array = value.as_array().ok_or_else(|| {
        ManifestError::new(
            ManifestErrorKind::InvalidField,
            location,
            "must be an array of portable relative paths",
        )
    })?;
    if array.len() > maximum {
        return Err(limit(location, maximum));
    }
    let mut paths = array
        .iter()
        .enumerate()
        .map(|(index, value)| parse_portable_path(value, &format!("{location}[{index}]")))
        .collect::<Result<Vec<_>, _>>()?;
    let mut exact = BTreeSet::new();
    let mut folded = BTreeMap::new();
    for path in &paths {
        if !exact.insert(path.clone()) {
            return Err(ManifestError::new(
                ManifestErrorKind::InvalidField,
                location,
                format!("duplicate path `{path}`"),
            ));
        }
        if let Some(previous) = folded.insert(path.collision_key(), path.clone()) {
            return Err(ManifestError::new(
                ManifestErrorKind::InvalidField,
                location,
                format!("portable path collision between `{previous}` and `{path}`"),
            ));
        }
    }
    paths.sort();
    Ok(paths)
}
fn parse_name_array(
    value: &toml::Value,
    location: &str,
    maximum: usize,
) -> Result<Vec<Name>, ManifestError> {
    let array = value.as_array().ok_or_else(|| {
        ManifestError::new(
            ManifestErrorKind::InvalidField,
            location,
            "must be an array of names",
        )
    })?;
    if array.len() > maximum {
        return Err(limit(location, maximum));
    }
    array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let item_location = format!("{location}[{index}]");
            parse_alias(parse_string(value, &item_location)?, &item_location)
        })
        .collect()
}
fn parse_portable_path(value: &toml::Value, location: &str) -> Result<PortablePath, ManifestError> {
    let raw = parse_string(value, location)?;
    PortablePath::new(raw)
        .map_err(|error| ManifestError::new(error.kind(), location, error.message().to_owned()))
}
fn validate_portable_path(raw: &str, allow_parent: bool) -> Result<String, ManifestError> {
    if raw.is_empty()
        || raw.len() > MAX_PORTABLE_PATH_BYTES
        || raw.starts_with('/')
        || raw.ends_with('/')
        || raw.contains(['\\', '\0'])
        || raw.as_bytes().get(1) == Some(&b':')
    {
        return Err(invalid_path(
            "path must be a bounded portable relative path",
        ));
    }
    if raw == "." {
        return Ok(raw.to_owned());
    }
    let components = raw.split('/').collect::<Vec<_>>();
    if components.len() > MAX_PORTABLE_COMPONENTS {
        return Err(limit("path", MAX_PORTABLE_COMPONENTS));
    }
    for component in components {
        if component == ".." {
            if allow_parent {
                continue;
            }
            return Err(invalid_path("path contains a traversal component"));
        }
        if component.is_empty()
            || component == "."
            || component.len() > MAX_PORTABLE_COMPONENT_BYTES
            || component.ends_with([' ', '.'])
            || component.contains([':', '<', '>', '"', '|', '?', '*'])
            || component
                .chars()
                .any(|character| character.is_control() || is_bidi_control(character))
        {
            return Err(invalid_path("path contains a nonportable component"));
        }
        if portable_reserved_name(component) {
            return Err(invalid_path("path contains a reserved portable name"));
        }
        if normalize_portable_component(component).as_deref() != Ok(component) {
            return Err(invalid_path(
                "path component is not in canonical Unicode NFC form",
            ));
        }
    }
    Ok(raw.to_owned())
}
fn portable_reserved_name(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem)
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "CONIN$"
            | "CONOUT$"
            | "CLOCK$"
    ) {
        return true;
    }
    if let (Some(prefix), Some(suffix)) = (stem.get(..3), stem.get(3..)) {
        let numbered = prefix == "COM" || prefix == "LPT";
        return numbered && matches!(suffix, "¹" | "²" | "³");
    }
    false
}
fn normalize_portable_component(component: &str) -> Result<String, ()> {
    let mut output = String::with_capacity(component.len());
    let mut segment = String::new();
    let flush = |segment: &mut String, output: &mut String| -> Result<(), ()> {
        if segment.is_empty() {
            return Ok(());
        }
        let normalized = Name::from_str(segment).map_err(|_| ())?;
        output.push_str(normalized.as_ref());
        segment.clear();
        Ok(())
    };
    for character in component.chars() {
        if matches!(character, '@' | '#' | '$') || character.is_whitespace() {
            flush(&mut segment, &mut output)?;
            output.push(character);
        } else {
            segment.push(character);
        }
    }
    flush(&mut segment, &mut output)?;
    Ok(output)
}
fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}
fn parse_alias(raw: &str, location: &str) -> Result<Name, ManifestError> {
    raw.parse().map_err(|error| invalid(location, error))
}
fn parse_bounded_text(
    value: &toml::Value,
    location: &str,
    maximum: usize,
) -> Result<String, ManifestError> {
    let raw = parse_string(value, location)?;
    if raw.is_empty() || raw.len() > maximum || raw.chars().any(char::is_control) {
        return Err(ManifestError::new(
            ManifestErrorKind::InvalidField,
            location,
            format!("must be nonempty, control-free text of at most {maximum} bytes"),
        ));
    }
    Ok(raw.to_owned())
}
fn parse_string<'a>(value: &'a toml::Value, location: &str) -> Result<&'a str, ManifestError> {
    value.as_str().ok_or_else(|| {
        ManifestError::new(
            ManifestErrorKind::InvalidField,
            location,
            "must be a string",
        )
    })
}
fn parse_optional_string_value<'a>(
    table: &'a toml::Table,
    key: &str,
    location: &str,
) -> Result<Option<&'a str>, ManifestError> {
    table
        .get(key)
        .map(|value| parse_string(value, location))
        .transpose()
}
fn required_integer(table: &toml::Table, key: &str, location: &str) -> Result<i64, ManifestError> {
    required_value(table, key, location)?
        .as_integer()
        .ok_or_else(|| {
            ManifestError::new(
                ManifestErrorKind::InvalidField,
                location,
                "must be an integer",
            )
        })
}
fn required_value<'a>(
    table: &'a toml::Table,
    key: &str,
    location: &str,
) -> Result<&'a toml::Value, ManifestError> {
    table.get(key).ok_or_else(|| {
        ManifestError::new(
            ManifestErrorKind::MissingField,
            location,
            format!("required field `{key}` is missing"),
        )
    })
}
fn required_value_table<'a>(
    value: &'a toml::Value,
    location: &str,
) -> Result<&'a toml::Table, ManifestError> {
    value.as_table().ok_or_else(|| {
        ManifestError::new(ManifestErrorKind::InvalidField, location, "must be a table")
    })
}
fn reject_unknown(
    table: &toml::Table,
    allowed: &[&str],
    location: &str,
) -> Result<(), ManifestError> {
    if let Some(key) = table
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .min()
    {
        let dotted = if location.is_empty() {
            key.clone()
        } else {
            format!("{location}.{key}")
        };
        return Err(ManifestError::new(
            ManifestErrorKind::UnknownField,
            dotted,
            format!("unknown field `{key}` in closed Musubi V1 table"),
        ));
    }
    Ok(())
}
fn reject_unsupported_root_fields(table: &toml::Table) -> Result<(), ManifestError> {
    for field in ["build-dependencies", "target", "features"] {
        if table.contains_key(field) {
            return Err(ManifestError::new(
                ManifestErrorKind::UnknownField,
                field,
                format!("`{field}` is not supported in Musubi V1"),
            ));
        }
    }
    Ok(())
}
fn ensure_unique_names(values: &[Name], location: &str) -> Result<(), ManifestError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(ManifestError::new(
                ManifestErrorKind::InvalidField,
                location,
                format!("duplicate name `{value}`"),
            ));
        }
    }
    Ok(())
}
fn ensure_unique_strings(values: &[String], location: &str) -> Result<(), ManifestError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(ManifestError::new(
                ManifestErrorKind::InvalidField,
                location,
                format!("duplicate value `{value}`"),
            ));
        }
    }
    Ok(())
}
fn invalid(location: impl Into<String>, error: impl fmt::Display) -> ManifestError {
    ManifestError::new(ManifestErrorKind::InvalidField, location, error.to_string())
}
fn invalid_path(message: impl Into<String>) -> ManifestError {
    ManifestError::new(ManifestErrorKind::InvalidField, "path", message)
}
fn limit(location: impl Into<String>, maximum: usize) -> ManifestError {
    ManifestError::new(
        ManifestErrorKind::Limit,
        location,
        format!("contains more than the Musubi V1 maximum of {maximum} entries"),
    )
}
fn render_dependency(dependency: &DependencySpec) -> String {
    match dependency {
        DependencySpec::Workspace => "{ workspace = true }".to_owned(),
        DependencySpec::Concrete(ConcreteDependency::Registry {
            package,
            requirement,
        }) => format!(
            "{{ package = {}, version = {} }}",
            toml_string(&package.to_string()),
            toml_string(&requirement.to_string())
        ),
        DependencySpec::Concrete(ConcreteDependency::Path {
            path,
            package,
            requirement,
        }) => {
            let mut fields = vec![format!("path = {}", toml_string(path.as_str()))];
            if let (Some(package), Some(requirement)) = (package, requirement) {
                fields.push(format!("package = {}", toml_string(&package.to_string())));
                fields.push(format!(
                    "version = {}",
                    toml_string(&requirement.to_string())
                ));
            }
            format!("{{ {} }}", fields.join(", "))
        }
    }
}
fn toml_string(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len() + 2);
    output.push('"');
    for character in raw.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character => output.push(character),
        }
    }
    output.push('"');
    output
}
fn edit_dependency_line(
    source: &str,
    section: DependencySection,
    alias: &str,
    replacement: Option<&str>,
) -> Result<String, ManifestError> {
    let lines = line_spans(source);
    let header = section.header();
    let section_bounds = find_section(source, &lines, header);
    let Some((header_line, end_line)) = section_bounds else {
        let Some(replacement) = replacement else {
            return Err(ManifestError::new(
                ManifestErrorKind::Edit,
                header,
                format!("dependency `{alias}` is absent"),
            ));
        };
        let mut output = source.to_owned();
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        if !output.is_empty() && !output.ends_with("\n\n") {
            output.push('\n');
        }
        output.push('[');
        output.push_str(header);
        output.push_str("]\n");
        output.push_str(alias);
        output.push_str(" = ");
        output.push_str(replacement);
        output.push('\n');
        return Ok(output);
    };
    let mut found = None;
    for index in (header_line + 1)..end_line {
        let text = &source[lines[index].0..lines[index].1];
        if assignment_key(text).as_deref() == Some(alias) {
            found = Some(index);
            break;
        }
    }
    match (found, replacement) {
        (Some(index), Some(replacement)) => {
            let (start, end) = lines[index];
            let original = &source[start..end];
            let indent_len = original.len() - original.trim_start_matches([' ', '\t']).len();
            let indent = &original[..indent_len];
            let newline = if original.ends_with("\r\n") {
                "\r\n"
            } else if original.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            let body = original.trim_end_matches(['\r', '\n']);
            let comment = trailing_comment(body).map_or("", |offset| body[offset..].trim_start());
            let mut line = format!("{indent}{alias} = {replacement}");
            if !comment.is_empty() {
                line.push(' ');
                line.push_str(comment);
            }
            line.push_str(newline);
            Ok(replace_span(source, start, end, &line))
        }
        (Some(index), None) => {
            let (start, end) = lines[index];
            Ok(replace_span(source, start, end, ""))
        }
        (None, Some(replacement)) => {
            let insertion = if end_line < lines.len() {
                lines[end_line].0
            } else {
                source.len()
            };
            let newline = preferred_newline(source);
            let mut line = format!("{alias} = {replacement}{newline}");
            if insertion == source.len() && !source.is_empty() && !source.ends_with('\n') {
                line.insert_str(0, newline);
            }
            Ok(replace_span(source, insertion, insertion, &line))
        }
        (None, None) => Err(ManifestError::new(
            ManifestErrorKind::Edit,
            header,
            format!("dependency `{alias}` is absent"),
        )),
    }
}
fn line_spans(source: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            spans.push((start, index + 1));
            start = index + 1;
        }
    }
    if start < source.len() {
        spans.push((start, source.len()));
    }
    spans
}
fn find_section(source: &str, lines: &[(usize, usize)], wanted: &str) -> Option<(usize, usize)> {
    let mut start = None;
    for (index, (line_start, line_end)) in lines.iter().copied().enumerate() {
        let line = source[line_start..line_end].trim();
        let table_boundary = line
            .split_once('#')
            .map_or(line, |(body, _)| body)
            .trim()
            .starts_with('[');
        let Some(header) = parse_table_header(line) else {
            if let (Some(start), true) = (start, table_boundary) {
                return Some((start, index));
            }
            continue;
        };
        if let Some(start) = start {
            return Some((start, index));
        }
        if header == wanted {
            start = Some(index);
        }
    }
    start.map(|start| (start, lines.len()))
}
fn parse_table_header(line: &str) -> Option<&str> {
    if line.starts_with("[[") {
        return None;
    }
    let without_comment = line.split_once('#').map_or(line, |(body, _)| body).trim();
    without_comment
        .strip_prefix('[')?
        .strip_suffix(']')
        .map(str::trim)
}
fn assignment_key(line: &str) -> Option<String> {
    let body = line.trim_start();
    if body.is_empty() || body.starts_with('#') || body.starts_with('[') {
        return None;
    }
    let equals = find_unquoted(body, '=')?;
    let key = body[..equals].trim();
    if let Some(quoted) = key.strip_prefix('"').and_then(|key| key.strip_suffix('"')) {
        return Some(quoted.replace("\\\"", "\"").replace("\\\\", "\\"));
    }
    if key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') || byte >= 0x80)
    {
        Some(key.to_owned())
    } else {
        None
    }
}
fn trailing_comment(line: &str) -> Option<usize> {
    find_unquoted(line, '#')
}
fn find_unquoted(line: &str, needle: char) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote == Some('"') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            match quote {
                Some(current) if current == character => quote = None,
                None => quote = Some(character),
                Some(_) => {}
            }
            continue;
        }
        if quote.is_none() && character == needle {
            return Some(index);
        }
    }
    None
}
fn preferred_newline(source: &str) -> &'static str {
    if source.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}
fn replace_span(source: &str, start: usize, end: usize, replacement: &str) -> String {
    let mut output = String::with_capacity(source.len() - (end - start) + replacement.len());
    output.push_str(&source[..start]);
    output.push_str(replacement);
    output.push_str(&source[end..]);
    output
}
#[cfg(test)]
mod tests {
    use super::*;
    const PACKAGE: &str = r#"
manifest-version = 1

[package]
namespace = "apps.sora"
name = "router-core"
version = "1.2.3-alpha.1"
edition = "1"
abi-version = 1
description = "Routing primitives"
readme = "README.md"
license = "Apache-2.0"
license-file = "LICENSE"
repository = "https://example.com/router"
keywords = ["routing", "defi"]
include = ["assets"]

[lib]
source-dir = "src"
exports = ["quote", "route"]

[[contract]]
name = "router"
path = "contracts/router.ko"

[[test]]
name = "router_test"
path = "tests/router.ko"

[dependencies]
math = { package = "std/math", version = "^1.4.0" }
local = { path = "vendor/local", package = "std/local", version = "~2.0.0" }

[dev-dependencies]
fixtures = { path = "tests/fixtures" }
"#;
    #[test]
    fn parses_full_package_into_structured_v1_types() {
        let manifest = parse_manifest(PACKAGE).expect("valid package manifest");
        let package = manifest.resolve_package(None).expect("local fields");
        assert_eq!(package.selector.to_string(), "apps.sora/router-core");
        assert_eq!(package.version.to_string(), "1.2.3-alpha.1");
        assert_eq!(package.abi_version, 1);
        assert_eq!(package.keywords, ["defi", "routing"]);
        let library = manifest.library.expect("library");
        assert_eq!(library.source_dir.as_str(), "src");
        assert_eq!(
            library
                .exports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["quote", "route"]
        );
        assert_eq!(manifest.contracts[0].path.as_str(), "contracts/router.ko");
        assert!(matches!(
            manifest.dependencies.get("math"),
            Some(DependencySpec::Concrete(
                ConcreteDependency::Registry { .. }
            ))
        ));
    }
    #[test]
    fn lints_table_selects_levels_and_rejects_unknown_lints() {
        use kotodama_lang::lint::LintLevel;
        let with_lints = |lints: &str| format!("{PACKAGE}\n[lints]\n{lints}\n");
        let manifest = parse_manifest(&with_lints(
            "unused-local = \"deny\"\ndead-store = \"allow\"\ndeny-warnings = true",
        ))
        .expect("valid lints");
        let lints = manifest.lints.expect("[lints] is parsed");
        assert_eq!(lints.level("unused-local"), LintLevel::Deny);
        assert_eq!(lints.level("dead-store"), LintLevel::Allow);
        assert_eq!(lints.level("unused-state"), LintLevel::Deny);
        assert!(parse_manifest(PACKAGE).expect("no lints").lints.is_none());
        for (lints, kind, message) in [
            (
                "unused-locl = \"deny\"",
                ManifestErrorKind::UnknownField,
                "did you mean `unused-local`?",
            ),
            (
                "unused-local = \"error\"",
                ManifestErrorKind::InvalidField,
                "must be \"allow\", \"warn\", or \"deny\"",
            ),
            (
                "deny-warnings = \"yes\"",
                ManifestErrorKind::InvalidField,
                "`deny-warnings` must be",
            ),
        ] {
            let error = parse_manifest(&with_lints(lints)).expect_err(lints);
            assert_eq!(error.kind(), kind, "{lints}");
            assert!(error.message().contains(message), "{lints}: {error}");
        }
    }
    #[test]
    fn virtual_workspace_and_inheritance_are_explicit() {
        let root = parse_manifest(
            r#"
manifest-version = 1
[workspace]
members = ["packages/app"]
default-members = ["packages/app"]

[workspace.package]
namespace = "apps.sora"
version = "2.0.0"
edition = "1"
abi-version = 1
license = "Apache-2.0"

[workspace.dependencies]
math = { package = "std/math", version = "1.0.0" }
"#,
        )
        .expect("virtual root");
        assert!(root.is_virtual_workspace());
        let member = parse_manifest(
            r#"
manifest-version = 1
[package]
namespace = { workspace = true }
name = "app"
version = { workspace = true }
edition = { workspace = true }
abi-version = { workspace = true }
license = { workspace = true }
[lib]
exports = []
[dependencies]
math = { workspace = true }
"#,
        )
        .expect("member syntax");
        let defaults = &root.workspace.expect("workspace").package;
        let effective = member.resolve_package(Some(defaults)).expect("inheritance");
        assert_eq!(effective.selector.to_string(), "apps.sora/app");
        assert_eq!(effective.version.to_string(), "2.0.0");
        assert_eq!(effective.license.as_deref(), Some("Apache-2.0"));
    }
    #[test]
    fn rejects_unknown_duplicate_and_deferred_dependency_fields() {
        let unknown = PACKAGE.replace("description =", "mystery = true\ndescription =");
        assert_eq!(
            parse_manifest(&unknown).expect_err("unknown").kind(),
            ManifestErrorKind::UnknownField
        );
        let duplicate = PACKAGE.replace(
            "name = \"router-core\"",
            "name = \"router-core\"\nname = \"again\"",
        );
        assert_eq!(
            parse_manifest(&duplicate).expect_err("duplicate").kind(),
            ManifestErrorKind::Toml
        );
        let features = PACKAGE.replace(
            "version = \"^1.4.0\"",
            "version = \"^1.4.0\", features = [\"fast\"]",
        );
        assert!(
            parse_manifest(&features)
                .expect_err("features")
                .to_string()
                .contains("not supported")
        );
    }
    #[test]
    fn rejects_noncanonical_versions_and_unsafe_paths() {
        let build = PACKAGE.replace("1.2.3-alpha.1", "1.2.3+local");
        assert!(parse_manifest(&build).is_err());
        let traversal = PACKAGE.replace("vendor/local", "../../outside");
        assert!(parse_manifest(&traversal).is_ok());
        let absolute = PACKAGE.replace("assets", "/etc");
        assert!(parse_manifest(&absolute).is_err());
        let reserved = PACKAGE.replace("assets", "con/secret");
        assert!(parse_manifest(&reserved).is_err());
    }
    #[test]
    fn normal_path_publication_requires_registry_pair() {
        let manifest = parse_manifest(PACKAGE).expect("manifest");
        let DependencySpec::Concrete(dependency) = manifest
            .dev_dependencies
            .get("fixtures")
            .expect("fixture dependency")
        else {
            panic!("expected concrete dependency");
        };
        assert!(dependency.publication_requirement().is_err());
    }
    #[test]
    fn focused_edits_preserve_unrelated_bytes_and_comments() {
        let dependency = DependencySpec::Concrete(ConcreteDependency::Registry {
            package: "std/crypto".parse().expect("selector"),
            requirement: "^3.0.0".parse().expect("requirement"),
        });
        let source = PACKAGE.replace(
            "math = { package = \"std/math\", version = \"^1.4.0\" }",
            "  math = { package = \"std/math\", version = \"^1.4.0\" } # keep me",
        );
        let edited = upsert_dependency(&source, DependencySection::Normal, "math", &dependency)
            .expect("focused replace");
        assert!(
            edited
                .contains("  math = { package = \"std/crypto\", version = \"^3.0.0\" } # keep me")
        );
        assert_eq!(
            edited.replace(
                "  math = { package = \"std/crypto\", version = \"^3.0.0\" } # keep me",
                "  math = { package = \"std/math\", version = \"^1.4.0\" } # keep me"
            ),
            source
        );
        let added = upsert_dependency(&edited, DependencySection::Normal, "codec", &dependency)
            .expect("focused add");
        assert!(added.contains("codec = { package = \"std/crypto\", version = \"^3.0.0\" }"));
        let removed =
            remove_dependency(&added, DependencySection::Normal, "codec").expect("focused remove");
        assert_eq!(removed, edited);
    }
    #[test]
    fn focused_edit_appends_missing_table_without_rerendering() {
        let source = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "plain"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
exports = []
"#;
        let dependency = DependencySpec::Concrete(ConcreteDependency::Path {
            path: "vendor/tool".parse().expect("path"),
            package: None,
            requirement: None,
        });
        let edited = upsert_dependency(source, DependencySection::Development, "tool", &dependency)
            .expect("append table");
        assert!(edited.starts_with(source));
        assert!(edited.ends_with("[dev-dependencies]\ntool = { path = \"vendor/tool\" }\n"));
    }

    #[test]
    fn contract_only_packages_require_an_actual_contract_target() {
        let source = include_str!("../../../examples/coffee-club/Musubi.toml");
        let manifest = parse_manifest(source).expect("contract-only package");
        assert!(manifest.library.is_none());
        assert_eq!(manifest.contracts.len(), 1);
        assert_eq!(manifest.tests.len(), 1);
        let no_targets = source
            .split("[[contract]]")
            .next()
            .expect("package metadata");
        assert!(
            parse_manifest(no_targets)
                .expect_err("no source targets")
                .to_string()
                .contains("at least one `[[contract]]`")
        );
    }

    #[test]
    fn named_contract_targets_require_one_ko_source_while_tests_accept_directories() {
        for invalid in [
            "contracts",
            ".",
            "contracts/router.to",
            "contracts/router.KO",
        ] {
            let source = PACKAGE.replace("contracts/router.ko", invalid);
            let error = parse_manifest(&source).expect_err("contract targets must name one source");
            assert!(error.to_string().contains("one `.ko` source file"));
            assert!(error.to_string().contains("contract[0].path"));
        }
        let manifest = parse_manifest(&PACKAGE.replace("tests/router.ko", "tests"))
            .expect("test directories remain supported");
        assert_eq!(manifest.contracts[0].name.as_ref(), "router");
        assert_eq!(manifest.contracts[0].path.as_str(), "contracts/router.ko");
        assert_eq!(manifest.tests[0].path.as_str(), "tests");
    }
}
