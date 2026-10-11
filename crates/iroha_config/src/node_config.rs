//! Loading a node configuration file.
//!
//! One shared loader serves both kinds of node file through [`open_node_config`] or the
//! retained, self-contained source entry [`open_node_config_source`]:
//!
//! - A **custom file** (no `profile` key) supplies its configuration directly, including `extends`.
//! - A **profile node file** sets `profile` and `validators`, with an optional `role`
//!   that defaults to `validator`. Its
//!   sources are layered as code defaults, then the profile's `static`, `derive(n)`, `policy`
//!   and role overlay, then the node file (later sources win). The node file may contain only
//!   [`crate::profile::PROFILE_NODE_KEYS`] and the profile's `node_tunable` keys; anything
//!   else is rejected with the file and key. Such a file must not be combined with `--sora`
//!   and must not use `extends`.
//!
//! In both cases a `data_dir` completes every state path the configuration leaves unset under
//! `<data_dir>/state/` and every secret file under `<data_dir>/secrets/`
//! ([`crate::parameters::defaults::data_dir`]). Explicit per-path values win. A relative
//! `data_dir` resolves against the directory of the file that sets it and is then made absolute
//! against the working directory, so every completed path is absolute. The resolved `data_dir`
//! is written to the loader-owned source [`crate::parameters::defaults::data_dir::LAYOUT_SOURCE`],
//! which the parser requires: a configuration read without this loader that sets `data_dir` is
//! rejected.

use crate::{
    parameters::{defaults::data_dir as layout, user},
    profile::{
        DerivedGeometryV1, Profile, ProfileDigest, ProfileError, ProfileId, ProfileRole,
        deep_merge, leaf_keys,
    },
};
use error_stack::{Report, ResultExt};
use iroha_config_base::{ParameterId, read::ConfigReader, toml::TomlSource};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Node-file key selecting a compiled profile.
pub const PROFILE_KEY: &str = "profile";
/// Optional node-file key selecting the role; defaults to `validator`.
pub const ROLE_KEY: &str = "role";
/// Required node-file key carrying the validator count `n` for `derive(n)`.
pub const VALIDATORS_KEY: &str = "validators";

/// Tables that the node schema reads as one value, so layers contributing to them are merged
/// into the last contributing layer. A `true` flag marks a section that exists only when the
/// node file binds it: the profile's content for it is a template applied under the node's
/// values and dropped otherwise.
const MERGED_VALUE_TABLES: &[(&[&str], bool)] = &[
    (&["soracloud_runtime", "cache_budgets"], false),
    (&["soracloud_runtime", "inrou"], false),
    (&["soracloud_runtime", "submission"], false),
    (&["soracloud_runtime", "egress"], false),
    (&["torii", "faucet"], true),
    (&["torii", "account_onboarding"], true),
];

/// One secret file completed from `data_dir`.
struct SecretFile {
    /// Configuration key of the file path.
    key: &'static [&'static str],
    /// File name under `<data_dir>/secrets/`.
    name: &'static str,
    /// Keys that provide the secret another way; any of them suppresses the completion.
    alternatives: &'static [&'static [&'static str]],
    /// The completion applies only when the parent section is configured.
    needs_parent: bool,
}

/// Secret files completed from `data_dir`.
const SECRET_FILES: &[SecretFile] = &[
    SecretFile {
        key: &["private_key_file"],
        name: layout::VALIDATOR_KEY,
        alternatives: &[&["private_key"]],
        needs_parent: false,
    },
    SecretFile {
        key: &["soranet_transport_private_key_file"],
        name: layout::TRANSPORT_KEY,
        alternatives: &[&["soranet_transport_private_key"]],
        needs_parent: false,
    },
    SecretFile {
        key: &["streaming", "identity_private_key_file"],
        name: layout::STREAMING_KEY,
        alternatives: &[&["streaming", "identity_private_key"]],
        needs_parent: false,
    },
    SecretFile {
        key: &["torii", "faucet", "private_key_file"],
        name: layout::FAUCET_AUTHORITY_KEY,
        alternatives: &[],
        needs_parent: true,
    },
    SecretFile {
        key: &["torii", "account_onboarding", "private_key_file"],
        name: layout::ONBOARDING_AUTHORITY_KEY,
        alternatives: &[],
        needs_parent: true,
    },
];

/// A node configuration file handed to [`open_node_config`].
#[derive(Debug, Clone)]
pub enum NodeFile {
    /// Read from disk. Flat files may use `extends`.
    Path(PathBuf),
    /// Already read and integrity-checked (for example against `--config-blake3`). It must be
    /// self-contained: `extends` is rejected.
    Verified {
        /// Where the table was read from; relative paths resolve against its directory.
        path: PathBuf,
        /// Parsed contents.
        table: toml::Table,
    },
}

/// Loader options that come from the command line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeConfigOptions {
    /// The daemon was started with `--sora`.
    pub sora: bool,
}

/// The profile a node file selected, with its derived geometry and digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileBinding {
    /// Compiled profile.
    pub profile: ProfileId,
    /// Role overlay.
    pub role: ProfileRole,
    /// Roster size passed to `derive(n)`.
    pub roster_size: usize,
    /// `derive(n)` result.
    pub geometry: DerivedGeometryV1,
    /// `H(static ‖ derive(n) ‖ genesis recipe)`.
    pub consensus_digest: ProfileDigest,
    /// `H(policy ‖ roles)`.
    pub policy_digest: ProfileDigest,
}

/// A node configuration that cannot be loaded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NodeConfigError {
    /// The file cannot be read or parsed.
    #[error("failed to read node configuration `{}`", .0.display())]
    ReadFile(PathBuf),
    /// The layered sources do not form a valid user configuration.
    #[error("failed to read the layered node configuration")]
    Read,
    /// A self-contained file uses `extends`.
    #[error("`{}` must be self-contained and cannot use `extends`", .0.display())]
    Extends(PathBuf),
    /// A profile node file was combined with `--sora`.
    #[error("`{}` selects a compiled profile and must not be started with `--sora`", .0.display())]
    SoraWithProfile(PathBuf),
    /// A profile selector key is missing or malformed.
    #[error("`{}`: `{key}` {message}", path.display())]
    ProfileKey {
        /// Node file.
        path: PathBuf,
        /// Selector key.
        key: &'static str,
        /// What is wrong.
        message: String,
    },
    /// The node file sets keys outside the per-node allowlist.
    #[error(
        "`{}`: keys {} are not per-node keys of profile `{profile}`; the profile owns them",
        path.display(),
        keys.iter().map(|key| format!("`{key}`")).collect::<Vec<_>>().join(", ")
    )]
    KeysNotAllowed {
        /// Node file.
        path: PathBuf,
        /// Selected profile.
        profile: ProfileId,
        /// Offending dotted keys.
        keys: Vec<String>,
    },
    /// A profile node file has no `data_dir`.
    #[error("`{}`: a profile node file must set `data_dir`", .0.display())]
    MissingDataDir(PathBuf),
    /// `data_dir` is not a non-empty string.
    #[error("`{}`: `data_dir` must be a non-empty path string", .0.display())]
    InvalidDataDir(PathBuf),
    /// The profile cannot be loaded, derived or digested.
    #[error(transparent)]
    Profile(#[from] ProfileError),
}

/// A node configuration ready to be read.
#[derive(Debug)]
pub struct NodeConfigReader {
    reader: ConfigReader,
    profile: Option<ProfileBinding>,
    data_dir: Option<PathBuf>,
}

impl NodeConfigReader {
    /// The resolved absolute `data_dir`, when the configuration sets one.
    ///
    /// Launchers use it to check the custody of the fixed `<data_dir>/secrets/` files before the
    /// parser reads the key files the configuration names.
    #[must_use]
    pub fn data_dir(&self) -> Option<&Path> {
        self.data_dir.as_deref()
    }

    /// The prepared reader, for example to test whether a parameter is set explicitly.
    #[must_use]
    pub fn reader(&self) -> &ConfigReader {
        &self.reader
    }

    /// The selected profile, if any.
    #[must_use]
    pub fn profile(&self) -> Option<&ProfileBinding> {
        self.profile.as_ref()
    }

    /// Split into the prepared reader and the profile binding.
    #[must_use]
    pub fn into_parts(self) -> (ConfigReader, Option<ProfileBinding>) {
        (self.reader, self.profile)
    }

    /// Read the user configuration.
    ///
    /// # Errors
    ///
    /// [`NodeConfigError::Read`] with the per-source report when the layered sources are not a
    /// valid user configuration.
    pub fn read(self) -> Result<(user::Root, Option<ProfileBinding>), Report<NodeConfigError>> {
        let root = self
            .reader
            .read_and_complete::<user::Root>()
            .change_context(NodeConfigError::Read)?;
        Ok((root, self.profile))
    }
}

/// Prepare a node configuration: resolve its profile layers (if it selects a profile) and
/// complete its `data_dir` layout. Environment overlays are disabled.
///
/// # Errors
///
/// [`NodeConfigError`] when the file cannot be read, a profile node file breaks the
/// allowlist or selector rules, or the profile cannot derive the roster.
pub fn open_node_config(
    file: NodeFile,
    options: NodeConfigOptions,
) -> Result<NodeConfigReader, Report<NodeConfigError>> {
    match file {
        NodeFile::Path(path) => {
            let source = TomlSource::from_file(&path)
                .change_context_lazy(|| NodeConfigError::ReadFile(path.clone()))?;
            if !source.table().contains_key(PROFILE_KEY) {
                let reader = ConfigReader::new()
                    .without_env()
                    .read_toml_with_extends(&path)
                    .change_context_lazy(|| NodeConfigError::ReadFile(path.clone()))?;
                return complete_data_dir(reader).map(|(reader, data_dir)| NodeConfigReader {
                    reader,
                    profile: None,
                    data_dir,
                });
            }
            open_profile_node(source, options)
        }
        NodeFile::Verified { path, table } => {
            open_node_config_source(TomlSource::new(path, table), options)
        }
    }
}

/// Prepare one retained, self-contained node source without replacing its cleanup owner.
///
/// Sensitive sources retain their scrubber through profile layering, layout completion and
/// reading. Relative paths resolve against the original source path; environment overlays and
/// `extends` remain disabled. The same node-file policy and layout kernel serve every input.
///
/// # Errors
///
/// [`NodeConfigError`] when the source uses `extends`, violates profile policy or has an
/// invalid `data_dir` layout.
pub fn open_node_config_source(
    source: TomlSource,
    options: NodeConfigOptions,
) -> Result<NodeConfigReader, Report<NodeConfigError>> {
    if source.table().contains_key("extends") {
        return Err(Report::new(NodeConfigError::Extends(source.path().clone())));
    }
    if source.table().contains_key(PROFILE_KEY) {
        return open_profile_node(source, options);
    }
    let reader = ConfigReader::new().without_env().with_toml_source(source);
    complete_data_dir(reader).map(|(reader, data_dir)| NodeConfigReader {
        reader,
        profile: None,
        data_dir,
    })
}

/// [`open_node_config`] followed by [`NodeConfigReader::read`].
///
/// # Errors
///
/// Any error of either step.
#[cfg(test)]
pub fn read_node_config(
    file: NodeFile,
    options: NodeConfigOptions,
) -> Result<(user::Root, Option<ProfileBinding>), Report<NodeConfigError>> {
    open_node_config(file, options)?.read()
}

fn open_profile_node(
    mut source: TomlSource,
    options: NodeConfigOptions,
) -> Result<NodeConfigReader, Report<NodeConfigError>> {
    let path = source.path().clone();
    let table = source.table_mut();
    if options.sora {
        return Err(Report::new(NodeConfigError::SoraWithProfile(path)));
    }
    if table.contains_key("extends") {
        return Err(Report::new(NodeConfigError::Extends(path)));
    }
    let key_error = |key: &'static str, message: String| {
        Report::new(NodeConfigError::ProfileKey {
            path: path.clone(),
            key,
            message,
        })
    };
    for (key, message) in [
        (
            "role_overlay",
            "is retired; use top-level `role` or omit it for a validator",
        ),
        (
            "profile_roster_size",
            "is retired; set `validators` to the network's validator count",
        ),
        (
            "chain_discriminant",
            "is supplied by `profile`; remove this key",
        ),
    ] {
        if table.contains_key(key) {
            return Err(key_error(key, message.to_owned()));
        }
    }
    if table_at(table, &["sumeragi"]).is_some_and(|section| section.contains_key("role")) {
        return Err(key_error(
            "sumeragi.role",
            "is selected by top-level `role`; remove this key".to_owned(),
        ));
    }
    let profile_id = match table.remove(PROFILE_KEY) {
        Some(toml::Value::String(name)) => name
            .parse::<ProfileId>()
            .map_err(|error| key_error(PROFILE_KEY, error.to_string()))?,
        _ => return Err(key_error(PROFILE_KEY, "must be a profile name".to_owned())),
    };
    let role = match table.remove(ROLE_KEY) {
        None => ProfileRole::Validator,
        Some(toml::Value::String(name)) => name
            .parse::<ProfileRole>()
            .map_err(|error| key_error(ROLE_KEY, error.to_string()))?,
        _ => {
            return Err(key_error(
                ROLE_KEY,
                "must be `validator`, `lane_validator` or `observer`".to_owned(),
            ));
        }
    };
    let roster_size = match table.remove(VALIDATORS_KEY) {
        Some(toml::Value::Integer(size)) => usize::try_from(size)
            .ok()
            .filter(|size| *size > 0)
            .ok_or_else(|| key_error(VALIDATORS_KEY, "must be a positive integer".to_owned()))?,
        _ => {
            return Err(key_error(
                VALIDATORS_KEY,
                "must be an explicit positive integer validator count (4, 7, ..., 31)".to_owned(),
            ));
        }
    };
    let profile = Profile::compiled(profile_id).map_err(profile_error)?;
    let disallowed: Vec<String> = leaf_keys(table)
        .into_iter()
        .filter(|key| !profile.admits_node_key(key))
        .collect();
    if !disallowed.is_empty() {
        return Err(Report::new(NodeConfigError::KeysNotAllowed {
            path,
            profile: profile_id,
            keys: disallowed,
        }));
    }
    if !table.contains_key("data_dir") {
        return Err(Report::new(NodeConfigError::MissingDataDir(path)));
    }
    let geometry = profile
        .derive(roster_size)
        .map_err(|error| key_error(VALIDATORS_KEY, error.to_string()))?;
    let binding = ProfileBinding {
        profile: profile_id,
        role,
        roster_size,
        geometry,
        consensus_digest: profile
            .consensus_digest_for(&geometry)
            .map_err(profile_error)?,
        policy_digest: profile.policy_digest().map_err(profile_error)?,
    };
    let mut sources = profile.layers(&geometry, role);
    sources.push(source);
    merge_value_tables(&mut sources);
    let reader = sources.into_iter().fold(
        ConfigReader::new().without_env(),
        ConfigReader::with_toml_source,
    );
    complete_data_dir(reader).map(|(reader, data_dir)| NodeConfigReader {
        reader,
        profile: Some(binding),
        data_dir,
    })
}

fn profile_error(error: ProfileError) -> Report<NodeConfigError> {
    Report::new(NodeConfigError::Profile(error))
}

/// Merge every [`MERGED_VALUE_TABLES`] entry into the last source that contributes to it. A
/// node-bound section that the last source (the node file) does not bind is removed from all
/// profile layers.
fn merge_value_tables(sources: &mut [TomlSource]) {
    let Some(node_index) = sources.len().checked_sub(1) else {
        return;
    };
    for (path, node_bound) in MERGED_VALUE_TABLES {
        let contributors: Vec<usize> = (0..sources.len())
            .filter(|index| table_at(sources[*index].table(), path).is_some())
            .collect();
        if *node_bound && !contributors.contains(&node_index) {
            for index in contributors {
                remove_at(sources[index].table_mut(), path);
            }
            continue;
        }
        let Some((&last, earlier)) = contributors.split_last() else {
            continue;
        };
        if earlier.is_empty() {
            continue;
        }
        let mut merged = toml::Table::new();
        for &index in earlier.iter().chain(std::iter::once(&last)) {
            let contribution = if index == last {
                table_at_mut(sources[index].table_mut(), path).map(std::mem::take)
            } else {
                remove_at(sources[index].table_mut(), path)
            };
            if let Some(contribution) = contribution {
                deep_merge(&mut merged, contribution);
            }
        }
        if let Some(slot) = table_at_mut(sources[last].table_mut(), path) {
            *slot = merged;
        }
    }
}

/// Complete the `data_dir` layout on a prepared reader.
///
/// Every completed value is absolute, so resolving it against the source that holds it (see
/// `WithOrigin::resolve_relative_path`) leaves it unchanged. The resolved `data_dir` itself goes to
/// the loader-owned [`layout::LAYOUT_SOURCE`], the marker the parser requires.
fn complete_data_dir(
    mut reader: ConfigReader,
) -> Result<(ConfigReader, Option<PathBuf>), Report<NodeConfigError>> {
    let Some(data_dir) = resolve_data_dir(&reader) else {
        return Ok((reader, None));
    };
    let data_dir = match data_dir {
        Ok(data_dir) => data_dir,
        Err(error) => {
            // Defuse the reader's drop guard; the error below replaces its report.
            let _ = reader.into_result();
            return Err(error);
        }
    };
    let state_dir = data_dir.join(layout::STATE_DIR);
    let secrets_dir = data_dir.join(layout::SECRETS_DIR);
    let mut completions: Vec<(&[&str], PathBuf)> = layout::STATE_PATHS
        .iter()
        .map(|(key, relative)| (*key, state_dir.join(relative)))
        .collect();
    for secret in SECRET_FILES {
        let parent = &secret.key[..secret.key.len() - 1];
        if secret
            .alternatives
            .iter()
            .any(|alternative| reader.contains_toml_parameter(*alternative))
        {
            continue;
        }
        if secret.needs_parent
            && !reader
                .toml_sources()
                .iter()
                .any(|source| table_at(source.table(), parent).is_some())
        {
            continue;
        }
        completions.push((secret.key, secrets_dir.join(secret.name)));
    }
    let mut layout_table = toml::Table::new();
    layout_table.insert(
        "data_dir".to_owned(),
        toml::Value::String(data_dir.to_string_lossy().into_owned()),
    );
    for (key, path) in completions {
        if reader.contains_toml_parameter(key) {
            continue;
        }
        let value = toml::Value::String(path.to_string_lossy().into_owned());
        let (leaf, parent) = key.split_last().expect("layout keys are not empty");
        // A section the schema reads as one value must receive the completion in the source that
        // already holds it; a later source would replace the whole section.
        let owner = if parent.is_empty() {
            None
        } else {
            reader
                .toml_sources()
                .iter()
                .rposition(|source| table_at(source.table(), parent).is_some())
        };
        match owner {
            Some(index) => {
                if let Some(table) =
                    table_at_mut(reader.toml_sources_mut()[index].table_mut(), parent)
                {
                    table.insert((*leaf).to_owned(), value);
                }
            }
            None => insert_at(&mut layout_table, key, value),
        }
    }
    Ok((
        reader.with_toml_source(TomlSource::new(
            PathBuf::from(layout::LAYOUT_SOURCE),
            layout_table,
        )),
        Some(data_dir),
    ))
}

/// The effective `data_dir`: resolved against the directory of the file that sets it, then made
/// absolute against the working directory ([`absolute_lexical`]).
fn resolve_data_dir(reader: &ConfigReader) -> Option<Result<PathBuf, Report<NodeConfigError>>> {
    let id = ParameterId::from(["data_dir"]);
    let source = reader
        .toml_sources()
        .iter()
        .rev()
        .find(|source| source.fetch(&id).is_some())?;
    let value = source.fetch(&id)?;
    let invalid = || Report::new(NodeConfigError::InvalidDataDir(source.path().clone()));
    Some(
        value
            .as_str()
            .filter(|path| !path.is_empty())
            .and_then(|path| {
                absolute_lexical(
                    &source
                        .path()
                        .parent()
                        .unwrap_or_else(|| Path::new(""))
                        .join(path),
                )
            })
            .ok_or_else(invalid),
    )
}

/// `path` made absolute against the working directory, with `.` removed and each `..` removing
/// the preceding component (lexically, without resolving symlinks).
fn absolute_lexical(path: &Path) -> Option<PathBuf> {
    let absolute = std::path::absolute(path).ok()?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized.is_absolute().then_some(normalized)
}

fn table_at<'a>(table: &'a toml::Table, path: &[&str]) -> Option<&'a toml::Table> {
    path.iter().try_fold(table, |table, segment| {
        table.get(*segment).and_then(toml::Value::as_table)
    })
}

fn table_at_mut<'a>(table: &'a mut toml::Table, path: &[&str]) -> Option<&'a mut toml::Table> {
    path.iter().try_fold(table, |table, segment| {
        table.get_mut(*segment).and_then(toml::Value::as_table_mut)
    })
}

fn remove_at(table: &mut toml::Table, path: &[&str]) -> Option<toml::Table> {
    let (leaf, parent) = path.split_last()?;
    match table_at_mut(table, parent)?.remove(*leaf)? {
        toml::Value::Table(removed) => Some(removed),
        _ => None,
    }
}

fn insert_at(table: &mut toml::Table, path: &[&str], value: toml::Value) {
    let (leaf, parent) = path.split_last().expect("insertion paths are not empty");
    let mut cursor = table;
    for segment in parent {
        cursor = cursor
            .entry((*segment).to_owned())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("the layout table only holds tables on the way to a leaf");
    }
    cursor.insert((*leaf).to_owned(), value);
}

#[cfg(test)]
mod tests;
