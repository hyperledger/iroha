//! Crash-atomic Kura lane-geometry transitions.
#[cfg(test)]
use super::Ordering;
use super::{
    BlockStore, BlockStoreCommitMarker, BoundProgressDirectory, BoundProgressNamespace,
    COUNT_FILE_NAME, DATA_FILE_NAME, Error, HASHES_FILE_NAME, INDEX_FILE_NAME, Kura,
    LaneStorageEntry, LaneStorageIdentity, Result, create_dir_all_with_context, sync_dir,
};
#[cfg(unix)]
use crate::json_macros::{JsonDeserialize, JsonSerialize};
use crate::secure_file_metadata::{self, SecureMetadata};
use iroha_config::parameters::actual::{LaneConfig, LaneConfigEntry};
use iroha_crypto::Hash;
#[cfg(test)]
use iroha_crypto::HashOf;
use iroha_data_model::NetworkId;
#[cfg(test)]
use iroha_data_model::block::BlockHeader;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use norito::codec::{Decode, Encode};
#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
use rustix::fs::{RenameFlags, renameat_with};
#[cfg(test)]
use std::num::NonZeroUsize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};
#[cfg(test)]
mod guarded_publication;
mod instance_recovery;
mod prepared_journal;
mod raw_attempt;
mod retained_journal;
use prepared_journal::PreparedGeometryJournalTransition;
pub(super) use raw_attempt::RawGeometryClaimGate;
use raw_attempt::RawGeometryMutation;
pub use raw_attempt::RawGeometryWait;
pub(crate) use raw_attempt::{RawGeometryAttempt, RawGeometryPhase};

#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_GEOMETRY_INSTANCE_AFTER_FILES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

const JOURNAL_VERSION: u8 = 9;
const MARKER_VERSION: u8 = 5;
const JOURNAL_FILE_NAME: &str = "lane_geometry_journal.norito";
const JOURNAL_TEMP_FILE_NAME: &str = "lane_geometry_journal.norito.tmp";
const JOURNAL_RESTORE_TEMP_FILE_NAME: &str = "lane_geometry_journal.norito.restore.tmp";
#[cfg(test)]
const JOURNAL_IDENTITY_SWAP_FILE_NAME: &str = "lane_geometry_journal.norito.identity-swap";
#[cfg(test)]
const JOURNAL_IDENTITY_DISPLACED_FILE_NAME: &str =
    "lane_geometry_journal.norito.identity-displaced";
const MARKER_FILE_NAME: &str = ".lane-incarnation.norito";
const MARKER_TEMP_FILE_NAME: &str = ".lane-incarnation.norito.tmp";
/// Exact geometry marker formats for the shared physical resource observer.
pub(super) fn resource_evidence_file_kind(name: &str) -> Option<(u64, bool)> {
    match name {
        JOURNAL_FILE_NAME => Some((MAX_GEOMETRY_JOURNAL_BYTES, false)),
        JOURNAL_TEMP_FILE_NAME | JOURNAL_RESTORE_TEMP_FILE_NAME => {
            Some((MAX_GEOMETRY_JOURNAL_BYTES, true))
        }
        MARKER_FILE_NAME => Some((MAX_LANE_MARKER_BYTES, false)),
        MARKER_TEMP_FILE_NAME => Some((MAX_LANE_MARKER_BYTES, true)),
        _ => None,
    }
}

const TRANSITION_DOMAIN: &[u8] = b"iroha:kura:lane-geometry-transition:v4\0";
const CATALOG_DOMAIN: &[u8] = b"iroha:kura:lane-geometry-catalog:v1\0";
#[cfg(test)]
const UNSCOPED_LINEAGE_DOMAIN: &[u8] = b"iroha:kura:lane-geometry-unscoped-lineage:v1\0";
const MAX_GEOMETRY_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GEOMETRY_TRANSITIONS: usize = 16_384;
const MAX_GEOMETRY_BINDINGS: usize = 65_536;
const MAX_GEOMETRY_ARCHIVE_DEPTH: usize = 128;
const MAX_GEOMETRY_ARCHIVE_ENTRIES: usize = 4_000_000;
const MAX_LANE_MARKER_BYTES: u64 = 4 * 1024;
const MAX_BLOCK_STORE_COMMIT_MARKER_BYTES: u64 = 4 * 1024;
#[cfg(test)]
static CONFIGURED_CATALOG_PREFLIGHT_IDENTITY_SWAP: std::sync::Mutex<Option<PathBuf>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static CONFIGURED_CATALOG_PREFLIGHT_FAIL_AFTER_ESTABLISH: std::sync::Mutex<Option<PathBuf>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
fn canonical_test_store_root(store_root: &Path) -> PathBuf {
    fs::canonicalize(store_root).unwrap_or_else(|_| {
        store_root
            .parent()
            .and_then(|parent| fs::canonicalize(parent).ok())
            .and_then(|parent| store_root.file_name().map(|name| parent.join(name)))
            .unwrap_or_else(|| store_root.to_path_buf())
    })
}
#[cfg(not(unix))]
static UNSUPPORTED_GEOMETRY_IDENTITY_NONCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::lane_geometry::LaneGeometryPhase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
enum LaneGeometryPhase {
    Intent,
    FilesApplied,
    CatalogPublished,
    RolledBack,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaneGeometryRecoveryCursor {
    #[cfg(test)]
    Catalog,
    AtHeight(u64),
    #[cfg(test)]
    BeforeTransition(u64),
    BeforeFirstTransitionAtHeight(u64),
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::lane_geometry::LaneGeometryOperationKind")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
enum LaneGeometryOperationKind {
    Create,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GeometryEvidencePolicy {
    FreshJournalIntent,
    AllowJournalIntentProvisioning,
    RequireDurableEvidence,
}
impl GeometryEvidencePolicy {
    const fn allows_journal_intent_provisioning(self) -> bool {
        matches!(
            self,
            Self::FreshJournalIntent | Self::AllowJournalIntentProvisioning
        )
    }
}
#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
fn rename_geometry_path_noreplace_at(
    source_parent: &File,
    source_name: &std::ffi::OsStr,
    target_parent: &File,
    target_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    renameat_with(
        source_parent,
        source_name,
        target_parent,
        target_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}
#[cfg(all(unix, not(any(target_os = "espidf", target_os = "redox"))))]
fn geometry_stat_identity(stat: &rustix::fs::Stat) -> GeometryFileIdentity {
    GeometryFileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    }
}
#[cfg(windows)]
fn rename_geometry_path_noreplace_at(
    _source_parent: &File,
    _source_name: &std::ffi::OsStr,
    _target_parent: &File,
    _target_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        ErrorKind::Unsupported,
        "atomic descriptor-relative lane geometry rename is unsupported on Windows",
    ))
}
#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    windows
)))]
fn rename_geometry_path_noreplace_at(
    _source_parent: &File,
    _source_name: &std::ffi::OsStr,
    _target_parent: &File,
    _target_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        ErrorKind::Unsupported,
        "atomic descriptor-relative lane geometry rename is unsupported on this platform",
    ))
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::lane_geometry::LaneGeometryBinding")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct LaneGeometryBinding {
    network_id: NetworkId,
    dataspace_id: DataSpaceId,
    lane_id: LaneId,
    incarnation: Hash,
    activation_height: u64,
    blocks_path: String,
}
impl LaneGeometryBinding {
    fn from_identity(identity: LaneStorageIdentity) -> Self {
        Self {
            network_id: identity.network_id,
            dataspace_id: identity.dataspace_id,
            lane_id: identity.lane_id,
            incarnation: identity.incarnation,
            activation_height: identity.activation_height,
            blocks_path: identity.blocks_relative(),
        }
    }
    fn identity(&self) -> LaneStorageIdentity {
        LaneStorageIdentity {
            network_id: self.network_id,
            lane_id: self.lane_id,
            dataspace_id: self.dataspace_id,
            incarnation: self.incarnation,
            activation_height: self.activation_height,
        }
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::lane_geometry::LaneGeometryOperation")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct LaneGeometryOperation {
    kind: LaneGeometryOperationKind,
    lane_id: LaneId,
    created: LaneGeometryBinding,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::lane_geometry::LaneGeometryIntent")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct LaneGeometryIntent {
    transition_id: Hash,
    transition_sequence: u64,
    transition_height: u64,
    previous_catalog: Hash,
    previous_lineage_root: Hash,
    updated_catalog: Hash,
    updated_lineage_root: Hash,
    previous_bindings: Vec<LaneGeometryBinding>,
    updated_bindings: Vec<LaneGeometryBinding>,
    phase: LaneGeometryPhase,
    operations: Vec<LaneGeometryOperation>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GeometryFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: Option<u32>,
    #[cfg(windows)]
    file_index: Option<u64>,
    #[cfg(not(unix))]
    unsupported_nonce: u64,
}
/// Authenticated filesystem identities carried across configured-primary constructor opens.
#[derive(Debug)]
pub(super) struct StorageOpenPreflight {
    store_root: PathBuf,
    root_identity: GeometryFileIdentity,
    blocks_path: PathBuf,
    blocks_identity: Option<GeometryFileIdentity>,
}
/// The two exact parent objects of one immutable instance. Display aliases
/// cannot affect these names; no unrelated tree or retained file is traversed.
struct LaneInstanceOpenPreflight {
    paths: StorageOpenPreflight,
    parents: [(PathBuf, Option<GeometryFileIdentity>); 2],
}
/// Fixed-cardinality canonical namespace identities; never scans unrelated lanes.
#[derive(Debug)]
pub(super) struct CanonicalStoragePreflight {
    paths: StorageOpenPreflight,
    parent_identity: Option<GeometryFileIdentity>,
    pub(super) requires_existing_files: bool,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::lane_geometry::LaneGeometryJournal")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct LaneGeometryJournal {
    version: u8,
    configured_catalog_hash: Option<Hash>,
    configured_primary_binding: Option<LaneGeometryBinding>,
    records: Vec<LaneGeometryIntent>,
}
impl Default for LaneGeometryJournal {
    fn default() -> Self {
        Self {
            version: JOURNAL_VERSION,
            configured_catalog_hash: None,
            configured_primary_binding: None,
            records: Vec::new(),
        }
    }
}
/// Exact identity marker for one admitted lane storage instance.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::lane_geometry::LaneIncarnationMarker")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct LaneIncarnationMarker {
    version: u8,
    network_id: NetworkId,
    dataspace_id: DataSpaceId,
    lane_id: LaneId,
    incarnation: Hash,
    activation_height: u64,
}
struct ConfiguredCatalogPreflightJournal {
    bytes: Vec<u8>,
    journal: LaneGeometryJournal,
    identity: GeometryFileIdentity,
}
fn configured_catalog_preflight_error(
    store_root: &Path,
    kind: ErrorKind,
    message: impl Into<String>,
) -> Error {
    Error::IO(
        std::io::Error::new(kind, message.into()),
        store_root.join(JOURNAL_FILE_NAME),
    )
}
fn configured_catalog_store_root_identity(store_root: &Path) -> Result<GeometryFileIdentity> {
    let metadata = secure_file_metadata::from_path(store_root)
        .map_err(|error| Error::IO(error, store_root.to_path_buf()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(configured_catalog_preflight_error(
            store_root,
            ErrorKind::InvalidData,
            "Kura configured-catalog store root must be a non-symlink directory",
        ));
    }
    checked_geometry_file_identity(&metadata, store_root)
}
fn configured_catalog_require_store_root_identity(
    store_root: &Path,
    expected: GeometryFileIdentity,
) -> Result<()> {
    let actual = configured_catalog_store_root_identity(store_root)?;
    if actual != expected {
        return Err(configured_catalog_preflight_error(
            store_root,
            ErrorKind::InvalidData,
            "Kura configured-catalog store root changed during startup preflight",
        ));
    }
    Ok(())
}
fn configured_catalog_store_root_lock_identity(
    store_root: &Path,
    lock_file: &File,
) -> Result<GeometryFileIdentity> {
    let lock_path = store_root.join(super::STORE_ROOT_LOCK_FILE_NAME);
    let opened_metadata = secure_file_metadata::from_file(lock_file)
        .map_err(|error| Error::IO(error, lock_path.clone()))?;
    let path_metadata = secure_file_metadata::from_path(&lock_path)
        .map_err(|error| Error::IO(error, lock_path.clone()))?;
    let opened_identity = geometry_file_identity(&opened_metadata);
    if opened_metadata.file_type().is_symlink()
        || !opened_metadata.file_type().is_file()
        || path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || !Kura::sidecar_is_single_link(&opened_metadata)
        || !Kura::sidecar_is_single_link(&path_metadata)
        || geometry_file_identity(&path_metadata) != opened_identity
    {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "authenticated Kura store-root lock changed before configured-catalog preflight",
            ),
            lock_path,
        ));
    }
    Ok(opened_identity)
}
fn read_configured_catalog_journal_for_preflight(
    store_root: &Path,
    root_identity: GeometryFileIdentity,
    path: &Path,
    inject_identity_swap: bool,
) -> Result<Option<ConfiguredCatalogPreflightJournal>> {
    if path.parent() != Some(store_root) {
        return Err(configured_catalog_preflight_error(
            store_root,
            ErrorKind::InvalidInput,
            "configured-catalog preflight file must be a direct child of the Kura store root",
        ));
    }
    configured_catalog_require_store_root_identity(store_root, root_identity)?;
    let path_metadata = match secure_file_metadata::from_path(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::IO(error, path.to_path_buf())),
    };
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured-catalog journal path is a symlink or has the wrong file type",
            ),
            path.to_path_buf(),
        ));
    }
    if path_metadata.len() > MAX_GEOMETRY_JOURNAL_BYTES {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "lane geometry journal exceeds the encoded byte limit",
            ),
            path.to_path_buf(),
        ));
    }
    let expected_identity = checked_geometry_file_identity(&path_metadata, path)?;
    let mut file = File::open(path).map_err(|error| Error::IO(error, path.to_path_buf()))?;
    let opened_metadata = secure_file_metadata::from_file(&file)
        .map_err(|error| Error::IO(error, path.to_path_buf()))?;
    if !opened_metadata.is_file()
        || checked_geometry_file_identity(&opened_metadata, path)? != expected_identity
        || opened_metadata.len() > MAX_GEOMETRY_JOURNAL_BYTES
    {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "opened configured-catalog journal does not match its directory entry",
            ),
            path.to_path_buf(),
        ));
    }
    #[cfg(test)]
    if inject_identity_swap {
        let should_swap = {
            let mut hook = CONFIGURED_CATALOG_PREFLIGHT_IDENTITY_SWAP
                .lock()
                .expect("configured-catalog identity-swap hook lock");
            if hook.as_deref() == Some(path) {
                hook.take();
                true
            } else {
                false
            }
        };
        if should_swap {
            let replacement = store_root.join(JOURNAL_IDENTITY_SWAP_FILE_NAME);
            let displaced = store_root.join(JOURNAL_IDENTITY_DISPLACED_FILE_NAME);
            fs::rename(path, &displaced).map_err(|error| Error::IO(error, path.to_path_buf()))?;
            fs::rename(&replacement, path)
                .map_err(|error| Error::IO(error, replacement.to_path_buf()))?;
        }
    }
    #[cfg(not(test))]
    let _ = inject_identity_swap;
    let capacity = usize::try_from(opened_metadata.len())?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(MAX_GEOMETRY_JOURNAL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| Error::IO(error, path.to_path_buf()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_GEOMETRY_JOURNAL_BYTES {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "lane geometry journal exceeded the encoded byte limit while being read",
            ),
            path.to_path_buf(),
        ));
    }
    let final_opened_metadata = secure_file_metadata::from_file(&file)
        .map_err(|error| Error::IO(error, path.to_path_buf()))?;
    let final_path_metadata = secure_file_metadata::from_path(path)
        .map_err(|error| Error::IO(error, path.to_path_buf()))?;
    if !final_opened_metadata.is_file()
        || checked_geometry_file_identity(&final_opened_metadata, path)? != expected_identity
        || final_opened_metadata.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        || final_path_metadata.file_type().is_symlink()
        || !final_path_metadata.file_type().is_file()
        || checked_geometry_file_identity(&final_path_metadata, path)? != expected_identity
    {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured-catalog journal changed during startup preflight",
            ),
            path.to_path_buf(),
        ));
    }
    configured_catalog_require_store_root_identity(store_root, root_identity)?;
    let journal = decode_exact::<LaneGeometryJournal>(&bytes).map_err(Error::NoritoFrame)?;
    validate_lane_geometry_journal_structure(store_root, &journal)?;
    Ok(Some(ConfiguredCatalogPreflightJournal {
        bytes,
        journal,
        identity: expected_identity,
    }))
}
fn validate_configured_catalog_journal(
    store_root: &Path,
    journal: &LaneGeometryJournal,
    attempted: Hash,
) -> Result<()> {
    validate_lane_geometry_journal_structure(store_root, journal)?;
    match journal.configured_catalog_hash {
        Some(expected) if expected == attempted => Ok(()),
        Some(expected) => Err(configured_catalog_preflight_error(
            store_root,
            ErrorKind::InvalidData,
            format!(
                "configured lane catalog baseline mismatch: expected {expected}, attempted {attempted}"
            ),
        )),
        None => Err(configured_catalog_preflight_error(
            store_root,
            ErrorKind::InvalidData,
            "existing lane geometry journal has no configured lane catalog baseline",
        )),
    }
}
fn preflight_configured_geometry_path(
    store_root: &Path,
    root_identity: GeometryFileIdentity,
    path: &Path,
    directory: bool,
) -> Result<bool> {
    let relative = path.strip_prefix(store_root).map_err(|_| {
        configured_catalog_preflight_error(
            store_root,
            ErrorKind::InvalidInput,
            "configured geometry path escapes the Kura store root",
        )
    })?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(configured_catalog_preflight_error(
            store_root,
            ErrorKind::InvalidInput,
            "configured geometry path is not a canonical store-root descendant",
        ));
    }
    configured_catalog_require_store_root_identity(store_root, root_identity)?;
    let mut current = store_root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            unreachable!("validated normal path component")
        };
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                configured_catalog_require_store_root_identity(store_root, root_identity)?;
                return Ok(false);
            }
            Err(error) => return Err(Error::IO(error, current)),
        };
        if metadata.file_type().is_symlink() {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "configured geometry path contains a symbolic link",
                ),
                current,
            ));
        }
        let is_target = index + 1 == components.len();
        let valid_type = if is_target {
            if directory {
                metadata.file_type().is_dir()
            } else {
                metadata.file_type().is_file()
            }
        } else {
            metadata.file_type().is_dir()
        };
        if !valid_type {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "configured geometry path has an unsafe file type",
                ),
                current,
            ));
        }
    }
    configured_catalog_require_store_root_identity(store_root, root_identity)?;
    Ok(true)
}
fn configured_geometry_path_identity(
    store_root: &Path,
    root_identity: GeometryFileIdentity,
    path: &Path,
    directory: bool,
) -> Result<Option<GeometryFileIdentity>> {
    if !preflight_configured_geometry_path(store_root, root_identity, path, directory)? {
        return Ok(None);
    }
    let metadata = secure_file_metadata::from_path(path)
        .map_err(|error| Error::IO(error, path.to_path_buf()))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink()
        || if directory {
            !file_type.is_dir()
        } else {
            !file_type.is_file()
        }
    {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured geometry path changed after preflight",
            ),
            path.to_path_buf(),
        ));
    }
    configured_catalog_require_store_root_identity(store_root, root_identity)?;
    Ok(Some(geometry_file_identity(&metadata)))
}
#[cfg(all(test, unix))]
fn preflight_configured_store_tree(
    store_root: &Path,
    root_identity: GeometryFileIdentity,
) -> Result<()> {
    let mut pending = vec![(store_root.to_path_buf(), 0_usize, root_identity)];
    let mut entries_seen = 0_usize;
    while let Some((directory, depth, expected_directory_identity)) = pending.pop() {
        configured_catalog_require_store_root_identity(store_root, root_identity)?;
        let before = secure_file_metadata::from_path(&directory)
            .map_err(|error| Error::IO(error, directory.clone()))?;
        if before.file_type().is_symlink()
            || !before.file_type().is_dir()
            || geometry_file_identity(&before) != expected_directory_identity
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "configured Kura directory changed during bounded tree preflight",
                ),
                directory,
            ));
        }
        let entries =
            fs::read_dir(&directory).map_err(|error| Error::IO(error, directory.clone()))?;
        for entry in entries {
            let entry = entry.map_err(|error| Error::IO(error, directory.clone()))?;
            entries_seen = entries_seen.checked_add(1).ok_or_else(|| {
                configured_catalog_preflight_error(
                    store_root,
                    ErrorKind::InvalidData,
                    "configured Kura tree entry count overflow",
                )
            })?;
            if entries_seen > MAX_GEOMETRY_ARCHIVE_ENTRIES {
                return Err(configured_catalog_preflight_error(
                    store_root,
                    ErrorKind::InvalidData,
                    "configured Kura tree exceeds its bounded entry count",
                ));
            }
            let path = entry.path();
            let metadata = secure_file_metadata::from_path(&path)
                .map_err(|error| Error::IO(error, path.clone()))?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "configured Kura tree contains a symbolic link",
                    ),
                    path,
                ));
            }
            let identity = geometry_file_identity(&metadata);
            if file_type.is_dir() {
                let child_depth = depth.checked_add(1).ok_or_else(|| {
                    configured_catalog_preflight_error(
                        store_root,
                        ErrorKind::InvalidData,
                        "configured Kura tree depth overflow",
                    )
                })?;
                if child_depth > MAX_GEOMETRY_ARCHIVE_DEPTH {
                    return Err(configured_catalog_preflight_error(
                        store_root,
                        ErrorKind::InvalidData,
                        "configured Kura tree exceeds its bounded depth",
                    ));
                }
                pending.push((path, child_depth, identity));
            } else if file_type.is_file() {
                let file = File::open(&path).map_err(|error| Error::IO(error, path.clone()))?;
                let opened = secure_file_metadata::from_file(&file)
                    .map_err(|error| Error::IO(error, path.clone()))?;
                let final_path = secure_file_metadata::from_path(&path)
                    .map_err(|error| Error::IO(error, path.clone()))?;
                if !opened.is_file()
                    || final_path.file_type().is_symlink()
                    || !final_path.file_type().is_file()
                    || geometry_file_identity(&opened) != identity
                    || geometry_file_identity(&final_path) != identity
                {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "configured Kura file changed while being opened for preflight",
                        ),
                        path,
                    ));
                }
            } else {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "configured Kura tree contains an unsafe file type",
                    ),
                    path,
                ));
            }
        }
        let after = secure_file_metadata::from_path(&directory)
            .map_err(|error| Error::IO(error, directory.clone()))?;
        if after.file_type().is_symlink()
            || !after.file_type().is_dir()
            || geometry_file_identity(&after) != expected_directory_identity
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "configured Kura directory changed during bounded tree traversal",
                ),
                directory,
            ));
        }
    }
    configured_catalog_require_store_root_identity(store_root, root_identity)
}
fn read_preflight_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    read_preflight_file_bounded_with_identity(path, max_bytes).map(|(bytes, _)| bytes)
}
fn read_preflight_file_bounded_with_identity(
    path: &Path,
    max_bytes: u64,
) -> Result<(Vec<u8>, GeometryFileIdentity)> {
    let path_metadata = secure_file_metadata::from_path(path)
        .map_err(|error| Error::IO(error, path.to_path_buf()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured geometry evidence is not a regular file",
            ),
            path.to_path_buf(),
        ));
    }
    if path_metadata.len() > max_bytes {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured geometry evidence exceeds its encoded byte limit",
            ),
            path.to_path_buf(),
        ));
    }
    let expected_identity = geometry_file_identity(&path_metadata);
    let mut file = File::open(path).map_err(|error| Error::IO(error, path.to_path_buf()))?;
    let opened_metadata = secure_file_metadata::from_file(&file)
        .map_err(|error| Error::IO(error, path.to_path_buf()))?;
    if !opened_metadata.is_file() || geometry_file_identity(&opened_metadata) != expected_identity {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured geometry evidence changed while being opened",
            ),
            path.to_path_buf(),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(path_metadata.len())?);
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| Error::IO(error, path.to_path_buf()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured geometry evidence exceeds its encoded byte limit",
            ),
            path.to_path_buf(),
        ));
    }
    let final_path_metadata = secure_file_metadata::from_path(path)
        .map_err(|error| Error::IO(error, path.to_path_buf()))?;
    let final_open_metadata = secure_file_metadata::from_file(&file)
        .map_err(|error| Error::IO(error, path.to_path_buf()))?;
    if final_path_metadata.file_type().is_symlink()
        || !final_path_metadata.file_type().is_file()
        || geometry_file_identity(&final_path_metadata) != expected_identity
        || geometry_file_identity(&final_open_metadata) != expected_identity
    {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured geometry evidence changed while being read",
            ),
            path.to_path_buf(),
        ));
    }
    Ok((bytes, expected_identity))
}
fn preflight_empty_block_store_without_marker(
    blocks_path: &Path,
    expected_marker: Option<&LaneGeometryBinding>,
    allow_durable_marker: bool,
) -> Result<()> {
    let count_temp_name = format!("{COUNT_FILE_NAME}.tmp");
    let lane_marker_temp_name = MARKER_TEMP_FILE_NAME;
    for entry in
        fs::read_dir(blocks_path).map_err(|error| Error::IO(error, blocks_path.to_path_buf()))?
    {
        let entry = entry.map_err(|error| Error::IO(error, blocks_path.to_path_buf()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| Error::IO(error, path.clone()))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "unbound configured primary block store contains a non-UTF-8 entry",
                ),
                path.clone(),
            )
        })?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "unbound configured primary block store contains an unsafe entry",
                ),
                path,
            ));
        }
        match name {
            INDEX_FILE_NAME | DATA_FILE_NAME | HASHES_FILE_NAME => {
                if entry
                    .metadata()
                    .map_err(|error| Error::IO(error, path.clone()))?
                    .len()
                    != 0
                {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "unbound configured primary block store is not empty",
                        ),
                        path,
                    ));
                }
            }
            COUNT_FILE_NAME => {
                let bytes =
                    read_preflight_file_bounded(&path, MAX_BLOCK_STORE_COMMIT_MARKER_BYTES)?;
                let marker = norito::decode_from_bytes::<BlockStoreCommitMarker>(&bytes)
                    .map_err(Error::NoritoFrame)?;
                if marker.version != BlockStoreCommitMarker::VERSION || marker.count != 0 {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "unbound configured primary block-store marker is not empty",
                        ),
                        path,
                    ));
                }
            }
            MARKER_FILE_NAME if allow_durable_marker => {
                let expected = expected_marker.ok_or_else(|| {
                    Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "journal-owned empty block store has a marker without an expected binding",
                        ),
                        path.clone(),
                    )
                })?;
                let bytes = read_preflight_file_bounded(&path, MAX_LANE_MARKER_BYTES)?;
                let marker =
                    decode_exact::<LaneIncarnationMarker>(&bytes).map_err(Error::NoritoFrame)?;
                if marker.version != MARKER_VERSION
                    || marker.network_id != expected.network_id
                    || marker.dataspace_id != expected.dataspace_id
                    || marker.lane_id != expected.lane_id
                    || marker.incarnation != expected.incarnation
                    || marker.activation_height != expected.activation_height
                {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "journal-owned empty block-store marker is not an exact unsealed binding",
                        ),
                        path,
                    ));
                }
            }
            name if name == count_temp_name => {
                let bytes =
                    read_preflight_file_bounded(&path, MAX_BLOCK_STORE_COMMIT_MARKER_BYTES)?;
                let marker = norito::decode_from_bytes::<BlockStoreCommitMarker>(&bytes)
                    .map_err(Error::NoritoFrame)?;
                if marker.version != BlockStoreCommitMarker::VERSION || marker.count != 0 {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "unbound configured primary block-store temp marker is not empty",
                        ),
                        path,
                    ));
                }
            }
            name if name == lane_marker_temp_name => {
                let expected = expected_marker.ok_or_else(|| {
                    Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "unbound configured primary block store contains a lane-marker temp",
                        ),
                        path.clone(),
                    )
                })?;
                let bytes = read_preflight_file_bounded(&path, MAX_LANE_MARKER_BYTES)?;
                let marker =
                    decode_exact::<LaneIncarnationMarker>(&bytes).map_err(Error::NoritoFrame)?;
                if marker.version != MARKER_VERSION
                    || marker.network_id != expected.network_id
                    || marker.dataspace_id != expected.dataspace_id
                    || marker.lane_id != expected.lane_id
                    || marker.incarnation != expected.incarnation
                    || marker.activation_height != expected.activation_height
                {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "lane-marker temp differs from the durable geometry binding",
                        ),
                        path,
                    ));
                }
            }
            _ => {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "unbound configured primary block store contains an unexpected entry",
                    ),
                    path,
                ));
            }
        }
    }
    Ok(())
}
fn require_pristine_configured_catalog_root(
    store_root: &Path,
    root_identity: GeometryFileIdentity,
    allowed_publication_temp: Option<&ConfiguredCatalogPreflightJournal>,
    authenticated_lock_identity: Option<GeometryFileIdentity>,
) -> Result<()> {
    configured_catalog_require_store_root_identity(store_root, root_identity)?;
    let allowed_path = allowed_publication_temp.map(|_| store_root.join(JOURNAL_TEMP_FILE_NAME));
    let lock_path = store_root.join(super::STORE_ROOT_LOCK_FILE_NAME);
    let mut saw_allowed_temp = false;
    let mut saw_authenticated_lock = false;
    let mut saw_public_reset_marker = false;
    for entry in
        fs::read_dir(store_root).map_err(|error| Error::IO(error, store_root.to_path_buf()))?
    {
        let entry = entry.map_err(|error| Error::IO(error, store_root.to_path_buf()))?;
        let path = entry.path();
        if path == lock_path && authenticated_lock_identity.is_some() {
            let expected = authenticated_lock_identity.expect("authenticated lock identity exists");
            let metadata = secure_file_metadata::from_path(&path)
                .map_err(|error| Error::IO(error, path.clone()))?;
            let file_type = entry
                .file_type()
                .map_err(|error| Error::IO(error, path.clone()))?;
            if saw_authenticated_lock
                || file_type.is_symlink()
                || !file_type.is_file()
                || !Kura::sidecar_is_single_link(&metadata)
                || geometry_file_identity(&metadata) != expected
            {
                return Err(configured_catalog_preflight_error(
                    store_root,
                    ErrorKind::InvalidData,
                    "authenticated Kura store-root lock changed during pristine-root validation",
                ));
            }
            saw_authenticated_lock = true;
            continue;
        }
        if allowed_path.as_deref() == Some(path.as_path()) {
            let expected = allowed_publication_temp.expect("allowed path has a preflight value");
            let metadata = secure_file_metadata::from_path(&path)
                .map_err(|error| Error::IO(error, path.clone()))?;
            let file_type = entry
                .file_type()
                .map_err(|error| Error::IO(error, path.clone()))?;
            if saw_allowed_temp
                || file_type.is_symlink()
                || !file_type.is_file()
                || geometry_file_identity(&metadata) != expected.identity
            {
                return Err(configured_catalog_preflight_error(
                    store_root,
                    ErrorKind::InvalidData,
                    "configured-catalog startup temp changed during pristine-root validation",
                ));
            }
            saw_allowed_temp = true;
            continue;
        }
        if path == store_root.join(".public-reset-generated-v1.json")
            && !saw_public_reset_marker
            && exact_public_reset_storage_marker(store_root)
        {
            saw_public_reset_marker = true;
            continue;
        }
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "cannot establish a configured-catalog baseline on a non-pristine Kura root",
            ),
            path,
        ));
    }
    if allowed_publication_temp.is_some() != saw_allowed_temp {
        return Err(configured_catalog_preflight_error(
            store_root,
            ErrorKind::InvalidData,
            "configured-catalog startup temp disappeared during pristine-root validation",
        ));
    }
    if authenticated_lock_identity.is_some() != saw_authenticated_lock {
        return Err(configured_catalog_preflight_error(
            store_root,
            ErrorKind::InvalidData,
            "authenticated Kura store-root lock disappeared during pristine-root validation",
        ));
    }
    configured_catalog_require_store_root_identity(store_root, root_identity)
}

/// The reset controller creates a marker in each new state directory before
/// starting a validator. A fresh configured Kura may ignore its own storage
/// marker only when the adjacent state-root marker proves the same exact reset.
#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
struct PublicResetGeneratedMarkerV1 {
    schema: String,
    kind: String,
    host_slug: String,
    inventory_sha256: String,
    authorization_nonce: String,
    revision: String,
    created_at_unix_ms: u64,
}

#[cfg(unix)]
fn exact_public_reset_storage_marker(store_root: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    fn lowercase_hex(value: &str, len: usize) -> bool {
        value.len() == len
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn read_marker(path: &Path, owner: u32, group: u32) -> Option<PublicResetGeneratedMarkerV1> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        const MAX_MARKER_BYTES: u64 = 1024;
        let before = secure_file_metadata::from_path(path).ok()?;
        if !before.is_file()
            || before.file_type().is_symlink()
            || before.uid() != owner
            || before.gid() != group
            || before.permissions().mode() & 0o7777 != 0o600
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > MAX_MARKER_BYTES
        {
            return None;
        }
        let (bytes, identity) =
            read_preflight_file_bounded_with_identity(path, MAX_MARKER_BYTES).ok()?;
        let after = secure_file_metadata::from_path(path).ok()?;
        if geometry_file_identity(&before) != identity
            || geometry_file_identity(&after) != identity
            || after.uid() != owner
            || after.gid() != group
            || after.permissions().mode() & 0o7777 != 0o600
            || after.nlink() != 1
            || after.len() != before.len()
        {
            return None;
        }
        let marker: PublicResetGeneratedMarkerV1 = norito::json::from_slice(&bytes).ok()?;
        (norito::json::to_json(&marker).ok()?.as_bytes() == bytes).then_some(marker)
    }

    let Some(state_root) = store_root.parent() else {
        return false;
    };
    let Some(slug) = state_root.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if store_root.file_name().and_then(|name| name.to_str()) != Some("storage")
        || !matches!(
            slug,
            "taira-validator-1" | "taira-validator-2" | "taira-validator-3" | "taira-validator-4"
        )
    {
        return false;
    }
    // The shipping reset is root-owned. Unit tests use their process owner so
    // the full constructor can exercise this gate without elevated privileges.
    #[cfg(test)]
    let (owner, group) = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    #[cfg(not(test))]
    let (owner, group) = (0, 0);
    for path in [state_root, store_root] {
        let Ok(metadata) = secure_file_metadata::from_path(path) else {
            return false;
        };
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner
            || metadata.gid() != group
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return false;
        }
    }
    let marker_name = ".public-reset-generated-v1.json";
    let Some(parent) = read_marker(&state_root.join(marker_name), owner, group) else {
        return false;
    };
    let Some(child) = read_marker(&store_root.join(marker_name), owner, group) else {
        return false;
    };
    parent.schema == "iroha.taira.public-reset.generated-path.v1"
        && child.schema == parent.schema
        && parent.kind == "fresh_state"
        && child.kind == "fresh_state_entry"
        && parent.host_slug == slug
        && child.host_slug == slug
        && lowercase_hex(&parent.inventory_sha256, 64)
        && lowercase_hex(&parent.authorization_nonce, 32)
        && lowercase_hex(&parent.revision, 40)
        && parent.created_at_unix_ms > 0
        && child.inventory_sha256 == parent.inventory_sha256
        && child.authorization_nonce == parent.authorization_nonce
        && child.revision == parent.revision
        && child.created_at_unix_ms == parent.created_at_unix_ms
}

#[cfg(not(unix))]
fn exact_public_reset_storage_marker(_store_root: &Path) -> bool {
    false
}
fn write_initial_configured_catalog_temp(
    store_root: &Path,
    root_identity: GeometryFileIdentity,
    temp_path: &Path,
    bytes: &[u8],
) -> Result<GeometryFileIdentity> {
    configured_catalog_require_store_root_identity(store_root, root_identity)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(temp_path)
        .map_err(|error| Error::IO(error, temp_path.to_path_buf()))?;
    let file_metadata = secure_file_metadata::from_file(&file)
        .map_err(|error| Error::IO(error, temp_path.to_path_buf()))?;
    let identity = checked_geometry_file_identity(&file_metadata, temp_path)?;
    file.write_all(bytes)
        .map_err(|error| Error::IO(error, temp_path.to_path_buf()))?;
    file.sync_all()
        .map_err(|error| Error::IO(error, temp_path.to_path_buf()))?;
    let path_metadata = secure_file_metadata::from_path(temp_path)
        .map_err(|error| Error::IO(error, temp_path.to_path_buf()))?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || checked_geometry_file_identity(&path_metadata, temp_path)? != identity
        || path_metadata.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured-catalog startup temp changed while being persisted",
            ),
            temp_path.to_path_buf(),
        ));
    }
    configured_catalog_require_store_root_identity(store_root, root_identity)?;
    Ok(identity)
}
fn configured_catalog_reserved_temp_identity(
    store_root: &Path,
    root_identity: GeometryFileIdentity,
    temp_path: &Path,
) -> Result<Option<GeometryFileIdentity>> {
    if temp_path.parent() != Some(store_root)
        || !matches!(
            temp_path.file_name().and_then(std::ffi::OsStr::to_str),
            Some(JOURNAL_TEMP_FILE_NAME | JOURNAL_RESTORE_TEMP_FILE_NAME)
        )
    {
        return Err(configured_catalog_preflight_error(
            store_root,
            ErrorKind::InvalidInput,
            "configured-catalog cleanup path is not a reserved direct-child temp",
        ));
    }
    configured_catalog_require_store_root_identity(store_root, root_identity)?;
    let metadata = match secure_file_metadata::from_path(temp_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::IO(error, temp_path.to_path_buf())),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured-catalog reserved temp is a symlink or has an unsafe file type",
            ),
            temp_path.to_path_buf(),
        ));
    }
    configured_catalog_require_store_root_identity(store_root, root_identity)?;
    Ok(Some(geometry_file_identity(&metadata)))
}
fn remove_uncommitted_configured_catalog_temp(
    store_root: &Path,
    root_identity: GeometryFileIdentity,
    temp_path: &Path,
    expected_identity: GeometryFileIdentity,
) -> Result<()> {
    let current_identity =
        configured_catalog_reserved_temp_identity(store_root, root_identity, temp_path)?
            .ok_or_else(|| {
                configured_catalog_preflight_error(
                    store_root,
                    ErrorKind::NotFound,
                    "configured-catalog reserved temp disappeared before cleanup",
                )
            })?;
    if current_identity != expected_identity {
        return Err(configured_catalog_preflight_error(
            store_root,
            ErrorKind::InvalidData,
            "configured-catalog reserved temp identity changed before cleanup",
        ));
    }
    fs::remove_file(temp_path).map_err(|error| Error::IO(error, temp_path.to_path_buf()))?;
    sync_dir(store_root).map_err(|error| Error::IO(error, store_root.to_path_buf()))?;
    configured_catalog_require_store_root_identity(store_root, root_identity)
}
fn promote_initial_configured_catalog_temp(
    store_root: &Path,
    root_identity: GeometryFileIdentity,
    temp_path: &Path,
    temp_identity: GeometryFileIdentity,
    journal_path: &Path,
    expected_bytes: &[u8],
) -> Result<()> {
    configured_catalog_require_store_root_identity(store_root, root_identity)?;
    let temp_metadata = secure_file_metadata::from_path(temp_path)
        .map_err(|error| Error::IO(error, temp_path.to_path_buf()))?;
    if temp_metadata.file_type().is_symlink()
        || !temp_metadata.file_type().is_file()
        || checked_geometry_file_identity(&temp_metadata, temp_path)? != temp_identity
        || temp_metadata.len() != u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured-catalog startup temp identity changed before promotion",
            ),
            temp_path.to_path_buf(),
        ));
    }
    match fs::hard_link(temp_path, journal_path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let existing = read_configured_catalog_journal_for_preflight(
                store_root,
                root_identity,
                journal_path,
                false,
            )?
            .ok_or_else(|| Error::IO(error, journal_path.to_path_buf()))?;
            if existing.bytes != expected_bytes {
                return Err(configured_catalog_preflight_error(
                    store_root,
                    ErrorKind::AlreadyExists,
                    "a different configured-catalog journal won the startup establishment race",
                ));
            }
        }
        Err(error) => return Err(Error::IO(error, journal_path.to_path_buf())),
    }
    let journal_metadata = secure_file_metadata::from_path(journal_path)
        .map_err(|error| Error::IO(error, journal_path.to_path_buf()))?;
    if journal_metadata.file_type().is_symlink()
        || !journal_metadata.file_type().is_file()
        || checked_geometry_file_identity(&journal_metadata, journal_path)? != temp_identity
    {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured-catalog journal does not retain the promoted temp identity",
            ),
            journal_path.to_path_buf(),
        ));
    }
    sync_dir(store_root).map_err(|error| Error::IO(error, store_root.to_path_buf()))?;
    let final_temp_metadata = secure_file_metadata::from_path(temp_path)
        .map_err(|error| Error::IO(error, temp_path.to_path_buf()))?;
    if final_temp_metadata.file_type().is_symlink()
        || !final_temp_metadata.file_type().is_file()
        || checked_geometry_file_identity(&final_temp_metadata, temp_path)? != temp_identity
    {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "configured-catalog startup temp changed before exact cleanup",
            ),
            temp_path.to_path_buf(),
        ));
    }
    fs::remove_file(temp_path).map_err(|error| Error::IO(error, temp_path.to_path_buf()))?;
    sync_dir(store_root).map_err(|error| Error::IO(error, store_root.to_path_buf()))?;
    configured_catalog_require_store_root_identity(store_root, root_identity)
}
impl Kura {
    /// Establish or authenticate the stable configured-catalog journal before
    /// Kura opens any lane-derived storage path.
    #[cfg(test)]
    pub(super) fn establish_or_verify_configured_lane_catalog_baseline(
        store_root: &Path,
        attempted: Hash,
    ) -> Result<()> {
        Self::establish_or_verify_configured_lane_catalog_baseline_inner(
            store_root, attempted, None,
        )
    }
    pub(super) fn establish_or_verify_configured_lane_catalog_baseline_with_lock(
        store_root: &Path,
        attempted: Hash,
        lock_file: &File,
    ) -> Result<()> {
        let root_identity = configured_catalog_store_root_identity(store_root)?;
        let lock_identity = configured_catalog_store_root_lock_identity(store_root, lock_file)?;
        configured_catalog_require_store_root_identity(store_root, root_identity)?;
        Self::establish_or_verify_configured_lane_catalog_baseline_inner(
            store_root,
            attempted,
            Some(lock_identity),
        )
    }
    fn establish_or_verify_configured_lane_catalog_baseline_inner(
        store_root: &Path,
        attempted: Hash,
        authenticated_lock_identity: Option<GeometryFileIdentity>,
    ) -> Result<()> {
        create_dir_all_with_context(store_root)?;
        let root_identity = configured_catalog_store_root_identity(store_root)?;
        let journal_path = store_root.join(JOURNAL_FILE_NAME);
        let publication_temp_path = store_root.join(JOURNAL_TEMP_FILE_NAME);
        let restore_temp_path = store_root.join(JOURNAL_RESTORE_TEMP_FILE_NAME);
        let journal = read_configured_catalog_journal_for_preflight(
            store_root,
            root_identity,
            &journal_path,
            true,
        )?;
        if let Some(journal) = journal {
            validate_configured_catalog_journal(store_root, &journal.journal, attempted)?;
            for temp_path in [&publication_temp_path, &restore_temp_path] {
                if let Some(identity) =
                    configured_catalog_reserved_temp_identity(store_root, root_identity, temp_path)?
                {
                    let (temp_bytes, read_identity) = read_preflight_file_bounded_with_identity(
                        temp_path,
                        MAX_GEOMETRY_JOURNAL_BYTES,
                    )?;
                    if read_identity != identity {
                        return Err(configured_catalog_preflight_error(
                            store_root,
                            ErrorKind::InvalidData,
                            "configured-catalog reserved temp identity changed while being read",
                        ));
                    }
                    if temp_bytes == journal.bytes && read_identity != journal.identity {
                        return Err(configured_catalog_preflight_error(
                            store_root,
                            ErrorKind::InvalidData,
                            "configured-catalog byte-identical reserved temp lacks authoritative hard-link ownership",
                        ));
                    }
                    remove_uncommitted_configured_catalog_temp(
                        store_root,
                        root_identity,
                        temp_path,
                        read_identity,
                    )?;
                }
            }
            let authoritative = read_configured_catalog_journal_for_preflight(
                store_root,
                root_identity,
                &journal_path,
                false,
            )?
            .ok_or_else(|| {
                configured_catalog_preflight_error(
                    store_root,
                    ErrorKind::NotFound,
                    "authoritative configured-catalog journal disappeared during temp cleanup",
                )
            })?;
            if authoritative.identity != journal.identity || authoritative.bytes != journal.bytes {
                return Err(configured_catalog_preflight_error(
                    store_root,
                    ErrorKind::InvalidData,
                    "authoritative configured-catalog journal changed during temp cleanup",
                ));
            }
            configured_catalog_require_store_root_identity(store_root, root_identity)?;
            return Ok(());
        }
        if configured_catalog_reserved_temp_identity(store_root, root_identity, &restore_temp_path)?
            .is_some()
        {
            return Err(configured_catalog_preflight_error(
                store_root,
                ErrorKind::InvalidData,
                "configured-catalog restore temp exists without its authoritative journal",
            ));
        }
        let publication_temp = read_configured_catalog_journal_for_preflight(
            store_root,
            root_identity,
            &publication_temp_path,
            false,
        )?;
        require_pristine_configured_catalog_root(
            store_root,
            root_identity,
            publication_temp.as_ref(),
            authenticated_lock_identity,
        )?;
        let expected_journal = LaneGeometryJournal {
            configured_catalog_hash: Some(attempted),
            ..LaneGeometryJournal::default()
        };
        let expected_bytes = expected_journal.encode();
        let publication_temp_identity = if let Some(temp) = publication_temp {
            if temp.bytes != expected_bytes || temp.journal != expected_journal {
                return Err(configured_catalog_preflight_error(
                    store_root,
                    ErrorKind::InvalidData,
                    "configured-catalog startup temp is not the exact initial baseline journal",
                ));
            }
            temp.identity
        } else {
            write_initial_configured_catalog_temp(
                store_root,
                root_identity,
                &publication_temp_path,
                &expected_bytes,
            )?
        };
        let publication_temp = read_configured_catalog_journal_for_preflight(
            store_root,
            root_identity,
            &publication_temp_path,
            false,
        )?
        .ok_or_else(|| {
            configured_catalog_preflight_error(
                store_root,
                ErrorKind::NotFound,
                "configured-catalog startup temp disappeared before publication",
            )
        })?;
        require_pristine_configured_catalog_root(
            store_root,
            root_identity,
            Some(&publication_temp),
            authenticated_lock_identity,
        )?;
        promote_initial_configured_catalog_temp(
            store_root,
            root_identity,
            &publication_temp_path,
            publication_temp_identity,
            &journal_path,
            &expected_bytes,
        )?;
        let established = read_configured_catalog_journal_for_preflight(
            store_root,
            root_identity,
            &journal_path,
            false,
        )?
        .ok_or_else(|| {
            configured_catalog_preflight_error(
                store_root,
                ErrorKind::NotFound,
                "configured-catalog baseline journal disappeared after establishment",
            )
        })?;
        if established.bytes != expected_bytes || established.journal != expected_journal {
            return Err(configured_catalog_preflight_error(
                store_root,
                ErrorKind::InvalidData,
                "established configured-catalog baseline journal differs from the exact startup value",
            ));
        }
        configured_catalog_require_store_root_identity(store_root, root_identity)
    }
    /// Canonical storage is chain-scoped and never belongs to a lane binding.
    pub fn canonical_storage_path(store_root: &Path) -> PathBuf {
        store_root.join("blocks/canonical")
    }

    /// Reject retired storage namespaces without opening, adapting or deleting their contents.
    pub(super) fn reject_retired_merge_storage(store_root: &Path) -> Result<()> {
        let identity = configured_catalog_store_root_identity(store_root)?;
        for relative in ["merge_ledger", "retired/merge_ledger"] {
            let path = store_root.join(relative);
            if configured_geometry_path_identity(store_root, identity, &path, true)?.is_some() {
                return Err(configured_catalog_preflight_error(
                    store_root,
                    ErrorKind::InvalidData,
                    "retired merge storage namespace is not a current storage owner",
                ));
            }
        }
        Ok(())
    }

    /// Authenticate the fixed chain namespace before any canonical file is opened.
    /// An anchored catalog cannot silently recreate a missing canonical chain.
    pub(super) fn preflight_canonical_storage(
        store_root: &Path,
    ) -> Result<CanonicalStoragePreflight> {
        let root_identity = configured_catalog_store_root_identity(store_root)?;
        let journal = read_configured_catalog_journal_for_preflight(
            store_root,
            root_identity,
            &store_root.join(JOURNAL_FILE_NAME),
            false,
        )?;
        let bound = journal.as_ref().is_some_and(|journal| {
            journal.journal.configured_primary_binding.is_some()
                || !journal.journal.records.is_empty()
        });
        Self::reject_retired_merge_storage(store_root)?;
        let blocks = Self::canonical_storage_path(store_root);
        let blocks_identity =
            configured_geometry_path_identity(store_root, root_identity, &blocks, true)?;
        // Canonical journals are mutable single-owner files. A foreign hard link
        // must be rejected before startup can repair or truncate any journal.
        for path in [
            blocks.join(DATA_FILE_NAME),
            blocks.join(INDEX_FILE_NAME),
            blocks.join(HASHES_FILE_NAME),
            blocks.join(COUNT_FILE_NAME),
        ] {
            match secure_file_metadata::from_path(&path) {
                Ok(metadata)
                    if metadata.file_type().is_symlink()
                        || !metadata.is_file()
                        || !Self::sidecar_is_single_link(&metadata) =>
                {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "canonical journal must be a regular single-link file",
                        ),
                        path,
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(Error::IO(error, path)),
            }
        }
        if bound {
            if blocks_identity.is_none() {
                return Err(configured_catalog_preflight_error(
                    store_root,
                    ErrorKind::NotFound,
                    "bound canonical storage is missing",
                ));
            }
        } else {
            if blocks_identity.is_some() {
                preflight_empty_block_store_without_marker(&blocks, None, false)?;
            }
        }
        configured_catalog_require_store_root_identity(store_root, root_identity)?;
        let parent_identity = configured_geometry_path_identity(
            store_root,
            root_identity,
            &store_root.join("blocks"),
            true,
        )?;
        Ok(CanonicalStoragePreflight {
            paths: StorageOpenPreflight {
                store_root: store_root.to_owned(),
                root_identity,
                blocks_path: blocks,
                blocks_identity,
            },
            parent_identity,
            requires_existing_files: bound,
        })
    }

    /// Capture an exact instance's namespace before its provisioning/recovery.
    fn preflight_lane_instance_open(
        &self,
        binding: &LaneGeometryBinding,
    ) -> Result<LaneInstanceOpenPreflight> {
        self.validate_geometry_binding_from_journal(binding)?;
        let root_identity = configured_catalog_store_root_identity(&self.store_root)?;
        let blocks = self.binding_blocks_path(binding);
        let blocks_identity =
            configured_geometry_path_identity(&self.store_root, root_identity, &blocks, true)?;
        if blocks_identity.is_some()
            && self.validate_path_kind(&blocks.join(MARKER_FILE_NAME), false)?
        {
            self.require_lane_marker_at(&blocks, binding)?;
        }
        let mut parents =
            ["blocks", "blocks/instances"].map(|relative| (self.store_root.join(relative), None));
        for (path, identity) in &mut parents {
            *identity =
                configured_geometry_path_identity(&self.store_root, root_identity, path, true)?;
        }
        Ok(LaneInstanceOpenPreflight {
            parents,
            paths: StorageOpenPreflight {
                store_root: self.store_root.clone(),
                root_identity,
                blocks_path: blocks,
                blocks_identity,
            },
        })
    }
    fn prepare_lane_instance_parents(
        &self,
        preflight: &mut LaneInstanceOpenPreflight,
    ) -> Result<()> {
        for (path, expected) in &mut preflight.parents {
            let actual = configured_geometry_path_identity(
                &self.store_root,
                preflight.paths.root_identity,
                path,
                true,
            )?;
            match (*expected, actual) {
                (Some(expected), Some(actual)) if expected == actual => {}
                (None, None) => {
                    fs::create_dir(&path).map_err(|error| Error::IO(error, path.clone()))?;
                    *expected = configured_geometry_path_identity(
                        &self.store_root,
                        preflight.paths.root_identity,
                        path,
                        true,
                    )?;
                    self.sync_geometry_parent(Some(path))?;
                }
                _ => {
                    return Err(self.geometry_error(
                        ErrorKind::InvalidData,
                        "immutable lane instance parent changed before provisioning",
                    ));
                }
            }
        }
        self.reverify_lane_instance_parents(preflight)
    }
    fn reverify_lane_instance_parents(&self, preflight: &LaneInstanceOpenPreflight) -> Result<()> {
        for (path, expected) in &preflight.parents {
            let actual = configured_geometry_path_identity(
                &self.store_root,
                preflight.paths.root_identity,
                path,
                true,
            )?;
            if expected.is_none() || actual != *expected {
                return Err(self.geometry_error(
                    ErrorKind::InvalidData,
                    "immutable lane instance parent identity changed",
                ));
            }
        }
        Ok(())
    }
    fn reverify_storage_open_path(
        preflight: &mut StorageOpenPreflight,
        path: &Path,
        establish_created: bool,
    ) -> Result<()> {
        let store_root = preflight.store_root.clone();
        let expected_path = &preflight.blocks_path;
        if path != expected_path {
            return Err(configured_catalog_preflight_error(
                &store_root,
                ErrorKind::InvalidInput,
                "configured primary constructor path differs from its authenticated path",
            ));
        }
        let actual =
            configured_geometry_path_identity(&store_root, preflight.root_identity, path, true)?;
        let expected = &mut preflight.blocks_identity;
        match (*expected, actual, establish_created) {
            (Some(expected), Some(actual), _) if expected == actual => Ok(()),
            (None, None, false) => Ok(()),
            (None, Some(actual), true) => {
                *expected = Some(actual);
                Ok(())
            }
            (None, None, true) => Err(configured_catalog_preflight_error(
                &store_root,
                ErrorKind::NotFound,
                "configured primary constructor did not create its authenticated path",
            )),
            _ => Err(configured_catalog_preflight_error(
                &store_root,
                ErrorKind::InvalidData,
                "configured primary path identity changed across its constructor open",
            )),
        }
    }
    /// Bind parents created by this constructor's admitted initial lane provisioning.
    pub(super) fn reverify_canonical_storage_parents(
        preflight: &mut CanonicalStoragePreflight,
        establish_created: bool,
    ) -> Result<()> {
        let paths = &preflight.paths;
        {
            let path = paths.store_root.join("blocks");
            let actual = configured_geometry_path_identity(
                &paths.store_root,
                paths.root_identity,
                &path,
                true,
            )?;
            match (preflight.parent_identity, actual, establish_created) {
                (Some(expected), Some(actual), _) if expected == actual => {}
                (None, None, _) => {}
                (None, Some(actual), true) => preflight.parent_identity = Some(actual),
                _ => {
                    return Err(configured_catalog_preflight_error(
                        &paths.store_root,
                        ErrorKind::InvalidData,
                        "canonical storage parent identity changed during open",
                    ));
                }
            }
        }
        Ok(())
    }
    /// Reverify only the retained chain namespace, independent of retired lane evidence.
    pub(super) fn reverify_canonical_blocks_open(
        preflight: &mut CanonicalStoragePreflight,
        path: &Path,
        establish_created: bool,
    ) -> Result<()> {
        Self::reverify_canonical_storage_parents(preflight, establish_created)?;
        Self::reverify_storage_open_path(&mut preflight.paths, path, establish_created)
    }
    #[cfg(test)]
    pub(super) fn replace_configured_catalog_journal_after_open_for_test(store_root: &Path) {
        *CONFIGURED_CATALOG_PREFLIGHT_IDENTITY_SWAP
            .lock()
            .expect("configured-catalog identity-swap hook lock") =
            Some(canonical_test_store_root(store_root).join(JOURNAL_FILE_NAME));
    }
    #[cfg(test)]
    pub(super) fn fail_after_configured_catalog_preflight_for_test(store_root: &Path) {
        *CONFIGURED_CATALOG_PREFLIGHT_FAIL_AFTER_ESTABLISH
            .lock()
            .expect("configured-catalog crash hook lock") =
            Some(canonical_test_store_root(store_root));
    }
    #[cfg(test)]
    pub(super) fn configured_catalog_preflight_crash_boundary(store_root: &Path) -> Result<()> {
        let should_fail = {
            let mut hook = CONFIGURED_CATALOG_PREFLIGHT_FAIL_AFTER_ESTABLISH
                .lock()
                .expect("configured-catalog crash hook lock");
            if hook.as_deref() == Some(store_root) {
                hook.take();
                true
            } else {
                false
            }
        };
        if should_fail {
            return Err(configured_catalog_preflight_error(
                store_root,
                ErrorKind::Interrupted,
                "configured-catalog startup crash boundary injected after baseline establishment",
            ));
        }
        Ok(())
    }
    /// Verify the exact process-configured lane-catalog baseline.
    ///
    /// This commitment is independent of physical geometry because display-only
    /// catalog fields may not change any path or incarnation commitment.
    pub(crate) fn verify_configured_lane_catalog_baseline(&self, attempted: Hash) -> Result<()> {
        if self.store_root.as_os_str().is_empty() {
            return Ok(());
        }
        let _geometry_guard = self.lane_geometry_lock.lock();
        let journal = self.read_lane_geometry_journal()?;
        match journal.configured_catalog_hash {
            Some(expected) if expected == attempted => Ok(()),
            Some(expected) => Err(self.geometry_error_owned(
                ErrorKind::InvalidData,
                format!(
                    "configured lane catalog baseline mismatch: expected {expected}, attempted {attempted}"
                ),
            )),
            None => Err(self.geometry_error(
                ErrorKind::InvalidData,
                "durable chain has no configured lane catalog baseline",
            )),
        }
    }
    /// Read the exact configured-catalog baseline, if it has been initialized.
    pub(crate) fn configured_lane_catalog_baseline(&self) -> Result<Option<Hash>> {
        if self.store_root.as_os_str().is_empty() {
            return Ok(None);
        }
        let _geometry_guard = self.lane_geometry_lock.lock();
        Ok(self.read_lane_geometry_journal()?.configured_catalog_hash)
    }
    /// Join the recovered State's exact network before any active storage lookup.
    /// This changes no files and does not publish a catalog or grant write admission.
    pub(crate) fn bind_lane_storage_network(&self, network_id: NetworkId) -> Result<()> {
        let _geometry_guard = self.lane_geometry_lock.lock();
        self.raw_geometry_claim.ensure_unclaimed()?;
        let journal = self.read_lane_geometry_journal()?;
        let wrong_network = journal
            .configured_primary_binding
            .iter()
            .chain(journal.records.iter().flat_map(|record| {
                record
                    .previous_bindings
                    .iter()
                    .chain(record.updated_bindings.iter())
            }))
            .any(|binding| binding.network_id != network_id);
        if wrong_network {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "lane storage journal belongs to another authenticated network",
            ));
        }
        let mut current = self.lane_storage_network.lock();
        if current.is_some_and(|current| current != network_id) {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "lane storage network binding cannot change",
            ));
        }
        *current = Some(network_id);
        Ok(())
    }
    /// Authenticate the original configured reference against its exact durable binding.
    pub(crate) fn verify_configured_primary_geometry_reference(
        &self,
        primary: &LaneConfigEntry,
        incarnation: Hash,
        configured_catalog_hash: Hash,
    ) -> Result<()> {
        let expected = LaneGeometryBinding::from_identity(LaneStorageIdentity {
            network_id: self.bound_lane_storage_network()?,
            lane_id: primary.lane_id,
            dataspace_id: primary.dataspace_id,
            incarnation,
            activation_height: 0,
        });
        let _geometry = self.lane_geometry_lock.lock();
        let journal = self.read_lane_geometry_journal()?;
        if journal.configured_catalog_hash != Some(configured_catalog_hash)
            || journal.configured_primary_binding.as_ref() != Some(&expected)
        {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "configured H0 instance reference differs from the authenticated baseline",
            ));
        }
        Ok(())
    }
    /// Bind and provision only the exact configured H0 instance after State authentication.
    pub(crate) fn establish_or_verify_configured_primary_geometry_anchor(
        &self,
        primary: &LaneConfigEntry,
        incarnation: Hash,
        configured_catalog_hash: Hash,
    ) -> Result<()> {
        let network_id = self.bound_lane_storage_network()?;
        let _geometry_guard = self.lane_geometry_lock.lock();
        self.raw_geometry_claim.ensure_unclaimed()?;
        let binding = LaneGeometryBinding::from_identity(LaneStorageIdentity {
            network_id,
            lane_id: primary.lane_id,
            dataspace_id: primary.dataspace_id,
            incarnation,
            activation_height: 0,
        });
        if binding.lane_id != LaneId::SINGLE {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "configured primary binding is not lane zero",
            ));
        }
        let mut journal = self.read_lane_geometry_journal()?;
        if journal.configured_catalog_hash != Some(configured_catalog_hash) {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "configured primary anchor differs from the authenticated catalog baseline",
            ));
        }
        let blocks = self.binding_blocks_path(&binding);
        match journal.configured_primary_binding.as_ref() {
            Some(expected) if expected == &binding => {}
            Some(_) => {
                return Err(self.geometry_error(
                    ErrorKind::InvalidData,
                    "configured primary binding differs from its durable anchor",
                ));
            }
            None => {
                if self.validate_path_kind(&blocks, true)? {
                    return Err(self.geometry_error(
                        ErrorKind::AlreadyExists,
                        "unbound configured instance already has physical storage",
                    ));
                }
                journal.configured_primary_binding = Some(binding.clone());
                self.write_lane_geometry_journal(&journal)?;
            }
        }
        let complete = self.validate_path_kind(&blocks, true)?
            && self.validate_path_kind(&blocks.join(MARKER_FILE_NAME), false)?;
        if complete {
            self.require_complete_geometry_binding_at(&binding, &blocks)?;
        } else {
            if self.exact_durable_blocks_count()? != 0 || !journal.records.is_empty() {
                return Err(self.geometry_error(
                    ErrorKind::NotFound,
                    "authenticated configured instance is missing committed physical storage",
                ));
            }
            if self.validate_path_kind(&blocks, true)? {
                let marker = self.validate_path_kind(&blocks.join(MARKER_FILE_NAME), false)?;
                preflight_empty_block_store_without_marker(&blocks, Some(&binding), marker)?;
            }
            self.provision_geometry_binding(&binding)?;
        }
        self.lane_storage_entries.lock().insert(
            primary.lane_id,
            LaneStorageEntry {
                identity: binding.identity(),
            },
        );
        Ok(())
    }
    /// Apply one lane geometry transition under a durable, replayable intent.
    ///
    /// The intent remains in the journal after publication so a snapshot that
    /// predates several committed transitions can roll their filesystem effects
    /// back before block replay and deterministically reapply them afterwards.
    #[cfg(test)]
    pub(crate) fn apply_lane_geometry_transition(
        &self,
        previous: &LaneConfig,
        updated: &LaneConfig,
        previous_incarnations: &BTreeMap<LaneId, Hash>,
        updated_incarnations: &BTreeMap<LaneId, Hash>,
        previous_activation_heights: &BTreeMap<LaneId, u64>,
        updated_activation_heights: &BTreeMap<LaneId, u64>,
        replaced_lane_ids: &BTreeSet<LaneId>,
    ) -> Result<()> {
        self.apply_lane_geometry_transition_inner(
            previous,
            updated,
            previous_incarnations,
            updated_incarnations,
            previous_activation_heights,
            updated_activation_heights,
            replaced_lane_ids,
            None,
        )
    }

    /// Apply a test geometry transition at its exact committed height.
    #[cfg(test)]
    pub(crate) fn apply_lane_geometry_transition_at_height(
        &self,
        previous: &LaneConfig,
        updated: &LaneConfig,
        previous_incarnations: &BTreeMap<LaneId, Hash>,
        updated_incarnations: &BTreeMap<LaneId, Hash>,
        previous_activation_heights: &BTreeMap<LaneId, u64>,
        updated_activation_heights: &BTreeMap<LaneId, u64>,
        replaced_lane_ids: &BTreeSet<LaneId>,
        transition_height: u64,
    ) -> Result<()> {
        self.apply_lane_geometry_transition_inner(
            previous,
            updated,
            previous_incarnations,
            updated_incarnations,
            previous_activation_heights,
            updated_activation_heights,
            replaced_lane_ids,
            Some(transition_height),
        )
    }
    #[cfg(test)]
    fn apply_lane_geometry_transition_inner(
        &self,
        previous: &LaneConfig,
        updated: &LaneConfig,
        previous_incarnations: &BTreeMap<LaneId, Hash>,
        updated_incarnations: &BTreeMap<LaneId, Hash>,
        previous_activation_heights: &BTreeMap<LaneId, u64>,
        updated_activation_heights: &BTreeMap<LaneId, u64>,
        replaced_lane_ids: &BTreeSet<LaneId>,
        transition_height: Option<u64>,
    ) -> Result<()> {
        if self.store_root.as_os_str().is_empty() {
            *self.lane_storage_entries.lock() = self.lane_storage_entries_from_geometry(
                updated,
                updated_incarnations,
                updated_activation_heights,
            )?;
            return Ok(());
        }
        // This test-only structural transition owns its explicitly supplied
        // H0 preimage. Establish it through the same configured-anchor boundary;
        // production callers obtain this authority from authenticated State.
        if self
            .read_lane_geometry_journal()?
            .configured_primary_binding
            .is_none()
        {
            let baseline = self.configured_lane_catalog_baseline()?.ok_or_else(|| {
                self.geometry_error(
                    ErrorKind::InvalidData,
                    "fixture has no admitted configured catalog",
                )
            })?;
            let primary_incarnation = previous_incarnations
                .get(&previous.primary().lane_id)
                .copied()
                .ok_or_else(|| {
                    self.geometry_error(ErrorKind::InvalidData, "fixture omits primary incarnation")
                })?;
            self.establish_or_verify_configured_primary_geometry_anchor(
                previous.primary(),
                primary_incarnation,
                baseline,
            )?;
        }
        let previous_bindings =
            self.geometry_bindings(previous, previous_incarnations, previous_activation_heights)?;
        let updated_bindings =
            self.geometry_bindings(updated, updated_incarnations, updated_activation_heights)?;
        self.apply_lane_geometry_transition_with_lineage_roots_inner(
            previous,
            updated,
            previous_incarnations,
            updated_incarnations,
            previous_activation_heights,
            updated_activation_heights,
            unscoped_lineage_root(&previous_bindings),
            unscoped_lineage_root(&updated_bindings),
            replaced_lane_ids,
            transition_height,
        )
    }
    /// Apply an authenticated geometry transition at its exact committed height.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_lane_geometry_transition_at_height_with_lineage_roots(
        &self,
        previous: &LaneConfig,
        updated: &LaneConfig,
        previous_incarnations: &BTreeMap<LaneId, Hash>,
        updated_incarnations: &BTreeMap<LaneId, Hash>,
        previous_activation_heights: &BTreeMap<LaneId, u64>,
        updated_activation_heights: &BTreeMap<LaneId, u64>,
        previous_lineage_root: Hash,
        updated_lineage_root: Hash,
        replaced_lane_ids: &BTreeSet<LaneId>,
        transition_height: u64,
    ) -> Result<()> {
        self.apply_lane_geometry_transition_with_lineage_roots_inner(
            previous,
            updated,
            previous_incarnations,
            updated_incarnations,
            previous_activation_heights,
            updated_activation_heights,
            previous_lineage_root,
            updated_lineage_root,
            replaced_lane_ids,
            Some(transition_height),
        )
    }
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn apply_lane_geometry_transition_with_lineage_roots_inner(
        &self,
        previous: &LaneConfig,
        updated: &LaneConfig,
        previous_incarnations: &BTreeMap<LaneId, Hash>,
        updated_incarnations: &BTreeMap<LaneId, Hash>,
        previous_activation_heights: &BTreeMap<LaneId, u64>,
        updated_activation_heights: &BTreeMap<LaneId, u64>,
        previous_lineage_root: Hash,
        updated_lineage_root: Hash,
        replaced_lane_ids: &BTreeSet<LaneId>,
        transition_height: Option<u64>,
    ) -> Result<()> {
        self.apply_lane_geometry_transition_owned_for_tests(
            previous,
            updated,
            previous_incarnations,
            updated_incarnations,
            previous_activation_heights,
            updated_activation_heights,
            previous_lineage_root,
            updated_lineage_root,
            replaced_lane_ids,
            transition_height,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn apply_lane_geometry_transition_owned_for_tests(
        &self,
        previous: &LaneConfig,
        updated: &LaneConfig,
        previous_incarnations: &BTreeMap<LaneId, Hash>,
        updated_incarnations: &BTreeMap<LaneId, Hash>,
        previous_activation_heights: &BTreeMap<LaneId, u64>,
        updated_activation_heights: &BTreeMap<LaneId, u64>,
        previous_lineage_root: Hash,
        updated_lineage_root: Hash,
        replaced_lane_ids: &BTreeSet<LaneId>,
        transition_height: Option<u64>,
    ) -> Result<()> {
        // Structural storage fixtures deliberately surrender only a complete,
        // durable operation boundary. Production State retains the raw owner.
        let previous_bindings =
            self.geometry_bindings(previous, previous_incarnations, previous_activation_heights)?;
        let updated_bindings =
            self.geometry_bindings(updated, updated_incarnations, updated_activation_heights)?;
        let previous_catalog = geometry_catalog_fingerprint(&previous_bindings);
        let updated_catalog = geometry_catalog_fingerprint(&updated_bindings);
        let journal = if self.store_root.as_os_str().is_empty() {
            LaneGeometryJournal::default()
        } else {
            self.read_lane_geometry_journal()?
        };
        let transition_height = match transition_height {
            Some(height) => height,
            None => journal
                .records
                .iter()
                .rev()
                .find(|record| {
                    record.previous_catalog == previous_catalog
                        && record.updated_catalog == updated_catalog
                        && record.previous_lineage_root == previous_lineage_root
                        && record.updated_lineage_root == updated_lineage_root
                })
                .map(|record| record.transition_height)
                .map_or_else(
                    || {
                        journal
                            .records
                            .last()
                            .map(|record| record.transition_height)
                            .map_or(Ok(0), |height| {
                                height.checked_add(1).ok_or_else(|| {
                                    self.geometry_error(
                                        ErrorKind::InvalidData,
                                        "fixture transition height overflow",
                                    )
                                })
                            })
                    },
                    Ok,
                )?,
        };
        let lease = self.try_publication_lease().map_err(|error| match error {
            super::KuraPublicationPreparationError::Storage(error) => error,
            super::KuraPublicationPreparationError::Busy { .. } => self.geometry_error(
                ErrorKind::WouldBlock,
                "fixture geometry physical owner is busy",
            ),
        })?;
        let request = GeometryBindingRequest {
            previous,
            updated,
            previous_incarnations,
            updated_incarnations,
            previous_activation_heights,
            updated_activation_heights,
            previous_lineage_root,
            updated_lineage_root,
            transition_height,
        };
        let mut attempt = lease.begin_raw_geometry_attempt(&request, replaced_lane_ids)?;
        let result = attempt.resume_under(&lease);
        if result.is_err() && !attempt.has_pending_journal_write() {
            // Fixture cancellation uses the same owned inverse, never generic
            // journal reconstruction that could discard an unfinished phase.
            let _ = attempt.rollback_under(&lease);
        }
        attempt.surrender_structural_fixture();
        result
    }
    /// Mark the transition targeting the authoritative catalog as published.
    #[cfg(test)]
    pub(crate) fn mark_lane_geometry_catalog_published(
        &self,
        authoritative: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        configured_baseline: Option<Hash>,
    ) -> Result<()> {
        if self.store_root.as_os_str().is_empty() {
            return Ok(());
        }
        let bindings = self.geometry_bindings(authoritative, incarnations, activation_heights)?;
        self.mark_lane_geometry_catalog_published_with_lineage_root(
            authoritative,
            incarnations,
            activation_heights,
            unscoped_lineage_root(&bindings),
            configured_baseline,
        )
    }
    /// Publish a fully durable structural fixture after its test-only owner surrender.
    #[cfg(test)]
    pub(crate) fn mark_lane_geometry_catalog_published_with_lineage_root(
        &self,
        authoritative: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        lineage_root: Hash,
        configured_baseline: Option<Hash>,
    ) -> Result<()> {
        if self.store_root.as_os_str().is_empty() {
            return Ok(());
        }
        self.ensure_nonzero_lineage_root(lineage_root)?;
        let _prune_guard = self.prune_lock.lock();
        self.ensure_prune_recovery_not_required()?;
        let _canonical_chain_guard = self.canonical_chain_lock.lock();
        self.resolve_canonical_storage_before_mutation()?;
        let pending_canonical_bytes =
            self.pending_canonical_capacity_bytes_under_prune_and_canonical_guards()?;
        let _geometry_guard = self.lane_geometry_lock.lock();
        self.raw_geometry_claim.ensure_unclaimed()?;
        #[cfg(test)]
        if self
            .fail_next_lane_geometry_publication
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(self.geometry_error(
                ErrorKind::Other,
                "lane geometry publication failed for test injection",
            ));
        }
        let bindings = self.geometry_bindings(authoritative, incarnations, activation_heights)?;
        let fingerprint = geometry_catalog_fingerprint(&bindings);
        let journal = self.read_lane_geometry_journal()?;
        if let Some(attempted) = configured_baseline {
            if journal.configured_catalog_hash != Some(attempted) {
                return Err(self.geometry_error(
                    ErrorKind::InvalidData,
                    "configured catalog publication differs from its authenticated startup baseline",
                ));
            }
            let primary_binding = bindings.first().ok_or_else(|| {
                self.geometry_error(
                    ErrorKind::InvalidData,
                    "configured catalog publication has no primary geometry binding",
                )
            })?;
            if journal.configured_primary_binding.as_ref() != Some(primary_binding) {
                return Err(self.geometry_error(
                    ErrorKind::InvalidData,
                    "configured catalog publication has no matching authenticated primary geometry anchor",
                ));
            }
            self.require_lane_marker(primary_binding)?;
        }
        let lease = super::publication_lease::KuraPublicationLease::from_geometry_guards(
            self,
            self.sidecar_lock.lock(),
            _geometry_guard,
            _canonical_chain_guard,
            _prune_guard,
            pending_canonical_bytes,
        );
        lease.publish_prepared_lane_geometry_catalog(
            guarded_publication::PreparedLaneGeometryCatalog {
                bindings,
                fingerprint,
                lineage_root,
                configured_baseline,
                journal,
            },
        )
    }
    #[cfg(test)]
    pub(crate) fn fail_next_lane_geometry_publication_for_test(&self) {
        self.fail_next_lane_geometry_publication
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(test)]
    pub(crate) fn fail_next_lane_geometry_publication_after_write_for_test(&self) {
        self.fail_next_lane_geometry_publication_after_write
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(test)]
    pub(crate) fn lane_geometry_journal_state_for_test(
        &self,
    ) -> Result<(Option<Hash>, Vec<&'static str>, bool)> {
        let _geometry_guard = self.lane_geometry_lock.lock();
        let journal = self.read_lane_geometry_journal()?;
        let phases = journal
            .records
            .iter()
            .map(|record| match record.phase {
                LaneGeometryPhase::Intent => "intent",
                LaneGeometryPhase::FilesApplied => "files_applied",
                LaneGeometryPhase::CatalogPublished => "catalog_published",
                LaneGeometryPhase::RolledBack => "rolled_back",
            })
            .collect();
        let has_temp = self
            .validate_path_kind(&self.store_root.join(JOURNAL_TEMP_FILE_NAME), false)?
            || self
                .validate_path_kind(&self.store_root.join(JOURNAL_RESTORE_TEMP_FILE_NAME), false)?;
        Ok((journal.configured_catalog_hash, phases, has_temp))
    }
    /// Recover every retained geometry intent against a restored authoritative catalog.
    #[cfg(test)]
    pub(crate) fn recover_lane_geometry_journal(
        &self,
        authoritative: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
    ) -> Result<()> {
        self.recover_lane_geometry_journal_inner(
            authoritative,
            incarnations,
            activation_heights,
            LaneGeometryRecoveryCursor::Catalog,
        )
    }
    #[cfg(test)]
    pub(crate) fn recover_lane_geometry_journal_at_height(
        &self,
        authoritative: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        authoritative_height: u64,
    ) -> Result<()> {
        self.recover_lane_geometry_journal_inner(
            authoritative,
            incarnations,
            activation_heights,
            LaneGeometryRecoveryCursor::AtHeight(authoritative_height),
        )
    }
    /// Recover to the exact cursor before every retained transition at `transition_height`.
    #[cfg(test)]
    pub(crate) fn recover_lane_geometry_journal_before_first_transition_at_height(
        &self,
        authoritative: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        transition_height: u64,
    ) -> Result<()> {
        self.recover_lane_geometry_journal_inner(
            authoritative,
            incarnations,
            activation_heights,
            LaneGeometryRecoveryCursor::BeforeFirstTransitionAtHeight(transition_height),
        )
    }
    #[cfg(test)]
    fn recover_lane_geometry_journal_inner(
        &self,
        authoritative: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        cursor: LaneGeometryRecoveryCursor,
    ) -> Result<()> {
        if self.store_root.as_os_str().is_empty() {
            *self.lane_storage_entries.lock() = self.lane_storage_entries_from_geometry(
                authoritative,
                incarnations,
                activation_heights,
            )?;
            return Ok(());
        }
        let bindings = self.geometry_bindings(authoritative, incarnations, activation_heights)?;
        self.recover_lane_geometry_journal_with_lineage_root_inner(
            authoritative,
            incarnations,
            activation_heights,
            unscoped_lineage_root(&bindings),
            cursor,
        )
    }
    /// Recover the authenticated geometry identity at an exact committed height.
    pub(crate) fn recover_lane_geometry_journal_at_height_with_lineage_root(
        &self,
        authoritative: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        authoritative_height: u64,
        lineage_root: Hash,
    ) -> Result<()> {
        self.recover_lane_geometry_journal_with_lineage_root_inner(
            authoritative,
            incarnations,
            activation_heights,
            lineage_root,
            LaneGeometryRecoveryCursor::AtHeight(authoritative_height),
        )
    }
    /// Recover the authenticated cursor immediately before its transition.
    #[cfg(test)]
    pub(crate) fn recover_lane_geometry_journal_before_transition_with_lineage_root(
        &self,
        authoritative: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        lineage_root: Hash,
        transition_height: u64,
    ) -> Result<()> {
        self.recover_lane_geometry_journal_with_lineage_root_inner(
            authoritative,
            incarnations,
            activation_heights,
            lineage_root,
            LaneGeometryRecoveryCursor::BeforeTransition(transition_height),
        )
    }
    /// Recover the authenticated cursor before every transition at one height.
    pub(crate) fn recover_lane_geometry_journal_before_first_transition_at_height_with_lineage_root(
        &self,
        authoritative: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        lineage_root: Hash,
        transition_height: u64,
    ) -> Result<()> {
        self.recover_lane_geometry_journal_with_lineage_root_inner(
            authoritative,
            incarnations,
            activation_heights,
            lineage_root,
            LaneGeometryRecoveryCursor::BeforeFirstTransitionAtHeight(transition_height),
        )
    }
    /// Verify that the full retained creation history reaches the configured-primary replay floor.
    ///
    /// This read-only preflight checks exact catalog and lineage bindings before original replay.
    /// It cannot authorize snapshot state, repair a marker, or discard retained history.
    pub(crate) fn preflight_lane_geometry_recovery_floor_with_lineage_root(
        &self,
        authoritative: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        lineage_root: Hash,
    ) -> Result<()> {
        if self.store_root.as_os_str().is_empty() {
            return Ok(());
        }
        self.ensure_nonzero_lineage_root(lineage_root)?;
        let _prune_guard = self.prune_lock.lock();
        self.ensure_prune_recovery_not_required()?;
        let _canonical_chain_guard = self.canonical_chain_lock.lock();
        let _geometry_guard = self.lane_geometry_lock.lock();
        let bindings = self.geometry_bindings(authoritative, incarnations, activation_heights)?;
        let fingerprint = geometry_catalog_fingerprint(&bindings);
        let journal = self.read_lane_geometry_journal()?;
        let primary_binding = bindings.first().ok_or_else(|| {
            self.geometry_error(
                ErrorKind::InvalidData,
                "configured-primary replay geometry has no primary binding",
            )
        })?;
        if journal
            .configured_primary_binding
            .as_ref()
            .is_some_and(|expected| expected != primary_binding)
        {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "configured-primary geometry binding differs from its durable anchor",
            ));
        }
        let recovery_floor = Self::lane_geometry_identity_at_applied_count(&journal, 0);
        if recovery_floor.is_some_and(|identity| identity != (fingerprint, lineage_root)) {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "configured-primary geometry identity does not match the retained recovery floor",
            ));
        }
        Ok(())
    }
    fn recover_lane_geometry_journal_with_lineage_root_inner(
        &self,
        authoritative: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        lineage_root: Hash,
        cursor: LaneGeometryRecoveryCursor,
    ) -> Result<()> {
        if self.store_root.as_os_str().is_empty() {
            *self.lane_storage_entries.lock() = self.lane_storage_entries_from_geometry(
                authoritative,
                incarnations,
                activation_heights,
            )?;
            return Ok(());
        }
        self.ensure_nonzero_lineage_root(lineage_root)?;
        let _prune_guard = self.prune_lock.lock();
        self.ensure_prune_recovery_not_required()?;
        let _canonical_chain_guard = self.canonical_chain_lock.lock();
        self.resolve_canonical_storage_before_mutation()?;
        let _geometry_guard = self.lane_geometry_lock.lock();
        self.raw_geometry_claim.ensure_unclaimed()?;
        let bindings = self.geometry_bindings(authoritative, incarnations, activation_heights)?;
        let fingerprint = geometry_catalog_fingerprint(&bindings);
        let mut journal = self.read_lane_geometry_journal()?;
        let _sidecar_guard = self.sidecar_lock.lock();
        match cursor {
            #[cfg(test)]
            LaneGeometryRecoveryCursor::Catalog => {
                self.reconcile_lane_geometry_history(&mut journal, fingerprint, lineage_root)?;
            }
            LaneGeometryRecoveryCursor::AtHeight(authoritative_height) => {
                let desired_applied_count = journal
                    .records
                    .iter()
                    .take_while(|record| record.transition_height <= authoritative_height)
                    .count();
                self.reconcile_lane_geometry_history_to_count(
                    &mut journal,
                    fingerprint,
                    lineage_root,
                    desired_applied_count,
                )?;
            }
            LaneGeometryRecoveryCursor::BeforeFirstTransitionAtHeight(transition_height) => {
                let desired_applied_count = journal
                    .records
                    .iter()
                    .take_while(|record| record.transition_height < transition_height)
                    .count();
                self.reconcile_lane_geometry_history_to_count(
                    &mut journal,
                    fingerprint,
                    lineage_root,
                    desired_applied_count,
                )?;
            }
            #[cfg(test)]
            LaneGeometryRecoveryCursor::BeforeTransition(transition_height) => {
                let mut matching =
                    journal
                        .records
                        .iter()
                        .enumerate()
                        .filter_map(|(index, record)| {
                            (record.transition_height == transition_height
                                && record.previous_catalog == fingerprint
                                && record.previous_lineage_root == lineage_root)
                                .then_some(index)
                        });
                let candidate = matching.next();
                if candidate.is_some() && matching.next().is_some() {
                    return Err(self.geometry_error(
                        ErrorKind::InvalidData,
                        "authoritative geometry is ambiguous before transitions at the requested height",
                    ));
                }
                let desired_applied_count = candidate.unwrap_or_else(|| {
                    journal
                        .records
                        .iter()
                        .take_while(|record| record.transition_height < transition_height)
                        .count()
                });
                self.reconcile_lane_geometry_history_to_count(
                    &mut journal,
                    fingerprint,
                    lineage_root,
                    desired_applied_count,
                )?;
            }
        }
        self.ensure_authoritative_lane_markers(authoritative, incarnations, activation_heights)?;
        *self.lane_storage_entries.lock() = self.lane_storage_entries_from_geometry(
            authoritative,
            incarnations,
            activation_heights,
        )?;
        self.write_lane_geometry_journal(&journal)
    }

    #[cfg(test)]
    fn reconcile_lane_geometry_history(
        &self,
        journal: &mut LaneGeometryJournal,
        authoritative_catalog: Hash,
        authoritative_lineage_root: Hash,
    ) -> Result<()> {
        if journal.records.is_empty() {
            return Ok(());
        }
        let mut candidates = Vec::new();
        if journal.records[0].previous_catalog == authoritative_catalog
            && journal.records[0].previous_lineage_root == authoritative_lineage_root
        {
            candidates.push(0);
        }
        candidates.extend(
            journal
                .records
                .iter()
                .enumerate()
                .filter_map(|(index, record)| {
                    (record.updated_catalog == authoritative_catalog
                        && record.updated_lineage_root == authoritative_lineage_root)
                        .then_some(index + 1)
                }),
        );
        if candidates.len() != 1 {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "authoritative geometry identity is absent or ambiguous without an exact transition height",
            ));
        }
        self.reconcile_lane_geometry_history_to_count(
            journal,
            authoritative_catalog,
            authoritative_lineage_root,
            candidates[0],
        )
    }
    fn reconcile_lane_geometry_history_to_count(
        &self,
        journal: &mut LaneGeometryJournal,
        authoritative_catalog: Hash,
        authoritative_lineage_root: Hash,
        desired_applied_count: usize,
    ) -> Result<()> {
        self.raw_geometry_claim.ensure_unclaimed()?;
        self.reconcile_lane_geometry_history_to_count_with_custody(
            journal,
            authoritative_catalog,
            authoritative_lineage_root,
            desired_applied_count,
            None,
        )
    }

    fn reconcile_lane_geometry_history_to_count_with_custody(
        &self,
        journal: &mut LaneGeometryJournal,
        authoritative_catalog: Hash,
        authoritative_lineage_root: Hash,
        desired_applied_count: usize,
        mut custody: Option<&mut RawGeometryMutation<'_, '_>>,
    ) -> Result<()> {
        if let Some(custody) = custody.as_deref() {
            custody.authenticate(self)?;
        }
        if desired_applied_count > journal.records.len() {
            return Err(self.geometry_error(
                ErrorKind::InvalidInput,
                "lane geometry recovery cursor exceeds retained transition history",
            ));
        }
        for pair in journal.records.windows(2) {
            if pair[0].updated_catalog != pair[1].previous_catalog
                || pair[0].updated_lineage_root != pair[1].previous_lineage_root
            {
                return Err(self.geometry_error(
                    ErrorKind::InvalidData,
                    "lane geometry journal transition chain is not contiguous",
                ));
            }
        }
        let identity_at_cursor =
            Self::lane_geometry_identity_at_applied_count(journal, desired_applied_count);
        if identity_at_cursor
            .is_some_and(|identity| identity != (authoritative_catalog, authoritative_lineage_root))
        {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "authoritative geometry identity does not match its exact transition cursor",
            ));
        }
        if let Some(boundary) = journal.records.iter().position(|record| {
            matches!(
                record.phase,
                LaneGeometryPhase::Intent | LaneGeometryPhase::FilesApplied
            )
        }) {
            let evidence_policy = if journal.records[boundary].phase == LaneGeometryPhase::Intent {
                GeometryEvidencePolicy::AllowJournalIntentProvisioning
            } else {
                GeometryEvidencePolicy::RequireDurableEvidence
            };
            if boundary < desired_applied_count {
                self.apply_geometry_operations_forward(
                    &journal.records[boundary].operations,
                    evidence_policy,
                )?;
                journal.records[boundary].phase = LaneGeometryPhase::CatalogPublished;
            } else {
                self.apply_geometry_operations_rollback(
                    &journal.records[boundary].operations,
                    evidence_policy,
                )?;
                journal.records[boundary].phase = LaneGeometryPhase::RolledBack;
            }
            self.write_lane_geometry_journal_with_custody(journal, custody.as_deref_mut())?;
        }
        let mut current_applied_count = journal
            .records
            .iter()
            .position(|record| record.phase == LaneGeometryPhase::RolledBack)
            .unwrap_or(journal.records.len());
        for index in (desired_applied_count..current_applied_count).rev() {
            // Preserve `CatalogPublished` as durable evidence provenance until the inverse is
            // complete. The authoritative cursor makes this idempotently resumable after a crash.
            self.apply_geometry_operations_rollback(
                &journal.records[index].operations,
                GeometryEvidencePolicy::RequireDurableEvidence,
            )?;
            journal.records[index].phase = LaneGeometryPhase::RolledBack;
            self.write_lane_geometry_journal_with_custody(journal, custody.as_deref_mut())?;
        }
        current_applied_count = journal
            .records
            .iter()
            .position(|record| record.phase == LaneGeometryPhase::RolledBack)
            .unwrap_or(journal.records.len());
        for index in current_applied_count..desired_applied_count {
            // Preserve `RolledBack` until the exact retained image is live again. Only a newly
            // appended transition may carry `Intent` and authorize empty staging provisioning.
            self.apply_geometry_operations_forward(
                &journal.records[index].operations,
                GeometryEvidencePolicy::RequireDurableEvidence,
            )?;
            journal.records[index].phase = LaneGeometryPhase::CatalogPublished;
            self.write_lane_geometry_journal_with_custody(journal, custody.as_deref_mut())?;
        }
        // A terminal phase is a durable direction decision, not proof that a process completed
        // both filesystem renames before it died. Reassert the exact frontier operation on every
        // recovery. The original journal owner authenticates complete marker-bound storage or
        // resumes its own interrupted empty creation; it never substitutes committed evidence.
        if let Some(record) = journal.records.get(desired_applied_count) {
            self.apply_geometry_operations_rollback(
                &record.operations,
                GeometryEvidencePolicy::RequireDurableEvidence,
            )?;
        } else if let Some(record) = desired_applied_count
            .checked_sub(1)
            .and_then(|index| journal.records.get(index))
        {
            self.apply_geometry_operations_forward(
                &record.operations,
                GeometryEvidencePolicy::RequireDurableEvidence,
            )?;
        }
        Ok(())
    }
    fn lane_geometry_identity_at_applied_count(
        journal: &LaneGeometryJournal,
        desired_applied_count: usize,
    ) -> Option<(Hash, Hash)> {
        if desired_applied_count == 0 {
            journal
                .records
                .first()
                .map(|record| (record.previous_catalog, record.previous_lineage_root))
        } else {
            journal
                .records
                .get(desired_applied_count - 1)
                .map(|record| (record.updated_catalog, record.updated_lineage_root))
        }
    }

    fn build_geometry_operations(
        &self,
        _transition_id: Hash,
        previous: &[LaneGeometryBinding],
        updated: &[LaneGeometryBinding],
        replaced_lane_ids: &BTreeSet<LaneId>,
    ) -> Result<Vec<LaneGeometryOperation>> {
        if !replaced_lane_ids.is_empty()
            || previous
                .iter()
                .any(|before| !updated.iter().any(|after| before == after))
        {
            return Err(self.geometry_error(ErrorKind::InvalidInput,
                "native geometry currently permits exact additions only; release authority is unavailable"));
        }
        let mut operations = Vec::new();
        for binding in updated {
            if previous
                .iter()
                .any(|before| before.lane_id == binding.lane_id)
            {
                continue;
            }
            let operation = LaneGeometryOperation {
                kind: LaneGeometryOperationKind::Create,
                lane_id: binding.lane_id,
                created: binding.clone(),
            };
            self.preflight_geometry_operation(&operation)?;
            operations.push(operation);
        }
        Ok(operations)
    }
    fn preflight_geometry_operation(&self, operation: &LaneGeometryOperation) -> Result<()> {
        let updated = &operation.created;
        if self.validate_path_kind(&self.binding_blocks_path(updated), true)? {
            return Err(self.geometry_error(
                ErrorKind::AlreadyExists,
                "new lane instance target already contains storage",
            ));
        }
        Ok(())
    }
    /// Prepare exact new instances without moving or deleting predecessor objects.
    /// The journal already owns every creation; terminal retries require existing evidence.
    fn apply_geometry_operations_forward(
        &self,
        operations: &[LaneGeometryOperation],
        evidence_policy: GeometryEvidencePolicy,
    ) -> Result<()> {
        self.apply_geometry_operations_forward_with_progress(operations, evidence_policy, None)
    }
    fn apply_geometry_operations_forward_with_progress(
        &self,
        operations: &[LaneGeometryOperation],
        evidence_policy: GeometryEvidencePolicy,
        mut provisioning_started: Option<&mut bool>,
    ) -> Result<()> {
        for operation in operations {
            self.prepare_journal_owned_lane_instance_with_progress(
                &operation.created,
                evidence_policy,
                provisioning_started.as_deref_mut(),
            )?;
        }
        #[cfg(test)]
        self.geometry_reference_publication_pause_for_test();
        Ok(())
    }
    /// Rollback changes only the published reference frontier. Exact instances remain retained.
    /// TODO(S6): release requires original native closing authority and a dedicated storage owner.
    fn apply_geometry_operations_rollback(
        &self,
        operations: &[LaneGeometryOperation],
        evidence_policy: GeometryEvidencePolicy,
    ) -> Result<()> {
        for operation in operations.iter().rev() {
            self.prepare_journal_owned_lane_instance(&operation.created, evidence_policy)?;
        }
        #[cfg(test)]
        self.geometry_reference_publication_pause_for_test();
        Ok(())
    }
    #[cfg(test)]
    fn geometry_reference_publication_pause_for_test(&self) {
        if !self
            .pause_geometry_reference_publication
            .swap(false, Ordering::AcqRel)
        {
            return;
        }
        self.geometry_reference_publication_paused
            .store(true, Ordering::Release);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while self
            .geometry_reference_publication_paused
            .load(Ordering::Acquire)
        {
            assert!(
                std::time::Instant::now() < deadline,
                "reference publication hook was not resumed"
            );
            std::thread::yield_now();
        }
    }
    fn prepare_journal_owned_lane_instance(
        &self,
        binding: &LaneGeometryBinding,
        evidence_policy: GeometryEvidencePolicy,
    ) -> Result<()> {
        self.prepare_journal_owned_lane_instance_with_progress(binding, evidence_policy, None)
    }
    fn prepare_journal_owned_lane_instance_with_progress(
        &self,
        binding: &LaneGeometryBinding,
        evidence_policy: GeometryEvidencePolicy,
        provisioning_started: Option<&mut bool>,
    ) -> Result<()> {
        let blocks = self.binding_blocks_path(binding);
        let blocks_exists = self.validate_path_kind(&blocks, true)?;
        if evidence_policy == GeometryEvidencePolicy::FreshJournalIntent && blocks_exists {
            return Err(self.geometry_error(
                ErrorKind::AlreadyExists,
                "fresh lane instance target became occupied after admission",
            ));
        }
        if blocks_exists && self.validate_path_kind(&blocks.join(MARKER_FILE_NAME), false)? {
            if evidence_policy.allows_journal_intent_provisioning() {
                self.require_exact_empty_journal_owned_storage_at(binding, &blocks)?;
            } else {
                self.require_complete_geometry_binding_at(binding, &blocks)?;
            }
            return Ok(());
        }
        if !evidence_policy.allows_journal_intent_provisioning() {
            return Err(self.geometry_error(
                ErrorKind::NotFound,
                "durable lane instance evidence is missing; refusing empty provisioning",
            ));
        }
        if blocks_exists {
            let marker_exists = self.validate_path_kind(&blocks.join(MARKER_FILE_NAME), false)?;
            preflight_empty_block_store_without_marker(&blocks, Some(binding), marker_exists)?;
        }
        self.provision_geometry_binding_with_progress(binding, provisioning_started)?;
        self.require_exact_empty_journal_owned_storage_at(binding, &blocks)
    }

    fn require_complete_geometry_binding_at(
        &self,
        binding: &LaneGeometryBinding,
        blocks: &Path,
    ) -> Result<()> {
        if !self.validate_path_kind(blocks, true)? {
            return Err(self.geometry_error(
                ErrorKind::NotFound,
                "complete authenticated lane geometry storage is missing",
            ));
        }
        for name in [
            DATA_FILE_NAME,
            INDEX_FILE_NAME,
            HASHES_FILE_NAME,
            COUNT_FILE_NAME,
        ] {
            self.geometry_path_identity(&blocks.join(name), false)?;
        }
        self.require_lane_marker_at(blocks, binding)
    }
    fn require_exact_empty_journal_owned_storage_at(
        &self,
        binding: &LaneGeometryBinding,
        blocks: &Path,
    ) -> Result<()> {
        self.require_complete_geometry_binding_at(binding, blocks)?;
        preflight_empty_block_store_without_marker(blocks, Some(binding), true)?;
        let marker = self.read_lane_marker(&blocks.join(MARKER_FILE_NAME))?;
        self.require_lane_marker_value(&marker, blocks, binding)?;
        Ok(())
    }

    fn sync_geometry_path_contents(&self, path: &Path, directory: bool) -> Result<()> {
        if !directory {
            let file = File::open(path).map_err(|error| Error::IO(error, path.to_path_buf()))?;
            self.verify_open_geometry_file(path, &file)?;
            file.sync_all()
                .map_err(|error| Error::IO(error, path.to_path_buf()))?;
            return Ok(());
        }
        let root_identity = self.geometry_path_identity(path, true)?;
        let mut seen = 0_usize;
        let mut pending = vec![(path.to_path_buf(), 0_usize)];
        let mut directories = Vec::new();
        while let Some((current, depth)) = pending.pop() {
            if depth > MAX_GEOMETRY_ARCHIVE_DEPTH {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "lane geometry storage exceeds the maximum directory depth",
                    ),
                    current,
                ));
            }
            self.geometry_path_identity(&current, true)?;
            directories.push(current.clone());
            for entry in
                fs::read_dir(&current).map_err(|error| Error::IO(error, current.clone()))?
            {
                let entry = entry.map_err(|error| Error::IO(error, current.clone()))?;
                seen = seen.saturating_add(1);
                if seen > MAX_GEOMETRY_ARCHIVE_ENTRIES {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "lane geometry storage exceeds the maximum entry count",
                        ),
                        current,
                    ));
                }
                let child = entry.path();
                let file_type = entry
                    .file_type()
                    .map_err(|error| Error::IO(error, child.clone()))?;
                if file_type.is_symlink() {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "lane geometry storage contains a symbolic link",
                        ),
                        child,
                    ));
                }
                if file_type.is_dir() {
                    pending.push((child, depth.saturating_add(1)));
                } else if file_type.is_file() {
                    let file =
                        File::open(&child).map_err(|error| Error::IO(error, child.clone()))?;
                    self.verify_open_geometry_file(&child, &file)?;
                    file.sync_all().map_err(|error| Error::IO(error, child))?;
                } else {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "lane geometry storage contains a non-regular entry",
                        ),
                        child,
                    ));
                }
            }
        }
        for directory in directories.into_iter().rev() {
            sync_dir(&directory).map_err(|error| Error::IO(error, directory))?;
        }
        self.require_geometry_path_identity(path, true, root_identity)
    }
    fn provision_geometry_binding(&self, binding: &LaneGeometryBinding) -> Result<()> {
        self.provision_geometry_binding_with_progress(binding, None)
    }
    fn provision_geometry_binding_with_progress(
        &self,
        binding: &LaneGeometryBinding,
        provisioning_started: Option<&mut bool>,
    ) -> Result<()> {
        let blocks = self.binding_blocks_path(binding);
        let mut open = self.preflight_lane_instance_open(binding)?;
        // Failure from this point may leave a native object. Only the original
        // Strict recovery journal can complete it without a retained creator.
        if let Some(started) = provisioning_started {
            *started = true;
        }
        self.prepare_lane_instance_parents(&mut open)?;
        let blocks_exist = self.validate_path_kind(&blocks, true)?;
        let marker_exists = if blocks_exist {
            let marker_path = blocks.join(MARKER_FILE_NAME);
            let marker_exists = self.validate_path_kind(&marker_path, false)?;
            if !marker_exists {
                preflight_empty_block_store_without_marker(&blocks, Some(binding), false)?;
            }
            marker_exists
        } else {
            if let Some(parent) = blocks.parent() {
                create_dir_all_with_context(parent)?;
                self.validate_path_kind(parent, true)?;
            }
            false
        };
        let before = Self::block_store_bytes(&blocks)?;
        let accounting_mutation = self
            .begin_total_disk_usage_mutation()
            .with_startup_resource_tree(&blocks);
        #[cfg(test)]
        super::configured_primary_open_identity_swap_boundary(&blocks)?;
        self.reverify_lane_instance_parents(&open)?;
        Self::reverify_storage_open_path(&mut open.paths, &blocks, false)?;
        let mut store = BlockStore::new(&blocks);
        store.create_files_if_they_do_not_exist()?;
        #[cfg(test)]
        if FAIL_NEXT_GEOMETRY_INSTANCE_AFTER_FILES.with(|fault| fault.replace(false)) {
            return Err(Error::IO(
                std::io::Error::other(
                    "injected original instance provisioning failure after base files",
                ),
                blocks,
            ));
        }
        self.reverify_lane_instance_parents(&open)?;
        Self::reverify_storage_open_path(&mut open.paths, &blocks, true)?;
        self.sync_geometry_path_contents(&blocks, true)?;
        let after = Self::block_store_bytes(&blocks)?;
        self.update_disk_usage_delta(before, after);
        accounting_mutation.finish();
        if marker_exists {
            self.require_lane_marker(binding)?;
        } else {
            self.write_lane_marker(binding)?;
        }
        self.reverify_lane_instance_parents(&open)?;
        Self::reverify_storage_open_path(&mut open.paths, &blocks, true)?;
        Ok(())
    }
    fn ensure_authoritative_lane_markers(
        &self,
        lane_config: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
    ) -> Result<()> {
        for entry in lane_config.entries() {
            let binding = self.geometry_binding(entry, incarnations, activation_heights)?;
            let blocks = self.binding_blocks_path(&binding);
            let blocks_exists = self.validate_path_kind(&blocks, true)?;
            if !blocks_exists {
                return Err(self.geometry_error(
                    ErrorKind::NotFound,
                    "authoritative lane storage is missing; refusing to provision an empty replacement",
                ));
            }
            let marker_path = blocks.join(MARKER_FILE_NAME);
            if !self.validate_path_kind(&marker_path, false)? {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "authoritative lane storage has no incarnation marker",
                    ),
                    marker_path,
                ));
            }
            // Creation belongs only to the admitted initial/Intent owner. A
            // restored reference cannot recreate a lost marker, including H0.
            let marker = self.read_lane_marker(&marker_path)?;
            self.require_lane_marker_value(&marker, &blocks, &binding)?;
        }
        Ok(())
    }
    fn require_lane_marker(&self, binding: &LaneGeometryBinding) -> Result<()> {
        self.require_lane_marker_at(&self.binding_blocks_path(binding), binding)
    }
    fn require_lane_marker_at(
        &self,
        blocks_path: &Path,
        binding: &LaneGeometryBinding,
    ) -> Result<()> {
        let path = blocks_path.join(MARKER_FILE_NAME);
        let marker = self.read_lane_marker(&path)?;
        self.require_lane_marker_value(&marker, blocks_path, binding)
    }
    fn require_lane_marker_value(
        &self,
        marker: &LaneIncarnationMarker,
        blocks_path: &Path,
        binding: &LaneGeometryBinding,
    ) -> Result<()> {
        if marker.version != MARKER_VERSION
            || marker.network_id != binding.network_id
            || marker.dataspace_id != binding.dataspace_id
            || marker.lane_id != binding.lane_id
            || marker.incarnation != binding.incarnation
            || marker.activation_height != binding.activation_height
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "lane storage incarnation marker does not match authoritative binding",
                ),
                blocks_path.join(MARKER_FILE_NAME),
            ));
        }
        Ok(())
    }

    /// Require an incarnation and proposal height to match an active marker.
    ///
    /// This lower-level form is reserved for replay claims that do not carry a
    /// full lane descriptor. Artifact paths should use
    /// [`Self::require_active_lane_artifact`] so lane and dataspace are checked
    /// as well.
    pub(super) fn require_active_lane_incarnation(
        &self,
        entry: &LaneStorageEntry,
        expected_incarnation: Hash,
        proposal_height: u64,
    ) -> Result<()> {
        let path = entry.blocks_dir(&self.store_root).join(MARKER_FILE_NAME);
        let marker = self.read_lane_marker(&path)?;
        let identity = &entry.identity;
        if marker.version != MARKER_VERSION
            || marker.network_id != identity.network_id
            || marker.dataspace_id != identity.dataspace_id
            || marker.incarnation != identity.incarnation
            || marker.activation_height != identity.activation_height
            || marker.lane_id != entry.lane_id
            || marker.incarnation != expected_incarnation
            || proposal_height <= marker.activation_height
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "lane artifact does not match the active geometry marker",
                ),
                path,
            ));
        }
        Ok(())
    }
    /// Return the exact active incarnation and activation height under the
    /// caller-held geometry lock.
    pub(super) fn active_lane_incarnation_marker(
        &self,
        entry: &LaneStorageEntry,
    ) -> Result<(Hash, u64)> {
        let path = entry.blocks_dir(&self.store_root).join(MARKER_FILE_NAME);
        let marker = self.read_lane_marker(&path)?;
        let identity = &entry.identity;
        if marker.version != MARKER_VERSION
            || marker.network_id != identity.network_id
            || marker.dataspace_id != identity.dataspace_id
            || marker.incarnation != identity.incarnation
            || marker.activation_height != identity.activation_height
            || marker.lane_id != entry.lane_id
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "active lane marker has the wrong route identity",
                ),
                path,
            ));
        }
        Ok((marker.incarnation, marker.activation_height))
    }
    /// Select authenticated physical storage without publishing a State catalog.
    #[cfg(test)]
    fn selected_canonical_recovery_physical_bindings(&self) -> Result<Vec<LaneGeometryBinding>> {
        let journal = self.read_lane_geometry_journal()?;
        self.selected_canonical_recovery_physical_bindings_in_journal(&journal)
    }
    fn selected_canonical_recovery_physical_bindings_in_journal(
        &self,
        journal: &LaneGeometryJournal,
    ) -> Result<Vec<LaneGeometryBinding>> {
        if journal.configured_catalog_hash.is_none() || journal.configured_primary_binding.is_none()
        {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "canonical association recovery has no admitted physical geometry journal",
            ));
        }
        let applied = journal
            .records
            .iter()
            .take_while(|record| {
                matches!(
                    record.phase,
                    LaneGeometryPhase::FilesApplied | LaneGeometryPhase::CatalogPublished,
                )
            })
            .count();
        if journal.records[applied..].iter().any(|record| {
            !matches!(
                record.phase,
                LaneGeometryPhase::Intent | LaneGeometryPhase::RolledBack
            )
        }) {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "canonical association recovery has a discontinuous physical geometry prefix",
            ));
        }
        let bindings: &[LaneGeometryBinding] = if applied > 0 {
            &journal.records[applied - 1].updated_bindings
        } else if let Some(first) = journal.records.first() {
            &first.previous_bindings
        } else {
            std::slice::from_ref(
                journal
                    .configured_primary_binding
                    .as_ref()
                    .expect("checked primary binding"),
            )
        };
        Ok(bindings.to_vec())
    }
    /// Enumerate exact immutable instances retained by the creation journal.
    /// This inventory cannot authorize a release, replacement or consensus signature.
    fn retained_lane_instance_bindings(
        &self,
        journal: &LaneGeometryJournal,
    ) -> Result<Vec<LaneGeometryBinding>> {
        let active = self.selected_canonical_recovery_physical_bindings_in_journal(journal)?;
        let mut references = active
            .into_iter()
            .map(|binding| (binding.identity(), binding))
            .collect::<BTreeMap<_, _>>();
        for binding in journal.records.iter().flat_map(|record| {
            record
                .previous_bindings
                .iter()
                .chain(&record.updated_bindings)
        }) {
            references
                .entry(binding.identity())
                .or_insert_with(|| binding.clone());
        }
        Ok(references.into_values().collect())
    }
    /// Read-only restart inventory from exact retained journal identities. The
    /// caller holds geometry; this never installs active-lane admission.
    pub(super) fn retained_lane_storage_entries_under_geometry_guard(
        &self,
    ) -> Result<Vec<LaneStorageEntry>> {
        let journal = self.read_lane_geometry_journal()?;
        self.retained_lane_instance_bindings(&journal)?
            .into_iter()
            .map(|binding| {
                self.require_retained_lane_instance_storage(&binding)?;
                Ok(LaneStorageEntry {
                    identity: binding.identity(),
                })
            })
            .collect()
    }
    /// Revalidate a captured restart/recovery target against the exact retained
    /// journal references. This does not install it in the active State catalog
    /// and cannot authorize fresh lane production or a new proposal.
    pub(super) fn require_retained_lane_storage_entry(
        &self,
        entry: &LaneStorageEntry,
    ) -> Result<()> {
        if !self
            .retained_lane_storage_entries_under_geometry_guard()?
            .contains(entry)
        {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "lane recovery target no longer has its exact retained journal reference",
            ));
        }
        Ok(())
    }
    /// Require an exact current or retained target for existing durable work.
    /// Absence remains an error for terminal/readback consumers that already
    /// own a specific durable source.
    pub(super) fn existing_work_lane_storage_entry_under_geometry_guard(
        &self,
        network_id: NetworkId,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        incarnation: Hash,
        proposal_height: u64,
    ) -> Result<LaneStorageEntry> {
        self.find_existing_work_lane_storage_entry_under_geometry_guard(
            network_id,
            lane_id,
            dataspace_id,
            incarnation,
            proposal_height,
        )?
        .ok_or_else(|| {
            self.geometry_error(
                ErrorKind::InvalidData,
                "durable lane work has no exact retained instance reference",
            )
        })
    }
    /// Resolve existing work without scanning history when the exact current
    /// State identity still owns it. `None` proves absence from a successfully
    /// authenticated retained inventory; failed authentication is never absence.
    pub(super) fn find_existing_work_lane_storage_entry_under_geometry_guard(
        &self,
        network_id: NetworkId,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        incarnation: Hash,
        proposal_height: u64,
    ) -> Result<Option<LaneStorageEntry>> {
        let current = self.lane_storage_entries.lock().get(&lane_id).cloned();
        if let Some(entry) = current.filter(|entry| {
            entry.network_id == network_id
                && entry.dataspace_id == dataspace_id
                && entry.incarnation == incarnation
        }) {
            self.require_active_lane_incarnation(&entry, incarnation, proposal_height)?;
            return Ok(Some(entry));
        }
        self.find_retained_lane_storage_entry_for_route_under_geometry_guard(
            network_id,
            lane_id,
            dataspace_id,
            incarnation,
            proposal_height,
        )
    }
    /// Locate existing durable work by its original network, route and incarnation.
    /// Activation comes only from a unique retained authenticated catalog reference;
    /// a reused LaneId is never substituted. This is private recovery/read authority.
    pub(super) fn retained_lane_storage_entry_for_route_under_geometry_guard(
        &self,
        network_id: NetworkId,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        incarnation: Hash,
        proposal_height: u64,
    ) -> Result<LaneStorageEntry> {
        self.find_retained_lane_storage_entry_for_route_under_geometry_guard(
            network_id,
            lane_id,
            dataspace_id,
            incarnation,
            proposal_height,
        )?
        .ok_or_else(|| {
            self.geometry_error(
                ErrorKind::InvalidData,
                "durable lane work has no exact retained instance reference",
            )
        })
    }
    /// Distinguish authenticated absence from corrupt, missing or ambiguous
    /// retained storage. A matching identity outside its activation bound is
    /// invalid work for that identity, not evidence that it was collected.
    fn find_retained_lane_storage_entry_for_route_under_geometry_guard(
        &self,
        network_id: NetworkId,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        incarnation: Hash,
        proposal_height: u64,
    ) -> Result<Option<LaneStorageEntry>> {
        let mut candidates = self
            .retained_lane_storage_entries_under_geometry_guard()?
            .into_iter()
            .filter(|entry| {
                entry.network_id == network_id
                    && entry.lane_id == lane_id
                    && entry.dataspace_id == dataspace_id
                    && entry.incarnation == incarnation
            });
        let Some(entry) = candidates.next() else {
            return Ok(None);
        };
        if candidates.next().is_some() {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "durable lane work has ambiguous retained instance activation",
            ));
        }
        self.require_active_lane_incarnation(&entry, incarnation, proposal_height)?;
        Ok(Some(entry))
    }

    /// Provision original instance block storage with its exact marker for a test fixture.
    pub(crate) fn install_lane_incarnation_marker_for_test(
        &self,
        entry: &LaneConfigEntry,
        incarnation: Hash,
        activation_height: u64,
    ) -> Result<()> {
        let binding = LaneGeometryBinding::from_identity(LaneStorageIdentity {
            network_id: self.bound_lane_storage_network()?,
            lane_id: entry.lane_id,
            dataspace_id: entry.dataspace_id,
            incarnation,
            activation_height,
        });
        self.write_lane_marker(&binding)?;
        self.provision_geometry_binding(&binding)
    }
    /// Install instance storage for a blank test store without rewriting existing geometry.
    pub(crate) fn install_lane_incarnation_marker_if_missing_for_test(
        &self,
        entry: &LaneConfigEntry,
        incarnation: Hash,
        activation_height: u64,
    ) -> Result<()> {
        let identity = LaneStorageIdentity {
            network_id: self.bound_lane_storage_network()?,
            lane_id: entry.lane_id,
            dataspace_id: entry.dataspace_id,
            incarnation,
            activation_height,
        };
        let path = identity.blocks_dir(&self.store_root).join(MARKER_FILE_NAME);
        if self.validate_path_kind(&path, false)? {
            return Ok(());
        }
        self.install_lane_incarnation_marker_for_test(entry, incarnation, activation_height)
    }
    /// Inject marker identity corruption at the original physical object.
    #[cfg(test)]
    pub(super) fn substitute_lane_marker_identity_for_test(
        &self,
        entry: &LaneStorageEntry,
        incarnation: Hash,
        activation_height: u64,
    ) -> Result<()> {
        let _geometry = self.lane_geometry_lock.lock();
        let path = entry.blocks_dir(&self.store_root).join(MARKER_FILE_NAME);
        let mut marker = self.read_lane_marker(&path)?;
        marker.incarnation = incarnation;
        marker.activation_height = activation_height;
        self.atomic_write_geometry_file(&path, &path.with_extension("norito.tmp"), &marker.encode())
    }
    /// Restore a structural storage fixture from its actual published journal.
    /// Tests supply the expected route catalog; no incarnation or predecessor
    /// is synthesized from a configuration alias or the later active map.
    #[cfg(test)]
    pub(crate) fn restore_published_lane_geometry_for_test(
        &self,
        config: &LaneConfig,
    ) -> Result<()> {
        let bindings = {
            let _geometry = self.lane_geometry_lock.lock();
            self.selected_canonical_recovery_physical_bindings()?
        };
        if bindings.len() != config.entries().len()
            || config.entries().iter().any(|entry| {
                !bindings.iter().any(|binding| {
                    binding.lane_id == entry.lane_id && binding.dataspace_id == entry.dataspace_id
                })
            })
        {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "structural fixture catalog differs from its actual published instance references",
            ));
        }
        let network_id = bindings
            .first()
            .ok_or_else(|| {
                self.geometry_error(
                    ErrorKind::InvalidData,
                    "structural fixture has no published instance",
                )
            })?
            .network_id;
        self.bind_lane_storage_network(network_id)?;
        let incarnations = bindings
            .iter()
            .map(|binding| (binding.lane_id, binding.incarnation))
            .collect();
        let activations = bindings
            .iter()
            .map(|binding| (binding.lane_id, binding.activation_height))
            .collect();
        self.recover_lane_geometry_journal(config, &incarnations, &activations)?;
        self.finish_restored_lane_segments_with_geometry(config)
    }
    /// Install an explicit structural fixture identity; no alias can identify its storage.
    pub(crate) fn replace_lane_storage_entries_for_test(
        &self,
        lane_config: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
    ) -> Result<()> {
        let _geometry_guard = self.lane_geometry_lock.lock();
        self.raw_geometry_claim.ensure_unclaimed()?;
        *self.lane_storage_entries.lock() =
            self.lane_storage_entries_from_geometry(lane_config, incarnations, activation_heights)?;
        Ok(())
    }
    fn read_lane_marker(&self, path: &Path) -> Result<LaneIncarnationMarker> {
        let identity = self.geometry_path_identity(path, false)?;
        let mut file = File::open(path).map_err(|error| Error::IO(error, path.to_path_buf()))?;
        self.verify_open_geometry_file(path, &file)?;
        let length = file
            .metadata()
            .map_err(|error| Error::IO(error, path.to_path_buf()))?
            .len();
        if length > MAX_LANE_MARKER_BYTES {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "lane incarnation marker exceeds its encoded byte limit",
                ),
                path.to_path_buf(),
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(length)?);
        (&mut file)
            .take(MAX_LANE_MARKER_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_LANE_MARKER_BYTES {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "lane incarnation marker exceeds its encoded byte limit",
                ),
                path.to_path_buf(),
            ));
        }
        self.verify_open_geometry_file(path, &file)?;
        self.require_geometry_path_identity(path, false, identity)?;
        decode_exact(&bytes).map_err(Error::NoritoFrame)
    }
    fn write_lane_marker(&self, binding: &LaneGeometryBinding) -> Result<()> {
        let blocks = self.binding_blocks_path(binding);
        let path = blocks.join(MARKER_FILE_NAME);
        let temp = blocks.join(MARKER_TEMP_FILE_NAME);
        self.validate_path_kind(&path, false)?;
        let marker = LaneIncarnationMarker {
            version: MARKER_VERSION,
            network_id: binding.network_id,
            dataspace_id: binding.dataspace_id,
            lane_id: binding.lane_id,
            incarnation: binding.incarnation,
            activation_height: binding.activation_height,
        };
        self.prepare_lane_marker_temp_for_write(&temp, binding, &marker)?;
        self.atomic_write_geometry_file(&path, &temp, &marker.encode())
    }
    fn prepare_lane_marker_temp_for_write(
        &self,
        temp: &Path,
        binding: &LaneGeometryBinding,
        intended: &LaneIncarnationMarker,
    ) -> Result<()> {
        if !self.validate_path_kind(temp, false)? {
            return Ok(());
        }
        let identity = self.geometry_path_identity(temp, false)?;
        let stale = self.read_lane_marker(temp)?;
        if &stale == intended {
            return Ok(());
        }
        self.require_lane_marker_value(&stale, temp.parent().unwrap_or(temp), binding)?;
        self.require_geometry_path_identity(temp, false, identity)?;
        Err(self.geometry_error(
            ErrorKind::AlreadyExists,
            "lane marker temporary file differs from the original exact creation marker",
        ))
    }
    fn geometry_bindings(
        &self,
        lane_config: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
    ) -> Result<Vec<LaneGeometryBinding>> {
        let bindings = lane_config
            .entries()
            .iter()
            .map(|entry| self.geometry_binding(entry, incarnations, activation_heights))
            .collect::<Result<Vec<_>>>()?;
        self.validate_geometry_binding_set(&bindings)?;
        Ok(bindings)
    }
    fn geometry_binding(
        &self,
        entry: &LaneConfigEntry,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
    ) -> Result<LaneGeometryBinding> {
        let incarnation = incarnations.get(&entry.lane_id).copied().ok_or_else(|| {
            self.geometry_error(
                ErrorKind::InvalidInput,
                "lane geometry is missing an incarnation commitment",
            )
        })?;
        let activation_height =
            activation_heights
                .get(&entry.lane_id)
                .copied()
                .ok_or_else(|| {
                    self.geometry_error(
                        ErrorKind::InvalidInput,
                        "lane geometry is missing an incarnation activation height",
                    )
                })?;
        Ok(LaneGeometryBinding::from_identity(LaneStorageIdentity {
            network_id: self.bound_lane_storage_network()?,
            lane_id: entry.lane_id,
            dataspace_id: entry.dataspace_id,
            incarnation,
            activation_height,
        }))
    }

    fn relative_geometry_path(&self, path: &Path) -> Result<String> {
        let relative = path.strip_prefix(&self.store_root).map_err(|_| {
            self.geometry_error(
                ErrorKind::InvalidInput,
                "lane geometry path escapes the Kura store root",
            )
        })?;
        validate_relative_path(relative)?;
        relative.to_str().map(str::to_owned).ok_or_else(|| {
            self.geometry_error(
                ErrorKind::InvalidInput,
                "lane geometry path is not valid UTF-8",
            )
        })
    }
    fn resolve_relative_path(&self, relative: &str) -> Result<PathBuf> {
        let relative = Path::new(relative);
        validate_relative_path(relative)?;
        Ok(self.store_root.join(relative))
    }
    fn binding_blocks_path(&self, binding: &LaneGeometryBinding) -> PathBuf {
        self.store_root.join(&binding.blocks_path)
    }

    fn validate_path_kind(&self, path: &Path, directory: bool) -> Result<bool> {
        self.validate_geometry_ancestors(path)?;
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(Error::IO(error, path.to_path_buf())),
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink()
            || (directory && !file_type.is_dir())
            || (!directory && !file_type.is_file())
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "lane geometry path is a symlink or has the wrong file type",
                ),
                path.to_path_buf(),
            ));
        }
        Ok(true)
    }
    fn geometry_path_identity(&self, path: &Path, directory: bool) -> Result<GeometryFileIdentity> {
        if !self.validate_path_kind(path, directory)? {
            return Err(Error::IO(
                std::io::Error::new(ErrorKind::NotFound, "lane geometry path is missing"),
                path.to_path_buf(),
            ));
        }
        let metadata = secure_file_metadata::from_path(path)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink()
            || (directory && !file_type.is_dir())
            || (!directory && !file_type.is_file())
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "lane geometry path changed type during identity validation",
                ),
                path.to_path_buf(),
            ));
        }
        checked_geometry_file_identity(&metadata, path)
    }
    fn require_geometry_path_identity(
        &self,
        path: &Path,
        directory: bool,
        expected: GeometryFileIdentity,
    ) -> Result<()> {
        let actual = self.geometry_path_identity(path, directory)?;
        if actual != expected {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "lane geometry path inode changed during a protected operation",
                ),
                path.to_path_buf(),
            ));
        }
        Ok(())
    }
    fn open_geometry_parent(&self, parent: &Path) -> Result<(File, GeometryFileIdentity)> {
        let before = self.geometry_path_identity(parent, true)?;
        let directory =
            File::open(parent).map_err(|error| Error::IO(error, parent.to_path_buf()))?;
        let opened = secure_file_metadata::from_file(&directory)
            .map_err(|error| Error::IO(error, parent.to_path_buf()))?;
        if !opened.is_dir()
            || checked_geometry_file_identity(&opened, parent)? != before
            || self.geometry_path_identity(parent, true)? != before
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "lane geometry parent changed while being opened",
                ),
                parent.to_path_buf(),
            ));
        }
        Ok((directory, before))
    }
    fn verify_open_geometry_file(&self, path: &Path, file: &File) -> Result<()> {
        let path_identity = self.geometry_path_identity(path, false)?;
        let metadata = secure_file_metadata::from_file(file)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        if !metadata.is_file() || checked_geometry_file_identity(&metadata, path)? != path_identity
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "opened lane geometry file does not match its directory entry",
                ),
                path.to_path_buf(),
            ));
        }
        Ok(())
    }
    fn validate_geometry_ancestors(&self, path: &Path) -> Result<()> {
        let root_metadata = fs::symlink_metadata(&self.store_root)
            .map_err(|error| Error::IO(error, self.store_root.clone()))?;
        if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Kura geometry store root must be a non-symlink directory",
                ),
                self.store_root.clone(),
            ));
        }
        let relative = path.strip_prefix(&self.store_root).map_err(|_| {
            self.geometry_error(
                ErrorKind::InvalidInput,
                "lane geometry path escapes the Kura store root",
            )
        })?;
        if relative.as_os_str().is_empty() {
            return Ok(());
        }
        validate_relative_path(relative)?;
        let mut cursor = self.store_root.clone();
        let components = relative.components().collect::<Vec<_>>();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            cursor.push(component.as_os_str());
            match fs::symlink_metadata(&cursor) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "lane geometry path traverses a symlink",
                        ),
                        cursor,
                    ));
                }
                Ok(metadata) if !metadata.file_type().is_dir() => {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "lane geometry path traverses a non-directory",
                        ),
                        cursor,
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => break,
                Err(error) => return Err(Error::IO(error, cursor)),
            }
        }
        Ok(())
    }
    fn read_geometry_file_bytes(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        if !self.validate_path_kind(path, false)? {
            return Ok(None);
        }
        let mut file = File::open(path).map_err(|error| Error::IO(error, path.to_path_buf()))?;
        self.verify_open_geometry_file(path, &file)?;
        let initial_metadata = secure_file_metadata::from_file(&file)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let file_len = initial_metadata.len();
        let identity = geometry_file_identity(&initial_metadata);
        if file_len > MAX_GEOMETRY_JOURNAL_BYTES {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "lane geometry journal exceeds the encoded byte limit",
                ),
                path.to_path_buf(),
            ));
        }
        let capacity = usize::try_from(file_len)?;
        let mut bytes = Vec::with_capacity(capacity);
        (&mut file)
            .take(MAX_GEOMETRY_JOURNAL_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let final_len = file
            .metadata()
            .map_err(|error| Error::IO(error, path.to_path_buf()))?
            .len();
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_GEOMETRY_JOURNAL_BYTES
            || final_len != file_len
            || bytes.len() != capacity
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "lane geometry journal changed while it was read or exceeded its encoded byte limit",
                ),
                path.to_path_buf(),
            ));
        }
        self.verify_open_geometry_file(path, &file)?;
        self.require_geometry_path_identity(path, false, identity)?;
        Ok(Some(bytes))
    }
    fn read_lane_geometry_journal(&self) -> Result<LaneGeometryJournal> {
        let journal = self.read_lane_geometry_journal_structure()?;
        self.validate_lane_geometry_journal(&journal)?;
        Ok(journal)
    }
    /// Pure capture; durable evidence remains mandatory before any owned application.
    fn read_lane_geometry_journal_structure(&self) -> Result<LaneGeometryJournal> {
        let path = self.lane_geometry_journal_path();
        let Some(bytes) = self.read_geometry_file_bytes(&path)? else {
            return Ok(LaneGeometryJournal::default());
        };
        let journal = decode_exact::<LaneGeometryJournal>(&bytes).map_err(Error::NoritoFrame)?;
        if journal.version != JOURNAL_VERSION {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "unsupported lane geometry journal version {}; expected {JOURNAL_VERSION}",
                        journal.version
                    ),
                ),
                path,
            ));
        }
        validate_lane_geometry_journal_structure(&self.store_root, &journal)?;
        Ok(journal)
    }
    #[cfg(test)]
    fn restore_lane_geometry_journal_file(
        &self,
        prior_bytes: Option<&[u8]>,
        published_bytes: &[u8],
        publication_temp_preexisted: bool,
    ) -> Result<()> {
        let path = self.lane_geometry_journal_path();
        let current_bytes = self.read_geometry_file_bytes(&path)?;
        match (prior_bytes, current_bytes.as_deref()) {
            (None, None) => {}
            (None, Some(current)) if current == published_bytes => {
                self.remove_accounted_geometry_file(&path)?;
            }
            (None, Some(_)) => {
                return Err(self.geometry_error(
                    ErrorKind::InvalidData,
                    "refusing to remove an unexpected lane geometry journal while restoring prior absence",
                ));
            }
            (Some(prior), Some(current)) if current == prior => {}
            (Some(prior), Some(current)) if current == published_bytes => {
                let restore_temp = self.store_root.join(JOURNAL_RESTORE_TEMP_FILE_NAME);
                self.atomic_write_geometry_file(&path, &restore_temp, prior)?;
            }
            (Some(prior), None) => {
                let restore_temp = self.store_root.join(JOURNAL_RESTORE_TEMP_FILE_NAME);
                self.atomic_write_geometry_file(&path, &restore_temp, prior)?;
            }
            (Some(_), Some(_)) => {
                return Err(self.geometry_error(
                    ErrorKind::InvalidData,
                    "refusing to overwrite an unexpected lane geometry journal while restoring the exact prior value",
                ));
            }
        }
        // A preexisting temp is never ours to remove. `atomic_write_geometry_file` consumes it
        // only when its bytes exactly equal this publication; otherwise it is left untouched and
        // the publication fails. A temp absent at entry can be cleaned only when its full value
        // proves that it belongs to this attempt.
        if !publication_temp_preexisted {
            let publication_temp = self.store_root.join(JOURNAL_TEMP_FILE_NAME);
            if let Some(temp_bytes) = self.read_geometry_file_bytes(&publication_temp)? {
                if temp_bytes != published_bytes {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "refusing to remove an unexpected lane geometry publication temp file",
                        ),
                        publication_temp,
                    ));
                }
                self.remove_accounted_geometry_file(&publication_temp)?;
            }
            if self.validate_path_kind(&publication_temp, false)? {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "lane geometry publication temp remained after rollback cleanup",
                    ),
                    publication_temp,
                ));
            }
        }
        let restored_bytes = self.read_geometry_file_bytes(&path)?;
        if restored_bytes.as_deref() != prior_bytes {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "lane geometry publication rollback did not restore the exact prior journal value",
            ));
        }
        Ok(())
    }
    fn validate_lane_geometry_journal(&self, journal: &LaneGeometryJournal) -> Result<()> {
        validate_lane_geometry_journal_structure(&self.store_root, journal)
    }
    fn validate_geometry_binding_from_journal(&self, binding: &LaneGeometryBinding) -> Result<()> {
        validate_geometry_binding_structure(&self.store_root, binding)
    }
    fn validate_geometry_binding_set(&self, bindings: &[LaneGeometryBinding]) -> Result<()> {
        if bindings.is_empty()
            || bindings.len() > MAX_GEOMETRY_BINDINGS
            || bindings
                .windows(2)
                .any(|pair| pair[0].lane_id >= pair[1].lane_id)
        {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "lane geometry catalog bindings are empty, duplicated, or unsorted",
            ));
        }
        let mut incarnations = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for binding in bindings {
            self.validate_geometry_binding_from_journal(binding)?;
            if !incarnations.insert(binding.incarnation)
                || !paths.insert(binding.blocks_path.clone())
            {
                return Err(self.geometry_error(
                    ErrorKind::InvalidData,
                    "lane geometry catalog contains duplicate incarnations or storage paths",
                ));
            }
        }
        Ok(())
    }
    fn write_lane_geometry_journal(&self, journal: &LaneGeometryJournal) -> Result<()> {
        self.raw_geometry_claim.ensure_unclaimed()?;
        self.validate_lane_geometry_journal(journal)?;
        let path = self.lane_geometry_journal_path();
        let temp = self.store_root.join(JOURNAL_TEMP_FILE_NAME);
        self.atomic_write_geometry_file(&path, &temp, &journal.encode())
    }

    fn write_lane_geometry_journal_with_custody(
        &self,
        journal: &LaneGeometryJournal,
        custody: Option<&mut RawGeometryMutation<'_, '_>>,
    ) -> Result<()> {
        match custody {
            Some(custody) => custody.write(self, journal),
            None => self.write_lane_geometry_journal(journal),
        }
    }
    #[cfg(test)]
    fn remove_accounted_geometry_file(&self, path: &Path) -> Result<()> {
        let before = Self::file_len_or_zero(path)?;
        let accounting_mutation = self
            .begin_total_disk_usage_mutation()
            .with_resource_paths(vec![path.to_path_buf()]);
        fs::remove_file(path).map_err(|error| Error::IO(error, path.to_path_buf()))?;
        self.sync_geometry_parent(path.parent())?;
        self.update_disk_usage_delta(before, 0);
        accounting_mutation.finish();
        Ok(())
    }
    fn accounted_atomic_geometry_file_len(&self, path: &Path) -> Result<u64> {
        // The restore temp is deliberately excluded from Kura's usage scans: it is an
        // attempt-local rollback file, whereas the authoritative journal and its publication
        // temp are durable recovery state. All other atomic geometry files live in counted block
        // stores or are one of those two journal names.
        if path == self.store_root.join(JOURNAL_RESTORE_TEMP_FILE_NAME) {
            return Ok(0);
        }
        Self::file_len_or_zero(path)
    }
    fn atomic_write_geometry_file(&self, path: &Path, temp: &Path, bytes: &[u8]) -> Result<()> {
        if path.parent() != temp.parent() || path == temp {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "geometry sidecar temp must be a distinct sibling of its target",
                ),
                temp.to_path_buf(),
            ));
        }
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_GEOMETRY_JOURNAL_BYTES {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "geometry sidecar exceeds the encoded byte limit",
                ),
                path.to_path_buf(),
            ));
        }
        self.validate_geometry_ancestors(path)?;
        self.validate_geometry_ancestors(temp)?;
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() =>
            {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "geometry sidecar target has an unsafe file type",
                    ),
                    path.to_path_buf(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(Error::IO(error, path.to_path_buf())),
        }
        self.validate_path_kind(temp, false)?;
        let before = self
            .accounted_atomic_geometry_file_len(path)?
            .saturating_add(self.accounted_atomic_geometry_file_len(temp)?);
        // The temp creation/write and target replacement are one accounting mutation. Counting
        // both sibling names makes exact recovery of a preexisting, authenticated temp possible
        // without transiently under-reporting either enforced or total usage.
        let accounting_mutation = self
            .begin_total_disk_usage_mutation()
            .with_resource_paths(vec![path.to_path_buf(), temp.to_path_buf()]);
        if let Some(parent) = path.parent() {
            create_dir_all_with_context(parent)?;
            self.validate_path_kind(parent, true)?;
            self.sync_geometry_parent(Some(parent))?;
        }
        let file = match fs::symlink_metadata(temp) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::AlreadyExists,
                            "geometry sidecar temp collision has an unsafe file type",
                        ),
                        temp.to_path_buf(),
                    ));
                }
                let mut stale = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(temp)
                    .map_err(|error| Error::IO(error, temp.to_path_buf()))?;
                self.verify_open_geometry_file(temp, &stale)?;
                let intended_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                if metadata.len() != intended_len {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::AlreadyExists,
                            "geometry sidecar temp collision differs from the intended write",
                        ),
                        temp.to_path_buf(),
                    ));
                }
                let mut stale_bytes = Vec::with_capacity(bytes.len());
                (&mut stale)
                    .take(intended_len.saturating_add(1))
                    .read_to_end(&mut stale_bytes)
                    .map_err(|error| Error::IO(error, temp.to_path_buf()))?;
                if stale_bytes != bytes {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::AlreadyExists,
                            "geometry sidecar temp collision differs from the intended write",
                        ),
                        temp.to_path_buf(),
                    ));
                }
                stale
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let mut created = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(temp)
                    .map_err(|error| Error::IO(error, temp.to_path_buf()))?;
                self.verify_open_geometry_file(temp, &created)?;
                created
                    .write_all(bytes)
                    .map_err(|error| Error::IO(error, temp.to_path_buf()))?;
                created
            }
            Err(error) => return Err(Error::IO(error, temp.to_path_buf())),
        };
        // Geometry intents and incarnation markers are correctness barriers even when ordinary
        // block fsync is deferred by batching. Always synchronize the file before its directory
        // entry.
        file.sync_all()
            .map_err(|error| Error::IO(error, temp.to_path_buf()))?;
        self.verify_open_geometry_file(temp, &file)?;
        fs::rename(temp, path).map_err(|error| Error::IO(error, path.to_path_buf()))?;
        self.verify_open_geometry_file(path, &file)?;
        file.sync_all()
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        self.sync_geometry_parent(path.parent())?;
        let after = self
            .accounted_atomic_geometry_file_len(path)?
            .saturating_add(self.accounted_atomic_geometry_file_len(temp)?);
        self.update_disk_usage_delta(before, after);
        accounting_mutation.finish();
        Ok(())
    }
    fn sync_geometry_parent(&self, parent: Option<&Path>) -> Result<()> {
        let Some(mut directory) = parent else {
            return Ok(());
        };
        loop {
            if !directory.starts_with(&self.store_root) {
                return Err(self.geometry_error(
                    ErrorKind::InvalidInput,
                    "geometry durability path escapes the Kura store root",
                ));
            }
            self.geometry_path_identity(directory, true)?;
            sync_dir(directory).map_err(|error| Error::IO(error, directory.to_path_buf()))?;
            if directory == self.store_root {
                break;
            }
            directory = directory.parent().ok_or_else(|| {
                self.geometry_error(
                    ErrorKind::InvalidInput,
                    "geometry durability path has no store-root ancestor",
                )
            })?;
        }
        Ok(())
    }
    pub(crate) fn lane_geometry_journal_path(&self) -> PathBuf {
        self.store_root.join(JOURNAL_FILE_NAME)
    }
    fn geometry_error(&self, kind: ErrorKind, message: &'static str) -> Error {
        Error::IO(
            std::io::Error::new(kind, message),
            self.lane_geometry_journal_path(),
        )
    }
    fn geometry_error_owned(&self, kind: ErrorKind, message: String) -> Error {
        Error::IO(
            std::io::Error::new(kind, message),
            self.lane_geometry_journal_path(),
        )
    }
    fn ensure_nonzero_lineage_root(&self, lineage_root: Hash) -> Result<()> {
        if lineage_root_is_zero(lineage_root) {
            return Err(self.geometry_error(
                ErrorKind::InvalidInput,
                "lane geometry lineage root must not be all zero",
            ));
        }
        Ok(())
    }
}
include!("lane_geometry/catalog_validation.rs");
#[cfg(test)]
mod tests {
    use iroha_model_base::topology::DataSpaceId;
    include!("lane_geometry_tests/00_support.rs");
    include!("lane_geometry_tests/00_retirement.rs");
    include!("lane_geometry_tests/01_retirement_and_recovery.rs");
    include!("lane_geometry_tests/02_geometry_moves_and_journal.rs");
    include!("lane_geometry_tests/03_gc_and_startup.rs");
    include!("lane_geometry_tests/04_physical_resource_accounting.rs");
    include!("lane_geometry_tests/05_prepared_journal.rs");
    include!("lane_geometry_tests/08_raw_attempt.rs");
    include!("lane_geometry_tests/07_guarded_publication.rs");
}

include!("geometry_request.rs");
