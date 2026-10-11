//! Immutable, commitment-addressed source cache for Musubi V1.
//!
//! Cache paths are derived exclusively from a trusted user cache root and an [`ArchiveId`].
//! Consumer lockfiles never supply a filesystem path. Incoming CAR bytes are checked incrementally
//! against the finalized archive commitment, their raw payload is written to a private temporary
//! file, and the validated `SoraFS` file plan materializes the source tree. Publication is an
//! absent-destination atomic rename, so readers observe either no entry or a complete immutable
//! `src` directory.
//!
//! Cache custody and atomic publication use the native `iroha_fs` authority on Unix and Windows.
//! Destructive cache-tree removal is
//! intentionally unavailable on every platform. Safe `std` does not expose an atomic
//! handle-relative compare-and-delete operation, so explicit prune fails before isolation and
//! install failures retain their private staging and payload residue for inspection.
use crate::workspace::MAX_MANIFEST_BYTES;
use iroha_data_model::musubi::{
    ArchiveId, MUSUBI_MAX_ARTIFACT_DESCRIPTOR_BYTES_V1, MUSUBI_MAX_BUNDLE_METADATA_FILE_BYTES_V1,
    MUSUBI_MAX_FILES_V1, MusubiArchiveCommitmentV1, MusubiArtifactDescriptorV1,
    MusubiContentDigestV1, MusubiDependencyKindV1, MusubiDependencyReqV1, MusubiReleaseManifestV1,
    MusubiSemanticReleaseManifestV1, MusubiVerificationLockV1, MusubiVerificationNodeV1,
};
use iroha_model_base::name::Name;
use sorafs_car::{
    CarBuildPlan, CarStreamingWriter, ChunkSink, ChunkStore, ChunkStoreError, DirectoryPayload,
    FilePayload, ProfileId, compute_chunk_plan_digest_sha3,
    streaming_verifier::{StreamingCarVerifier, StreamingVerifierConfig},
};
use sorafs_manifest::{DagCodecId, GovernanceProofs, ManifestBuilder, PinPolicy, StorageClass};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};
const REGISTRY_DIRECTORY: &str = "registry-v1";
const SOURCE_DIRECTORY: &str = "src";
const RELEASE_PATH: &str = ".musubi/semantic-release.norito";
const DESCRIPTOR_PATH: &str = ".musubi/artifact-descriptor.norito";
const VERIFICATION_LOCK_PATH: &str = ".musubi/verification-lock.norito";
const SOURCE_TREE_DOMAIN: &[u8] = b"musubi-source-tree-v1\0";
const ARTIFACT_DESCRIPTOR_DOMAIN: &[u8] = b"musubi-artifact-descriptor-v1\0";
const BUNDLE_DOMAIN: &[u8] = b"musubi-bundle-v1\0";
const CAR_PRAGMA_BYTES: usize = 11;
const CAR_HEADER_BYTES: usize = 40;
const CAR_DATA_OFFSET: u64 = (CAR_PRAGMA_BYTES + CAR_HEADER_BYTES) as u64;
const CAR_MAX_HEADER_BYTES: u64 = 64 * 1024;
const CAR_MAX_SECTION_BYTES: u64 = 4 * 1024 * 1024 + 128;
const RAW_CODEC: u64 = 0x55;
const DAG_CBOR_CODEC: u64 = 0x71;
const BLAKE3_MULTIHASH: u64 = 0x1f;
const CID_DIGEST_BYTES: u64 = 32;
const CID_DIGEST_BYTES_USIZE: usize = 32;
const IO_BUFFER_BYTES: usize = 64 * 1024;
const TEMP_RETRIES: usize = 32;
const BUNDLE_METADATA_FILE_COUNT: usize = 3;
const MAX_CACHE_FILE_COUNT: usize = MUSUBI_MAX_FILES_V1 as usize + BUNDLE_METADATA_FILE_COUNT;
const MAX_CACHE_PATH_COMPONENTS: usize = 64;
const MAX_CACHE_ENTRY_COUNT: usize = MAX_CACHE_FILE_COUNT * (MAX_CACHE_PATH_COMPONENTS + 1);
// These are deterministic retained-allocation/ingest-estimate envelopes, not a
// claim about whole-process RSS. HTTP/TLS and JSON DOMs live in the fetch client;
// deployment-equivalent process-RSS qualification remains a separate launch gate.
const MUSUBI_MAX_RETAINED_PLAN_HEAP_BYTES: usize = 16 * 1024 * 1024;
const MUSUBI_CACHE_CHUNK_STORE_HEAP_LIMIT_BYTES: usize = 24 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(all(test, unix))]
const CACHE_INSTALL_CRASH_CUT_ENV_V1: &str = "IROHA_MUSUBI_TEST_CACHE_INSTALL_CRASH_CUT_V1";
#[cfg(all(test, unix))]
const CACHE_INSTALL_CRASH_ROOT_ENV_V1: &str = "IROHA_MUSUBI_TEST_CACHE_INSTALL_CRASH_ROOT_V1";
#[cfg(all(test, unix))]
const CACHE_INSTALL_CRASH_EXIT_CODE_V1: i32 = 86;
/// Test-only abrupt process cuts at cache-install mutation and durability boundaries.
#[cfg(all(test, unix))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CacheInstallCrashCutV1 {
    VerifiedPayloadWritten,
    VerifiedPayloadSynced,
    SourceChunkWritten,
    SourceFileSynced,
    VerifiedPayloadRetained,
    SourceTreeVerified,
    SourceTreeSynced,
    SourceTreePublished,
    ArchiveDirectorySynced,
}
#[cfg(all(test, unix))]
impl CacheInstallCrashCutV1 {
    #[cfg(unix)]
    const ALL: [Self; 9] = [
        Self::VerifiedPayloadWritten,
        Self::VerifiedPayloadSynced,
        Self::SourceChunkWritten,
        Self::SourceFileSynced,
        Self::VerifiedPayloadRetained,
        Self::SourceTreeVerified,
        Self::SourceTreeSynced,
        Self::SourceTreePublished,
        Self::ArchiveDirectorySynced,
    ];
    const fn label(self) -> &'static str {
        match self {
            Self::VerifiedPayloadWritten => "verified_payload_written",
            Self::VerifiedPayloadSynced => "verified_payload_synced",
            Self::SourceChunkWritten => "source_chunk_written",
            Self::SourceFileSynced => "source_file_synced",
            Self::VerifiedPayloadRetained => "verified_payload_retained",
            Self::SourceTreeVerified => "source_tree_verified",
            Self::SourceTreeSynced => "source_tree_synced",
            Self::SourceTreePublished => "source_tree_published",
            Self::ArchiveDirectorySynced => "archive_directory_synced",
        }
    }
}
#[cfg(all(test, unix))]
fn crash_cache_install_at(cut: CacheInstallCrashCutV1) {
    if std::env::var_os(CACHE_INSTALL_CRASH_CUT_ENV_V1)
        .is_some_and(|value| value == std::ffi::OsStr::new(cut.label()))
    {
        // This is the filesystem state a fresh process must recover from after an abrupt
        // termination. Normal unwinding retains the same private residue deliberately.
        std::process::exit(CACHE_INSTALL_CRASH_EXIT_CODE_V1);
    }
}
/// Return the one platform-derived user cache root shared by fetch and compiler workflows.
///
/// The returned root is `~/Library/Caches/Iroha/musubi` on macOS,
/// `$XDG_CACHE_HOME/iroha/musubi` (or `~/.cache/iroha/musubi`) on other Unix systems,
/// and `%LOCALAPPDATA%/Iroha/musubi/cache` on Windows. The path must be absolute;
/// no project, lockfile, or current-directory input participates in its derivation. The same
/// retained native filesystem authority validates each platform convention before access.
///
/// # Errors
/// Returns [`CacheError::UnsafeRoot`] when the required platform directory variable is absent,
/// empty, or relative.
pub fn platform_cache_root_v1() -> Result<PathBuf, CacheError> {
    #[cfg(target_os = "macos")]
    {
        derive_platform_cache_root(
            std::env::var_os("HOME").map(PathBuf::from),
            &["Library", "Caches", "Iroha", "musubi"],
        )
    }
    #[cfg(windows)]
    {
        derive_platform_cache_root(
            std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
            &["Iroha", "musubi", "cache"],
        )
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(root) = std::env::var_os("XDG_CACHE_HOME") {
            return derive_platform_cache_root(Some(PathBuf::from(root)), &["iroha", "musubi"]);
        }
        derive_platform_cache_root(
            std::env::var_os("HOME").map(PathBuf::from),
            &[".cache", "iroha", "musubi"],
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(CacheError::UnsafeRoot(
            "the platform has no Musubi V1 cache-root convention".to_owned(),
        ))
    }
}
fn derive_platform_cache_root(
    base: Option<PathBuf>,
    components: &[&str],
) -> Result<PathBuf, CacheError> {
    let mut root = base.ok_or_else(|| {
        CacheError::UnsafeRoot("the platform user cache directory is unavailable".to_owned())
    })?;
    if root.as_os_str().is_empty() || !root.is_absolute() {
        return Err(CacheError::UnsafeRoot(
            "the platform user cache directory must be absolute".to_owned(),
        ));
    }
    for component in components {
        root.push(component);
    }
    Ok(root)
}
/// A cache rooted below an explicit user-owned directory.
#[derive(Debug, Clone)]
pub struct MusubiCache {
    root: PathBuf,
    root_identity: std::sync::Arc<iroha_fs::OwnerDirectory>,
    registry_root: PathBuf,
    registry_identity: std::sync::Arc<iroha_fs::OwnerDirectory>,
}
/// A verified immutable cache entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheEntry {
    /// Commitment identity used in the cache path.
    pub archive_id: ArchiveId,
    /// Immutable extracted source directory.
    pub source_path: PathBuf,
}
/// Authenticated bundle metadata and source root accepted for compiler input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedCompilerPackageV1 {
    /// Immutable extracted source directory.
    pub source_path: PathBuf,
    /// Exact canonical `Musubi.toml` bytes decoded as UTF-8 after digest verification.
    pub manifest: String,
    /// Digest-verified Kotodama sources, ordered by portable bundle path.
    pub kotodama_sources: Vec<CachedKotodamaSourceV1>,
    /// Complete compiled interfaces authenticated by the same immutable package commitment.
    pub contract_artifacts: Vec<kotodama_lang::linker::SourceContractArtifact>,
    /// Canonical archive-independent release metadata embedded in the bundle.
    pub semantic_release: MusubiSemanticReleaseManifestV1,
    /// Publisher-supplied exact proof lock embedded in the bundle.
    pub publication_lock: MusubiVerificationLockV1,
}
/// One immutable Kotodama source copied out of a verified cache tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedKotodamaSourceV1 {
    /// Portable path relative to the package root.
    pub path: String,
    /// Complete UTF-8 source text.
    pub source: String,
}
/// Result of installing an archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    /// This invocation published a new immutable entry.
    Installed(CacheEntry),
    /// An identical, healthy entry was already present.
    AlreadyPresent(CacheEntry),
}
/// Result of checking and repairing one cache entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepairOutcome {
    /// The existing entry passed every commitment check.
    Healthy(CacheEntry),
    /// No source directory exists for the archive.
    Missing,
    /// A structurally safe but corrupt tree was moved aside for inspection.
    Quarantined {
        /// Path of the quarantined tree.
        path: PathBuf,
    },
}
/// Summary of a cache prune operation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PruneReport {
    /// Archive identities removed from the cache.
    pub removed: Vec<ArchiveId>,
}
/// Errors raised by the immutable cache.
#[derive(Debug)]
pub enum CacheError {
    /// The platform cannot provide the required stable-identity and rename guarantees.
    UnsupportedPlatform,
    /// A filesystem operation failed.
    Io {
        /// Stable operation label without secret-bearing input.
        operation: &'static str,
        /// Cache-owned path involved in the operation.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
    /// The configured cache root is not a stable private directory.
    UnsafeRoot(String),
    /// The archive commitment and `SoraFS` plan disagree.
    InvalidPlan(String),
    /// Incoming CAR bytes did not match the finalized commitment.
    InvalidArchive(String),
    /// Extracted bytes or filesystem objects failed verification.
    CorruptEntry(String),
    /// A repair or prune candidate contains a descendant that cannot be safely mutated.
    UnsafeDescendant(PathBuf),
}
impl fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter.write_str(
                "secure Musubi cache access requires native Unix or Windows retained filesystem authority",
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} cache path `{}`: {source}",
                path.display()
            ),
            Self::UnsafeRoot(reason) => write!(formatter, "unsafe Musubi cache root: {reason}"),
            Self::InvalidPlan(reason) => {
                write!(formatter, "invalid Musubi archive plan: {reason}")
            }
            Self::InvalidArchive(reason) => {
                write!(formatter, "Musubi archive verification failed: {reason}")
            }
            Self::CorruptEntry(reason) => write!(formatter, "corrupt Musubi cache entry: {reason}"),
            Self::UnsafeDescendant(path) => write!(
                formatter,
                "cache descendant `{}` is not safe to quarantine or prune",
                path.display()
            ),
        }
    }
}
impl Error for CacheError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
impl MusubiCache {
    /// Open or create `registry-v1` below an explicit user cache root.
    ///
    /// The supplied path is configuration, not lockfile data. Its final component must not be a
    /// symlink and neither it nor the registry root may be group- or world-writable.
    ///
    /// # Errors
    ///
    /// Returns an error when retained directory creation fails or either root has unsafe custody.
    pub fn open(user_root: impl AsRef<Path>) -> Result<Self, CacheError> {
        let requested = absolute_path(user_root.as_ref())?;
        let root_identity = std::sync::Arc::new(
            iroha_fs::OwnerDirectory::open_or_create(&requested)
                .map_err(|source| io_error("retain user cache root", &requested, source))?,
        );
        let registry_identity = std::sync::Arc::new(
            root_identity
                .ensure_child(REGISTRY_DIRECTORY)
                .map_err(|source| io_error("retain registry cache root", &requested, source))?,
        );
        root_identity
            .sync()
            .map_err(|source| io_error("sync cache root", &requested, source))?;
        Ok(Self {
            root: root_identity.path().to_path_buf(),
            registry_root: registry_identity.path().to_path_buf(),
            root_identity,
            registry_identity,
        })
    }
    /// Return the trusted user cache root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Derive the immutable source path for an archive identity.
    #[must_use]
    pub fn source_path(&self, archive_id: &ArchiveId) -> PathBuf {
        self.archive_directory(archive_id).join(SOURCE_DIRECTORY)
    }
    /// Enumerate canonical archive identities currently owned by this cache.
    ///
    /// Fixed non-archive files, temporary siblings, resolver-index snapshots, and every
    /// noncanonical name are ignored. A canonical archive name must identify a real private
    /// directory; a symlink or other substituted object fails the inventory instead of being
    /// treated as a verification or prune target.
    ///
    /// # Errors
    ///
    /// Returns an error when a cache anchor changed, the registry directory
    /// cannot be read, or a canonical archive descendant is unsafe.
    pub fn archive_ids(&self) -> Result<Vec<ArchiveId>, CacheError> {
        self.validate_anchors()?;
        let mut archive_ids = Vec::new();
        let mut archive_pins = Vec::new();
        for entry in fs::read_dir(&self.registry_root)
            .map_err(|source| io_error("read registry cache root", &self.registry_root, source))?
        {
            let entry = entry.map_err(|source| {
                io_error("read registry cache entry", &self.registry_root, source)
            })?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(archive_id) = decode_archive_directory_name(&name) else {
                continue;
            };
            if archive_id.is_zero() {
                return Err(CacheError::CorruptEntry(
                    "cache contains a zero archive identity".to_owned(),
                ));
            }
            let path = self.registry_root.join(&name);
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("inspect archive cache directory", &path, source))?;
            validate_private_directory(&path, &metadata)?;
            archive_pins.push(DirectoryPin::capture_expected(&path, &metadata)?);
            archive_ids.push(archive_id);
        }
        for pin in &archive_pins {
            pin.validate()?;
        }
        archive_ids.sort_unstable();
        archive_ids.dedup();
        Ok(archive_ids)
    }
    /// Re-authenticate one immutable cached bundle for compiler consumption.
    ///
    /// This boundary does not trust permissions or a consumer lock as cache integrity evidence. It
    /// re-inventories every descendant without following links, reproduces the normalized source
    /// digest, validates the canonical bundle metadata, and binds the semantic release to the
    /// consumer node's exact archive and release digest. The publisher's packaged proof lock is
    /// validated independently; its exact selections need not match a consumer's independently
    /// resolved graph.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache ancestry is unsafe, the tree changed while being read, a bound
    /// is exceeded, or any immutable node/bundle commitment disagrees.
    pub fn load_compiler_package(
        &self,
        node: &MusubiVerificationNodeV1,
    ) -> Result<CachedCompilerPackageV1, CacheError> {
        node.validate()
            .map_err(|error| CacheError::CorruptEntry(error.to_string()))?;
        self.validate_anchors()?;
        let archive_dir = self.validate_existing_archive_directory(&node.archive_id)?;
        let archive_pin = DirectoryPin::capture(&archive_dir)?;
        let source_path = archive_dir.join(SOURCE_DIRECTORY);
        let inventory = inventory_tree(&source_path)?;
        let (semantic_release, publication_lock) =
            verify_compiler_bundle(&source_path, node, &inventory.files)?;
        let (manifest, kotodama_sources, contract_artifacts) =
            load_compiler_sources(&source_path, &inventory.files)?;
        archive_pin.validate()?;
        Ok(CachedCompilerPackageV1 {
            source_path,
            manifest,
            kotodama_sources,
            contract_artifacts,
            semantic_release,
            publication_lock,
        })
    }
    /// Verify and atomically install a canonical CAR stream.
    ///
    /// The reader is consumed to EOF. Any trailing byte, malformed section, digest mismatch, unsafe
    /// plan, or incomplete commitment leaves `src` absent. A racing identical installer is treated
    /// idempotently. Private `.src.*.partial` and `.payload.*.partial` residue is retained because
    /// safe automatic compare-and-delete is unavailable.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid commitments, untrusted CAR bytes, unsafe filesystem state,
    /// failed durability operations, or a corrupt existing destination.
    pub fn install<R: Read>(
        &self,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
        reader: R,
    ) -> Result<InstallOutcome, CacheError> {
        self.validate_anchors()?;
        validate_plan_commitment(commitment, plan)?;
        let archive_id = commitment.archive_id();
        let archive_dir = self.ensure_archive_directory(&archive_id)?;
        let archive_pin = DirectoryPin::capture(&archive_dir)?;
        let source_path = archive_dir.join(SOURCE_DIRECTORY);
        if source_path
            .try_exists()
            .map_err(|source| io_error("inspect cache destination", &source_path, source))?
        {
            return self
                .verify(commitment, plan)
                .map(InstallOutcome::AlreadyPresent);
        }
        let (staging_path, _staging_metadata, staging_pin) =
            create_staging_directory(&archive_dir)?;
        let (payload_path, mut payload_file, _payload_metadata) =
            create_temporary_file(&archive_dir, ".payload")?;
        let _residue = RetainedInstallResidue::new(staging_path.clone(), payload_path.clone());
        stream_and_verify_car(reader, commitment, plan, payload_file.file_mut())?;
        #[cfg(all(test, unix))]
        crash_cache_install_at(CacheInstallCrashCutV1::VerifiedPayloadWritten);
        payload_file
            .file()
            .sync_all()
            .map_err(|source| io_error("sync verified CAR payload", &payload_path, source))?;
        #[cfg(all(test, unix))]
        crash_cache_install_at(CacheInstallCrashCutV1::VerifiedPayloadSynced);
        let mut payload = FilePayload::from_retained_file(payload_file)
            .map_err(|source| io_error("retain verified CAR payload", &payload_path, source))?;
        let mut store = bounded_musubi_chunk_store(plan)?;
        let sink = SourceTreeSink::new(staging_path.clone(), staging_pin);
        let mut staging_pins = store
            .ingest_plan_source_with_sink(plan, &mut payload, sink)
            .map_err(|error| CacheError::CorruptEntry(error.to_string()))?;
        drop(payload);
        verify_por(commitment, &store)?;
        // TODO: Delete verified payload and staging residue only after a safe workspace
        // abstraction provides handle-relative atomic compare-and-delete. Pathname revalidation
        // followed by unlink remains vulnerable to same-UID substitution, so first-release
        // behavior retains operation-owned residue on both success and failure.
        #[cfg(all(test, unix))]
        crash_cache_install_at(CacheInstallCrashCutV1::VerifiedPayloadRetained);
        verify_tree(&staging_path, commitment, plan)?;
        #[cfg(all(test, unix))]
        crash_cache_install_at(CacheInstallCrashCutV1::SourceTreeVerified);
        make_tree_immutable_and_sync(&staging_path)?;
        #[cfg(all(test, unix))]
        crash_cache_install_at(CacheInstallCrashCutV1::SourceTreeSynced);
        for pin in &staging_pins {
            pin.validate()?;
        }
        archive_pin.validate()?;
        let root_index = staging_pins
            .iter()
            .position(|pin| pin.path == staging_path)
            .ok_or_else(|| {
                CacheError::CorruptEntry("source staging tree has no retained root pin".to_owned())
            })?;
        let staging_root_pin = staging_pins.remove(root_index);
        drop(staging_pins);
        let _published_pin = match rename_no_replace(&staging_path, &source_path, staging_root_pin)
        {
            Ok(pin) => pin,
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                return self
                    .verify(commitment, plan)
                    .map(InstallOutcome::AlreadyPresent);
            }
            Err(source) => {
                return Err(io_error(
                    "publish immutable source tree",
                    &source_path,
                    source,
                ));
            }
        };
        #[cfg(all(test, unix))]
        crash_cache_install_at(CacheInstallCrashCutV1::SourceTreePublished);
        sync_directory(&archive_dir)
            .map_err(|source| io_error("sync archive cache directory", &archive_dir, source))?;
        #[cfg(all(test, unix))]
        crash_cache_install_at(CacheInstallCrashCutV1::ArchiveDirectorySynced);
        let entry = self.verify(commitment, plan)?;
        Ok(InstallOutcome::Installed(entry))
    }
    /// Verify an extracted entry against every archive and bundle commitment.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry is missing, has unsafe or extra
    /// descendants, differs from the plan, or cannot reproduce the canonical
    /// CAR, `PoR`, descriptor, source-tree, and bundle commitments.
    pub fn verify(
        &self,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
    ) -> Result<CacheEntry, CacheError> {
        self.validate_anchors()?;
        validate_plan_commitment(commitment, plan)?;
        self.verify_validated(commitment, plan)
    }
    fn verify_validated(
        &self,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
    ) -> Result<CacheEntry, CacheError> {
        let archive_id = commitment.archive_id();
        let archive_dir = self.validate_existing_archive_directory(&archive_id)?;
        let archive_pin = DirectoryPin::capture(&archive_dir)?;
        let source_path = archive_dir.join(SOURCE_DIRECTORY);
        verify_tree(&source_path, commitment, plan)?;
        archive_pin.validate()?;
        Ok(CacheEntry {
            archive_id,
            source_path,
        })
    }
    /// Verify an entry and quarantine it only when every descendant is safe.
    ///
    /// The finalized commitment and file plan are validated before local cache
    /// state is interpreted. Only an integrity failure reported while verifying
    /// the local tree is eligible for quarantine.
    ///
    /// Content-corrupt regular trees are renamed to a private sibling. Trees containing symlinks,
    /// hardlinks, special files, or unstable identities are left untouched for manual inspection.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid registry inputs, unsafe filesystem state,
    /// or a failed quarantine.
    pub fn repair(
        &self,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
    ) -> Result<RepairOutcome, CacheError> {
        self.validate_anchors()?;
        validate_plan_commitment(commitment, plan)?;
        match self.verify_validated(commitment, plan) {
            Ok(entry) => return Ok(RepairOutcome::Healthy(entry)),
            Err(CacheError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(RepairOutcome::Missing);
            }
            Err(CacheError::CorruptEntry(_)) => {}
            Err(error) => return Err(error),
        }
        self.validate_anchors()?;
        let archive_id = commitment.archive_id();
        let archive_dir = self.ensure_archive_directory(&archive_id)?;
        let archive_pin = DirectoryPin::capture(&archive_dir)?;
        let source_path = archive_dir.join(SOURCE_DIRECTORY);
        if !source_path
            .try_exists()
            .map_err(|source| io_error("inspect repair candidate", &source_path, source))?
        {
            return Ok(RepairOutcome::Missing);
        }
        let tree = validate_mutable_tree(&source_path)?;
        let quarantine = allocate_absent_path(&archive_dir, ".quarantine")?;
        archive_pin.validate()?;
        rename_no_replace(&source_path, &quarantine, tree.into_root_pin()?)
            .map_err(|source| io_error("quarantine corrupt cache entry", &quarantine, source))?;
        sync_directory(&archive_dir)
            .map_err(|source| io_error("sync archive cache directory", &archive_dir, source))?;
        Ok(RepairOutcome::Quarantined { path: quarantine })
    }
    /// Remove only the exact archive identities authorized by a finalized retention query.
    ///
    /// First-release safe `std` cannot atomically compare and delete a retained filesystem object.
    /// Consequently, an empty candidate set succeeds as a no-op and every non-empty set fails
    /// before candidates are inspected, isolated, permission-mutated, or removed.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero identity, unsafe cache anchors, or every non-empty prune.
    pub(crate) fn prune_exact(
        &self,
        candidates: &BTreeSet<ArchiveId>,
    ) -> Result<PruneReport, CacheError> {
        self.validate_anchors()?;
        for archive_id in candidates {
            if archive_id.is_zero() {
                return Err(CacheError::CorruptEntry(
                    "cache prune candidate uses the zero archive identity".to_owned(),
                ));
            }
        }
        if candidates.is_empty() {
            return Ok(PruneReport::default());
        }
        Err(destructive_cache_removal_unsupported(&self.registry_root))
    }
    fn archive_directory(&self, archive_id: &ArchiveId) -> PathBuf {
        self.registry_root.join(hex::encode(archive_id.as_bytes()))
    }
    fn ensure_archive_directory(&self, archive_id: &ArchiveId) -> Result<PathBuf, CacheError> {
        self.validate_anchors()?;
        let path = self.archive_directory(archive_id);
        create_or_validate_private_directory(&path)?;
        sync_directory(&self.registry_root)
            .map_err(|source| io_error("sync registry cache root", &self.registry_root, source))?;
        Ok(path)
    }
    fn validate_existing_archive_directory(
        &self,
        archive_id: &ArchiveId,
    ) -> Result<PathBuf, CacheError> {
        let path = self.archive_directory(archive_id);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect archive cache directory", &path, source))?;
        validate_private_directory(&path, &metadata)?;
        Ok(path)
    }
    fn validate_anchors(&self) -> Result<(), CacheError> {
        validate_directory_identity(&self.root, &self.root_identity)?;
        validate_directory_identity(&self.registry_root, &self.registry_identity)?;
        Ok(())
    }
}
#[derive(Debug)]
struct DirectoryPin {
    path: PathBuf,
    identity: iroha_fs::FileIdentity,
    authority: iroha_fs::OwnerDirectory,
}
impl DirectoryPin {
    fn from_authority(authority: iroha_fs::OwnerDirectory) -> Result<Self, CacheError> {
        let path = authority.path().to_path_buf();
        let identity = authority
            .identity()
            .map_err(|source| io_error("identify retained cache directory", &path, source))?;
        Ok(Self {
            path,
            identity,
            authority,
        })
    }
    fn capture(path: &Path) -> Result<Self, CacheError> {
        Self::from_authority(
            iroha_fs::OwnerDirectory::open(path)
                .map_err(|source| io_error("retain cache directory", path, source))?,
        )
    }
    fn capture_in_tree(path: &Path, pins: &[Self]) -> Result<Self, CacheError> {
        if let Some(parent) = pins
            .iter()
            .find(|pin| Some(pin.path.as_path()) == path.parent())
        {
            return Self::from_authority(
                parent
                    .authority
                    .open_child(path.file_name().expect("child name"))
                    .map_err(|source| io_error("retain cache child directory", path, source))?,
            );
        }
        Self::capture(path)
    }
    fn capture_expected(path: &Path, expected: &fs::Metadata) -> Result<Self, CacheError> {
        let pin = Self::capture(path)?;
        #[cfg(unix)]
        {
            let actual = fs::symlink_metadata(path)
                .map_err(|source| io_error("compare retained directory", path, source))?;
            if !same_file(expected, &actual) {
                return Err(CacheError::UnsafeDescendant(path.to_path_buf()));
            }
        }
        #[cfg(not(unix))]
        let _ = expected;
        pin.validate()?;
        Ok(pin)
    }
    fn validate(&self) -> Result<(), CacheError> {
        self.authority.revalidate().map_err(|source| {
            io_error("revalidate retained cache directory", &self.path, source)
        })?;
        if self
            .authority
            .identity()
            .map_err(|source| io_error("identify cache directory", &self.path, source))?
            != self.identity
        {
            return Err(CacheError::UnsafeDescendant(self.path.clone()));
        }
        Ok(())
    }
}
fn absolute_path(path: &Path) -> Result<PathBuf, CacheError> {
    if path.as_os_str().is_empty() {
        return Err(CacheError::UnsafeRoot(
            "cache root must not be empty".to_owned(),
        ));
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|source| io_error("resolve user cache root", path, source))
    }
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
#[cfg(unix)]
fn metadata_has_one_hard_link(metadata: &fs::Metadata) -> bool {
    metadata.nlink() == 1
}
fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), CacheError> {
    if metadata_is_link_or_reparse(metadata) || !metadata.is_dir() {
        return Err(CacheError::UnsafeRoot(format!(
            "`{}` must be a real directory",
            path.display()
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(CacheError::UnsafeRoot(format!(
            "`{}` must not be group- or world-writable",
            path.display()
        )));
    }
    Ok(())
}
fn create_or_validate_private_directory(path: &Path) -> Result<(), CacheError> {
    let authority = iroha_fs::OwnerDirectory::open_or_create(path)
        .map_err(|source| io_error("create retained cache directory", path, source))?;
    authority
        .sync()
        .map_err(|source| io_error("sync cache directory", path, source))
}
fn validate_directory_identity(
    path: &Path,
    authority: &iroha_fs::OwnerDirectory,
) -> Result<(), CacheError> {
    if authority.path() != path {
        return Err(CacheError::UnsafeDescendant(path.to_path_buf()));
    }
    authority
        .revalidate()
        .map_err(|source| io_error("validate cache root identity", path, source))
}
fn validate_plan_commitment(
    commitment: &MusubiArchiveCommitmentV1,
    plan: &CarBuildPlan,
) -> Result<(), CacheError> {
    commitment
        .validate()
        .map_err(|error| CacheError::InvalidPlan(error.to_string()))?;
    plan.validate()
        .map_err(|error| CacheError::InvalidPlan(error.to_string()))?;
    validate_musubi_plan_memory(plan)?;
    if plan.content_length != commitment.content_length {
        return Err(CacheError::InvalidPlan(format!(
            "payload length {} differs from commitment {}",
            plan.content_length, commitment.content_length
        )));
    }
    if plan.chunks.len() != commitment.chunk_count as usize {
        return Err(CacheError::InvalidPlan(format!(
            "chunk count {} differs from commitment {}",
            plan.chunks.len(),
            commitment.chunk_count
        )));
    }
    let plan_digest = compute_chunk_plan_digest_sha3(&plan.chunks);
    if commitment.chunk_plan_digest.as_bytes() != &plan_digest {
        return Err(CacheError::InvalidPlan(
            "canonical chunk-plan digest mismatch".to_owned(),
        ));
    }
    let descriptor = sorafs_car::chunker_registry::lookup(ProfileId(commitment.chunker.profile_id))
        .ok_or_else(|| CacheError::InvalidPlan("unknown chunker profile id".to_owned()))?;
    if descriptor.namespace != commitment.chunker.namespace
        || descriptor.name != commitment.chunker.name
        || descriptor.semver != commitment.chunker.semver
        || descriptor.multihash_code != commitment.chunker.multihash_code
        || descriptor.profile != plan.chunk_profile
    {
        return Err(CacheError::InvalidPlan(
            "chunker handle does not identify the plan profile".to_owned(),
        ));
    }
    let mut source_count = 0usize;
    let mut release_count = 0usize;
    let mut descriptor_count = 0usize;
    let mut lock_count = 0usize;
    for file in &plan.files {
        let path = file.path.join("/");
        match path.as_str() {
            RELEASE_PATH => release_count += 1,
            DESCRIPTOR_PATH => descriptor_count += 1,
            VERIFICATION_LOCK_PATH => lock_count += 1,
            _ if path.starts_with(".musubi/") => {
                return Err(CacheError::InvalidPlan(format!(
                    "unexpected bundle metadata entry `{path}`"
                )));
            }
            _ => {
                source_count += 1;
            }
        }
    }
    if release_count != 1 || descriptor_count != 1 || lock_count != 1 {
        return Err(CacheError::InvalidPlan(
            "bundle requires one release, descriptor, and verification lock".to_owned(),
        ));
    }
    if source_count != commitment.file_count as usize {
        return Err(CacheError::InvalidPlan(format!(
            "source file count {source_count} differs from commitment {}",
            commitment.file_count
        )));
    }
    Ok(())
}
fn validate_musubi_plan_memory(plan: &CarBuildPlan) -> Result<(), CacheError> {
    let retained = retained_plan_heap_bytes(plan).ok_or_else(|| {
        CacheError::InvalidPlan("retained CAR plan heap accounting overflow".to_owned())
    })?;
    if retained > MUSUBI_MAX_RETAINED_PLAN_HEAP_BYTES {
        return Err(CacheError::InvalidPlan(format!(
            "retained CAR plan requires {retained} bytes; Musubi V1 permits at most {MUSUBI_MAX_RETAINED_PLAN_HEAP_BYTES}"
        )));
    }
    validate_musubi_ingest_memory(plan, MUSUBI_CACHE_CHUNK_STORE_HEAP_LIMIT_BYTES)
}
fn validate_musubi_ingest_memory(plan: &CarBuildPlan, heap_limit: usize) -> Result<(), CacheError> {
    plan.validate_for_ingest_with_limit(heap_limit)
        .map_err(|error| CacheError::InvalidPlan(error.to_string()))?;
    Ok(())
}
fn retained_plan_heap_bytes(plan: &CarBuildPlan) -> Option<usize> {
    let mut retained = plan
        .chunks
        .capacity()
        .checked_mul(std::mem::size_of::<sorafs_car::CarChunk>())?
        .checked_add(
            plan.files
                .capacity()
                .checked_mul(std::mem::size_of::<sorafs_car::FilePlan>())?,
        )?;
    for file in &plan.files {
        retained = retained.checked_add(
            file.path
                .capacity()
                .checked_mul(std::mem::size_of::<String>())?,
        )?;
        for component in &file.path {
            retained = retained.checked_add(component.capacity())?;
        }
    }
    Some(retained)
}
fn bounded_musubi_chunk_store(plan: &CarBuildPlan) -> Result<ChunkStore, CacheError> {
    ChunkStore::with_profile_and_heap_limit(
        plan.chunk_profile,
        MUSUBI_CACHE_CHUNK_STORE_HEAP_LIMIT_BYTES,
    )
    .map_err(|error| CacheError::InvalidPlan(error.to_string()))
}
fn manifest_for_commitment(
    commitment: &MusubiArchiveCommitmentV1,
    plan: &CarBuildPlan,
) -> Result<sorafs_manifest::ManifestV1, CacheError> {
    ManifestBuilder::new()
        .root_cid(commitment.root_cid.as_bytes().to_vec())
        .dag_codec(DagCodecId(DAG_CBOR_CODEC))
        .chunking_from_profile(plan.chunk_profile, BLAKE3_MULTIHASH)
        .chunk_digest_sha3_256(*commitment.chunk_plan_digest.as_bytes())
        .por_root(*commitment.por_root.as_bytes())
        .content_length(commitment.content_length)
        .car_digest(*commitment.car_digest.as_bytes())
        .car_size(commitment.car_size)
        .pin_policy(PinPolicy {
            min_replicas: 1,
            storage_class: StorageClass::Hot,
            retention_epoch: 0,
        })
        .governance(GovernanceProofs::default())
        .build()
        .map_err(|error| CacheError::InvalidPlan(error.to_string()))
}
fn stream_and_verify_car<R: Read>(
    reader: R,
    commitment: &MusubiArchiveCommitmentV1,
    plan: &CarBuildPlan,
    payload: &mut File,
) -> Result<(), CacheError> {
    let manifest = manifest_for_commitment(commitment, plan)?;
    let verifier = StreamingCarVerifier::new(
        manifest,
        StreamingVerifierConfig {
            max_chunk_size: 4 * 1024 * 1024,
        },
    );
    let mut stream = VerifiedCarStream::new(reader, verifier, commitment.car_size);
    let mut header = [0u8; CAR_PRAGMA_BYTES + CAR_HEADER_BYTES];
    stream.read_exact(&mut header)?;
    let data_offset = decode_u64(&header[CAR_PRAGMA_BYTES + 16..CAR_PRAGMA_BYTES + 24]);
    let data_size = decode_u64(&header[CAR_PRAGMA_BYTES + 24..CAR_PRAGMA_BYTES + 32]);
    let index_offset = decode_u64(&header[CAR_PRAGMA_BYTES + 32..CAR_PRAGMA_BYTES + 40]);
    if data_offset != CAR_DATA_OFFSET
        || data_offset.checked_add(data_size) != Some(index_offset)
        || index_offset > commitment.car_size
    {
        return Err(CacheError::InvalidArchive(
            "invalid CARv2 offsets".to_owned(),
        ));
    }
    let data_end = index_offset;
    let (carv1_header_len, _) = stream.read_varint()?;
    if carv1_header_len > CAR_MAX_HEADER_BYTES {
        return Err(CacheError::InvalidArchive(
            "CARv1 header exceeds V1 bound".to_owned(),
        ));
    }
    ensure_within_data(&stream, carv1_header_len, data_end)?;
    stream.copy_exact(carv1_header_len, None)?;
    let mut raw_chunk_index = 0usize;
    while stream.position < data_end {
        let section_start = stream.position;
        let (section_len, _) = stream.read_varint()?;
        if section_len == 0 || section_len > CAR_MAX_SECTION_BYTES {
            return Err(CacheError::InvalidArchive(format!(
                "CAR section at byte {section_start} has invalid length {section_len}"
            )));
        }
        ensure_within_data(&stream, section_len, data_end)?;
        let cid_start = stream.position;
        let (version, _) = stream.read_varint()?;
        let (codec, _) = stream.read_varint()?;
        let (multihash, _) = stream.read_varint()?;
        let (digest_len, _) = stream.read_varint()?;
        if version != 1 || multihash != BLAKE3_MULTIHASH || digest_len != CID_DIGEST_BYTES {
            return Err(CacheError::InvalidArchive(
                "CAR section uses a noncanonical CID".to_owned(),
            ));
        }
        let mut digest = [0u8; CID_DIGEST_BYTES_USIZE];
        stream.read_exact(&mut digest)?;
        let cid_len = stream
            .position
            .checked_sub(cid_start)
            .ok_or_else(|| CacheError::InvalidArchive("CAR CID length underflow".to_owned()))?;
        let data_len = section_len.checked_sub(cid_len).ok_or_else(|| {
            CacheError::InvalidArchive("CAR section is shorter than its CID".to_owned())
        })?;
        match codec {
            RAW_CODEC => {
                let expected = plan.chunks.get(raw_chunk_index).ok_or_else(|| {
                    CacheError::InvalidArchive("CAR contains too many raw chunks".to_owned())
                })?;
                if data_len != u64::from(expected.length) || digest != expected.digest {
                    return Err(CacheError::InvalidArchive(format!(
                        "raw CAR chunk {raw_chunk_index} differs from the canonical plan"
                    )));
                }
                stream.copy_exact(data_len, Some(payload))?;
                raw_chunk_index += 1;
            }
            DAG_CBOR_CODEC => stream.copy_exact(data_len, None)?,
            _ => {
                return Err(CacheError::InvalidArchive(format!(
                    "unsupported CAR section codec {codec:#x}"
                )));
            }
        }
    }
    if stream.position != data_end || raw_chunk_index != plan.chunks.len() {
        return Err(CacheError::InvalidArchive(
            "CAR raw chunk inventory is incomplete".to_owned(),
        ));
    }
    let index_bytes = commitment
        .car_size
        .checked_sub(stream.position)
        .ok_or_else(|| CacheError::InvalidArchive("CAR size underflow".to_owned()))?;
    stream.copy_exact(index_bytes, None)?;
    stream.finish()
}
fn ensure_within_data<R: Read>(
    stream: &VerifiedCarStream<R>,
    additional: u64,
    data_end: u64,
) -> Result<(), CacheError> {
    if stream
        .position
        .checked_add(additional)
        .is_none_or(|end| end > data_end)
    {
        return Err(CacheError::InvalidArchive(
            "CAR section crosses the declared data boundary".to_owned(),
        ));
    }
    Ok(())
}
fn decode_u64(bytes: &[u8]) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(bytes);
    u64::from_le_bytes(value)
}
struct VerifiedCarStream<R> {
    reader: R,
    verifier: StreamingCarVerifier,
    position: u64,
    expected_size: u64,
}
impl<R: Read> VerifiedCarStream<R> {
    fn new(reader: R, verifier: StreamingCarVerifier, expected_size: u64) -> Self {
        Self {
            reader,
            verifier,
            position: 0,
            expected_size,
        }
    }
    fn read_exact(&mut self, bytes: &mut [u8]) -> Result<(), CacheError> {
        let count = u64::try_from(bytes.len())
            .map_err(|_| CacheError::InvalidArchive("host byte count exceeds u64".to_owned()))?;
        if self
            .position
            .checked_add(count)
            .is_none_or(|end| end > self.expected_size)
        {
            return Err(CacheError::InvalidArchive(
                "CAR exceeds its committed size".to_owned(),
            ));
        }
        self.reader
            .read_exact(bytes)
            .map_err(|error| CacheError::InvalidArchive(error.to_string()))?;
        let consumed = self
            .verifier
            .update(bytes)
            .map_err(|error| CacheError::InvalidArchive(error.to_string()))?;
        if consumed != bytes.len() {
            return Err(CacheError::InvalidArchive(
                "streaming verifier stopped before the supplied bytes".to_owned(),
            ));
        }
        self.position = self
            .position
            .checked_add(count)
            .ok_or_else(|| CacheError::InvalidArchive("CAR position overflow".to_owned()))?;
        Ok(())
    }
    fn read_varint(&mut self) -> Result<(u64, usize), CacheError> {
        let mut value = 0u64;
        for index in 0..10usize {
            let mut byte = [0u8; 1];
            self.read_exact(&mut byte)?;
            let payload = u64::from(byte[0] & 0x7f);
            let shift = u32::try_from(index * 7).expect("ten-byte u64 varint shift fits u32");
            if shift == 63 && payload > 1 {
                return Err(CacheError::InvalidArchive("varint overflow".to_owned()));
            }
            value |= payload << shift;
            if byte[0] & 0x80 == 0 {
                if index > 0 && payload == 0 {
                    return Err(CacheError::InvalidArchive(
                        "noncanonical varint encoding".to_owned(),
                    ));
                }
                return Ok((value, index + 1));
            }
        }
        Err(CacheError::InvalidArchive("varint overflow".to_owned()))
    }
    fn copy_exact(
        &mut self,
        mut remaining: u64,
        mut output: Option<&mut File>,
    ) -> Result<(), CacheError> {
        let mut buffer = vec![0_u8; IO_BUFFER_BYTES];
        while remaining != 0 {
            let count = usize::try_from(remaining.min(IO_BUFFER_BYTES as u64))
                .expect("bounded I/O count fits usize");
            self.read_exact(&mut buffer[..count])?;
            if let Some(file) = output.as_deref_mut() {
                file.write_all(&buffer[..count])
                    .map_err(|source| CacheError::Io {
                        operation: "write verified CAR payload",
                        path: PathBuf::from("<private-payload>"),
                        source,
                    })?;
            }
            remaining -= count as u64;
        }
        Ok(())
    }
    fn finish(mut self) -> Result<(), CacheError> {
        if self.position != self.expected_size {
            return Err(CacheError::InvalidArchive(format!(
                "CAR ended at {} bytes instead of {}",
                self.position, self.expected_size
            )));
        }
        let mut trailing = [0u8; 1];
        if self
            .reader
            .read(&mut trailing)
            .map_err(|error| CacheError::InvalidArchive(error.to_string()))?
            != 0
        {
            return Err(CacheError::InvalidArchive(
                "CAR stream has trailing bytes".to_owned(),
            ));
        }
        self.verifier
            .finalize()
            .map_err(|error| CacheError::InvalidArchive(error.to_string()))
    }
}
#[derive(Debug)]
struct SourceTreeSink {
    root: PathBuf,
    files: Vec<sorafs_car::FilePlan>,
    chunk_files: Vec<usize>,
    next_chunk: usize,
    current: Option<OpenTarget>,
    directory_pins: Vec<DirectoryPin>,
}
#[derive(Debug)]
struct OpenTarget {
    file_index: usize,
    path: PathBuf,
    file: iroha_fs::RetainedFile,
    written: u64,
}
impl SourceTreeSink {
    fn new(root: PathBuf, root_pin: DirectoryPin) -> Self {
        Self {
            root,
            files: Vec::new(),
            chunk_files: Vec::new(),
            next_chunk: 0,
            current: None,
            directory_pins: vec![root_pin],
        }
    }
    fn create_target(&self, file_index: usize) -> Result<OpenTarget, ChunkStoreError> {
        validate_directory_pins_io(&self.directory_pins)?;
        let plan = self.files.get(file_index).ok_or_else(|| {
            ChunkStoreError::Io(io::Error::other("source-tree file index is out of range"))
        })?;
        let path = join_components(&self.root, &plan.path);
        let file = open_new_regular_file(&path).map_err(ChunkStoreError::Io)?;
        Ok(OpenTarget {
            file_index,
            path,
            file,
            written: 0,
        })
    }
    fn finish_target(&mut self) -> Result<(), ChunkStoreError> {
        let Some(mut target) = self.current.take() else {
            return Ok(());
        };
        let expected = self.files[target.file_index].size;
        if target.written != expected {
            return Err(ChunkStoreError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "source-tree file `{}` has {} bytes; expected {expected}",
                    target.path.display(),
                    target.written
                ),
            )));
        }
        target
            .file
            .file_mut()
            .flush()
            .map_err(ChunkStoreError::Io)?;
        #[cfg(unix)]
        target
            .file
            .file()
            .set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(ChunkStoreError::Io)?;
        target.file.file().sync_all().map_err(ChunkStoreError::Io)?;
        target.file.revalidate().map_err(ChunkStoreError::Io)?;
        #[cfg(all(test, unix))]
        crash_cache_install_at(CacheInstallCrashCutV1::SourceFileSynced);
        Ok(())
    }
}
impl ChunkSink for SourceTreeSink {
    type Output = Vec<DirectoryPin>;
    fn prepare(&mut self, plan: &CarBuildPlan) -> Result<(), ChunkStoreError> {
        plan.validate().map_err(ChunkStoreError::InvalidPlan)?;
        let root_metadata = fs::symlink_metadata(&self.root).map_err(ChunkStoreError::Io)?;
        if metadata_is_link_or_reparse(&root_metadata) || !root_metadata.is_dir() {
            return Err(ChunkStoreError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "source-tree staging root is not a real directory",
            )));
        }
        validate_directory_pins_io(&self.directory_pins)?;
        if fs::read_dir(&self.root)
            .map_err(ChunkStoreError::Io)?
            .next()
            .is_some()
        {
            return Err(ChunkStoreError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "source-tree staging root is not empty",
            )));
        }
        self.files.clone_from(&plan.files);
        self.chunk_files = vec![usize::MAX; plan.chunks.len()];
        let mut directories = BTreeSet::<Vec<String>>::new();
        for (file_index, file) in self.files.iter().enumerate() {
            for depth in 1..file.path.len() {
                directories.insert(file.path[..depth].to_vec());
            }
            let end = file
                .first_chunk
                .checked_add(file.chunk_count)
                .ok_or_else(|| {
                    ChunkStoreError::Io(io::Error::other("file chunk range overflow"))
                })?;
            for chunk_file in self
                .chunk_files
                .get_mut(file.first_chunk..end)
                .ok_or_else(|| {
                    ChunkStoreError::Io(io::Error::other("file chunk range is out of bounds"))
                })?
            {
                if *chunk_file != usize::MAX {
                    return Err(ChunkStoreError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "source-tree chunk belongs to more than one file",
                    )));
                }
                *chunk_file = file_index;
            }
        }
        if self.chunk_files.contains(&usize::MAX) {
            return Err(ChunkStoreError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "source-tree plan does not cover every chunk",
            )));
        }
        for components in directories {
            validate_directory_pins_io(&self.directory_pins)?;
            let path = join_components(&self.root, &components);
            let parent = self
                .directory_pins
                .iter()
                .find(|pin| Some(pin.path.as_path()) == path.parent())
                .ok_or_else(|| {
                    ChunkStoreError::Io(io::Error::other("source directory parent is not retained"))
                })?;
            let directory = parent
                .authority
                .create_child(path.file_name().expect("planned source directory name"))
                .map_err(ChunkStoreError::Io)?;
            self.directory_pins.push(
                DirectoryPin::from_authority(directory)
                    .map_err(|error| ChunkStoreError::Io(io::Error::other(error.to_string())))?,
            );
            validate_directory_pins_io(&self.directory_pins)?;
        }
        for index in 0..self.files.len() {
            if self.files[index].size == 0 {
                let target = self.create_target(index)?;
                self.current = Some(target);
                self.finish_target()?;
            }
        }
        Ok(())
    }
    fn write_chunk(
        &mut self,
        index: usize,
        _chunk: &sorafs_car::CarChunk,
        data: &[u8],
    ) -> Result<(), ChunkStoreError> {
        if index != self.next_chunk {
            return Err(ChunkStoreError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "source-tree chunks arrived out of order",
            )));
        }
        let file_index = *self.chunk_files.get(index).ok_or_else(|| {
            ChunkStoreError::Io(io::Error::other("source-tree chunk index is out of range"))
        })?;
        if self
            .current
            .as_ref()
            .is_some_and(|target| target.file_index != file_index)
        {
            self.finish_target()?;
        }
        if self.current.is_none() {
            self.current = Some(self.create_target(file_index)?);
        }
        let target = self.current.as_mut().ok_or_else(|| {
            ChunkStoreError::Io(io::Error::other("source-tree target was not opened"))
        })?;
        target
            .file
            .file_mut()
            .write_all(data)
            .map_err(ChunkStoreError::Io)?;
        #[cfg(all(test, unix))]
        crash_cache_install_at(CacheInstallCrashCutV1::SourceChunkWritten);
        target.written = target
            .written
            .checked_add(u64::try_from(data.len()).map_err(|_| {
                ChunkStoreError::Io(io::Error::other("source-tree write length exceeds u64"))
            })?)
            .ok_or_else(|| {
                ChunkStoreError::Io(io::Error::other("source-tree file length overflow"))
            })?;
        self.next_chunk += 1;
        let file = &self.files[file_index];
        if index + 1 == file.first_chunk + file.chunk_count {
            self.finish_target()?;
        }
        Ok(())
    }
    fn finish(mut self) -> Result<Self::Output, ChunkStoreError> {
        self.finish_target()?;
        if self.next_chunk != self.chunk_files.len() {
            return Err(ChunkStoreError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "source-tree plan was not fully materialized",
            )));
        }
        sync_tree_directories(&self.root).map_err(ChunkStoreError::Io)?;
        validate_directory_pins_io(&self.directory_pins)?;
        Ok(self.directory_pins)
    }
}
fn validate_directory_pins_io(pins: &[DirectoryPin]) -> Result<(), ChunkStoreError> {
    for pin in pins {
        pin.validate()
            .map_err(|error| ChunkStoreError::Io(io::Error::other(error.to_string())))?;
    }
    Ok(())
}
fn verify_tree(
    source_path: &Path,
    commitment: &MusubiArchiveCommitmentV1,
    plan: &CarBuildPlan,
) -> Result<(), CacheError> {
    let inventory = inventory_tree(source_path)?;
    compare_inventory(plan, &inventory.files)?;
    let mut payload = DirectoryPayload::new(source_path, &plan.files)
        .map_err(|source| io_error("open cached source payload", source_path, source))?;
    let mut store = bounded_musubi_chunk_store(plan)?;
    store
        .ingest_plan_source(plan, &mut payload)
        .map_err(|error| CacheError::CorruptEntry(error.to_string()))?;
    verify_por(commitment, &store)?;
    drop(payload);
    let mut canonical_payload = DirectoryPayload::new(source_path, &plan.files)
        .map_err(|source| io_error("reopen cached source payload", source_path, source))?;
    let mut reader = SequentialPayloadReader {
        source: &mut canonical_payload,
        offset: 0,
        length: plan.content_length,
    };
    let roots = vec![commitment.root_cid.as_bytes().to_vec()];
    let stats = CarStreamingWriter::with_expected_roots(plan, roots)
        .write_from_reader(&mut reader, io::sink())
        .map_err(|error| CacheError::CorruptEntry(error.to_string()))?;
    let actual_car_digest = stats.car_archive_digest.as_bytes();
    let expected_car_digest = commitment.car_digest.as_bytes();
    if stats.car_size != commitment.car_size
        || actual_car_digest != expected_car_digest
        || stats.root_cids.as_slice() != [commitment.root_cid.as_bytes().as_slice()]
        || stats.dag_codec != DAG_CBOR_CODEC
        || stats.chunk_count != commitment.chunk_count as usize
        || stats.payload_bytes != commitment.content_length
    {
        return Err(CacheError::CorruptEntry(
            "canonical CAR reconstructed from cache differs from commitment".to_owned(),
        ));
    }
    verify_bundle_commitments(source_path, commitment, &inventory.files)
}
struct SequentialPayloadReader<'a> {
    source: &'a mut DirectoryPayload,
    offset: u64,
    length: u64,
}
impl Read for SequentialPayloadReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.length || buffer.is_empty() {
            return Ok(0);
        }
        let remaining = self.length - self.offset;
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded payload read fits usize");
        sorafs_car::PayloadSource::read_exact(self.source, self.offset, &mut buffer[..count])
            .map_err(io::Error::other)?;
        self.offset += count as u64;
        Ok(count)
    }
}
fn verify_por(
    commitment: &MusubiArchiveCommitmentV1,
    store: &ChunkStore,
) -> Result<(), CacheError> {
    if store.por_tree().root() != commitment.por_root.as_bytes() {
        return Err(CacheError::CorruptEntry(
            "proof-of-retrievability root mismatch".to_owned(),
        ));
    }
    Ok(())
}
#[derive(Clone, Debug)]
struct FileInventory {
    path: String,
    size: u64,
    digest: [u8; 32],
}
struct TreeInventory {
    files: Vec<FileInventory>,
    // Retained until all commitment consumers have finished so native callers revalidate
    // the same directory identities between inventory, hashing, and compiler/archive verification.
    _directory_pins: Vec<DirectoryPin>,
}
fn validate_portable_cache_component(component: &str) -> Result<(), CacheError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains(['/', '\\', ':'])
        || component.ends_with(['.', ' '])
        || component.chars().any(|character| {
            character.is_control()
                || is_bidi_control(character)
                || matches!(character, '<' | '>' | '"' | '|' | '?' | '*')
        })
        || is_reserved_windows_component(component)
        || normalize_nfc_cache_component(component).as_deref() != Ok(component)
    {
        return Err(CacheError::CorruptEntry(format!(
            "cache path component `{component}` is not portable"
        )));
    }
    Ok(())
}
fn normalize_nfc_cache_component(component: &str) -> Result<String, ()> {
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
fn portable_cache_component_key(component: &str) -> String {
    component.chars().flat_map(char::to_lowercase).collect()
}
fn is_reserved_windows_component(component: &str) -> bool {
    let basename = component.split('.').next().unwrap_or(component);
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"]
        .iter()
        .any(|reserved| basename.eq_ignore_ascii_case(reserved))
    {
        return true;
    }
    if let (Some(prefix), Some(suffix)) = (basename.get(..3), basename.get(3..)) {
        let numbered = prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT");
        let digit = suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9');
        return numbered && (digit || matches!(suffix, "¹" | "²" | "³"));
    }
    false
}
fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}
fn inventory_tree(root: &Path) -> Result<TreeInventory, CacheError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| io_error("inspect cached source root", root, source))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(CacheError::CorruptEntry(
            "cached source root is not a real directory".to_owned(),
        ));
    }
    let mut output = Vec::new();
    let mut directory_pins = Vec::new();
    let mut entry_count = 0usize;
    inventory_directory(
        root,
        root,
        0,
        &mut entry_count,
        &mut output,
        &mut directory_pins,
    )?;
    output.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    for pin in &directory_pins {
        pin.validate()?;
    }
    Ok(TreeInventory {
        files: output,
        _directory_pins: directory_pins,
    })
}
fn inventory_directory(
    root: &Path,
    directory: &Path,
    depth: usize,
    entry_count: &mut usize,
    output: &mut Vec<FileInventory>,
    directory_pins: &mut Vec<DirectoryPin>,
) -> Result<(), CacheError> {
    if depth > MAX_CACHE_PATH_COMPONENTS {
        return Err(CacheError::CorruptEntry(
            "cache tree exceeds the portable path-depth bound".to_owned(),
        ));
    }
    directory_pins.push(DirectoryPin::capture_in_tree(directory, directory_pins)?);
    let mut entries = Vec::new();
    let mut portable_names = BTreeMap::<String, String>::new();
    for entry in fs::read_dir(directory)
        .map_err(|source| io_error("read cached source directory", directory, source))?
    {
        let entry =
            entry.map_err(|source| io_error("read cached source entry", directory, source))?;
        *entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| CacheError::CorruptEntry("cache entry count overflow".to_owned()))?;
        if *entry_count > MAX_CACHE_ENTRY_COUNT {
            return Err(CacheError::CorruptEntry(
                "cache tree exceeds the bounded descendant count".to_owned(),
            ));
        }
        let file_name = entry.file_name();
        let file_name = file_name.to_str().ok_or_else(|| {
            CacheError::CorruptEntry("cache path component is not UTF-8".to_owned())
        })?;
        validate_portable_cache_component(file_name)?;
        let collision_key = portable_cache_component_key(file_name);
        if let Some(previous) = portable_names.insert(collision_key, file_name.to_owned())
            && previous != file_name
        {
            return Err(CacheError::CorruptEntry(format!(
                "cache path components `{previous}` and `{file_name}` have a portable name collision"
            )));
        }
        entries.push(entry);
    }
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect cached source entry", &path, source))?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err(CacheError::CorruptEntry(format!(
                "symlink or reparse point `{}` is forbidden",
                path.display()
            )));
        }
        if metadata.is_dir() {
            inventory_directory(root, &path, depth + 1, entry_count, output, directory_pins)?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            if !metadata_has_one_hard_link(&metadata) {
                return Err(CacheError::CorruptEntry(format!(
                    "hard-linked cache file `{}` is forbidden",
                    path.display()
                )));
            }
            let relative = path.strip_prefix(root).map_err(|_| {
                CacheError::CorruptEntry("cache path escaped source root".to_owned())
            })?;
            let path_text = relative
                .components()
                .map(|component| {
                    component.as_os_str().to_str().ok_or_else(|| {
                        CacheError::CorruptEntry("cache path is not UTF-8".to_owned())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            let (size, digest) = hash_regular_file(&path)?;
            output.push(FileInventory {
                path: path_text,
                size,
                digest,
            });
            if output.len() > MAX_CACHE_FILE_COUNT {
                return Err(CacheError::CorruptEntry(
                    "cache tree exceeds the bounded file count".to_owned(),
                ));
            }
        } else {
            return Err(CacheError::CorruptEntry(format!(
                "special cache entry `{}` is forbidden",
                path.display()
            )));
        }
    }
    Ok(())
}
fn decode_cached_artifact_descriptor_v1(
    bytes: &[u8],
) -> Result<MusubiArtifactDescriptorV1, CacheError> {
    MusubiArtifactDescriptorV1::decode_canonical_bundle_file(bytes).map_err(|_| {
        CacheError::CorruptEntry(
            "artifact descriptor bundle metadata is invalid or out of bounds".to_owned(),
        )
    })
}
fn decode_cached_semantic_release_v1(
    bytes: &[u8],
) -> Result<MusubiSemanticReleaseManifestV1, CacheError> {
    MusubiSemanticReleaseManifestV1::decode_canonical_bundle_file(bytes).map_err(|_| {
        CacheError::CorruptEntry(
            "semantic release bundle metadata is invalid or out of bounds".to_owned(),
        )
    })
}
fn decode_cached_verification_lock_v1(
    bytes: &[u8],
) -> Result<MusubiVerificationLockV1, CacheError> {
    MusubiVerificationLockV1::decode_canonical_bundle_file(bytes).map_err(|_| {
        CacheError::CorruptEntry(
            "verification lock bundle metadata is invalid or out of bounds".to_owned(),
        )
    })
}
fn verify_compiler_bundle(
    root: &Path,
    node: &MusubiVerificationNodeV1,
    files: &[FileInventory],
) -> Result<(MusubiSemanticReleaseManifestV1, MusubiVerificationLockV1), CacheError> {
    let by_path = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let release = by_path
        .get(RELEASE_PATH)
        .ok_or_else(|| CacheError::CorruptEntry("bundle release manifest is missing".to_owned()))?;
    let descriptor_file = by_path.get(DESCRIPTOR_PATH).ok_or_else(|| {
        CacheError::CorruptEntry("bundle artifact descriptor is missing".to_owned())
    })?;
    let verification_lock = by_path.get(VERIFICATION_LOCK_PATH).ok_or_else(|| {
        CacheError::CorruptEntry("bundle verification lock is missing".to_owned())
    })?;
    if release.size > MUSUBI_MAX_BUNDLE_METADATA_FILE_BYTES_V1
        || verification_lock.size > MUSUBI_MAX_BUNDLE_METADATA_FILE_BYTES_V1
        || descriptor_file.size > MUSUBI_MAX_ARTIFACT_DESCRIPTOR_BYTES_V1
    {
        return Err(CacheError::CorruptEntry(
            "bundle compiler metadata exceeds its verification bound".to_owned(),
        ));
    }
    let source_files = files
        .iter()
        .filter(|file| !file.path.starts_with(".musubi/"))
        .collect::<Vec<_>>();
    let source_count = u32::try_from(source_files.len())
        .map_err(|_| CacheError::CorruptEntry("source file count exceeds u32".to_owned()))?;
    let source_bytes = source_files.iter().try_fold(0u64, |total, file| {
        total
            .checked_add(file.size)
            .ok_or_else(|| CacheError::CorruptEntry("source byte count overflow".to_owned()))
    })?;
    let source_material_len = source_material_length(&source_files)?;
    let mut source_hasher = blake3::Hasher::new();
    source_hasher.update(SOURCE_TREE_DOMAIN);
    source_hasher.update(&source_material_len.to_be_bytes());
    update_source_material(&mut source_hasher, &source_files);
    let source_digest = MusubiContentDigestV1::new(*source_hasher.finalize().as_bytes());
    if source_digest != node.source_digest {
        return Err(CacheError::CorruptEntry(
            "consumer node source digest does not match the cached tree".to_owned(),
        ));
    }
    let descriptor_bytes = read_regular_file_bounded(
        &root.join(DESCRIPTOR_PATH),
        MUSUBI_MAX_ARTIFACT_DESCRIPTOR_BYTES_V1,
    )?;
    let descriptor = decode_cached_artifact_descriptor_v1(&descriptor_bytes)?;
    if descriptor.source_tree_digest != source_digest
        || descriptor.source_file_count != source_count
        || descriptor.source_bytes != source_bytes
    {
        return Err(CacheError::CorruptEntry(
            "artifact descriptor does not match the cached source tree".to_owned(),
        ));
    }
    let release_bytes = read_regular_file_bounded(
        &root.join(RELEASE_PATH),
        MUSUBI_MAX_BUNDLE_METADATA_FILE_BYTES_V1,
    )?;
    let semantic_release = decode_cached_semantic_release_v1(&release_bytes)?;
    let lock_bytes = read_regular_file_bounded(
        &root.join(VERIFICATION_LOCK_PATH),
        MUSUBI_MAX_BUNDLE_METADATA_FILE_BYTES_V1,
    )?;
    let publication_lock = decode_cached_verification_lock_v1(&lock_bytes)?;
    let semantic_requirements = node
        .dependencies
        .iter()
        .map(|edge| {
            if edge.kind != MusubiDependencyKindV1::Normal {
                return Err(CacheError::CorruptEntry(
                    "cached registry node contains a development dependency".to_owned(),
                ));
            }
            Ok(MusubiDependencyReqV1 {
                alias: edge.alias.clone(),
                package: edge.package.clone(),
                requirement: edge.requirement.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let full_release = MusubiReleaseManifestV1 {
        release: semantic_release.release.clone(),
        edition: semantic_release.edition,
        abi: semantic_release.abi,
        dependencies: semantic_release.dependencies.clone(),
        exports: semantic_release.exports.clone(),
        interface_digest: semantic_release.interface_digest,
        metadata: semantic_release.metadata.clone(),
        archive_id: node.archive_id,
        verification_lock_digest: semantic_release.verification_lock_digest,
    };
    full_release
        .validate()
        .map_err(|error| CacheError::CorruptEntry(error.to_string()))?;
    if semantic_release.release != node.release
        || semantic_release.abi != node.abi
        || semantic_release.interface_digest != node.interface_digest
        || semantic_release.dependencies != semantic_requirements
        || semantic_release.verification_lock_digest != publication_lock.digest()
        || publication_lock.root != node.release
        || descriptor.semantic_release_manifest_digest != semantic_release.semantic_digest()
        || descriptor.verification_lock_digest != publication_lock.digest()
        || full_release.release_digest() != node.release_digest
    {
        return Err(CacheError::CorruptEntry(
            "cached bundle does not match the exact consumer release node".to_owned(),
        ));
    }
    Ok((semantic_release, publication_lock))
}
fn load_compiler_sources(
    root: &Path,
    files: &[FileInventory],
) -> Result<
    (
        String,
        Vec<CachedKotodamaSourceV1>,
        Vec<kotodama_lang::linker::SourceContractArtifact>,
    ),
    CacheError,
> {
    let manifest_entry = files
        .binary_search_by(|entry| entry.path.as_str().cmp("Musubi.toml"))
        .ok()
        .and_then(|index| files.get(index))
        .ok_or_else(|| CacheError::CorruptEntry("cached Musubi.toml is missing".to_owned()))?;
    let manifest_bytes = read_regular_file_bounded(
        &root.join("Musubi.toml"),
        manifest_entry.size.min(MAX_MANIFEST_BYTES),
    )?;
    if *blake3::hash(&manifest_bytes).as_bytes() != manifest_entry.digest {
        return Err(CacheError::CorruptEntry(
            "cached Musubi.toml changed after source authentication".to_owned(),
        ));
    }
    let manifest = String::from_utf8(manifest_bytes)
        .map_err(|_| CacheError::CorruptEntry("cached Musubi.toml is not UTF-8".to_owned()))?;
    let mut sources = Vec::new();
    let mut artifacts = Vec::new();
    let mut source_bytes = 0u64;
    for entry in files.iter().filter(|entry| {
        !entry.path.starts_with(".musubi/")
            && Path::new(&entry.path)
                .extension()
                .is_some_and(|extension| extension == "ko" || extension == "to")
    }) {
        source_bytes = source_bytes.checked_add(entry.size).ok_or_else(|| {
            CacheError::CorruptEntry("Kotodama source byte count overflow".to_owned())
        })?;
        if source_bytes > iroha_data_model::musubi::MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1 {
            return Err(CacheError::CorruptEntry(
                "Kotodama sources exceed the V1 payload bound".to_owned(),
            ));
        }
        let bytes = read_regular_file_bounded(&root.join(&entry.path), entry.size)?;
        if *blake3::hash(&bytes).as_bytes() != entry.digest {
            return Err(CacheError::CorruptEntry(format!(
                "cached Kotodama source `{}` changed after source authentication",
                entry.path
            )));
        }
        if Path::new(&entry.path)
            .extension()
            .is_some_and(|extension| extension == "to")
        {
            artifacts.push(kotodama_lang::linker::SourceContractArtifact {
                source_name: entry.path.clone(),
                artifact: bytes,
            });
            continue;
        }
        let source = String::from_utf8(bytes).map_err(|_| {
            CacheError::CorruptEntry(format!(
                "cached Kotodama source `{}` is not UTF-8",
                entry.path
            ))
        })?;
        sources.push(CachedKotodamaSourceV1 {
            path: entry.path.clone(),
            source,
        });
    }
    Ok((manifest, sources, artifacts))
}
fn compare_inventory(plan: &CarBuildPlan, files: &[FileInventory]) -> Result<(), CacheError> {
    if plan.files.len() != files.len() {
        return Err(CacheError::CorruptEntry(format!(
            "cache contains {} files; plan requires {}",
            files.len(),
            plan.files.len()
        )));
    }
    for (planned, actual) in plan.files.iter().zip(files) {
        let path = planned.path.join("/");
        if path != actual.path || planned.size != actual.size {
            return Err(CacheError::CorruptEntry(format!(
                "cache inventory differs at `{}`",
                actual.path
            )));
        }
    }
    Ok(())
}
fn verify_bundle_commitments(
    root: &Path,
    commitment: &MusubiArchiveCommitmentV1,
    files: &[FileInventory],
) -> Result<(), CacheError> {
    let by_path = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let release = by_path
        .get(RELEASE_PATH)
        .ok_or_else(|| CacheError::CorruptEntry("bundle release manifest is missing".to_owned()))?;
    let descriptor_file = by_path.get(DESCRIPTOR_PATH).ok_or_else(|| {
        CacheError::CorruptEntry("bundle artifact descriptor is missing".to_owned())
    })?;
    let verification_lock = by_path.get(VERIFICATION_LOCK_PATH).ok_or_else(|| {
        CacheError::CorruptEntry("bundle verification lock is missing".to_owned())
    })?;
    if descriptor_file.size > MUSUBI_MAX_ARTIFACT_DESCRIPTOR_BYTES_V1 {
        return Err(CacheError::CorruptEntry(
            "artifact descriptor exceeds its cache verification bound".to_owned(),
        ));
    }
    let descriptor_path = root.join(DESCRIPTOR_PATH);
    let descriptor_bytes =
        read_regular_file_bounded(&descriptor_path, MUSUBI_MAX_ARTIFACT_DESCRIPTOR_BYTES_V1)?;
    let descriptor = decode_cached_artifact_descriptor_v1(&descriptor_bytes)?;
    let source_files = files
        .iter()
        .filter(|file| !file.path.starts_with(".musubi/"))
        .collect::<Vec<_>>();
    let source_count = u32::try_from(source_files.len())
        .map_err(|_| CacheError::CorruptEntry("source file count exceeds u32".to_owned()))?;
    let source_bytes = source_files.iter().try_fold(0u64, |total, file| {
        total
            .checked_add(file.size)
            .ok_or_else(|| CacheError::CorruptEntry("source file byte count overflow".to_owned()))
    })?;
    if source_count != commitment.file_count
        || source_count != descriptor.source_file_count
        || source_bytes != descriptor.source_bytes
    {
        return Err(CacheError::CorruptEntry(
            "artifact descriptor source inventory mismatch".to_owned(),
        ));
    }
    let source_material_len = source_material_length(&source_files)?;
    let mut source_hasher = blake3::Hasher::new();
    source_hasher.update(SOURCE_TREE_DOMAIN);
    source_hasher.update(&source_material_len.to_be_bytes());
    update_source_material(&mut source_hasher, &source_files);
    let source_digest = *source_hasher.finalize().as_bytes();
    if commitment.source_tree_digest.as_bytes() != &source_digest
        || descriptor.source_tree_digest.as_bytes() != &source_digest
    {
        return Err(CacheError::CorruptEntry(
            "normalized source-tree digest mismatch".to_owned(),
        ));
    }
    let descriptor_material = framed_descriptor_material(&descriptor_bytes)?;
    let descriptor_digest = domain_digest_bytes(ARTIFACT_DESCRIPTOR_DOMAIN, &descriptor_material);
    if commitment.descriptor_digest.as_bytes() != &descriptor_digest {
        return Err(CacheError::CorruptEntry(
            "artifact descriptor digest mismatch".to_owned(),
        ));
    }
    if release.size > MUSUBI_MAX_BUNDLE_METADATA_FILE_BYTES_V1
        || verification_lock.size > MUSUBI_MAX_BUNDLE_METADATA_FILE_BYTES_V1
    {
        return Err(CacheError::CorruptEntry(
            "semantic release or verification lock exceeds its verification bound".to_owned(),
        ));
    }
    let release_path = root.join(RELEASE_PATH);
    let release_bytes =
        read_regular_file_bounded(&release_path, MUSUBI_MAX_BUNDLE_METADATA_FILE_BYTES_V1)?;
    let semantic_release = decode_cached_semantic_release_v1(&release_bytes)?;
    if descriptor.semantic_release_manifest_digest != semantic_release.semantic_digest() {
        return Err(CacheError::CorruptEntry(
            "semantic release-manifest digest mismatch".to_owned(),
        ));
    }
    let lock_path = root.join(VERIFICATION_LOCK_PATH);
    let lock_bytes =
        read_regular_file_bounded(&lock_path, MUSUBI_MAX_BUNDLE_METADATA_FILE_BYTES_V1)?;
    let lock = decode_cached_verification_lock_v1(&lock_bytes)?;
    if descriptor.verification_lock_digest != lock.digest()
        || semantic_release.verification_lock_digest != lock.digest()
        || semantic_release.release != lock.root
    {
        return Err(CacheError::CorruptEntry(
            "normalized verification-lock digest mismatch".to_owned(),
        ));
    }
    let bundle_material_len = frame_length(BUNDLE_DOMAIN.len() as u64)?
        .checked_add(frame_length(release.size)?)
        .and_then(|value| value.checked_add(frame_length(descriptor_material.len() as u64).ok()?))
        .and_then(|value| value.checked_add(frame_length(source_material_len).ok()?))
        .and_then(|value| value.checked_add(frame_length(verification_lock.size).ok()?))
        .ok_or_else(|| CacheError::CorruptEntry("bundle transcript length overflow".to_owned()))?;
    let mut bundle_hasher = blake3::Hasher::new();
    bundle_hasher.update(BUNDLE_DOMAIN);
    bundle_hasher.update(&bundle_material_len.to_be_bytes());
    update_frame_bytes(&mut bundle_hasher, BUNDLE_DOMAIN);
    bundle_hasher.update(&release.size.to_be_bytes());
    hash_file_into(&release_path, &mut bundle_hasher)?;
    update_frame_bytes(&mut bundle_hasher, &descriptor_material);
    bundle_hasher.update(&source_material_len.to_be_bytes());
    update_source_material(&mut bundle_hasher, &source_files);
    bundle_hasher.update(&verification_lock.size.to_be_bytes());
    hash_file_into(&lock_path, &mut bundle_hasher)?;
    let bundle_digest = *bundle_hasher.finalize().as_bytes();
    if commitment.bundle_digest.as_bytes() != &bundle_digest {
        return Err(CacheError::CorruptEntry(
            "canonical bundle digest mismatch".to_owned(),
        ));
    }
    Ok(())
}
fn source_material_length(files: &[&FileInventory]) -> Result<u64, CacheError> {
    files.iter().try_fold(
        frame_length(SOURCE_TREE_DOMAIN.len() as u64)? + 4,
        |total, file| {
            total
                .checked_add(frame_length(file.path.len() as u64)?)
                .and_then(|value| value.checked_add(8 + 32))
                .ok_or_else(|| {
                    CacheError::CorruptEntry("source transcript length overflow".to_owned())
                })
        },
    )
}
fn update_source_material(hasher: &mut blake3::Hasher, files: &[&FileInventory]) {
    update_frame_bytes(hasher, SOURCE_TREE_DOMAIN);
    hasher.update(
        &u32::try_from(files.len())
            .expect("validated Musubi V1 source file count fits u32")
            .to_be_bytes(),
    );
    for file in files {
        update_frame_bytes(hasher, file.path.as_bytes());
        hasher.update(&file.size.to_be_bytes());
        hasher.update(&file.digest);
    }
}
fn framed_descriptor_material(bytes: &[u8]) -> Result<Vec<u8>, CacheError> {
    let capacity = usize::try_from(
        frame_length(ARTIFACT_DESCRIPTOR_DOMAIN.len() as u64)?
            .checked_add(frame_length(bytes.len() as u64)?)
            .ok_or_else(|| {
                CacheError::CorruptEntry("descriptor transcript length overflow".to_owned())
            })?,
    )
    .map_err(|_| CacheError::CorruptEntry("descriptor transcript exceeds host width".to_owned()))?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&(ARTIFACT_DESCRIPTOR_DOMAIN.len() as u64).to_be_bytes());
    output.extend_from_slice(ARTIFACT_DESCRIPTOR_DOMAIN);
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(output)
}
fn domain_digest_bytes(domain: &[u8], material: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(material.len() as u64).to_be_bytes());
    hasher.update(material);
    *hasher.finalize().as_bytes()
}
fn update_frame_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}
fn frame_length(length: u64) -> Result<u64, CacheError> {
    length
        .checked_add(8)
        .ok_or_else(|| CacheError::CorruptEntry("commitment frame length overflow".to_owned()))
}
fn hash_regular_file(path: &Path) -> Result<(u64, [u8; 32]), CacheError> {
    let mut hasher = blake3::Hasher::new();
    let size = hash_file_into(path, &mut hasher)?;
    Ok((size, *hasher.finalize().as_bytes()))
}
fn retained_file_identity(path: &Path) -> Result<iroha_fs::FileIdentity, CacheError> {
    iroha_fs::RetainedFile::open_regular(path)
        .and_then(|file| file.identity())
        .map_err(|source| io_error("identify exact cache file", path, source))
}
fn hash_file_into(path: &Path, hasher: &mut blake3::Hasher) -> Result<u64, CacheError> {
    let mut file = iroha_fs::RetainedFile::open_regular(path)
        .map_err(|source| io_error("retain cached source file", path, source))?;
    let length = file
        .file()
        .metadata()
        .map_err(|source| io_error("inspect retained source", path, source))?
        .len();
    if length > crate::package::MAX_CAR_BYTES {
        return Err(CacheError::CorruptEntry(
            "cache file exceeds package byte bound".to_owned(),
        ));
    }
    let mut total = 0u64;
    let mut buffer = vec![0; IO_BUFFER_BYTES];
    let mut reader = file.file_mut().take(length.saturating_add(1));
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|source| io_error("read cached source file", path, source))?;
        if count == 0 {
            break;
        }
        total += count as u64;
        hasher.update(&buffer[..count]);
    }
    file.revalidate()
        .map_err(|source| io_error("revalidate cached source file", path, source))?;
    if total != length {
        return Err(CacheError::CorruptEntry(
            "cache file changed while being read".to_owned(),
        ));
    }
    Ok(total)
}
fn read_regular_file_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, CacheError> {
    let maximum = usize::try_from(maximum)
        .map_err(|_| CacheError::CorruptEntry("file exceeds host width".to_owned()))?;
    iroha_fs::read_regular(path, maximum)
        .map(|bytes| bytes.to_vec())
        .map_err(|source| io_error("read bounded cached file", path, source))
}
fn open_new_regular_file(path: &Path) -> io::Result<iroha_fs::RetainedFile> {
    iroha_fs::RetainedFile::create_new_private(path)
}
fn create_staging_directory(
    parent: &Path,
) -> Result<(PathBuf, fs::Metadata, DirectoryPin), CacheError> {
    for _ in 0..TEMP_RETRIES {
        let path = allocate_candidate(parent, ".src", "partial");
        let authority = iroha_fs::OwnerDirectory::open(parent)
            .map_err(|source| io_error("retain staging parent", parent, source))?;
        match authority.create_child(path.file_name().expect("generated staging name")) {
            Ok(directory) => {
                let metadata = fs::symlink_metadata(directory.path())
                    .map_err(|source| io_error("inspect source staging tree", &path, source))?;
                let pin = DirectoryPin::from_authority(directory)?;
                authority
                    .sync()
                    .map_err(|source| io_error("sync archive cache directory", parent, source))?;
                return Ok((path, metadata, pin));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(io_error("create source staging tree", &path, source)),
        }
    }
    Err(CacheError::Io {
        operation: "allocate source staging tree",
        path: parent.to_path_buf(),
        source: io::Error::new(io::ErrorKind::AlreadyExists, "temporary name collision"),
    })
}
fn create_temporary_file(
    parent: &Path,
    prefix: &str,
) -> Result<(PathBuf, iroha_fs::RetainedFile, fs::Metadata), CacheError> {
    for _ in 0..TEMP_RETRIES {
        let path = allocate_candidate(parent, prefix, "partial");
        match open_new_regular_file(&path) {
            Ok(file) => {
                let metadata = file
                    .file()
                    .metadata()
                    .map_err(|source| io_error("inspect cache temporary", &path, source))?;
                sync_directory(parent)
                    .map_err(|source| io_error("sync cache temporary parent", parent, source))?;
                return Ok((path, file, metadata));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(io_error("create cache temporary", &path, source)),
        }
    }
    Err(CacheError::Io {
        operation: "allocate cache temporary",
        path: parent.to_path_buf(),
        source: io::Error::new(io::ErrorKind::AlreadyExists, "temporary name collision"),
    })
}
fn allocate_absent_path(parent: &Path, prefix: &str) -> Result<PathBuf, CacheError> {
    for _ in 0..TEMP_RETRIES {
        let candidate = allocate_candidate(parent, prefix, "entry");
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => {}
            Err(source) => {
                return Err(io_error(
                    "inspect cache quarantine destination",
                    &candidate,
                    source,
                ));
            }
        }
    }
    Err(CacheError::Io {
        operation: "allocate cache quarantine destination",
        path: parent.to_path_buf(),
        source: io::Error::new(io::ErrorKind::AlreadyExists, "temporary name collision"),
    })
}
fn allocate_candidate(parent: &Path, prefix: &str, suffix: &str) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        "{prefix}.{}.{sequence:016x}.{suffix}",
        std::process::id()
    ))
}
// TODO: Replace retained install residue with automatic cleanup only after the workspace exposes
// a safe handle-relative atomic compare-and-delete primitive. Neither pathname identity checks nor
// a retained handle followed by pathname unlink closes the same-UID substitution race.
struct RetainedInstallResidue {
    _staging_path: PathBuf,
    _payload_path: PathBuf,
}
impl RetainedInstallResidue {
    fn new(staging_path: PathBuf, payload_path: PathBuf) -> Self {
        Self {
            _staging_path: staging_path,
            _payload_path: payload_path,
        }
    }
}
fn destructive_cache_removal_unsupported(path: &Path) -> CacheError {
    CacheError::Io {
        operation: "remove cache tree",
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::Unsupported,
            "safe handle-relative atomic compare-and-delete is unavailable",
        ),
    }
}
struct ValidatedMutableTree {
    root: PathBuf,
    directories: Vec<DirectoryPin>,
    files: BTreeMap<PathBuf, iroha_fs::FileIdentity>,
}
impl ValidatedMutableTree {
    fn into_root_pin(mut self) -> Result<DirectoryPin, CacheError> {
        self.validate()?;
        let index = self
            .directories
            .iter()
            .position(|pin| pin.path == self.root)
            .ok_or_else(|| CacheError::UnsafeDescendant(self.root.clone()))?;
        Ok(self.directories.remove(index))
    }
    fn validate(&self) -> Result<(), CacheError> {
        for pin in &self.directories {
            pin.validate()?;
        }
        for (path, identity) in &self.files {
            let metadata = fs::symlink_metadata(path)
                .map_err(|source| io_error("revalidate cache mutation file", path, source))?;
            if metadata_is_link_or_reparse(&metadata)
                || !metadata.is_file()
                || retained_file_identity(path)? != *identity
            {
                return Err(CacheError::UnsafeDescendant(path.clone()));
            }
        }
        self.validate_exact_inventory()
    }
    fn validate_exact_inventory(&self) -> Result<(), CacheError> {
        let directory_paths = self
            .directories
            .iter()
            .map(|pin| pin.path.as_path())
            .collect::<BTreeSet<_>>();
        for pin in &self.directories {
            for entry in fs::read_dir(&pin.path).map_err(|source| {
                io_error("revalidate cache mutation directory", &pin.path, source)
            })? {
                let path = entry
                    .map_err(|source| {
                        io_error("revalidate cache mutation descendant", &pin.path, source)
                    })?
                    .path();
                if !directory_paths.contains(path.as_path()) && !self.files.contains_key(&path) {
                    return Err(CacheError::UnsafeDescendant(path));
                }
            }
        }
        Ok(())
    }
}
fn validate_mutable_tree(root: &Path) -> Result<ValidatedMutableTree, CacheError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| io_error("inspect cache mutation root", root, source))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(CacheError::UnsafeDescendant(root.to_path_buf()));
    }
    let mut tree = ValidatedMutableTree {
        root: root.to_path_buf(),
        directories: Vec::new(),
        files: BTreeMap::new(),
    };
    validate_mutable_directory(root, &mut tree)?;
    tree.validate()?;
    Ok(tree)
}
fn validate_mutable_directory(
    directory: &Path,
    tree: &mut ValidatedMutableTree,
) -> Result<(), CacheError> {
    tree.directories
        .push(DirectoryPin::capture_in_tree(directory, &tree.directories)?);
    for entry in fs::read_dir(directory)
        .map_err(|source| io_error("read cache mutation candidate", directory, source))?
    {
        let entry = entry
            .map_err(|source| io_error("read cache mutation descendant", directory, source))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect cache mutation descendant", &path, source))?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err(CacheError::UnsafeDescendant(path));
        }
        if metadata.is_dir() {
            validate_mutable_directory(&path, tree)?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            if !metadata_has_one_hard_link(&metadata) {
                return Err(CacheError::UnsafeDescendant(path));
            }
            let identity = retained_file_identity(&path)?;
            tree.files.insert(path, identity);
        } else {
            return Err(CacheError::UnsafeDescendant(path));
        }
    }
    Ok(())
}
fn make_tree_immutable_and_sync(root: &Path) -> Result<(), CacheError> {
    let mut directories = Vec::new();
    collect_directories(root, &mut directories)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in &directories {
        sync_directory(directory)
            .map_err(|source| io_error("sync immutable source directory", directory, source))?;
        #[cfg(unix)]
        fs::set_permissions(directory, fs::Permissions::from_mode(0o555))
            .map_err(|source| io_error("make source directory immutable", directory, source))?;
        sync_directory(directory)
            .map_err(|source| io_error("resync immutable source directory", directory, source))?;
    }
    Ok(())
}
fn sync_tree_directories(root: &Path) -> io::Result<()> {
    let mut directories = Vec::new();
    collect_directories_io(root, &mut directories)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        sync_directory(&directory)?;
    }
    Ok(())
}
fn collect_directories(root: &Path, output: &mut Vec<PathBuf>) -> Result<(), CacheError> {
    collect_directories_io(root, output)
        .map_err(|source| io_error("inventory source directories", root, source))
}
fn collect_directories_io(root: &Path, output: &mut Vec<PathBuf>) -> io::Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source directory is not a real directory",
        ));
    }
    output.push(root.to_path_buf());
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source tree contains a symlink",
            ));
        }
        if metadata.is_dir() {
            collect_directories_io(&path, output)?;
        } else if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source tree contains a special file",
            ));
        }
    }
    Ok(())
}
fn join_components(root: &Path, components: &[String]) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in components {
        path.push(component);
    }
    path
}
fn decode_archive_directory_name(name: &str) -> Option<ArchiveId> {
    if name.len() != 64
        || name
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(name, &mut bytes).ok()?;
    Some(ArchiveId::new(bytes))
}
fn sync_directory(path: &Path) -> io::Result<()> {
    iroha_fs::OwnerDirectory::open(path)?.sync()
}
#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}
fn rename_no_replace(
    source: &Path,
    destination: &Path,
    source_pin: DirectoryPin,
) -> io::Result<DirectoryPin> {
    if source_pin.path != source || source.parent() != destination.parent() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cache publication must retain the exact source and its parent",
        ));
    }
    source_pin
        .validate()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let expected = source_pin.identity;
    let published = source_pin.authority.rename_to_sibling(
        destination.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache publication has no filename",
            )
        })?,
        iroha_fs::PublishMode::CreateNew,
    )?;
    if published.identity()? != expected {
        return Err(io::Error::other("cache publication changed identity"));
    }
    DirectoryPin::from_authority(published).map_err(|error| io::Error::other(error.to_string()))
}
fn io_error(operation: &'static str, path: &Path, source: io::Error) -> CacheError {
    CacheError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::{PackageCar, PackageLayout, plan_package};
    use iroha_data_model::{
        musubi::{
            MUSUBI_REGISTRY_VERSION_V1, MusubiAbiBindingV1, MusubiContentDigestV1,
            MusubiKotodamaEditionV1, MusubiPackageIdV1, MusubiPackageScopeV1, MusubiReleaseIdV1,
            MusubiReleaseManifestV1, MusubiReleaseMetadataV1, MusubiSemanticReleaseManifestV1,
            MusubiVerificationLockV1, MusubiVerificationNodeV1,
        },
        sorafs::pin_registry::{ChunkerProfileHandle, ManifestRootCid},
    };
    use iroha_model_base::topology::DataSpaceId;
    use norito::codec::Encode as _;
    use std::{io::Cursor, path::Path};
    use tempfile::TempDir;
    struct Fixture {
        car: PackageCar,
        commitment: MusubiArchiveCommitmentV1,
        semantic: MusubiSemanticReleaseManifestV1,
    }
    #[test]
    fn platform_cache_root_derivation_requires_an_absolute_base() {
        let temporary = tempfile::tempdir().expect("absolute platform base");
        assert_eq!(
            derive_platform_cache_root(
                Some(temporary.path().to_owned()),
                &["cache", "iroha", "musubi"]
            )
            .expect("absolute platform cache base"),
            temporary.path().join("cache").join("iroha").join("musubi")
        );
        assert!(matches!(
            derive_platform_cache_root(Some(PathBuf::from("relative")), &["iroha", "musubi"]),
            Err(CacheError::UnsafeRoot(_))
        ));
    }
    #[test]
    fn platform_cache_root_never_falls_back_to_the_project_directory() {
        match platform_cache_root_v1() {
            Ok(root) => assert!(root.is_absolute()),
            Err(CacheError::UnsafeRoot(_)) => {}
            Err(error) => panic!("unexpected platform cache-root error: {error}"),
        }
    }
    fn fixture(temp: &TempDir, name: &str) -> Fixture {
        fixture_at(temp.path(), name)
    }
    fn fixture_at(root: &Path, name: &str) -> Fixture {
        let package_root = root.join(name);
        fs::create_dir_all(package_root.join("src")).expect("create fixture source tree");
        fs::write(
            package_root.join("src/lib.ko"),
            format!("fn {name}() {{}}\n"),
        )
        .expect("write fixture source");
        let mut layout = PackageLayout::new(&package_root);
        layout.set_library("src");
        let manifest =
            format!("manifest-version = 1\n\n[package]\nname = \"{name}\"\nversion = \"1.0.0\"\n");
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            name.parse().expect("fixture package name"),
        );
        let release = MusubiReleaseIdV1::new(package, "1.0.0".parse().expect("version"));
        let verification_lock = MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: release.clone(),
            root_dependencies: Vec::new(),
            nodes: Vec::new(),
        };
        let semantic = MusubiSemanticReleaseManifestV1 {
            release,
            edition: MusubiKotodamaEditionV1::V1,
            abi: MusubiAbiBindingV1::new([8; 32]).expect("ABI"),
            dependencies: Vec::new(),
            exports: Vec::new(),
            interface_digest: MusubiContentDigestV1::new([9; 32]),
            metadata: MusubiReleaseMetadataV1::default(),
            verification_lock_digest: verification_lock.digest(),
        };
        let car = plan_package(&layout, &manifest, &verification_lock)
            .expect("plan fixture")
            .into_car(&semantic, &verification_lock)
            .expect("encode fixture CAR");
        let descriptor = sorafs_car::chunker_registry::default_descriptor();
        let root_cid = ManifestRootCid::try_from(car.stats().root_cids[0].clone())
            .expect("canonical fixture root");
        let por_root =
            sorafs_car::compute_por_root(car.payload(), car.plan()).expect("fixture PoR root");
        let commitment = MusubiArchiveCommitmentV1 {
            root_cid,
            chunker: ChunkerProfileHandle {
                profile_id: descriptor.id.0,
                namespace: descriptor.namespace.to_owned(),
                name: descriptor.name.to_owned(),
                semver: descriptor.semver.to_owned(),
                multihash_code: descriptor.multihash_code,
            },
            chunk_plan_digest: MusubiContentDigestV1::new(compute_chunk_plan_digest_sha3(
                &car.plan().chunks,
            )),
            por_root: MusubiContentDigestV1::new(por_root),
            content_length: car.plan().content_length,
            car_digest: MusubiContentDigestV1::new(*car.stats().car_archive_digest.as_bytes()),
            car_size: car.stats().car_size,
            bundle_digest: car.commitments().bundle_digest(),
            source_tree_digest: car.commitments().source_tree_digest(),
            descriptor_digest: car.commitments().descriptor_digest(),
            file_count: u32::try_from(car.source_file_count()).expect("fixture file count fits"),
            chunk_count: u32::try_from(car.plan().chunks.len()).expect("fixture chunks fit"),
        };
        commitment.validate().expect("valid fixture commitment");
        Fixture {
            car,
            commitment,
            semantic,
        }
    }
    fn cache(temp: &TempDir) -> MusubiCache {
        MusubiCache::open(temp.path().join("user-cache")).expect("open fixture cache")
    }
    #[test]
    fn cache_metadata_decoders_use_fixed_payload_free_corruption_reasons() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "metadata-decode");
        let descriptor = *fixture.car.commitments().descriptor();
        let lock = MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: fixture.semantic.release.clone(),
            root_dependencies: Vec::new(),
            nodes: Vec::new(),
        };
        assert_eq!(
            decode_cached_artifact_descriptor_v1(&descriptor.encode())
                .expect("canonical descriptor"),
            descriptor
        );
        assert_eq!(
            decode_cached_semantic_release_v1(&fixture.semantic.encode())
                .expect("canonical semantic release"),
            fixture.semantic
        );
        assert_eq!(
            decode_cached_verification_lock_v1(&lock.encode())
                .expect("canonical verification lock"),
            lock
        );
        let mut trailing_semantic = fixture.semantic.encode();
        trailing_semantic.push(0);
        let error = decode_cached_semantic_release_v1(&trailing_semantic)
            .expect_err("trailing semantic bytes must fail");
        assert!(matches!(
            error,
            CacheError::CorruptEntry(ref reason)
                if reason == "semantic release bundle metadata is invalid or out of bounds"
        ));
        let error = decode_cached_verification_lock_v1(&[u8::MAX; 32])
            .expect_err("declared-length bomb must fail");
        assert!(matches!(
            error,
            CacheError::CorruptEntry(ref reason)
                if reason == "verification lock bundle metadata is invalid or out of bounds"
        ));
        let oversized_descriptor_bytes =
            usize::try_from(MUSUBI_MAX_ARTIFACT_DESCRIPTOR_BYTES_V1 + 1)
                .expect("V1 oversized artifact descriptor length fits usize");
        let oversized_descriptor = vec![0; oversized_descriptor_bytes].into_boxed_slice();
        let error = decode_cached_artifact_descriptor_v1(&oversized_descriptor)
            .expect_err("oversized descriptor must fail");
        assert!(matches!(
            error,
            CacheError::CorruptEntry(ref reason)
                if reason == "artifact descriptor bundle metadata is invalid or out of bounds"
        ));
    }
    fn launch_max_sf1_geometry_plan() -> CarBuildPlan {
        let profile = sorafs_car::chunker_registry::default_descriptor().profile;
        let content_length = iroha_data_model::musubi::MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1;
        let file_count = usize::try_from(iroha_data_model::musubi::MUSUBI_MAX_FILES_V1)
            .expect("V1 file count fits usize")
            .saturating_add(BUNDLE_METADATA_FILE_COUNT);
        let mut extra = usize::try_from(content_length)
            .expect("V1 payload length fits usize")
            .checked_sub(file_count)
            .expect("one byte per file fits launch payload");
        let mut chunks = Vec::new();
        let mut files = Vec::new();
        let mut offset = 0_u64;
        for file_index in 0..file_count {
            let first_chunk = chunks.len();
            let mut file_size = 1_u64;
            if file_index == 0 {
                let maximum = profile.max_size.min(extra);
                if maximum >= profile.min_size {
                    push_geometry_chunk(&mut chunks, &mut offset, maximum);
                    file_size += u64::try_from(maximum).expect("registered chunk length fits u64");
                    extra -= maximum;
                }
                while extra >= profile.min_size {
                    push_geometry_chunk(&mut chunks, &mut offset, profile.min_size);
                    file_size +=
                        u64::try_from(profile.min_size).expect("registered chunk length fits u64");
                    extra -= profile.min_size;
                }
                file_size += u64::try_from(extra).expect("registered chunk length fits u64");
                push_geometry_chunk(&mut chunks, &mut offset, extra.saturating_add(1));
                extra = 0;
            } else {
                push_geometry_chunk(&mut chunks, &mut offset, 1);
            }
            files.push(sorafs_car::FilePlan {
                path: vec![format!("file-{file_index:04}")],
                first_chunk,
                chunk_count: chunks.len() - first_chunk,
                size: file_size,
            });
        }
        assert_eq!(offset, content_length);
        CarBuildPlan {
            chunk_profile: profile,
            payload_digest: blake3::hash(b"launch-max-geometry-only"),
            content_length,
            chunks,
            files,
        }
    }
    fn push_geometry_chunk(
        chunks: &mut Vec<sorafs_car::CarChunk>,
        offset: &mut u64,
        length: usize,
    ) {
        chunks.push(sorafs_car::CarChunk {
            offset: *offset,
            length: u32::try_from(length).expect("SF1 chunk length fits u32"),
            digest: [0_u8; 32],
        });
        *offset += u64::try_from(length).expect("registered chunk length fits u64");
    }
    #[test]
    fn launch_max_sf1_geometry_fits_musubi_cache_accounting() {
        let plan = launch_max_sf1_geometry_plan();
        let validation = plan.validate().expect("valid launch-max SF1 geometry");
        let retained = retained_plan_heap_bytes(&plan).expect("checked retained plan geometry");
        assert_eq!(
            plan.content_length,
            iroha_data_model::musubi::MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1
        );
        assert!(
            retained <= MUSUBI_MAX_RETAINED_PLAN_HEAP_BYTES,
            "launch-max retained plan estimate {retained} exceeds {MUSUBI_MAX_RETAINED_PLAN_HEAP_BYTES}"
        );
        assert!(
            validation.estimated_ingest_heap_bytes() <= MUSUBI_CACHE_CHUNK_STORE_HEAP_LIMIT_BYTES,
            "launch-max chunk-store estimate {} exceeds {}",
            validation.estimated_ingest_heap_bytes(),
            MUSUBI_CACHE_CHUNK_STORE_HEAP_LIMIT_BYTES
        );
        validate_musubi_plan_memory(&plan).expect("launch-max geometry fits cache accounting");
    }
    #[test]
    fn musubi_cache_uses_its_fetch_specific_ingest_heap_ceiling() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "heap-ceiling");
        let plan = fixture.car.plan();
        let estimate = plan
            .validate()
            .expect("valid fixture plan")
            .estimated_ingest_heap_bytes();
        validate_musubi_plan_memory(plan).expect("fixture fits Musubi cache ceiling");
        assert!(estimate <= MUSUBI_CACHE_CHUNK_STORE_HEAP_LIMIT_BYTES);
        assert!(matches!(
            validate_musubi_ingest_memory(plan, estimate.saturating_sub(1)),
            Err(CacheError::InvalidPlan(_))
        ));
        assert_eq!(
            bounded_musubi_chunk_store(plan)
                .expect("bounded Musubi chunk store")
                .max_estimated_heap_bytes(),
            MUSUBI_CACHE_CHUNK_STORE_HEAP_LIMIT_BYTES
        );
    }
    #[test]
    fn overcapacity_plan_is_rejected_before_archive_bytes_are_read() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "retained-plan-ceiling");
        let mut plan = fixture.car.plan().clone();
        let item_size = std::mem::size_of::<sorafs_car::CarChunk>();
        let required_capacity = MUSUBI_MAX_RETAINED_PLAN_HEAP_BYTES
            .div_ceil(item_size)
            .saturating_add(1);
        plan.chunks
            .reserve_exact(required_capacity.saturating_sub(plan.chunks.len()));
        assert!(
            retained_plan_heap_bytes(&plan).expect("checked retained plan geometry")
                > MUSUBI_MAX_RETAINED_PLAN_HEAP_BYTES
        );
        let error = cache(&temp)
            .install(&fixture.commitment, &plan, Cursor::new(Vec::<u8>::new()))
            .expect_err("overcapacity plan must fail before the empty reader is consumed");
        assert!(matches!(
            error,
            CacheError::InvalidPlan(reason) if reason.contains("retained CAR plan requires")
        ));
    }
    #[test]
    fn installs_under_archive_id_and_is_idempotent() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "alpha");
        let cache = cache(&temp);
        let archive_id = fixture.commitment.archive_id();
        let expected = cache
            .root()
            .join(REGISTRY_DIRECTORY)
            .join(hex::encode(archive_id.as_bytes()))
            .join(SOURCE_DIRECTORY);
        let outcome = cache
            .install(
                &fixture.commitment,
                fixture.car.plan(),
                Cursor::new(fixture.car.bytes()),
            )
            .expect("install archive");
        assert_eq!(
            outcome,
            InstallOutcome::Installed(CacheEntry {
                archive_id,
                source_path: expected.clone(),
            })
        );
        assert_eq!(
            fs::read_to_string(expected.join("src/lib.ko")).expect("read cached source"),
            "fn alpha() {}\n"
        );
        assert_eq!(
            cache
                .install(
                    &fixture.commitment,
                    fixture.car.plan(),
                    Cursor::new(fixture.car.bytes()),
                )
                .expect("idempotent install"),
            InstallOutcome::AlreadyPresent(CacheEntry {
                archive_id,
                source_path: expected,
            })
        );
    }
    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess-only abrupt cache-install worker"]
    fn cache_install_crash_child() {
        let Some(root) = std::env::var_os(CACHE_INSTALL_CRASH_ROOT_ENV_V1) else {
            return;
        };
        let root = PathBuf::from(root);
        let fixture = fixture_at(&root, "crashmatrix");
        let cache = MusubiCache::open(root.join("user-cache")).expect("open child cache");
        let outcome = cache.install(
            &fixture.commitment,
            fixture.car.plan(),
            Cursor::new(fixture.car.bytes()),
        );
        panic!("configured abrupt cache-install cut was not reached: {outcome:?}");
    }
    #[cfg(unix)]
    #[test]
    fn abrupt_install_cuts_never_publish_a_partial_tree_and_retry_converges() {
        let executable = std::env::current_exe().expect("current unit-test executable");
        for cut in CacheInstallCrashCutV1::ALL {
            let temp = tempfile::tempdir().expect("crash-matrix tempdir");
            let fixture = fixture(&temp, "crashmatrix");
            let output = std::process::Command::new(&executable)
                .arg("--ignored")
                .arg("--exact")
                .arg("cache::tests::cache_install_crash_child")
                .env(CACHE_INSTALL_CRASH_ROOT_ENV_V1, temp.path())
                .env(CACHE_INSTALL_CRASH_CUT_ENV_V1, cut.label())
                .output()
                .expect("launch abrupt cache-install worker");
            assert_eq!(
                output.status.code(),
                Some(CACHE_INSTALL_CRASH_EXIT_CODE_V1),
                "cut {cut:?} did not stop at its exact boundary; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            let cache = cache(&temp);
            let source = cache.source_path(&fixture.commitment.archive_id());
            match fs::symlink_metadata(&source) {
                Ok(_) => {
                    cache
                        .verify(&fixture.commitment, fixture.car.plan())
                        .unwrap_or_else(|error| {
                            panic!("cut {cut:?} exposed a partial source tree: {error}")
                        });
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => panic!("cut {cut:?} left an unreadable source boundary: {error}"),
            }
            let retry = cache
                .install(
                    &fixture.commitment,
                    fixture.car.plan(),
                    Cursor::new(fixture.car.bytes()),
                )
                .unwrap_or_else(|error| panic!("cut {cut:?} did not converge on retry: {error}"));
            assert!(matches!(
                retry,
                InstallOutcome::Installed(_) | InstallOutcome::AlreadyPresent(_)
            ));
            cache
                .verify(&fixture.commitment, fixture.car.plan())
                .unwrap_or_else(|error| {
                    panic!("cut {cut:?} retry did not publish the exact tree: {error}")
                });
        }
    }
    #[test]
    fn compiler_load_reauthenticates_consumer_node_and_rejects_tampering() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "compiler-cache");
        let cache = cache(&temp);
        cache
            .install(
                &fixture.commitment,
                fixture.car.plan(),
                Cursor::new(fixture.car.bytes()),
            )
            .expect("install compiler fixture");
        let release = MusubiReleaseManifestV1 {
            release: fixture.semantic.release.clone(),
            edition: fixture.semantic.edition,
            abi: fixture.semantic.abi,
            dependencies: fixture.semantic.dependencies.clone(),
            exports: fixture.semantic.exports.clone(),
            interface_digest: fixture.semantic.interface_digest,
            metadata: fixture.semantic.metadata.clone(),
            archive_id: fixture.commitment.archive_id(),
            verification_lock_digest: fixture.semantic.verification_lock_digest,
        };
        let node = MusubiVerificationNodeV1 {
            release: fixture.semantic.release.clone(),
            release_digest: release.release_digest(),
            archive_id: fixture.commitment.archive_id(),
            source_digest: fixture.commitment.source_tree_digest,
            interface_digest: fixture.semantic.interface_digest,
            abi: fixture.semantic.abi,
            dependencies: Vec::new(),
        };
        let loaded = cache
            .load_compiler_package(&node)
            .expect("load authenticated compiler package");
        assert_eq!(loaded.semantic_release, fixture.semantic);
        assert_eq!(loaded.publication_lock.root, node.release);
        assert_eq!(loaded.source_path, cache.source_path(&node.archive_id));
        assert!(loaded.manifest.starts_with("manifest-version = 1"));
        assert_eq!(loaded.kotodama_sources.len(), 1);
        assert_eq!(loaded.kotodama_sources[0].path, "src/lib.ko");
        let source = loaded.source_path.join("src/lib.ko");
        make_writable(&source);
        fs::write(&source, b"fn substituted() {}\n").expect("tamper compiler source");
        let error = cache
            .load_compiler_package(&node)
            .expect_err("tampered source digest must fail closed");
        assert!(matches!(error, CacheError::CorruptEntry(_)));
    }
    #[test]
    fn rejects_corrupt_car_without_publishing_source() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "bravo");
        let cache = cache(&temp);
        let mut bytes = fixture.car.bytes().to_vec();
        let last = bytes.last_mut().expect("nonempty CAR");
        *last ^= 0x80;
        let error = cache
            .install(&fixture.commitment, fixture.car.plan(), Cursor::new(bytes))
            .expect_err("corrupt archive must fail");
        assert!(matches!(error, CacheError::InvalidArchive(_)));
        assert!(!cache.source_path(&fixture.commitment.archive_id()).exists());
    }
    #[test]
    fn rejects_plan_traversal_before_reading_archive() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "charlie");
        let cache = cache(&temp);
        let mut plan = fixture.car.plan().clone();
        plan.files[0].path = vec!["..".to_owned(), "escape".to_owned()];
        let error = cache
            .install(&fixture.commitment, &plan, Cursor::new(Vec::<u8>::new()))
            .expect_err("traversing plan must fail before extraction");
        assert!(matches!(error, CacheError::InvalidPlan(_)));
        assert!(!cache.root().join("escape").exists());
    }
    #[test]
    fn repair_quarantines_only_structurally_safe_corruption() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "delta");
        let cache = cache(&temp);
        cache
            .install(
                &fixture.commitment,
                fixture.car.plan(),
                Cursor::new(fixture.car.bytes()),
            )
            .expect("install fixture");
        let source = cache.source_path(&fixture.commitment.archive_id());
        let target = source.join("src/lib.ko");
        make_writable(&target);
        fs::write(&target, b"corrupt").expect("corrupt cached source");
        let RepairOutcome::Quarantined { path } = cache
            .repair(&fixture.commitment, fixture.car.plan())
            .expect("quarantine safe corruption")
        else {
            panic!("corrupt entry should be quarantined");
        };
        assert!(!source.exists());
        assert!(path.exists());
    }
    #[test]
    fn repair_rejects_an_invalid_plan_without_quarantining_a_healthy_entry() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "repair-invalid-plan");
        let cache = cache(&temp);
        cache
            .install(
                &fixture.commitment,
                fixture.car.plan(),
                Cursor::new(fixture.car.bytes()),
            )
            .expect("install fixture");
        let source = cache.source_path(&fixture.commitment.archive_id());
        let mut invalid_plan = fixture.car.plan().clone();
        invalid_plan.files[0].path = vec!["..".to_owned(), "substitute".to_owned()];
        let error = cache
            .repair(&fixture.commitment, &invalid_plan)
            .expect_err("invalid plan must fail before cache mutation");
        assert!(matches!(error, CacheError::InvalidPlan(_)));
        assert!(source.exists(), "healthy cache entry must remain published");
        cache
            .verify(&fixture.commitment, fixture.car.plan())
            .expect("healthy cache entry remains verifiable");
    }
    #[cfg(unix)]
    #[test]
    fn repair_refuses_symlink_descendant() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "echo");
        let cache = cache(&temp);
        cache
            .install(
                &fixture.commitment,
                fixture.car.plan(),
                Cursor::new(fixture.car.bytes()),
            )
            .expect("install fixture");
        let source = cache.source_path(&fixture.commitment.archive_id());
        let source_dir = source.join("src");
        make_writable(&source_dir);
        let target = source_dir.join("lib.ko");
        fs::remove_file(&target).expect("remove cached target");
        symlink(temp.path().join("outside"), &target).expect("create hostile symlink");
        let error = cache
            .repair(&fixture.commitment, fixture.car.plan())
            .expect_err("unsafe descendant must remain untouched");
        assert!(matches!(error, CacheError::UnsafeDescendant(path) if path == target));
        assert!(source.exists());
    }
    #[test]
    fn prune_exact_fails_before_isolating_a_real_candidate() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cache = cache(&temp);
        let archive_id = ArchiveId::new([0x31; 32]);
        let archive = cache.archive_directory(&archive_id);
        fs::create_dir(&archive).expect("create archive candidate");
        let sentinel = archive.join("sentinel");
        fs::write(&sentinel, b"retained candidate").expect("write candidate sentinel");
        let error = cache
            .prune_exact(&BTreeSet::from([archive_id]))
            .expect_err("destructive prune must fail closed");
        assert!(matches!(
            error,
            CacheError::Io { source, .. } if source.kind() == io::ErrorKind::Unsupported
        ));
        assert_eq!(
            fs::read(&sentinel).expect("read retained candidate"),
            b"retained candidate"
        );
        assert!(
            fs::read_dir(&cache.registry_root)
                .expect("read registry root")
                .all(|entry| !entry
                    .expect("read registry entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".prune."))
        );
    }
    #[cfg(unix)]
    #[test]
    fn prune_exact_does_not_touch_a_symlink_substitution_or_outside_sentinel() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().expect("tempdir");
        let cache = cache(&temp);
        let archive_id = ArchiveId::new([0x32; 32]);
        let archive = cache.archive_directory(&archive_id);
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).expect("create outside directory");
        let sentinel = outside.join("sentinel");
        fs::write(&sentinel, b"outside sentinel").expect("write outside sentinel");
        let outside_mode = fs::metadata(&outside)
            .expect("outside metadata")
            .permissions()
            .mode()
            & 0o777;
        symlink(&outside, &archive).expect("substitute archive symlink");
        let error = cache
            .prune_exact(&BTreeSet::from([archive_id]))
            .expect_err("destructive prune must fail before inspecting the candidate");
        assert!(matches!(
            error,
            CacheError::Io { source, .. } if source.kind() == io::ErrorKind::Unsupported
        ));
        assert!(
            fs::symlink_metadata(&archive)
                .expect("archive symlink remains")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(&sentinel).expect("read outside sentinel"),
            b"outside sentinel"
        );
        assert_eq!(
            fs::metadata(&outside)
                .expect("outside metadata")
                .permissions()
                .mode()
                & 0o777,
            outside_mode
        );
    }
    #[test]
    fn failed_install_retains_private_staging_and_payload_residue() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "retained-failure-residue");
        let cache = cache(&temp);
        let mut bytes = fixture.car.bytes().to_vec();
        *bytes.last_mut().expect("nonempty CAR") ^= 0x80;
        let error = cache
            .install(&fixture.commitment, fixture.car.plan(), Cursor::new(bytes))
            .expect_err("corrupt archive must fail");
        assert!(matches!(error, CacheError::InvalidArchive(_)));
        let archive = cache.archive_directory(&fixture.commitment.archive_id());
        let (staging, payloads) = install_residue_paths(&archive);
        assert_eq!(staging.len(), 1);
        assert_eq!(payloads.len(), 1);
        assert!(
            fs::symlink_metadata(&staging[0])
                .expect("staging residue")
                .is_dir()
        );
        assert!(
            fs::symlink_metadata(&payloads[0])
                .expect("payload residue")
                .is_file()
        );
        assert!(!cache.source_path(&fixture.commitment.archive_id()).exists());
    }
    #[test]
    fn successful_install_retains_verified_payload_residue() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&temp, "retained-success-residue");
        let cache = cache(&temp);
        cache
            .install(
                &fixture.commitment,
                fixture.car.plan(),
                Cursor::new(fixture.car.bytes()),
            )
            .expect("install fixture");
        let archive = cache.archive_directory(&fixture.commitment.archive_id());
        let (staging, payloads) = install_residue_paths(&archive);
        assert!(staging.is_empty(), "published staging tree moved to `src`");
        assert_eq!(payloads.len(), 1);
        assert!(
            fs::symlink_metadata(&payloads[0])
                .expect("verified payload residue")
                .is_file()
        );
        cache
            .verify(&fixture.commitment, fixture.car.plan())
            .expect("published tree remains exact");
    }
    #[cfg(unix)]
    #[test]
    fn dropping_retained_install_residue_never_touches_substitutions() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().expect("tempdir");
        let staging = temp.path().join("staging");
        let payload = temp.path().join("payload");
        fs::create_dir(&staging).expect("create staging residue");
        fs::write(&payload, b"verified payload").expect("create payload residue");
        let residue = RetainedInstallResidue::new(staging.clone(), payload.clone());
        let displaced_staging = temp.path().join("displaced-staging");
        let displaced_payload = temp.path().join("displaced-payload");
        fs::rename(&staging, &displaced_staging).expect("displace staging residue");
        fs::rename(&payload, &displaced_payload).expect("displace payload residue");
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).expect("create outside directory");
        let sentinel = outside.join("sentinel");
        fs::write(&sentinel, b"outside sentinel").expect("write outside sentinel");
        let outside_mode = fs::metadata(&outside)
            .expect("outside metadata")
            .permissions()
            .mode()
            & 0o777;
        symlink(&outside, &staging).expect("substitute staging symlink");
        symlink(&sentinel, &payload).expect("substitute payload symlink");
        drop(residue);
        assert!(displaced_staging.is_dir());
        assert_eq!(
            fs::read(&displaced_payload).expect("read displaced payload"),
            b"verified payload"
        );
        assert!(
            fs::symlink_metadata(&staging)
                .expect("staging substitution remains")
                .file_type()
                .is_symlink()
        );
        assert!(
            fs::symlink_metadata(&payload)
                .expect("payload substitution remains")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(&sentinel).expect("read outside sentinel"),
            b"outside sentinel"
        );
        assert_eq!(
            fs::metadata(&outside)
                .expect("outside metadata")
                .permissions()
                .mode()
                & 0o777,
            outside_mode
        );
    }
    fn install_residue_paths(archive: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let mut staging = Vec::new();
        let mut payloads = Vec::new();
        for entry in fs::read_dir(archive).expect("read archive residue") {
            let entry = entry.expect("read archive residue entry");
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".src.") && name.ends_with(".partial") {
                staging.push(entry.path());
            } else if name.starts_with(".payload.") && name.ends_with(".partial") {
                payloads.push(entry.path());
            }
        }
        staging.sort();
        payloads.sort();
        (staging, payloads)
    }
    fn make_writable(path: &Path) {
        #[cfg(not(unix))]
        let _ = path;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("make fixture writable");
    }
    #[test]
    fn portable_cache_component_policy_rejects_windows_aliases_and_collisions() {
        for rejected in ["CON", "con.txt", "LPT9.log", "name.", "name ", "a:b"] {
            assert!(
                validate_portable_cache_component(rejected).is_err(),
                "`{rejected}` must be rejected"
            );
        }
        assert_eq!(
            portable_cache_component_key("Source.KO"),
            portable_cache_component_key("source.ko")
        );
        assert!(validate_portable_cache_component("e\u{301}.ko").is_err());
        assert!(validate_portable_cache_component("\u{202e}source.ko").is_err());
        assert!(validate_portable_cache_component("source.ko").is_ok());
    }
}
#[cfg(all(test, not(any(unix, windows))))]
mod unsupported_platform_tests {
    use super::{CacheError, MusubiCache};
    #[test]
    fn cache_open_fails_before_inspecting_or_creating_the_requested_root() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let requested = parent.path().join("must-remain-absent");
        let error = MusubiCache::open(&requested).expect_err("non-Unix cache access must fail");
        assert!(matches!(error, CacheError::UnsupportedPlatform));
        assert!(!requested.exists());
    }
}
