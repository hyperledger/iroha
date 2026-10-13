//! Minimal ZK attachments store for the app-facing API.
//!
//! Feature-gated behind `app_api`:
//! - Stores attachments (proof envelopes or JSON DTOs) under `./storage/torii/zk_attachments/`.
//!   Base directory is configured via `torii.data_dir`; tests may use `data_dir::OverrideGuard`.
//!   The configured directory must be exclusively writable by the Torii process owner.
//! - Deterministic id: Blake2b-32 of the sanitized request bytes (lowercase hex).
//! - Multi-tenant: attachments are isolated per signed Iroha account. API tokens, when enabled,
//!   are an additional access-control requirement but do not define tenant identity.
//! - Endpoints:
//!   - POST `/v1/zk/attachments` – store attachment, returns metadata `{ id, size, content_type, created_ms }`.
//!   - GET  `/v1/zk/attachments` – list metadata for stored attachments.
//!   - GET  `/v1/zk/attachments/{id}` – fetch stored attachment bytes by id.
//!   - DELETE `/v1/zk/attachments/{id}` – delete stored attachment and its metadata.
//! - A background GC task periodically deletes entries older than a TTL;
//!   TTL and size caps are provided via `iroha_config` (Torii).
//! - The prover keeps a versioned, content-ID processing receipt separately
//!   from evictable reports. Per-tenant live-reference shards retain that
//!   receipt only while at least one matching attachment remains stored.
use crate::{
    NoritoQuery, routing::MaybeTelemetry, utils::NORITO_MIME_TYPE,
    zk1::parse_tags as parse_zk1_tags,
};
use axum::{extract::Path as AxumPath, http::StatusCode, response::IntoResponse};
use flate2::read::GzDecoder;
use iroha_config::parameters::actual::AttachmentSanitizerMode;
use iroha_data_model::{account::AccountId, proof::PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1};
use iroha_futures::supervisor::ShutdownSignal;
use iroha_logger::prelude::*;
use norito::json;
use parking_lot::{Mutex as SyncMutex, RwLock};
use sha2::{Digest as _, Sha256};
#[cfg(test)]
use std::sync::Arc;
use std::{
    collections::BTreeSet,
    env,
    ffi::OsStr,
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use zstd::stream::read::Decoder as ZstdDecoder;

mod sanitizer;

#[cfg(test)]
use crate::zk1::MAX_TLV_COUNT as ZK1_MAX_TLV_COUNT;
#[cfg(test)]
use sanitizer::decode_sanitizer_response_bytes;
#[cfg(test)]
use sanitizer::read_limited;
#[cfg(test)]
use sanitizer::read_sanitizer_stdout_limited;
#[cfg(test)]
use sanitizer::sandboxed_sanitizer_command_for_search_path;
#[cfg(test)]
use sanitizer::sanitizer_executable_with_override;
#[cfg(test)]
use sanitizer::set_clean_sanitizer_environment;
#[cfg(test)]
use sanitizer::spawn_sanitizer_stdout_reader;
#[cfg(test)]
use sanitizer::validate_sanitizer_executable;
use sanitizer::{normalize_mime, sanitize_attachment, sanitize_attachment_sync};
pub(crate) use sanitizer::{
    validate_attachment_body_contract, validate_attachment_metadata_contract,
};

const MAX_ATTACHMENT_BYTES_FALLBACK: usize = 4 * 1024 * 1024; // fallback 4 MiB
const ATTACHMENT_TTL_SECS_FALLBACK: u64 = 7 * 24 * 60 * 60; // fallback 7 days
const GC_INTERVAL_SECS: u64 = 60; // run every minute
/// Lowercase hex length of an attachment or report identifier.
pub(crate) const ATTACHMENT_ID_HEX_LEN: usize = 64;
/// Lowercase hex length of a tenant key.
pub(crate) const TENANT_KEY_HEX_LEN: usize = 64;
const ZK1_MIME_TYPE: &str = "application/x-zk1";
const OCTET_STREAM_MIME_TYPE: &str = "application/octet-stream";
const JSON_MIME_TYPE: &str = "application/json";
const ATTACHMENT_SANITIZER_ENV: &str = "IROHA_ATTACHMENT_SANITIZER";
const ATTACHMENT_SANITIZER_MAX_INPUT_ENV: &str = "IROHA_ATTACHMENT_SANITIZER_MAX_INPUT_BYTES";
const ATTACHMENT_SANITIZER_SANDBOXED_ENV: &str = "IROHA_ATTACHMENT_SANITIZER_OS_SANDBOXED";
const ATTACHMENT_SANITIZER_BINARY_STEM: &str = "attachment_sanitizer";
const SANITIZER_POLL_INTERVAL_MS: u64 = 5;
const SANITIZER_RESPONSE_OVERHEAD_BYTES: usize = 64 * 1024;
const ATTACHMENT_META_SCAN_MAX_FILES: u64 =
    iroha_config::parameters::defaults::torii::ATTACHMENTS_GLOBAL_MAX_COUNT_MAX;
const ATTACHMENT_TENANT_SCAN_MAX_ENTRIES: u64 = ATTACHMENT_META_SCAN_MAX_FILES * 2;
const ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES: u64 = ATTACHMENT_META_SCAN_MAX_FILES + 1_024;
const ATTACHMENT_CHILD_RECOVERY_MAX_ENTRIES: u64 = ATTACHMENT_TENANT_SCAN_MAX_ENTRIES + 1_024;
const ATTACHMENT_TRANSACTION_RECOVERY_MAX_ENTRIES: u64 = 1_024;
const PROVER_PROCESSING_RECOVERY_MAX_ENTRIES: u64 = ATTACHMENT_META_SCAN_MAX_FILES * 4 + 1_024;
const ATTACHMENT_QUOTA_TRANSACTION_VERSION: u16 = 1;
const ATTACHMENT_DELETE_TRANSACTION_VERSION: u16 = 1;
const ATTACHMENT_MUTATION_TRANSACTION_MAX_BYTES: u64 = 2 * 1024 * 1024;
const ATTACHMENT_MUTATION_TRANSACTION_DIR: &str = "zk_attachment_mutation";
const ATTACHMENT_MUTATION_TRANSACTION_FILE: &str = "pending_v1.json";
const ATTACHMENT_MUTATION_TRANSACTION_TEMP_PREFIX: &str = ".tmp";
pub(super) const ZK_PROVER_PROCESSING_STATE_VERSION: u16 = 1;
const ZK_PROVER_PROCESSING_REFERENCE_MARKER: &[u8] = b"iroha-torii-zk-prover-live-reference-v1\n";
const ZK_PROVER_PROCESSING_RECEIPT_MAX_BYTES: u64 = 16 * 1024;
const ZK_PROVER_PROCESSING_TEMP_PREFIX: &str = ".tmp";
static ZK_PROVER_PROCESSING_STATE_LOCK: OnceLock<SyncMutex<()>> = OnceLock::new();
static ATTACHMENT_ENTRY_PAIRS_DIRTY: AtomicBool = AtomicBool::new(false);
static ATTACHMENT_MUTATION_DIRECTORY_DIRTY: AtomicBool = AtomicBool::new(true);
static ATTACHMENT_STORE_GATE: OnceLock<RwLock<()>> = OnceLock::new();
/// Maximum encoded size of one persisted attachment metadata record.
pub(super) const ATTACHMENT_META_FILE_MAX_BYTES: u64 = 64 * 1024;
/// Tenant namespace for the attachments store.
///
/// This is a stable, opaque identifier (64-hex) derived from a signed Iroha account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentTenant(String);
impl AttachmentTenant {
    /// Derive a tenant key from a signed account id.
    pub fn from_account(account: &AccountId) -> Self {
        Self(hash_identity_hex("account", &account.to_string()))
    }
    /// Tenant used when neither token nor remote address is available.
    pub fn anonymous() -> Self {
        Self(hash_identity_hex("anon", "anon"))
    }
    /// Return the stable tenant key (lowercase 64-hex).
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::zk_attachments::AttachmentHashes")]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
)]
/// Attachment digest metadata (hex-encoded).
pub struct AttachmentHashes {
    /// Blake2b-256 digest of the stored (sanitized) attachment bytes.
    pub blake2b_256: String,
    /// SHA-256 digest of the stored (sanitized) attachment bytes.
    pub sha256: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::zk_attachments::AttachmentSanitizerVerdict")]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
)]
/// Sanitizer outcome recorded for a stored attachment.
pub struct AttachmentSanitizerVerdict {
    /// Sanitizer verdict (e.g., "accepted").
    pub verdict: String,
    /// Expanded size in bytes after decompression (if any).
    pub expanded_bytes: u64,
    /// Archive depth encountered while expanding payloads.
    pub archive_depth: u32,
    /// Whether the sanitizer executed in an isolated subprocess.
    pub sandboxed: bool,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::zk_attachments::AttachmentProvenance")]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
)]
/// Provenance metadata recorded alongside an attachment.
pub struct AttachmentProvenance {
    /// Declared MIME type from the request header (normalized).
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub declared_type: Option<String>,
    /// Sniffed MIME type derived from magic bytes (normalized).
    pub sniffed_type: String,
    /// Attachment digests of stored bytes.
    pub hashes: AttachmentHashes,
    /// Sanitizer summary for the stored attachment.
    pub sanitizer: AttachmentSanitizerVerdict,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::zk_attachments::AttachmentMeta")]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
)]
/// Metadata for a stored attachment.
pub struct AttachmentMeta {
    /// Deterministic id (hex of Blake2b-32 over sanitized body bytes).
    pub id: String,
    /// Content type derived from sniffing (e.g., application/json).
    pub content_type: String,
    /// Size of the stored attachment bytes.
    pub size: u64,
    /// Unix time in milliseconds when the attachment was created.
    pub created_ms: u64,
    /// Hashed tenant identity used for quota enforcement.
    pub tenant: Option<String>,
    /// Provenance metadata for the stored attachment.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<AttachmentProvenance>,
    /// ZK1 TLV tags extracted at ingest time (when content is `application/x-zk1`).
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub zk1_tags: Option<Vec<String>>,
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
struct AttachmentQuotaTransaction {
    version: u16,
    tenant: String,
    incoming_meta: AttachmentMeta,
    previous_meta: Option<AttachmentMeta>,
    victim_ids: Vec<String>,
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
struct AttachmentDeleteTransaction {
    version: u16,
    tenant: String,
    id: String,
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
)]
#[norito(tag = "kind", content = "value", rename_all = "snake_case")]
#[norito(deny_unknown_fields)]
enum AttachmentMutationTransaction {
    Write(Box<AttachmentQuotaTransaction>),
    Delete(AttachmentDeleteTransaction),
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub(super) struct ProverProcessingReceipt {
    pub(super) version: u16,
    pub(super) id: String,
    pub(super) processed_ms: u64,
    pub(super) terminal: bool,
    #[norito(required)]
    pub(super) retry_not_before_ms: Option<u64>,
    pub(super) retry_count: u32,
    pub(super) completed_proof_indices: Vec<u16>,
    #[norito(required)]
    pub(super) processing_context_hash: Option<String>,
}
impl ProverProcessingReceipt {
    pub(super) fn disposition_is_valid(&self) -> bool {
        let completed_indices_valid = self.completed_proof_indices.len()
            <= PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1
            && self
                .completed_proof_indices
                .iter()
                .all(|index| usize::from(*index) < PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1)
            && self
                .completed_proof_indices
                .windows(2)
                .all(|pair| pair[0] < pair[1]);
        let context_hash_valid = self.processing_context_hash.as_deref().is_some_and(|hash| {
            hash.len() == ATTACHMENT_ID_HEX_LEN
                && hash
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        });
        let cache_valid = if self.completed_proof_indices.is_empty() {
            self.processing_context_hash.is_none()
        } else {
            context_hash_valid
        };
        if self.terminal {
            self.retry_not_before_ms.is_none()
                && self.retry_count == 0
                && self.completed_proof_indices.is_empty()
                && self.processing_context_hash.is_none()
        } else {
            self.retry_not_before_ms.is_some()
                && self.retry_count > 0
                && completed_indices_valid
                && cache_valid
        }
    }
    pub(super) fn reconcile_committed(durable: Option<Self>, committed: Self) -> Self {
        if committed.terminal {
            return committed;
        }
        let Some(durable) = durable else {
            return committed;
        };
        if durable.terminal {
            return durable;
        }
        let committed_is_newer = (committed.retry_count, committed.processed_ms)
            >= (durable.retry_count, durable.processed_ms);
        if durable.processing_context_hash != committed.processing_context_hash {
            return if committed_is_newer {
                committed
            } else {
                durable
            };
        }
        let (mut selected, other) = if committed_is_newer {
            (committed, durable)
        } else {
            (durable, committed)
        };
        selected
            .completed_proof_indices
            .extend(other.completed_proof_indices);
        selected.completed_proof_indices.sort_unstable();
        selected.completed_proof_indices.dedup();
        selected
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProverProcessingDecision {
    Missing,
    Suppress,
    Due { retry_count: u32 },
}
pub(crate) fn base_dir() -> PathBuf {
    crate::data_dir::base_dir()
}
fn attachments_root_dir() -> PathBuf {
    base_dir().join("zk_attachments")
}
fn attachments_dir(tenant: &AttachmentTenant) -> PathBuf {
    attachments_root_dir().join(tenant.as_str())
}
fn direct_directory_type_error(path: &Path) -> std::io::Error {
    invalid_attachment_file(format!(
        "persistence path is not a direct directory: {}",
        path.display()
    ))
}
fn map_direct_directory_open_error(path: &Path, error: std::io::Error) -> std::io::Error {
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return direct_directory_type_error(path);
    }
    error
}
pub(super) fn verify_direct_directory(path: &Path) -> std::io::Result<()> {
    let named_before = fs::symlink_metadata(path)?;
    if named_before.file_type().is_symlink() || !named_before.is_dir() {
        return Err(direct_directory_type_error(path));
    }
    let directory = open_pinned_direct_directory(path)
        .map_err(|error| map_direct_directory_open_error(path, error))?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("persistence directory is missing: {}", path.display()),
            )
        })?;
    let metadata = crate::secure_file_metadata::from_file(&directory)?;
    let named_after = crate::secure_file_metadata::from_path(path)
        .map_err(|error| map_direct_directory_open_error(path, error))?;
    if !crate::secure_file_metadata::is_direct_directory(&metadata)
        || !crate::secure_file_metadata::is_direct_directory(&named_after)
        || !crate::secure_file_metadata::same_file(&metadata, &named_after)
    {
        return Err(direct_directory_type_error(path));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
            return Err(invalid_attachment_file(format!(
                "persistence directory must be owned by the Torii process user and deny group/world writes: {}",
                path.display()
            )));
        }
    }
    sorafs_node::validate_private_local_storage_acl(&directory, path)?;
    Ok(())
}
pub(super) fn ensure_direct_directory(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            #[cfg(windows)]
            if let Err(error) = verify_direct_directory(path)
                && error.kind() == std::io::ErrorKind::PermissionDenied
            {
                protect_existing_windows_directory(path)?;
            }
            return verify_direct_directory(path);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;

        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    #[cfg(windows)]
    create_private_windows_directories(path)?;
    #[cfg(not(any(unix, windows)))]
    return Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure attachment directory creation is unsupported on this platform",
    ));
    verify_direct_directory(path)
}
#[cfg(windows)]
fn protect_existing_windows_directory(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    use crate::secure_file_metadata::{from_file, from_path, is_direct_directory, same_file};

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ_WRITE: u32 = 0x0000_0001 | 0x0000_0002;
    const GENERIC_READ: u32 = 0x8000_0000;
    const WRITE_DAC: u32 = 0x0004_0000;

    let before = from_path(path)?;
    if !is_direct_directory(&before) {
        return Err(direct_directory_type_error(path));
    }
    let directory = fs::OpenOptions::new()
        .access_mode(GENERIC_READ | WRITE_DAC)
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let opened = from_file(&directory)?;
    let named = from_path(path)?;
    if !is_direct_directory(&opened)
        || !is_direct_directory(&named)
        || !same_file(&before, &opened)
        || !same_file(&opened, &named)
    {
        return Err(invalid_attachment_file(
            "persistence directory changed before ACL protection",
        ));
    }
    sorafs_node::protect_private_local_storage_acl(&directory, path)?;
    let protected = from_file(&directory)?;
    let named_after = from_path(path)?;
    if !same_file(&opened, &protected) || !same_file(&protected, &named_after) {
        return Err(invalid_attachment_file(
            "persistence directory changed during ACL protection",
        ));
    }
    Ok(())
}
#[cfg(windows)]
fn create_private_windows_directories(path: &Path) -> std::io::Result<()> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows attachment persistence path must be absolute",
        ));
    }
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        match fs::symlink_metadata(current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(direct_directory_type_error(current));
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(current.to_path_buf());
                current = current.parent().ok_or_else(|| {
                    invalid_attachment_file("Windows persistence path has no existing ancestor")
                })?;
            }
            Err(error) => return Err(error),
        }
    }
    for directory in missing.into_iter().rev() {
        match sorafs_node::create_private_local_storage_directory(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        verify_direct_directory(&directory)?;
    }
    Ok(())
}
fn ensure_root_dir() -> std::io::Result<()> {
    let base = base_dir();
    ensure_direct_directory(&base)?;
    ensure_direct_directory(&base.join("zk_attachments"))
}
#[cfg(test)]
fn ensure_dirs(tenant: &AttachmentTenant) -> std::io::Result<()> {
    ensure_root_dir()?;
    ensure_direct_directory(&attachments_dir(tenant))
}
fn meta_path(tenant: &AttachmentTenant, id: &str) -> PathBuf {
    attachments_dir(tenant).join(format!("{}.json", id))
}
fn bin_path(tenant: &AttachmentTenant, id: &str) -> PathBuf {
    attachments_dir(tenant).join(format!("{}.bin", id))
}
fn attachment_mutation_transaction_dir() -> PathBuf {
    base_dir().join(ATTACHMENT_MUTATION_TRANSACTION_DIR)
}
fn attachment_mutation_transaction_path() -> PathBuf {
    attachment_mutation_transaction_dir().join(ATTACHMENT_MUTATION_TRANSACTION_FILE)
}
#[cfg(test)]
fn test_directory_sync_failure_path() -> &'static SyncMutex<Option<PathBuf>> {
    static PATH: OnceLock<SyncMutex<Option<PathBuf>>> = OnceLock::new();
    PATH.get_or_init(|| SyncMutex::new(None))
}
#[cfg(test)]
struct TestDirectorySyncFailureGuard;
#[cfg(test)]
impl Drop for TestDirectorySyncFailureGuard {
    fn drop(&mut self) {
        test_directory_sync_failure_path().lock().take();
    }
}
#[cfg(test)]
fn fail_next_directory_sync(path: &Path) -> TestDirectorySyncFailureGuard {
    let mut failure = test_directory_sync_failure_path().lock();
    assert!(failure.is_none(), "directory-sync failure already armed");
    *failure = Some(path.to_path_buf());
    TestDirectorySyncFailureGuard
}
#[cfg(test)]
fn maybe_fail_directory_sync(path: &Path) -> std::io::Result<()> {
    let mut failure = test_directory_sync_failure_path().lock();
    if failure.as_deref() == Some(path) {
        failure.take();
        return Err(std::io::Error::other(
            "injected attachment directory-sync failure",
        ));
    }
    Ok(())
}
fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    maybe_fail_directory_sync(path)?;
    crate::durable_fs::sync_direct_directory(path)
}
#[cfg(unix)]
pub(super) fn sync_open_directory(directory: &fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let mut failure = test_directory_sync_failure_path().lock();
        if let Some(path) = failure.as_deref()
            && let Ok(named) = fs::symlink_metadata(path)
        {
            let opened = directory.metadata()?;
            if named.is_dir()
                && opened.is_dir()
                && named.dev() == opened.dev()
                && named.ino() == opened.ino()
            {
                failure.take();
                return Err(std::io::Error::other(
                    "injected attachment directory-sync failure",
                ));
            }
        }
    }
    directory.sync_all()
}
fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_attachment_file("persisted path has no containing directory"))?;
    sync_directory(parent)
}
fn sync_nearest_existing_parent(path: &Path) -> std::io::Result<()> {
    let base = base_dir();
    let mut current = path
        .parent()
        .ok_or_else(|| invalid_attachment_file("persisted path has no containing directory"))?;
    if !current.starts_with(&base) {
        return Err(invalid_attachment_file(
            "persisted path is outside the configured Torii data directory",
        ));
    }
    loop {
        match verify_direct_directory(current) {
            Ok(()) => return sync_directory(current),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if current == base {
                    return Err(invalid_attachment_file(
                        "Torii data directory is missing during durability recovery",
                    ));
                }
                current = current.parent().ok_or_else(|| {
                    invalid_attachment_file("persisted path has no existing data-dir ancestor")
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}
/// Atomically publish bytes and durably flush the containing directory.
///
/// # Errors
///
/// Returns an error if the temporary file cannot be written and synced, the
/// rename cannot commit, or the containing directory cannot be flushed.
pub(super) fn persist_bytes_atomically(
    path: &Path,
    body: &[u8],
    prefix: &str,
) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_attachment_file("persisted path has no containing directory"))?;
    ensure_direct_directory(parent)?;
    #[cfg(unix)]
    {
        let mut temporary = tempfile::Builder::new()
            .prefix(prefix)
            .tempfile_in(parent)?;
        temporary.write_all(body)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|error| error.error)?;
        drop(open_attachment_regular_file(path)?);
        sync_directory(parent)
    }
    #[cfg(windows)]
    {
        return persist_bytes_atomically_windows(path, body, prefix, parent);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (body, prefix);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secure atomic attachment persistence is unsupported on this platform",
        ))
    }
}
#[cfg(windows)]
fn persist_bytes_atomically_windows(
    path: &Path,
    body: &[u8],
    prefix: &str,
    parent: &Path,
) -> std::io::Result<()> {
    use crate::secure_file_metadata::{
        from_file, from_path, is_direct_file, number_of_links, same_file, unchanged,
    };

    const RETRIES: usize = 32;
    const ALPHANUMERIC: &[u8; 62] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if prefix != ".tmp" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows attachment temporary prefix must be canonical",
        ));
    }
    let (mut temporary, temporary_path) = (0..RETRIES)
        .find_map(|_| {
            let random: [u8; 6] = rand::random();
            let suffix = random.map(|byte| ALPHANUMERIC[usize::from(byte) % ALPHANUMERIC.len()]);
            let suffix = std::str::from_utf8(&suffix).expect("temporary alphabet is ASCII");
            let temporary_path = parent.join(format!("{prefix}{suffix}"));
            match sorafs_node::create_private_local_storage_file(
                &temporary_path,
                sorafs_node::PrivateLocalFileSharing::ReadDelete,
            ) {
                Ok(file) => Some(Ok((file, temporary_path))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .transpose()?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "could not allocate a unique attachment temporary file",
            )
        })?;
    sorafs_node::validate_private_local_storage_acl(&temporary, &temporary_path)?;
    let created = from_file(&temporary)?;
    temporary.write_all(body)?;
    temporary.flush()?;
    temporary.sync_all()?;
    let written = from_file(&temporary)?;
    let named_written = from_path(&temporary_path)?;
    if !is_direct_file(&created)
        || !is_direct_file(&written)
        || !is_direct_file(&named_written)
        || number_of_links(&created) != Some(1)
        || number_of_links(&written) != Some(1)
        || number_of_links(&named_written) != Some(1)
        || !same_file(&created, &written)
        || !unchanged(&written, &named_written)
        || u64::try_from(body.len()).ok() != Some(written.len())
    {
        drop((created, written, named_written, temporary));
        let _ = remove_direct_regular_file_if_present(&temporary_path);
        return Err(invalid_attachment_file(
            "attachment temporary file changed during atomic persistence",
        ));
    }
    match open_attachment_regular_file(path) {
        Ok(existing) => drop(existing),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            drop((created, written, named_written, temporary));
            let _ = remove_direct_regular_file_if_present(&temporary_path);
            return Err(error);
        }
    }
    if let Err(error) = fs::rename(&temporary_path, path) {
        drop((created, written, named_written, temporary));
        let _ = remove_direct_regular_file_if_present(&temporary_path);
        return Err(error);
    }
    // The rename is the commit point; make its namespace mutation durable before any
    // postcondition can return an error.
    sync_directory(parent)?;
    let published = from_path(path)?;
    if !is_direct_file(&published)
        || number_of_links(&published) != Some(1)
        || !same_file(&written, &published)
    {
        return Err(invalid_attachment_file(
            "attachment destination changed during atomic publication",
        ));
    }
    drop((created, written, named_written, published, temporary));
    drop(open_attachment_regular_file(path)?);
    Ok(())
}
fn ensure_attachment_dirs_durable(tenant: &AttachmentTenant) -> std::io::Result<()> {
    let root = attachments_root_dir();
    ensure_direct_directory(&root)?;
    sync_directory(&base_dir())?;
    ensure_direct_directory(&attachments_dir(tenant))?;
    sync_directory(&root)
}
fn ensure_attachment_mutation_transaction_dir_durable() -> std::io::Result<()> {
    ensure_direct_directory(&attachment_mutation_transaction_dir())?;
    sync_directory(&base_dir())
}
fn prover_processing_state_dir() -> PathBuf {
    base_dir()
        .join("zk_prover")
        .join(format!("processing_{ZK_PROVER_PROCESSING_STATE_VERSION}"))
}
fn prover_processing_receipt_path(id: &str) -> PathBuf {
    prover_processing_state_dir().join(id).join("receipt.json")
}
fn prover_processing_reference_dir(id: &str) -> PathBuf {
    prover_processing_state_dir().join(id).join("live")
}
fn prover_processing_reference_path(tenant_key: &str, id: &str) -> PathBuf {
    prover_processing_reference_dir(id).join(format!("{tenant_key}.ref"))
}
fn prover_processing_state_lock() -> &'static SyncMutex<()> {
    ZK_PROVER_PROCESSING_STATE_LOCK.get_or_init(|| SyncMutex::new(()))
}
/// Hold a stable attachment namespace while a synchronous reader snapshots it.
pub(super) fn attachment_store_read_lock() -> parking_lot::RwLockReadGuard<'static, ()> {
    ATTACHMENT_STORE_GATE.get_or_init(|| RwLock::new(())).read()
}
fn attachment_store_write_lock() -> parking_lot::RwLockWriteGuard<'static, ()> {
    ATTACHMENT_STORE_GATE
        .get_or_init(|| RwLock::new(()))
        .write()
}
fn ensure_prover_processing_dirs_durable(id: &str, include_live: bool) -> std::io::Result<()> {
    let base = base_dir();
    ensure_direct_directory(&base)?;
    let prover = base.join("zk_prover");
    ensure_direct_directory(&prover)?;
    sync_directory(&base)?;
    let state = prover_processing_state_dir();
    ensure_direct_directory(&state)?;
    sync_directory(&prover)?;
    let entry = state.join(id);
    ensure_direct_directory(&entry)?;
    sync_directory(&state)?;
    if include_live {
        ensure_direct_directory(&entry.join("live"))?;
        sync_directory(&entry)?;
    }
    Ok(())
}
fn persist_processing_marker(path: &Path) -> std::io::Result<()> {
    persist_bytes_atomically(
        path,
        ZK_PROVER_PROCESSING_REFERENCE_MARKER,
        ZK_PROVER_PROCESSING_TEMP_PREFIX,
    )
}
fn processing_marker_exists(path: &Path) -> std::io::Result<bool> {
    let max_bytes = u64::try_from(ZK_PROVER_PROCESSING_REFERENCE_MARKER.len())
        .expect("processing-reference marker length fits u64");
    match read_bounded_attachment_regular_file(path, max_bytes) {
        Ok(bytes) if bytes == ZK_PROVER_PROCESSING_REFERENCE_MARKER => Ok(true),
        Ok(_) => Err(invalid_attachment_file(
            "invalid ZK prover processing-reference marker",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
/// Ensure the global processing receipt for `id` remains referenced by one live tenant copy.
pub(super) fn ensure_prover_processing_reference(
    tenant_key: &str,
    id: &str,
) -> std::io::Result<()> {
    let tenant_key = sanitize_tenant_key(tenant_key)
        .ok_or_else(|| invalid_attachment_file("invalid processing-reference tenant"))?;
    let id = sanitize_attachment_id(id)
        .ok_or_else(|| invalid_attachment_file("invalid processing-reference attachment id"))?;
    let _guard = prover_processing_state_lock().lock();
    let tenant = AttachmentTenant(tenant_key.clone());
    drop(open_attachment_regular_file(&meta_path(&tenant, &id))?);
    drop(open_attachment_regular_file(&bin_path(&tenant, &id))?);
    ensure_prover_processing_dirs_durable(&id, true)?;
    let path = prover_processing_reference_path(&tenant_key, &id);
    if processing_marker_exists(&path)? {
        sync_parent_directory(&path)?;
        return Ok(());
    }
    persist_processing_marker(&path)
}
fn try_load_prover_processing_receipt_locked(
    id: &str,
) -> std::io::Result<Option<ProverProcessingReceipt>> {
    let path = prover_processing_receipt_path(id);
    let bytes =
        match read_bounded_attachment_regular_file(&path, ZK_PROVER_PROCESSING_RECEIPT_MAX_BYTES) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        invalid_attachment_file(format!(
            "ZK prover processing receipt is not UTF-8: {error}"
        ))
    })?;
    let receipt = json::from_json::<ProverProcessingReceipt>(text).map_err(|error| {
        invalid_attachment_file(format!("decode ZK prover processing receipt: {error}"))
    })?;
    if receipt.version != ZK_PROVER_PROCESSING_STATE_VERSION
        || receipt.id != id
        || !receipt.disposition_is_valid()
    {
        return Err(invalid_attachment_file(
            "invalid ZK prover processing receipt contract",
        ));
    }
    Ok(Some(receipt))
}
/// Load a validated processing receipt for one content ID.
pub(super) fn try_load_prover_processing_receipt(
    id: &str,
) -> std::io::Result<Option<ProverProcessingReceipt>> {
    let id = sanitize_attachment_id(id)
        .filter(|clean| clean == id)
        .ok_or_else(|| invalid_attachment_file("invalid processing-receipt attachment id"))?;
    let _guard = prover_processing_state_lock().lock();
    try_load_prover_processing_receipt_locked(&id)
}
/// Resolve whether a durable content-ID receipt suppresses work at `now_ms`.
pub(super) fn try_prover_processing_decision(
    id: &str,
    now_ms: u64,
) -> std::io::Result<ProverProcessingDecision> {
    let id = sanitize_attachment_id(id)
        .filter(|clean| clean == id)
        .ok_or_else(|| invalid_attachment_file("invalid processing-receipt attachment id"))?;
    let _guard = prover_processing_state_lock().lock();
    let Some(receipt) = try_load_prover_processing_receipt_locked(&id)? else {
        return Ok(ProverProcessingDecision::Missing);
    };
    if receipt.terminal
        || receipt
            .retry_not_before_ms
            .is_some_and(|retry_at| now_ms < retry_at)
    {
        Ok(ProverProcessingDecision::Suppress)
    } else {
        Ok(ProverProcessingDecision::Due {
            retry_count: receipt.retry_count,
        })
    }
}
#[cfg(test)]
pub(super) fn load_prover_processing_receipt(id: &str) -> Option<ProverProcessingReceipt> {
    try_load_prover_processing_receipt(id).expect("load ZK prover processing receipt")
}
#[cfg(test)]
pub(super) fn prover_processing_decision(id: &str, now_ms: u64) -> ProverProcessingDecision {
    try_prover_processing_decision(id, now_ms).expect("resolve ZK prover processing decision")
}
#[cfg(unix)]
pub(super) fn open_pinned_direct_directory(path: &Path) -> std::io::Result<Option<fs::File>> {
    use std::os::unix::fs::MetadataExt as _;

    use crate::secure_file_metadata::{from_file, from_path, is_direct_directory, same_file};

    let named_before = match from_path(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_direct_directory_open_error(path, error)),
    };
    if !is_direct_directory(&named_before) {
        return Err(direct_directory_type_error(path));
    }
    let directory = match rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(directory) => fs::File::from(directory),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(std::io::Error::from(error)),
    };
    let opened = from_file(&directory)?;
    let named_after =
        from_path(path).map_err(|error| map_direct_directory_open_error(path, error))?;
    if !is_direct_directory(&opened)
        || !is_direct_directory(&named_after)
        || !same_file(&named_before, &opened)
        || !same_file(&opened, &named_after)
    {
        return Err(invalid_attachment_file(
            "attachment persistence directory changed while it was pinned",
        ));
    }
    if opened.uid() != rustix::process::geteuid().as_raw() || opened.mode() & 0o022 != 0 {
        return Err(invalid_attachment_file(format!(
            "persistence directory must be owned by the Torii process user and deny group/world writes: {}",
            path.display()
        )));
    }
    sorafs_node::validate_private_local_storage_acl(&directory, path)?;
    Ok(Some(directory))
}
#[cfg(windows)]
pub(super) fn open_pinned_direct_directory(path: &Path) -> std::io::Result<Option<fs::File>> {
    use std::os::windows::fs::OpenOptionsExt as _;

    use crate::secure_file_metadata::{from_file, from_path, is_direct_directory, same_file};

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ_WRITE: u32 = 0x0000_0001 | 0x0000_0002;
    const GENERIC_READ: u32 = 0x8000_0000;
    let named_before = match from_path(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !is_direct_directory(&named_before) {
        return Err(invalid_attachment_file(
            "attachment persistence ancestor is not a direct directory",
        ));
    }
    let directory = fs::OpenOptions::new()
        .access_mode(GENERIC_READ)
        // Retaining this handle prevents the directory pathname from being renamed or deleted
        // while a Windows pathname-based iterator or unlink is in progress.
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let opened = from_file(&directory)?;
    let named_after = from_path(path)?;
    if !is_direct_directory(&opened)
        || !is_direct_directory(&named_after)
        || !same_file(&named_before, &opened)
        || !same_file(&opened, &named_after)
    {
        return Err(invalid_attachment_file(
            "attachment persistence directory changed while it was pinned",
        ));
    }
    sorafs_node::validate_private_local_storage_acl(&directory, path)?;
    Ok(Some(directory))
}
#[cfg(not(any(unix, windows)))]
pub(super) fn open_pinned_direct_directory(_path: &Path) -> std::io::Result<Option<fs::File>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pinned attachment directories are unsupported on this platform",
    ))
}
#[cfg(unix)]
fn open_pinned_direct_child_directory(
    parent: &fs::File,
    name: &str,
) -> std::io::Result<Option<fs::File>> {
    use std::os::unix::fs::MetadataExt as _;

    let directory = match rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(directory) => fs::File::from(directory),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(std::io::Error::from(error)),
    };
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid_attachment_file(
            "attachment persistence child is not an owner-controlled direct directory",
        ));
    }
    sorafs_node::validate_private_local_storage_acl(&directory, Path::new(name))?;
    Ok(Some(directory))
}
#[cfg(unix)]
pub(super) fn open_pinned_direct_regular_file(
    parent: &fs::File,
    name: &str,
) -> std::io::Result<Option<fs::File>> {
    use std::os::unix::fs::MetadataExt as _;

    let file = match rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOCTTY
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(file) => fs::File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(std::io::Error::from(error)),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid_attachment_file(
            "attachment persistence entry is not an owner-controlled direct single-link regular file",
        ));
    }
    sorafs_node::validate_private_local_storage_acl(&file, Path::new(name))?;
    Ok(Some(file))
}
#[cfg(unix)]
pub(super) fn pinned_directory_names(
    directory: &fs::File,
    limit: u64,
) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    let mut entries = rustix::fs::Dir::read_from(directory).map_err(std::io::Error::from)?;
    for entry in &mut entries {
        let entry = entry.map_err(std::io::Error::from)?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        if u64::try_from(names.len()).unwrap_or(u64::MAX) >= limit {
            return Err(invalid_attachment_file(format!(
                "attachment persistence scan exceeds {limit} entries"
            )));
        }
        names.push(
            std::str::from_utf8(bytes)
                .map_err(|_| {
                    invalid_attachment_file(
                        "attachment persistence directory contains a non-UTF-8 entry",
                    )
                })?
                .to_owned(),
        );
    }
    Ok(names)
}
#[cfg(unix)]
pub(super) fn pinned_directory_names_at(
    _path: &Path,
    directory: &fs::File,
    limit: u64,
) -> std::io::Result<Vec<String>> {
    pinned_directory_names(directory, limit)
}
#[cfg(windows)]
pub(super) fn pinned_directory_names_at(
    path: &Path,
    _directory: &fs::File,
    limit: u64,
) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    let mut entries = crate::secure_file_metadata::DirectDirectoryEntryStream::open(path)?;
    while let Some(name) = entries.next_name()? {
        if u64::try_from(names.len()).unwrap_or(u64::MAX) >= limit {
            return Err(invalid_attachment_file(format!(
                "attachment persistence scan exceeds {limit} entries"
            )));
        }
        names.push(name.into_string().map_err(|_| {
            invalid_attachment_file("attachment persistence directory contains a non-UTF-8 entry")
        })?);
    }
    Ok(names)
}
#[cfg(not(any(unix, windows)))]
pub(super) fn pinned_directory_names_at(
    _path: &Path,
    _directory: &fs::File,
    _limit: u64,
) -> std::io::Result<Vec<String>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure attachment directory enumeration is unsupported on this platform",
    ))
}
fn open_pinned_directory_names(
    path: &Path,
    limit: u64,
) -> std::io::Result<Option<(fs::File, Vec<String>)>> {
    let Some(directory) = open_pinned_direct_directory(path)? else {
        return Ok(None);
    };
    let names = pinned_directory_names_at(path, &directory, limit)?;
    verify_pinned_direct_directory(path, &directory)?;
    Ok(Some((directory, names)))
}
fn verify_pinned_direct_directory(path: &Path, directory: &fs::File) -> std::io::Result<()> {
    use crate::secure_file_metadata::{from_file, from_path, is_direct_directory, same_file};

    let opened = from_file(directory)?;
    let named = from_path(path).map_err(|error| map_direct_directory_open_error(path, error))?;
    if !is_direct_directory(&opened) || !is_direct_directory(&named) || !same_file(&opened, &named)
    {
        return Err(invalid_attachment_file(
            "attachment persistence directory changed during retained-handle enumeration",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if opened.uid() != rustix::process::geteuid().as_raw() || opened.mode() & 0o022 != 0 {
            return Err(invalid_attachment_file(format!(
                "persistence directory must be owned by the Torii process user and deny group/world writes: {}",
                path.display()
            )));
        }
    }
    sorafs_node::validate_private_local_storage_acl(directory, path)
}
#[cfg(unix)]
pub(super) fn open_direct_regular_file_in_pinned_directory(
    _directory_path: &Path,
    directory: &fs::File,
    name: &str,
) -> std::io::Result<Option<fs::File>> {
    open_pinned_direct_regular_file(directory, name)
}
#[cfg(windows)]
pub(super) fn open_direct_regular_file_in_pinned_directory(
    directory_path: &Path,
    _directory: &fs::File,
    name: &str,
) -> std::io::Result<Option<fs::File>> {
    match open_attachment_regular_file(&directory_path.join(name)) {
        Ok((file, _)) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
#[cfg(not(any(unix, windows)))]
pub(super) fn open_direct_regular_file_in_pinned_directory(
    _directory_path: &Path,
    _directory: &fs::File,
    _name: &str,
) -> std::io::Result<Option<fs::File>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure attachment child-file opening is unsupported on this platform",
    ))
}
#[cfg(unix)]
fn open_direct_directory_in_pinned_directory(
    _directory_path: &Path,
    directory: &fs::File,
    name: &str,
) -> std::io::Result<Option<fs::File>> {
    open_pinned_direct_child_directory(directory, name)
}
#[cfg(windows)]
fn open_direct_directory_in_pinned_directory(
    directory_path: &Path,
    _directory: &fs::File,
    name: &str,
) -> std::io::Result<Option<fs::File>> {
    open_pinned_direct_directory(&directory_path.join(name))
}
#[cfg(not(any(unix, windows)))]
fn open_direct_directory_in_pinned_directory(
    _directory_path: &Path,
    _directory: &fs::File,
    _name: &str,
) -> std::io::Result<Option<fs::File>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure attachment child-directory opening is unsupported on this platform",
    ))
}
#[cfg(unix)]
fn remove_direct_regular_file_in_pinned_directory(
    _directory_path: &Path,
    directory: &fs::File,
    name: &str,
) -> std::io::Result<bool> {
    unlink_pinned_regular_file_if_present(directory, name)
}
#[cfg(windows)]
fn remove_direct_regular_file_in_pinned_directory(
    directory_path: &Path,
    _directory: &fs::File,
    name: &str,
) -> std::io::Result<bool> {
    remove_direct_regular_file_if_present(&directory_path.join(name))
}
#[cfg(not(any(unix, windows)))]
fn remove_direct_regular_file_in_pinned_directory(
    _directory_path: &Path,
    _directory: &fs::File,
    _name: &str,
) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure attachment child-file removal is unsupported on this platform",
    ))
}
#[cfg(unix)]
fn processing_marker_exists_at(directory: &fs::File, name: &str) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let Some(file) = open_pinned_direct_regular_file(directory, name)? else {
        return Ok(false);
    };
    let opened = file.metadata()?;
    let maximum = u64::try_from(ZK_PROVER_PROCESSING_REFERENCE_MARKER.len())
        .expect("processing marker length fits u64");
    if opened.len() > maximum {
        return Err(invalid_attachment_file(
            "invalid ZK prover processing-reference marker",
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len())
            .map_err(|_| invalid_attachment_file("processing marker length is not addressable"))?,
    );
    let mut reader = file.take(maximum.saturating_add(1));
    reader.read_to_end(&mut bytes)?;
    let after = reader.get_ref().metadata()?;
    if opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || opened.len() != after.len()
        || bytes != ZK_PROVER_PROCESSING_REFERENCE_MARKER
    {
        return Err(invalid_attachment_file(
            "invalid ZK prover processing-reference marker",
        ));
    }
    Ok(true)
}
#[cfg(unix)]
fn processing_marker_exists_in_pinned_directory(
    _directory_path: &Path,
    directory: &fs::File,
    name: &str,
) -> std::io::Result<bool> {
    processing_marker_exists_at(directory, name)
}
#[cfg(not(unix))]
fn processing_marker_exists_in_pinned_directory(
    directory_path: &Path,
    _directory: &fs::File,
    name: &str,
) -> std::io::Result<bool> {
    processing_marker_exists(&directory_path.join(name))
}
#[cfg(unix)]
fn pinned_attachment_tenant_directory(
    tenant_key: &str,
) -> std::io::Result<(fs::File, Option<fs::File>)> {
    let base = open_pinned_direct_directory(&base_dir())?.ok_or_else(|| {
        invalid_attachment_file("attachment persistence base directory is missing")
    })?;
    let root = open_pinned_direct_child_directory(&base, "zk_attachments")?.ok_or_else(|| {
        invalid_attachment_file("attachment persistence root directory is missing")
    })?;
    let tenant = open_pinned_direct_child_directory(&root, tenant_key)?;
    Ok((root, tenant))
}
#[cfg(unix)]
fn delete_target_pair_is_complete(tenant_key: &str, id: &str) -> std::io::Result<bool> {
    let (_root, Some(tenant)) = pinned_attachment_tenant_directory(tenant_key)? else {
        return Ok(false);
    };
    let metadata = open_pinned_direct_regular_file(&tenant, &format!("{id}.json"))?;
    let body = open_pinned_direct_regular_file(&tenant, &format!("{id}.bin"))?;
    Ok(metadata.is_some() && body.is_some())
}
#[cfg(not(unix))]
fn delete_target_pair_is_complete(tenant_key: &str, id: &str) -> std::io::Result<bool> {
    let tenant = AttachmentTenant(tenant_key.to_owned());
    let metadata_path = meta_path(&tenant, id);
    let body_path = bin_path(&tenant, id);
    if !path_entry_exists(&metadata_path)? || !path_entry_exists(&body_path)? {
        return Ok(false);
    }
    drop(open_attachment_regular_file(&metadata_path)?);
    drop(open_attachment_regular_file(&body_path)?);
    Ok(true)
}
#[cfg(unix)]
fn validate_attachment_pair_pinned(tenant_key: &str, id: &str) -> std::io::Result<()> {
    let (_root, Some(tenant)) = pinned_attachment_tenant_directory(tenant_key)? else {
        return Err(invalid_attachment_file(
            "processing reference points to a missing attachment tenant",
        ));
    };
    for name in [format!("{id}.json"), format!("{id}.bin")] {
        if open_pinned_direct_regular_file(&tenant, &name)?.is_none() {
            return Err(invalid_attachment_file(
                "processing reference points to a missing attachment pair",
            ));
        }
    }
    Ok(())
}
#[cfg(unix)]
enum PinnedProcessingEntry {
    Missing {
        parent: fs::File,
    },
    Present {
        state: fs::File,
        entry: fs::File,
        live: Option<fs::File>,
    },
}
#[cfg(unix)]
fn pinned_processing_entry(id: &str) -> std::io::Result<PinnedProcessingEntry> {
    let base = open_pinned_direct_directory(&base_dir())?.ok_or_else(|| {
        invalid_attachment_file("attachment persistence base directory is missing")
    })?;
    let Some(prover) = open_pinned_direct_child_directory(&base, "zk_prover")? else {
        return Ok(PinnedProcessingEntry::Missing { parent: base });
    };
    let state_name = format!("processing_{ZK_PROVER_PROCESSING_STATE_VERSION}");
    let Some(state) = open_pinned_direct_child_directory(&prover, &state_name)? else {
        return Ok(PinnedProcessingEntry::Missing { parent: prover });
    };
    let Some(entry) = open_pinned_direct_child_directory(&state, id)? else {
        return Ok(PinnedProcessingEntry::Missing { parent: state });
    };
    let live = open_pinned_direct_child_directory(&entry, "live")?;
    Ok(PinnedProcessingEntry::Present { state, entry, live })
}
#[cfg(unix)]
fn delete_target_processing_reference_exists(tenant_key: &str, id: &str) -> std::io::Result<bool> {
    let PinnedProcessingEntry::Present {
        live: Some(live), ..
    } = pinned_processing_entry(id)?
    else {
        return Ok(false);
    };
    processing_marker_exists_at(&live, &format!("{tenant_key}.ref"))
}
#[cfg(not(unix))]
fn delete_target_processing_reference_exists(tenant_key: &str, id: &str) -> std::io::Result<bool> {
    processing_marker_exists(&prover_processing_reference_path(tenant_key, id))
}
fn processing_reference_dir_has_shards(id: &str) -> std::io::Result<bool> {
    processing_reference_dir_has_shards_except(id, None)
}
#[cfg(unix)]
fn processing_reference_dir_has_shards_pinned(
    live: &fs::File,
    id: &str,
    excluded_tenant: Option<&str>,
) -> std::io::Result<bool> {
    let mut has_shard = false;
    for name in pinned_directory_names(live, ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES)? {
        if is_attachment_writer_temp_name(&name) {
            if open_pinned_direct_regular_file(live, &name)?.is_none() {
                return Err(invalid_attachment_file(
                    "processing-reference temporary entry disappeared during validation",
                ));
            }
            continue;
        }
        let tenant_key = name
            .strip_suffix(".ref")
            .and_then(sanitize_tenant_key)
            .filter(|tenant| format!("{tenant}.ref") == name)
            .ok_or_else(|| {
                invalid_attachment_file(format!(
                    "processing-reference directory has an unexpected entry: {name}"
                ))
            })?;
        if !processing_marker_exists_at(live, &name)? {
            return Err(invalid_attachment_file(
                "processing-reference marker disappeared during validation",
            ));
        }
        if excluded_tenant != Some(tenant_key.as_str()) {
            validate_attachment_pair_pinned(&tenant_key, id)?;
        }
        has_shard = true;
    }
    Ok(has_shard)
}
#[cfg(unix)]
fn processing_reference_dir_has_shards_except(
    id: &str,
    excluded_tenant: Option<&str>,
) -> std::io::Result<bool> {
    let PinnedProcessingEntry::Present {
        live: Some(live), ..
    } = pinned_processing_entry(id)?
    else {
        return Ok(false);
    };
    processing_reference_dir_has_shards_pinned(&live, id, excluded_tenant)
}
#[cfg(not(unix))]
fn processing_reference_dir_has_shards_except(
    id: &str,
    excluded_tenant: Option<&str>,
) -> std::io::Result<bool> {
    let reference_dir = prover_processing_reference_dir(id);
    let Some((directory, names)) =
        open_pinned_directory_names(&reference_dir, ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES)?
    else {
        return Ok(false);
    };
    let mut has_shard = false;
    for name in names {
        let path = reference_dir.join(&name);
        if open_direct_regular_file_in_pinned_directory(&reference_dir, &directory, &name)?
            .is_none()
        {
            return Err(invalid_attachment_file(format!(
                "processing-reference entry disappeared during validation: {}",
                path.display()
            )));
        }
        if is_attachment_writer_temp_name(&name) {
            continue;
        }
        let tenant_key = name
            .strip_suffix(".ref")
            .and_then(sanitize_tenant_key)
            .filter(|tenant| format!("{tenant}.ref") == name)
            .ok_or_else(|| {
                invalid_attachment_file(format!(
                    "processing-reference directory has an unexpected entry: {name}"
                ))
            })?;
        if processing_marker_exists(&path)? {
            if excluded_tenant != Some(tenant_key.as_str()) {
                let tenant = AttachmentTenant(tenant_key);
                drop(open_attachment_regular_file(&meta_path(&tenant, id))?);
                drop(open_attachment_regular_file(&bin_path(&tenant, id))?);
            }
            has_shard = true;
        }
    }
    verify_pinned_direct_directory(&reference_dir, &directory)?;
    Ok(has_shard)
}
/// Persist a completed content-ID receipt only while at least one attachment copy is live.
pub(super) fn persist_prover_processing_receipt_if_referenced(
    receipt: &ProverProcessingReceipt,
) -> std::io::Result<bool> {
    let id = sanitize_attachment_id(&receipt.id)
        .ok_or_else(|| invalid_attachment_file("invalid processing-receipt attachment id"))?;
    if receipt.version != ZK_PROVER_PROCESSING_STATE_VERSION
        || receipt.id != id
        || !receipt.disposition_is_valid()
    {
        return Err(invalid_attachment_file(
            "invalid ZK prover processing receipt",
        ));
    }
    let _guard = prover_processing_state_lock().lock();
    persist_prover_processing_receipt_if_referenced_locked(receipt, &id)
}
fn persist_prover_processing_receipt_if_referenced_locked(
    receipt: &ProverProcessingReceipt,
    id: &str,
) -> std::io::Result<bool> {
    if !processing_reference_dir_has_shards(id)? {
        return Ok(false);
    }
    ensure_prover_processing_dirs_durable(id, false)?;
    let body = json::to_json(receipt).map_err(|error| {
        invalid_attachment_file(format!("encode ZK prover processing receipt: {error}"))
    })?;
    if body.len() as u64 > ZK_PROVER_PROCESSING_RECEIPT_MAX_BYTES {
        return Err(invalid_attachment_file(
            "ZK prover processing receipt exceeds its persistence limit",
        ));
    }
    persist_bytes_atomically(
        &prover_processing_receipt_path(id),
        body.as_bytes(),
        ZK_PROVER_PROCESSING_TEMP_PREFIX,
    )?;
    Ok(true)
}
/// Atomically reconcile a committed report disposition with its durable receipt.
pub(super) fn reconcile_prover_processing_receipt_if_referenced(
    committed: &ProverProcessingReceipt,
) -> std::io::Result<ProverProcessingReceipt> {
    let id = sanitize_attachment_id(&committed.id)
        .ok_or_else(|| invalid_attachment_file("invalid processing-receipt attachment id"))?;
    if committed.version != ZK_PROVER_PROCESSING_STATE_VERSION
        || committed.id != id
        || !committed.disposition_is_valid()
    {
        return Err(invalid_attachment_file(
            "invalid ZK prover processing receipt",
        ));
    }
    let _guard = prover_processing_state_lock().lock();
    let durable = try_load_prover_processing_receipt_locked(&id)?;
    let selected = ProverProcessingReceipt::reconcile_committed(durable.clone(), committed.clone());
    if durable.as_ref() != Some(&selected) {
        let _ = persist_prover_processing_receipt_if_referenced_locked(&selected, &id)?;
    }
    Ok(selected)
}
#[cfg(unix)]
fn remove_file_if_present(path: &Path) -> std::io::Result<()> {
    let parent_path = path
        .parent()
        .ok_or_else(|| invalid_attachment_file("persisted path has no containing directory"))?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| invalid_attachment_file("persisted path has no UTF-8 file name"))?;
    let Some(parent) = open_pinned_direct_directory(parent_path)? else {
        return sync_nearest_existing_parent(path);
    };
    let _ = unlink_pinned_regular_file_if_present(&parent, name)?;
    verify_pinned_direct_directory(parent_path, &parent)
}
#[cfg(windows)]
fn remove_file_if_present(path: &Path) -> std::io::Result<()> {
    remove_direct_regular_file_if_present(path).map(drop)
}
#[cfg(not(any(unix, windows)))]
fn remove_file_if_present(_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure attachment file removal is unsupported on this platform",
    ))
}
fn path_entry_exists(path: &Path) -> std::io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
/// Validate whether one canonical attachment pair is present.
pub(super) fn attachment_pair_exists(tenant_key: &str, id: &str) -> std::io::Result<bool> {
    let tenant_key = sanitize_tenant_key(tenant_key)
        .filter(|clean| clean == tenant_key)
        .ok_or_else(|| invalid_attachment_file("invalid attachment tenant key"))?;
    let id = sanitize_attachment_id(id)
        .filter(|clean| clean == id)
        .ok_or_else(|| invalid_attachment_file("invalid attachment id"))?;
    let tenant = AttachmentTenant(tenant_key);
    if attachment_mutation_hides_attachment(&tenant, &id)? {
        return Ok(false);
    }
    let metadata_path = meta_path(&tenant, &id);
    let body_path = bin_path(&tenant, &id);
    match (
        path_entry_exists(&metadata_path)?,
        path_entry_exists(&body_path)?,
    ) {
        (false, false) => Ok(false),
        (true, true) => {
            drop(open_attachment_regular_file(&metadata_path)?);
            drop(open_attachment_regular_file(&body_path)?);
            Ok(true)
        }
        (true, false) => Err(invalid_attachment_file(format!(
            "attachment metadata has no body: {id}"
        ))),
        (false, true) => Err(invalid_attachment_file(format!(
            "attachment body has no metadata: {id}"
        ))),
    }
}
#[cfg(unix)]
fn remove_dir_if_present(path: &Path) -> std::io::Result<()> {
    let parent_path = path.parent().ok_or_else(|| {
        invalid_attachment_file("persisted directory has no containing directory")
    })?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| invalid_attachment_file("persisted directory has no UTF-8 file name"))?;
    let Some(parent) = open_pinned_direct_directory(parent_path)? else {
        return sync_nearest_existing_parent(path);
    };
    let Some(directory) = open_pinned_direct_child_directory(&parent, name)? else {
        sync_open_directory(&parent)?;
        return verify_pinned_direct_directory(parent_path, &parent);
    };
    if !remove_pinned_directory_if_empty(&parent, name, &directory)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::DirectoryNotEmpty,
            format!(
                "attachment persistence directory is not empty: {}",
                path.display()
            ),
        ));
    }
    verify_pinned_direct_directory(parent_path, &parent)
}
#[cfg(windows)]
fn remove_dir_if_present(path: &Path) -> std::io::Result<()> {
    remove_direct_empty_directory_if_present(path).map(drop)
}
#[cfg(not(any(unix, windows)))]
fn remove_dir_if_present(_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure attachment directory removal is unsupported on this platform",
    ))
}
#[cfg(unix)]
fn unlink_pinned_file_if_present(parent: &fs::File, name: &str) -> std::io::Result<()> {
    unlink_pinned_regular_file_if_present(parent, name).map(drop)
}
#[cfg(unix)]
pub(super) fn unlink_pinned_regular_file_if_present(
    parent: &fs::File,
    name: &str,
) -> std::io::Result<bool> {
    let Some(file) = open_pinned_direct_regular_file(parent, name)? else {
        sync_open_directory(parent)?;
        return Ok(false);
    };
    let opened = rustix::fs::fstat(&file).map_err(std::io::Error::from)?;
    let named = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(std::io::Error::from)?;
    if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::RegularFile
        || named.st_nlink != 1
        || named.st_dev != opened.st_dev
        || named.st_ino != opened.st_ino
    {
        return Err(invalid_attachment_file(
            "attachment persistence entry changed before removal",
        ));
    }
    match rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::empty()) {
        Ok(()) => {
            sync_open_directory(parent)?;
            Ok(true)
        }
        Err(error) => Err(std::io::Error::from(error)),
    }
}
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_exact_delete {
    use std::{
        ffi::c_void,
        fs, io,
        mem::{align_of, size_of},
        os::windows::io::AsRawHandle as _,
        ptr,
    };

    const FILE_DISPOSITION_INFO_EX_CLASS: u32 = 21;
    const FILE_DISPOSITION_DELETE: u32 = 0x0000_0001;
    const FILE_DISPOSITION_POSIX_SEMANTICS: u32 = 0x0000_0002;
    const FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE: u32 = 0x0000_0010;

    #[repr(C)]
    struct FileDispositionInfoEx {
        flags: u32,
    }

    const _: () = assert!(size_of::<FileDispositionInfoEx>() == size_of::<u32>());
    const _: () = assert!(align_of::<FileDispositionInfoEx>() == align_of::<u32>());

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "SetFileInformationByHandle"]
        fn set_file_information_by_handle(
            file: *mut c_void,
            information_class: u32,
            information: *const c_void,
            buffer_size: u32,
        ) -> i32;
    }

    pub(super) fn remove(file: &fs::File) -> io::Result<()> {
        let information = FileDispositionInfoEx {
            flags: FILE_DISPOSITION_DELETE
                | FILE_DISPOSITION_POSIX_SEMANTICS
                | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
        };
        // SAFETY: `file` is a live DELETE-capable handle opened with delete sharing and
        // `information` has the documented fixed-size `FILE_DISPOSITION_INFO_EX` layout for the
        // duration of the call. POSIX semantics remove the name immediately even while other
        // delete-sharing identity handles retain the underlying object.
        let succeeded = unsafe {
            set_file_information_by_handle(
                file.as_raw_handle().cast(),
                FILE_DISPOSITION_INFO_EX_CLASS,
                ptr::from_ref(&information).cast(),
                u32::try_from(size_of::<FileDispositionInfoEx>())
                    .expect("FILE_DISPOSITION_INFO_EX size fits u32"),
            )
        };
        if succeeded == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
#[cfg(windows)]
pub(super) fn remove_direct_regular_file_if_present(path: &Path) -> std::io::Result<bool> {
    use std::os::windows::fs::OpenOptionsExt as _;

    use crate::secure_file_metadata::{
        from_file, from_path, is_direct_directory, is_direct_file, number_of_links, same_file,
    };

    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const GENERIC_READ: u32 = 0x8000_0000;

    let parent_path = path
        .parent()
        .ok_or_else(|| invalid_attachment_file("persisted path has no containing directory"))?;
    let Some(parent) = open_pinned_direct_directory(parent_path)? else {
        sync_nearest_existing_parent(path)?;
        return Ok(false);
    };
    let parent_identity = from_file(&parent)?;
    let file = match fs::OpenOptions::new()
        .access_mode(GENERIC_READ | DELETE_ACCESS)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::durable_fs::sync_direct_directory(parent_path)?;
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    sorafs_node::validate_private_local_storage_acl(&file, path)?;
    let opened = from_file(&file)?;
    let named = from_path(path)?;
    if !is_direct_file(&opened)
        || !is_direct_file(&named)
        || number_of_links(&opened) != Some(1)
        || number_of_links(&named) != Some(1)
        || !same_file(&opened, &named)
    {
        return Err(invalid_attachment_file(
            "persisted entry changed identity before exact removal",
        ));
    }
    // Release transient metadata handles before mutating the namespace. Any independently
    // retained identity handles share deletion and therefore do not delay POSIX name removal.
    drop((opened, named));
    let disposition = windows_exact_delete::remove(&file);
    drop(file);
    // A successful disposition is a namespace mutation even if a later postcondition fails.
    // Always attempt the durability barrier before reporting either outcome.
    let synced = crate::durable_fs::sync_direct_directory(parent_path);
    disposition?;
    synced?;

    let parent_after = from_file(&parent)?;
    let named_parent = from_path(parent_path)?;
    if !is_direct_directory(&parent_identity)
        || !is_direct_directory(&parent_after)
        || !is_direct_directory(&named_parent)
        || !same_file(&parent_identity, &parent_after)
        || !same_file(&parent_after, &named_parent)
    {
        return Err(invalid_attachment_file(
            "persistence directory changed during exact removal",
        ));
    }
    match from_path(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Err(invalid_attachment_file(
            "a replacement appeared at the removed persistence path",
        )),
        Err(error) => Err(error),
    }
}
#[cfg(windows)]
fn remove_direct_empty_directory_if_present(path: &Path) -> std::io::Result<bool> {
    use std::os::windows::fs::OpenOptionsExt as _;

    use crate::secure_file_metadata::{from_file, from_path, is_direct_directory, same_file};

    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ_WRITE_DELETE: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
    const GENERIC_READ: u32 = 0x8000_0000;

    let parent_path = path
        .parent()
        .ok_or_else(|| invalid_attachment_file("persisted path has no containing directory"))?;
    let Some(parent) = open_pinned_direct_directory(parent_path)? else {
        sync_nearest_existing_parent(path)?;
        return Ok(false);
    };
    let parent_identity = from_file(&parent)?;
    let directory = match fs::OpenOptions::new()
        .access_mode(GENERIC_READ | DELETE_ACCESS)
        .share_mode(FILE_SHARE_READ_WRITE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::durable_fs::sync_direct_directory(parent_path)?;
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    sorafs_node::validate_private_local_storage_acl(&directory, path)?;
    let opened = from_file(&directory)?;
    let named = from_path(path)?;
    if !is_direct_directory(&opened) || !is_direct_directory(&named) || !same_file(&opened, &named)
    {
        return Err(invalid_attachment_file(
            "persisted directory changed identity before exact removal",
        ));
    }
    // Release transient metadata handles before mutating the namespace. Any independently
    // retained identity handles share deletion and therefore do not delay POSIX name removal.
    drop((opened, named));
    let disposition = windows_exact_delete::remove(&directory);
    drop(directory);
    // A successful disposition is a namespace mutation even if a later postcondition fails.
    // Always attempt the durability barrier before reporting either outcome.
    let synced = crate::durable_fs::sync_direct_directory(parent_path);
    disposition?;
    synced?;

    let parent_after = from_file(&parent)?;
    let named_parent = from_path(parent_path)?;
    if !is_direct_directory(&parent_identity)
        || !is_direct_directory(&parent_after)
        || !is_direct_directory(&named_parent)
        || !same_file(&parent_identity, &parent_after)
        || !same_file(&parent_after, &named_parent)
    {
        return Err(invalid_attachment_file(
            "persistence parent directory changed during exact removal",
        ));
    }
    match from_path(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Err(invalid_attachment_file(
            "a replacement appeared at the removed persistence directory path",
        )),
        Err(error) => Err(error),
    }
}
#[cfg(unix)]
fn pinned_directory_name_matches(
    parent: &fs::File,
    name: &str,
    opened: &fs::File,
) -> std::io::Result<bool> {
    let named = match rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(named) => named,
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(error) => return Err(std::io::Error::from(error)),
    };
    let opened = rustix::fs::fstat(opened).map_err(std::io::Error::from)?;
    Ok(
        rustix::fs::FileType::from_raw_mode(named.st_mode) == rustix::fs::FileType::Directory
            && named.st_dev == opened.st_dev
            && named.st_ino == opened.st_ino,
    )
}
#[cfg(unix)]
fn remove_pinned_directory_if_empty(
    parent: &fs::File,
    name: &str,
    opened: &fs::File,
) -> std::io::Result<bool> {
    if !pinned_directory_name_matches(parent, name, opened)? {
        return Err(invalid_attachment_file(
            "attachment persistence directory changed before removal",
        ));
    }
    match rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR) {
        Ok(()) => {
            sync_open_directory(parent)?;
            Ok(true)
        }
        Err(rustix::io::Errno::NOTEMPTY | rustix::io::Errno::EXIST) => Ok(false),
        Err(error) => Err(std::io::Error::from(error)),
    }
}
#[cfg(unix)]
fn remove_processing_temp_files_pinned(directory: &fs::File) -> std::io::Result<()> {
    let names = pinned_directory_names(directory, PROVER_PROCESSING_RECOVERY_MAX_ENTRIES)?;
    for name in names {
        if !is_attachment_writer_temp_name(&name) {
            continue;
        }
        if open_pinned_direct_regular_file(directory, &name)?.is_none() {
            return Err(invalid_attachment_file(
                "processing temporary entry disappeared during cleanup",
            ));
        }
        unlink_pinned_file_if_present(directory, &name)?;
    }
    Ok(())
}
#[cfg(unix)]
fn remove_attachment_pair_pinned(tenant_key: &str, id: &str) -> std::io::Result<()> {
    let (root, tenant) = pinned_attachment_tenant_directory(tenant_key)?;
    let Some(tenant) = tenant else {
        sync_open_directory(&root)?;
        return Ok(());
    };
    let metadata_name = format!("{id}.json");
    let body_name = format!("{id}.bin");
    // Validate both entries before the first unlink so an unsafe half does not
    // convert an otherwise complete pair into a partial deletion.
    drop(open_pinned_direct_regular_file(&tenant, &metadata_name)?);
    drop(open_pinned_direct_regular_file(&tenant, &body_name)?);
    let _ = unlink_pinned_regular_file_if_present(&tenant, &metadata_name)?;
    let _ = unlink_pinned_regular_file_if_present(&tenant, &body_name)?;
    let _ = remove_pinned_directory_if_empty(&root, tenant_key, &tenant)?;
    Ok(())
}
#[cfg(not(unix))]
fn remove_processing_temp_files(dir: &Path) -> std::io::Result<()> {
    let Some((directory, names)) =
        open_pinned_directory_names(dir, PROVER_PROCESSING_RECOVERY_MAX_ENTRIES)?
    else {
        return Ok(());
    };
    for name in names {
        if !is_attachment_writer_temp_name(&name) {
            continue;
        }
        if open_direct_regular_file_in_pinned_directory(dir, &directory, &name)?.is_none() {
            return Err(invalid_attachment_file(
                "processing temporary entry disappeared during cleanup",
            ));
        }
        remove_direct_regular_file_in_pinned_directory(dir, &directory, &name)?;
    }
    verify_pinned_direct_directory(dir, &directory)
}
#[cfg(unix)]
fn remove_prover_processing_reference_locked(tenant_key: &str, id: &str) -> std::io::Result<()> {
    let (state, entry, live) = match pinned_processing_entry(id)? {
        PinnedProcessingEntry::Missing { parent } => {
            sync_open_directory(&parent)?;
            return Ok(());
        }
        PinnedProcessingEntry::Present { state, entry, live } => (state, entry, live),
    };
    if let Some(live) = live {
        unlink_pinned_file_if_present(&live, &format!("{tenant_key}.ref"))?;
        if processing_reference_dir_has_shards_pinned(&live, id, None)? {
            return Ok(());
        }
        remove_processing_temp_files_pinned(&live)?;
        remove_processing_temp_files_pinned(&entry)?;
        if !remove_pinned_directory_if_empty(&entry, "live", &live)? {
            return Err(invalid_attachment_file(
                "ZK prover live-reference directory is not empty after cleanup",
            ));
        }
    } else {
        sync_open_directory(&entry)?;
        remove_processing_temp_files_pinned(&entry)?;
    }
    unlink_pinned_file_if_present(&entry, "receipt.json")?;
    if !remove_pinned_directory_if_empty(&state, id, &entry)? {
        return Err(invalid_attachment_file(
            "ZK prover processing-state entry is not empty after cleanup",
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn remove_prover_processing_reference_locked(tenant_key: &str, id: &str) -> std::io::Result<()> {
    remove_file_if_present(&prover_processing_reference_path(tenant_key, id))?;
    if processing_reference_dir_has_shards(id)? {
        return Ok(());
    }
    let state_entry_dir = prover_processing_state_dir().join(id);
    let reference_dir = prover_processing_reference_dir(id);
    // Atomic persistence can leave its named temporary file behind if the
    // process stops before rename. Those files are not live-reference shards
    // and must not permanently pin the attachment or its processing state.
    remove_processing_temp_files(&reference_dir)?;
    remove_processing_temp_files(&state_entry_dir)?;
    remove_dir_if_present(&reference_dir)?;
    remove_file_if_present(&prover_processing_receipt_path(id))?;
    remove_dir_if_present(&state_entry_dir)
}
fn invalid_attachment_file(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}
/// Open one attachment-store entry without following its final path component.
///
/// Unix pins the containing directory and uses one non-blocking `openat`, so a
/// concurrent substitution with a symlink, FIFO, device, or directory cannot
/// redirect or indefinitely block a reader. Windows opens the reparse point
/// itself and requires a stable single-link file identity before accepting the
/// handle. Other targets fail closed until they expose equivalent primitives.
///
/// # Errors
///
/// Returns an error when the path cannot be anchored or the opened entry is not
/// a direct, single-link regular file with a stable identity.
pub(super) fn open_attachment_regular_file(
    path: &Path,
) -> std::io::Result<(fs::File, fs::Metadata)> {
    open_attachment_regular_file_platform(path)
}
#[cfg(unix)]
fn open_attachment_regular_file_platform(path: &Path) -> std::io::Result<(fs::File, fs::Metadata)> {
    use std::os::unix::fs::MetadataExt as _;
    let parent_path = path
        .parent()
        .ok_or_else(|| invalid_attachment_file("attachment path has no containing directory"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| invalid_attachment_file("attachment path has no file name"))?;
    let parent = open_pinned_direct_directory(parent_path)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "attachment containing directory is missing",
        )
    })?;
    let file = fs::File::from(
        rustix::fs::openat(
            &parent,
            file_name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::NOCTTY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid_attachment_file(
            "attachment entry is not an owner-controlled direct single-link regular file",
        ));
    }
    sorafs_node::validate_private_local_storage_acl(&file, path)?;
    Ok((file, metadata))
}
#[cfg(windows)]
fn open_attachment_regular_file_platform(path: &Path) -> std::io::Result<(fs::File, fs::Metadata)> {
    use crate::secure_file_metadata::{
        from_file, from_path, is_direct_file, number_of_links, open_direct_file, same_file,
    };

    let before = from_path(path)?;
    if !is_direct_file(&before) || number_of_links(&before) != Some(1) {
        return Err(invalid_attachment_file(
            "attachment entry is not a direct single-link regular file",
        ));
    }
    let file = open_direct_file(path)?;
    sorafs_node::validate_private_local_storage_acl(&file, path)?;
    let opened = from_file(&file)?;
    let named = from_path(path)?;
    if !is_direct_file(&opened)
        || !is_direct_file(&named)
        || number_of_links(&opened) != Some(1)
        || number_of_links(&named) != Some(1)
        || !same_file(&before, &opened)
        || !same_file(&opened, &named)
    {
        return Err(invalid_attachment_file(
            "attachment entry changed identity while being opened",
        ));
    }
    let metadata = file.metadata()?;
    Ok((file, metadata))
}
#[cfg(not(any(unix, windows)))]
fn open_attachment_regular_file_platform(
    _path: &Path,
) -> std::io::Result<(fs::File, fs::Metadata)> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this platform does not expose a secure direct-file attachment primitive",
    ))
}
/// Read one direct regular attachment entry under a hard byte ceiling.
///
/// # Errors
///
/// Returns an error when secure open fails, the entry exceeds `max_bytes`, or
/// its size or type changes during the read.
pub(super) fn read_bounded_attachment_regular_file(
    path: &Path,
    max_bytes: u64,
) -> std::io::Result<Vec<u8>> {
    let (file, opened_metadata) = open_attachment_regular_file(path)?;
    if opened_metadata.len() > max_bytes {
        return Err(invalid_attachment_file(format!(
            "attachment entry exceeds the {max_bytes}-byte read limit"
        )));
    }
    let mut reader = file.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened_metadata.len())
            .map_err(|_| invalid_attachment_file("attachment entry length is not addressable"))?,
    );
    reader.read_to_end(&mut bytes)?;
    let read_size = u64::try_from(bytes.len())
        .map_err(|_| invalid_attachment_file("attachment read length does not fit in u64"))?;
    let final_metadata = reader.get_ref().metadata()?;
    if read_size != opened_metadata.len()
        || final_metadata.len() != opened_metadata.len()
        || !final_metadata.is_file()
    {
        return Err(invalid_attachment_file(
            "attachment entry changed while being read",
        ));
    }
    Ok(bytes)
}
fn is_attachment_writer_temp_name(name: &str) -> bool {
    name.strip_prefix(".tmp").is_some_and(|suffix| {
        suffix.len() == 6 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}
fn remove_attachment_writer_temps_in(
    directory: &Path,
    directory_handle: &fs::File,
    scanned: &mut u64,
    scan_limit: u64,
) -> std::io::Result<()> {
    let names = pinned_directory_names_at(
        directory,
        directory_handle,
        scan_limit.saturating_sub(*scanned),
    )?;
    for name in names {
        *scanned = (*scanned).saturating_add(1);
        if *scanned > scan_limit {
            return Err(invalid_attachment_file(format!(
                "attachment temporary-file recovery exceeds {scan_limit} entries"
            )));
        }
        if open_direct_regular_file_in_pinned_directory(directory, directory_handle, &name)?
            .is_none()
        {
            return Err(invalid_attachment_file(format!(
                "attachment entry disappeared during temporary-file recovery: {}",
                directory.join(&name).display()
            )));
        }
        if !is_attachment_writer_temp_name(&name) {
            continue;
        }
        remove_direct_regular_file_in_pinned_directory(directory, directory_handle, &name)?;
    }
    verify_pinned_direct_directory(directory, directory_handle)
}
fn recover_attachment_mutation_writer_temps() -> std::io::Result<()> {
    let directory = attachment_mutation_transaction_dir();
    let Some((directory_handle, names)) =
        open_pinned_directory_names(&directory, ATTACHMENT_TRANSACTION_RECOVERY_MAX_ENTRIES)?
    else {
        return Ok(());
    };
    let mut scanned = 0_u64;
    for name in names {
        scanned = scanned.saturating_add(1);
        if scanned > ATTACHMENT_TRANSACTION_RECOVERY_MAX_ENTRIES {
            return Err(invalid_attachment_file(format!(
                "attachment mutation recovery exceeds {ATTACHMENT_TRANSACTION_RECOVERY_MAX_ENTRIES} entries"
            )));
        }
        if name != ATTACHMENT_MUTATION_TRANSACTION_FILE && !is_attachment_writer_temp_name(&name) {
            return Err(invalid_attachment_file(format!(
                "attachment mutation directory contains an unexpected entry: {name}"
            )));
        }
        if open_direct_regular_file_in_pinned_directory(&directory, &directory_handle, &name)?
            .is_none()
        {
            return Err(invalid_attachment_file(format!(
                "attachment mutation entry disappeared during recovery: {}",
                directory.join(&name).display()
            )));
        }
        if is_attachment_writer_temp_name(&name) {
            remove_direct_regular_file_in_pinned_directory(&directory, &directory_handle, &name)?;
        }
    }
    verify_pinned_direct_directory(&directory, &directory_handle)
}
fn recover_attachment_writer_temps() -> std::io::Result<()> {
    let root = attachments_root_dir();
    let (root_handle, names) =
        open_pinned_directory_names(&root, ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES)?.ok_or_else(
            || {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "attachment persistence root directory is missing",
                )
            },
        )?;
    let mut root_entries = 0_u64;
    let mut child_entries = 0_u64;
    for raw_tenant in names {
        root_entries = root_entries.saturating_add(1);
        if root_entries > ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES {
            return Err(invalid_attachment_file(format!(
                "attachment temporary-file recovery exceeds {ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES} tenant entries"
            )));
        }
        let tenant = sanitize_tenant_key(&raw_tenant)
            .filter(|tenant| tenant == &raw_tenant)
            .ok_or_else(|| {
                invalid_attachment_file(format!(
                    "attachment root contains a non-canonical tenant entry: {raw_tenant}"
                ))
            })?;
        let tenant_path = attachments_dir(&AttachmentTenant(tenant));
        let Some(tenant_handle) =
            open_direct_directory_in_pinned_directory(&root, &root_handle, &raw_tenant)?
        else {
            return Err(invalid_attachment_file(format!(
                "attachment tenant directory disappeared during recovery: {}",
                tenant_path.display()
            )));
        };
        remove_attachment_writer_temps_in(
            &tenant_path,
            &tenant_handle,
            &mut child_entries,
            ATTACHMENT_CHILD_RECOVERY_MAX_ENTRIES,
        )?;
    }
    verify_pinned_direct_directory(&root, &root_handle)?;
    recover_attachment_mutation_writer_temps()
}
fn recover_prover_processing_writer_temps() -> std::io::Result<()> {
    let base = base_dir();
    let base_handle = open_pinned_direct_directory(&base)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "attachment persistence base directory is missing",
        )
    })?;
    let prover = base.join("zk_prover");
    let Some(prover_handle) =
        open_direct_directory_in_pinned_directory(&base, &base_handle, "zk_prover")?
    else {
        return Ok(());
    };
    let state = prover_processing_state_dir();
    let state_name = format!("processing_{ZK_PROVER_PROCESSING_STATE_VERSION}");
    let Some(state_handle) =
        open_direct_directory_in_pinned_directory(&prover, &prover_handle, &state_name)?
    else {
        return Ok(());
    };
    let state_names = pinned_directory_names_at(
        &state,
        &state_handle,
        PROVER_PROCESSING_RECOVERY_MAX_ENTRIES,
    )?;
    let mut scanned = 0_u64;
    for raw_id in state_names {
        scanned = scanned.saturating_add(1);
        if scanned > PROVER_PROCESSING_RECOVERY_MAX_ENTRIES {
            return Err(invalid_attachment_file(format!(
                "ZK prover processing-state recovery exceeds {PROVER_PROCESSING_RECOVERY_MAX_ENTRIES} entries"
            )));
        }
        let id = sanitize_attachment_id(&raw_id)
            .filter(|id| id == &raw_id)
            .ok_or_else(|| {
                invalid_attachment_file(format!(
                    "ZK prover processing state contains a non-canonical entry: {raw_id}"
                ))
            })?;
        let Some(state_entry_handle) =
            open_direct_directory_in_pinned_directory(&state, &state_handle, &raw_id)?
        else {
            return Err(invalid_attachment_file(format!(
                "ZK prover processing-state entry disappeared during recovery: {raw_id}"
            )));
        };
        let state_entry = state.join(&id);
        let child_names = pinned_directory_names_at(
            &state_entry,
            &state_entry_handle,
            PROVER_PROCESSING_RECOVERY_MAX_ENTRIES.saturating_sub(scanned),
        )?;
        let mut has_receipt = false;
        let mut live_handle = None;
        for name in child_names {
            scanned = scanned.saturating_add(1);
            if scanned > PROVER_PROCESSING_RECOVERY_MAX_ENTRIES {
                return Err(invalid_attachment_file(format!(
                    "ZK prover processing-state recovery exceeds {PROVER_PROCESSING_RECOVERY_MAX_ENTRIES} entries"
                )));
            }
            if is_attachment_writer_temp_name(&name) {
                if open_direct_regular_file_in_pinned_directory(
                    &state_entry,
                    &state_entry_handle,
                    &name,
                )?
                .is_none()
                {
                    return Err(invalid_attachment_file(format!(
                        "ZK prover processing temporary entry disappeared during recovery: {}",
                        state_entry.join(&name).display()
                    )));
                }
                remove_direct_regular_file_in_pinned_directory(
                    &state_entry,
                    &state_entry_handle,
                    &name,
                )?;
                continue;
            }
            match name.as_str() {
                "receipt.json" => {
                    if open_direct_regular_file_in_pinned_directory(
                        &state_entry,
                        &state_entry_handle,
                        &name,
                    )?
                    .is_none()
                    {
                        return Err(invalid_attachment_file(format!(
                            "ZK prover processing receipt disappeared during recovery: {}",
                            state_entry.join(&name).display()
                        )));
                    }
                    has_receipt = true;
                }
                "live" => {
                    let Some(opened) = open_direct_directory_in_pinned_directory(
                        &state_entry,
                        &state_entry_handle,
                        &name,
                    )?
                    else {
                        return Err(invalid_attachment_file(format!(
                            "ZK prover live-reference directory disappeared during recovery: {}",
                            state_entry.join(&name).display()
                        )));
                    };
                    live_handle = Some(opened);
                }
                _ => {
                    return Err(invalid_attachment_file(format!(
                        "ZK prover processing-state entry contains an unexpected path: {name}"
                    )));
                }
            }
        }
        verify_pinned_direct_directory(&state_entry, &state_entry_handle)?;
        if has_receipt && try_load_prover_processing_receipt_locked(&id)?.is_none() {
            return Err(invalid_attachment_file(
                "ZK prover processing receipt disappeared during startup recovery",
            ));
        }
        let live = prover_processing_reference_dir(&id);
        let mut has_live_reference = false;
        let had_live_dir = live_handle.is_some();
        if let Some(live_directory) = live_handle.as_ref() {
            let reference_names = pinned_directory_names_at(
                &live,
                live_directory,
                PROVER_PROCESSING_RECOVERY_MAX_ENTRIES.saturating_sub(scanned),
            )?;
            for name in reference_names {
                scanned = scanned.saturating_add(1);
                if scanned > PROVER_PROCESSING_RECOVERY_MAX_ENTRIES {
                    return Err(invalid_attachment_file(format!(
                        "ZK prover processing-state recovery exceeds {PROVER_PROCESSING_RECOVERY_MAX_ENTRIES} entries"
                    )));
                }
                if open_direct_regular_file_in_pinned_directory(&live, live_directory, &name)?
                    .is_none()
                {
                    return Err(invalid_attachment_file(format!(
                        "ZK prover live-reference entry disappeared during recovery: {}",
                        live.join(&name).display()
                    )));
                }
                if is_attachment_writer_temp_name(&name) {
                    if !remove_direct_regular_file_in_pinned_directory(
                        &live,
                        live_directory,
                        &name,
                    )? {
                        return Err(invalid_attachment_file(format!(
                            "ZK prover live-reference temporary entry disappeared during cleanup: {}",
                            live.join(&name).display()
                        )));
                    }
                    continue;
                }
                let tenant_key = name
                    .strip_suffix(".ref")
                    .and_then(sanitize_tenant_key)
                    .filter(|tenant| format!("{tenant}.ref") == name)
                    .ok_or_else(|| {
                        invalid_attachment_file(format!(
                            "ZK prover live-reference directory contains an unexpected path: {name}"
                        ))
                    })?;
                if !processing_marker_exists_in_pinned_directory(&live, live_directory, &name)? {
                    return Err(invalid_attachment_file(format!(
                        "invalid ZK prover live-reference marker: {}",
                        live.join(&name).display()
                    )));
                }
                let tenant = AttachmentTenant(tenant_key);
                drop(open_attachment_regular_file(&meta_path(&tenant, &id))?);
                drop(open_attachment_regular_file(&bin_path(&tenant, &id))?);
                has_live_reference = true;
            }
            verify_pinned_direct_directory(&live, live_directory)?;
        }
        drop(live_handle);
        if !has_live_reference {
            if had_live_dir {
                remove_dir_if_present(&live)?;
            }
            remove_file_if_present(&prover_processing_receipt_path(&id))?;
            drop(state_entry_handle);
            remove_dir_if_present(&state_entry)?;
        }
    }
    verify_pinned_direct_directory(&state, &state_handle)?;
    verify_pinned_direct_directory(&prover, &prover_handle)?;
    verify_pinned_direct_directory(&base, &base_handle)
}
fn reconcile_attachment_entry_pairs() -> std::io::Result<()> {
    let root = attachments_root_dir();
    let (root_handle, root_names) =
        open_pinned_directory_names(&root, ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES)?.ok_or_else(
            || {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "attachment persistence root directory is missing",
                )
            },
        )?;
    let mut root_entries = 0_u64;
    let mut child_entries = 0_u64;
    for raw_tenant in root_names {
        root_entries = root_entries.saturating_add(1);
        if root_entries > ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES {
            return Err(invalid_attachment_file(format!(
                "attachment entry reconciliation exceeds {ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES} tenant entries"
            )));
        }
        let tenant_key = sanitize_tenant_key(&raw_tenant)
            .filter(|tenant| tenant == &raw_tenant)
            .ok_or_else(|| {
                invalid_attachment_file(format!(
                    "attachment root contains a non-canonical tenant entry: {raw_tenant}"
                ))
            })?;
        let tenant = AttachmentTenant(tenant_key);
        let directory = attachments_dir(&tenant);
        let Some(directory_handle) =
            open_direct_directory_in_pinned_directory(&root, &root_handle, &raw_tenant)?
        else {
            return Err(invalid_attachment_file(format!(
                "attachment tenant directory disappeared during reconciliation: {}",
                directory.display()
            )));
        };
        let child_names = pinned_directory_names_at(
            &directory,
            &directory_handle,
            ATTACHMENT_CHILD_RECOVERY_MAX_ENTRIES.saturating_sub(child_entries),
        )?;
        let mut metadata_ids = BTreeSet::new();
        let mut body_ids = BTreeSet::new();
        for name in child_names {
            child_entries = child_entries.saturating_add(1);
            if child_entries > ATTACHMENT_CHILD_RECOVERY_MAX_ENTRIES {
                return Err(invalid_attachment_file(format!(
                    "attachment entry reconciliation exceeds {ATTACHMENT_CHILD_RECOVERY_MAX_ENTRIES} child entries"
                )));
            }
            let (raw_id, ids) = if let Some(raw_id) = name.strip_suffix(".json") {
                (raw_id, &mut metadata_ids)
            } else if let Some(raw_id) = name.strip_suffix(".bin") {
                (raw_id, &mut body_ids)
            } else {
                return Err(invalid_attachment_file(format!(
                    "attachment store contains an unexpected entry: {name}"
                )));
            };
            let id = sanitize_attachment_id(raw_id)
                .filter(|id| id == raw_id)
                .ok_or_else(|| {
                    invalid_attachment_file(format!(
                        "attachment store contains a non-canonical entry: {name}"
                    ))
                })?;
            if open_direct_regular_file_in_pinned_directory(&directory, &directory_handle, &name)?
                .is_none()
            {
                return Err(invalid_attachment_file(format!(
                    "attachment entry disappeared during reconciliation: {}",
                    directory.join(&name).display()
                )));
            }
            if !ids.insert(id) {
                return Err(invalid_attachment_file(format!(
                    "attachment store contains a duplicate entry: {name}"
                )));
            }
        }
        verify_pinned_direct_directory(&directory, &directory_handle)?;
        if let Some(id) = metadata_ids.difference(&body_ids).next() {
            return Err(invalid_attachment_file(format!(
                "attachment metadata has no body: {id}"
            )));
        }
        for id in body_ids.difference(&metadata_ids) {
            let name = format!("{id}.bin");
            remove_direct_regular_file_in_pinned_directory(&directory, &directory_handle, &name)?;
        }
        for id in &metadata_ids {
            ensure_prover_processing_reference(tenant.as_str(), id)?;
        }
        drop(directory_handle);
        if metadata_ids.is_empty() {
            remove_empty_tenant_dir_if_present(&tenant)?;
        }
    }
    verify_pinned_direct_directory(&root, &root_handle)
}
fn reconcile_attachment_entry_pairs_if_dirty() -> std::io::Result<()> {
    if !ATTACHMENT_ENTRY_PAIRS_DIRTY.load(AtomicOrdering::Acquire) {
        return Ok(());
    }
    reconcile_attachment_entry_pairs()?;
    ATTACHMENT_ENTRY_PAIRS_DIRTY.store(false, AtomicOrdering::Release);
    Ok(())
}
/// Initialize on-disk directories and recover any pending attachment mutation.
///
/// A failure must prevent consumers such as the prover from observing the
/// attachment store until a later recovery attempt succeeds.
///
/// # Errors
///
/// Returns an I/O error if secure directory initialization, temporary-file
/// recovery, pending mutation recovery, or attachment-pair reconciliation fails.
pub fn init_persistence() -> std::io::Result<()> {
    let _store_guard = attachment_store_write_lock();
    ensure_root_dir()?;
    recover_attachment_writer_temps()?;
    recover_attachment_mutation_transaction()?;
    reconcile_attachment_entry_pairs()?;
    ATTACHMENT_ENTRY_PAIRS_DIRTY.store(false, AtomicOrdering::Release);
    {
        let _guard = prover_processing_state_lock().lock();
        recover_prover_processing_writer_temps()?;
    }
    Ok(())
}
fn try_list_all_ids(tenant: &AttachmentTenant) -> std::io::Result<Vec<String>> {
    let directory = attachments_dir(tenant);
    let Some((directory_handle, names)) =
        open_pinned_directory_names(&directory, ATTACHMENT_TENANT_SCAN_MAX_ENTRIES)?
    else {
        return Ok(Vec::new());
    };
    let mut metadata_ids = BTreeSet::new();
    let mut body_ids = BTreeSet::new();
    let mut scanned = 0_u64;
    for name in names {
        scanned = scanned.saturating_add(1);
        if scanned > ATTACHMENT_TENANT_SCAN_MAX_ENTRIES {
            return Err(invalid_attachment_file(format!(
                "attachment listing exceeds {ATTACHMENT_TENANT_SCAN_MAX_ENTRIES} tenant entries"
            )));
        }
        if is_attachment_writer_temp_name(&name) {
            if open_direct_regular_file_in_pinned_directory(&directory, &directory_handle, &name)?
                .is_none()
            {
                return Err(invalid_attachment_file(format!(
                    "attachment temporary entry disappeared during listing: {}",
                    directory.join(&name).display()
                )));
            }
            continue;
        }
        let (raw_id, ids) = if let Some(raw_id) = name.strip_suffix(".json") {
            (raw_id, &mut metadata_ids)
        } else if let Some(raw_id) = name.strip_suffix(".bin") {
            (raw_id, &mut body_ids)
        } else {
            return Err(invalid_attachment_file(format!(
                "attachment store contains an unexpected entry: {name}"
            )));
        };
        let Some(sanitized) =
            sanitize_attachment_id(raw_id).filter(|sanitized| sanitized == raw_id)
        else {
            return Err(invalid_attachment_file(format!(
                "attachment store contains a non-canonical entry: {name}"
            )));
        };
        if open_direct_regular_file_in_pinned_directory(&directory, &directory_handle, &name)?
            .is_none()
        {
            return Err(invalid_attachment_file(format!(
                "attachment entry disappeared during listing: {}",
                directory.join(&name).display()
            )));
        }
        if !ids.insert(sanitized) {
            return Err(invalid_attachment_file(format!(
                "attachment store contains a duplicate entry: {name}"
            )));
        }
    }
    verify_pinned_direct_directory(&directory, &directory_handle)?;
    if let Some(id) = metadata_ids.difference(&body_ids).next() {
        return Err(invalid_attachment_file(format!(
            "attachment metadata has no body: {id}"
        )));
    }
    if let Some(id) = body_ids.difference(&metadata_ids).next() {
        return Err(invalid_attachment_file(format!(
            "attachment body has no metadata: {id}"
        )));
    }
    Ok(metadata_ids.into_iter().collect())
}
#[cfg(test)]
fn list_all_ids(tenant: &AttachmentTenant) -> Vec<String> {
    try_list_all_ids(tenant).expect("list attachment metadata ids")
}
fn try_load_meta_raw(
    tenant: &AttachmentTenant,
    id: &str,
) -> std::io::Result<Option<AttachmentMeta>> {
    let Some(id) = sanitize_attachment_id(id) else {
        return Ok(None);
    };
    let path = meta_path(tenant, &id);
    let buf = match read_bounded_attachment_regular_file(&path, ATTACHMENT_META_FILE_MAX_BYTES) {
        Ok(buf) => buf,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let s = std::str::from_utf8(&buf).map_err(|error| {
        invalid_attachment_file(format!("attachment metadata is not UTF-8: {error}"))
    })?;
    let meta = json::from_json::<AttachmentMeta>(s)
        .map_err(|error| invalid_attachment_file(format!("decode attachment metadata: {error}")))?;
    validate_attachment_metadata_contract(&meta, tenant.as_str(), &id)
        .map_err(invalid_attachment_file)?;
    Ok(Some(meta))
}
fn try_load_meta(tenant: &AttachmentTenant, id: &str) -> std::io::Result<Option<AttachmentMeta>> {
    let Some(id) = sanitize_attachment_id(id) else {
        return Ok(None);
    };
    if attachment_mutation_hides_attachment(tenant, &id)? {
        return Ok(None);
    }
    try_load_meta_raw(tenant, &id)
}
/// Load validated attachment metadata from one canonical tenant namespace.
///
/// # Errors
///
/// Returns an error for invalid identities, unsafe or unreadable storage, or
/// metadata that violates the persisted attachment contract.
pub(super) fn try_load_meta_for_tenant_key(
    tenant_key: &str,
    id: &str,
) -> std::io::Result<Option<AttachmentMeta>> {
    let tenant_key = sanitize_tenant_key(tenant_key)
        .filter(|clean| clean == tenant_key)
        .ok_or_else(|| invalid_attachment_file("invalid attachment tenant key"))?;
    let id = sanitize_attachment_id(id)
        .filter(|clean| clean == id)
        .ok_or_else(|| invalid_attachment_file("invalid attachment id"))?;
    try_load_meta(&AttachmentTenant(tenant_key), &id)
}
fn save_meta(tenant: &AttachmentTenant, meta: &AttachmentMeta) -> std::io::Result<()> {
    let id = sanitize_attachment_id(&meta.id).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid attachment metadata id",
        )
    })?;
    let body = json::to_json_pretty(meta)
        .map_err(|error| invalid_attachment_file(format!("encode attachment metadata: {error}")))?;
    if body.len() as u64 > ATTACHMENT_META_FILE_MAX_BYTES {
        return Err(invalid_attachment_file(format!(
            "attachment metadata exceeds the {ATTACHMENT_META_FILE_MAX_BYTES}-byte persistence limit"
        )));
    }
    validate_attachment_metadata_contract(meta, tenant.as_str(), &id)
        .map_err(invalid_attachment_file)?;
    let path = meta_path(tenant, &id);
    ensure_attachment_dirs_durable(tenant)?;
    persist_bytes_atomically(&path, body.as_bytes(), ".tmp")?;
    ensure_prover_processing_reference(tenant.as_str(), &id)
}
fn persist_body(tenant: &AttachmentTenant, id: &str, body: &[u8]) -> std::io::Result<()> {
    let id = sanitize_attachment_id(id).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid attachment body id",
        )
    })?;
    let path = bin_path(tenant, &id);
    ensure_attachment_dirs_durable(tenant)?;
    persist_bytes_atomically(&path, body, ".tmp")
}
#[cfg(unix)]
fn remove_empty_tenant_dir_if_present(tenant: &AttachmentTenant) -> std::io::Result<()> {
    match remove_dir_if_present(&attachments_dir(tenant)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(error) => Err(error),
    }
}
#[cfg(windows)]
fn remove_empty_tenant_dir_if_present(tenant: &AttachmentTenant) -> std::io::Result<()> {
    match remove_direct_empty_directory_if_present(&attachments_dir(tenant)) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(error) => Err(error),
    }
}
#[cfg(not(any(unix, windows)))]
fn remove_empty_tenant_dir_if_present(_tenant: &AttachmentTenant) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure attachment tenant-directory removal is unsupported on this platform",
    ))
}
fn validate_attachment_delete_transaction(
    transaction: &AttachmentDeleteTransaction,
) -> std::io::Result<()> {
    if transaction.version != ATTACHMENT_DELETE_TRANSACTION_VERSION {
        return Err(invalid_attachment_file(
            "unsupported attachment delete transaction version",
        ));
    }
    sanitize_tenant_key(&transaction.tenant)
        .filter(|tenant| tenant == &transaction.tenant)
        .ok_or_else(|| invalid_attachment_file("invalid attachment delete transaction tenant"))?;
    sanitize_attachment_id(&transaction.id)
        .filter(|id| id == &transaction.id)
        .ok_or_else(|| invalid_attachment_file("invalid attachment delete transaction id"))?;
    Ok(())
}
fn validate_attachment_mutation_transaction(
    transaction: &AttachmentMutationTransaction,
) -> std::io::Result<()> {
    match transaction {
        AttachmentMutationTransaction::Write(transaction) => {
            validate_attachment_quota_transaction(transaction)
        }
        AttachmentMutationTransaction::Delete(transaction) => {
            validate_attachment_delete_transaction(transaction)
        }
    }
}
fn persist_attachment_mutation_transaction(
    transaction: &AttachmentMutationTransaction,
) -> std::io::Result<()> {
    validate_attachment_mutation_transaction(transaction)?;
    let body = json::to_json_pretty(transaction).map_err(|error| {
        invalid_attachment_file(format!("encode attachment mutation transaction: {error}"))
    })?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > ATTACHMENT_MUTATION_TRANSACTION_MAX_BYTES {
        return Err(invalid_attachment_file(format!(
            "attachment mutation transaction exceeds the {ATTACHMENT_MUTATION_TRANSACTION_MAX_BYTES}-byte persistence limit"
        )));
    }
    let path = attachment_mutation_transaction_path();
    ATTACHMENT_MUTATION_DIRECTORY_DIRTY.store(true, AtomicOrdering::Release);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "an attachment mutation transaction is already pending",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    ensure_attachment_mutation_transaction_dir_durable()?;
    persist_bytes_atomically(
        &path,
        body.as_bytes(),
        ATTACHMENT_MUTATION_TRANSACTION_TEMP_PREFIX,
    )
}
fn load_attachment_mutation_transaction() -> std::io::Result<Option<AttachmentMutationTransaction>>
{
    let path = attachment_mutation_transaction_path();
    let body = match read_bounded_attachment_regular_file(
        &path,
        ATTACHMENT_MUTATION_TRANSACTION_MAX_BYTES,
    ) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if ATTACHMENT_MUTATION_DIRECTORY_DIRTY.load(AtomicOrdering::Acquire) {
                sync_nearest_existing_parent(&path)?;
                ATTACHMENT_MUTATION_DIRECTORY_DIRTY.store(false, AtomicOrdering::Release);
            }
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let text = std::str::from_utf8(&body).map_err(|error| {
        invalid_attachment_file(format!(
            "decode attachment mutation transaction UTF-8: {error}"
        ))
    })?;
    let transaction = json::from_json::<AttachmentMutationTransaction>(text).map_err(|error| {
        invalid_attachment_file(format!("decode attachment mutation transaction: {error}"))
    })?;
    validate_attachment_mutation_transaction(&transaction)?;
    Ok(Some(transaction))
}
fn clear_attachment_mutation_transaction() -> std::io::Result<()> {
    ATTACHMENT_MUTATION_DIRECTORY_DIRTY.store(true, AtomicOrdering::Release);
    remove_file_if_present(&attachment_mutation_transaction_path())?;
    ATTACHMENT_MUTATION_DIRECTORY_DIRTY.store(false, AtomicOrdering::Release);
    Ok(())
}
fn persist_attachment_delete_transaction(
    transaction: &AttachmentDeleteTransaction,
) -> std::io::Result<()> {
    persist_attachment_mutation_transaction(&AttachmentMutationTransaction::Delete(
        transaction.clone(),
    ))
}
fn attachment_mutation_hides_attachment(
    tenant: &AttachmentTenant,
    id: &str,
) -> std::io::Result<bool> {
    Ok(match load_attachment_mutation_transaction()? {
        Some(AttachmentMutationTransaction::Delete(transaction)) => {
            transaction.tenant == tenant.as_str() && transaction.id == id
        }
        Some(AttachmentMutationTransaction::Write(transaction)) => {
            transaction.tenant == tenant.as_str() && transaction.incoming_meta.id == id
        }
        None => false,
    })
}
fn apply_attachment_delete_transaction(
    transaction: &AttachmentDeleteTransaction,
) -> std::io::Result<()> {
    validate_attachment_delete_transaction(transaction)?;
    let _guard = prover_processing_state_lock().lock();
    if delete_target_pair_is_complete(&transaction.tenant, &transaction.id)?
        && !delete_target_processing_reference_exists(&transaction.tenant, &transaction.id)?
    {
        return Err(invalid_attachment_file(
            "complete attachment pair has no durable processing reference",
        ));
    }
    // Validate the complete processing namespace while the attachment pair is
    // still present. If cleanup later fails, the durable delete intent keeps
    // this attachment invisible until recovery finishes the transaction.
    processing_reference_dir_has_shards_except(&transaction.id, Some(transaction.tenant.as_str()))?;
    #[cfg(unix)]
    remove_attachment_pair_pinned(&transaction.tenant, &transaction.id)?;
    #[cfg(not(unix))]
    {
        let tenant = AttachmentTenant(transaction.tenant.clone());
        verify_direct_directory(&attachments_root_dir())?;
        match verify_direct_directory(&attachments_dir(&tenant)) {
            Ok(()) => {
                remove_file_if_present(&meta_path(&tenant, &transaction.id))?;
                remove_file_if_present(&bin_path(&tenant, &transaction.id))?;
                remove_empty_tenant_dir_if_present(&tenant)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                sync_directory(&attachments_root_dir())?;
            }
            Err(error) => return Err(error),
        }
    }
    remove_prover_processing_reference_locked(&transaction.tenant, &transaction.id)
}
fn delete_attachment_files(tenant: &AttachmentTenant, id: &str) -> std::io::Result<()> {
    let clean = sanitize_attachment_id(id)
        .filter(|clean| clean == id)
        .ok_or_else(|| invalid_attachment_file("invalid attachment id for deletion"))?;
    let transaction = AttachmentDeleteTransaction {
        version: ATTACHMENT_DELETE_TRANSACTION_VERSION,
        tenant: tenant.as_str().to_owned(),
        id: clean,
    };
    persist_attachment_delete_transaction(&transaction)?;
    ATTACHMENT_ENTRY_PAIRS_DIRTY.store(true, AtomicOrdering::Release);
    let result = (|| {
        apply_attachment_delete_transaction(&transaction)?;
        clear_attachment_mutation_transaction()
    })();
    if result.is_ok() {
        ATTACHMENT_ENTRY_PAIRS_DIRTY.store(false, AtomicOrdering::Release);
    }
    result
}
fn validate_attachment_quota_transaction(
    transaction: &AttachmentQuotaTransaction,
) -> std::io::Result<()> {
    if transaction.version != ATTACHMENT_QUOTA_TRANSACTION_VERSION {
        return Err(invalid_attachment_file(
            "unsupported attachment quota transaction version",
        ));
    }
    let tenant = sanitize_tenant_key(&transaction.tenant)
        .filter(|tenant| tenant == &transaction.tenant)
        .ok_or_else(|| invalid_attachment_file("invalid attachment quota transaction tenant"))?;
    let incoming_id = sanitize_attachment_id(&transaction.incoming_meta.id)
        .filter(|id| id == &transaction.incoming_meta.id)
        .ok_or_else(|| {
            invalid_attachment_file("invalid attachment quota transaction incoming id")
        })?;
    validate_attachment_metadata_contract(&transaction.incoming_meta, &tenant, &incoming_id)
        .map_err(invalid_attachment_file)?;
    if let Some(previous) = &transaction.previous_meta {
        validate_attachment_metadata_contract(previous, &tenant, &incoming_id)
            .map_err(invalid_attachment_file)?;
    }
    let victim_count = u64::try_from(transaction.victim_ids.len()).unwrap_or(u64::MAX);
    if victim_count > ATTACHMENT_META_SCAN_MAX_FILES {
        return Err(invalid_attachment_file(format!(
            "attachment write transaction exceeds {ATTACHMENT_META_SCAN_MAX_FILES} victims"
        )));
    }
    let mut unique_victims = BTreeSet::new();
    for victim_id in &transaction.victim_ids {
        let victim_id = sanitize_attachment_id(victim_id)
            .filter(|id| id == victim_id)
            .ok_or_else(|| {
                invalid_attachment_file("invalid attachment quota transaction victim id")
            })?;
        if victim_id == incoming_id {
            return Err(invalid_attachment_file(
                "attachment quota transaction cannot evict its incoming attachment",
            ));
        }
        if !unique_victims.insert(victim_id) {
            return Err(invalid_attachment_file(
                "attachment quota transaction contains a duplicate victim",
            ));
        }
    }
    Ok(())
}
fn persist_attachment_quota_transaction(
    transaction: &AttachmentQuotaTransaction,
) -> std::io::Result<()> {
    persist_attachment_mutation_transaction(&AttachmentMutationTransaction::Write(Box::new(
        transaction.clone(),
    )))
}
fn load_attachment_quota_transaction() -> std::io::Result<Option<AttachmentQuotaTransaction>> {
    match load_attachment_mutation_transaction()? {
        None => Ok(None),
        Some(AttachmentMutationTransaction::Write(transaction)) => Ok(Some(*transaction)),
        Some(AttachmentMutationTransaction::Delete(_)) => Err(invalid_attachment_file(
            "pending attachment mutation is not a write transaction",
        )),
    }
}
fn attachment_quota_incoming_is_complete(
    transaction: &AttachmentQuotaTransaction,
) -> std::io::Result<bool> {
    let tenant = AttachmentTenant(transaction.tenant.clone());
    let Some(current_meta) = try_load_meta_raw(&tenant, &transaction.incoming_meta.id)? else {
        return Ok(false);
    };
    if current_meta != transaction.incoming_meta {
        return Ok(false);
    }
    let body = match read_bounded_attachment_regular_file(
        &bin_path(&tenant, &transaction.incoming_meta.id),
        transaction.incoming_meta.size,
    ) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    validate_attachment_body_contract(&transaction.incoming_meta, &body)
        .map_err(invalid_attachment_file)?;
    // A previous metadata rename may have succeeded while its directory flush
    // failed. Re-flush the complete pair's tenant directory before treating
    // the write as committed during journal replay.
    sync_directory(&attachments_dir(&tenant))?;
    // A metadata rename can complete before its live-reference marker. Repair
    // that final durable side effect before any quota victim is removed.
    ensure_prover_processing_reference(&transaction.tenant, &transaction.incoming_meta.id)?;
    Ok(true)
}
fn rollback_attachment_quota_transaction(
    transaction: &AttachmentQuotaTransaction,
) -> std::io::Result<()> {
    let tenant = AttachmentTenant(transaction.tenant.clone());
    if let Some(previous_meta) = &transaction.previous_meta {
        let body = read_bounded_attachment_regular_file(
            &bin_path(&tenant, &previous_meta.id),
            previous_meta.size,
        )?;
        validate_attachment_body_contract(previous_meta, &body).map_err(invalid_attachment_file)?;
        save_meta(&tenant, previous_meta)?;
    } else {
        apply_attachment_delete_transaction(&AttachmentDeleteTransaction {
            version: ATTACHMENT_DELETE_TRANSACTION_VERSION,
            tenant: transaction.tenant.clone(),
            id: transaction.incoming_meta.id.clone(),
        })?;
    }
    Ok(())
}
fn finalize_attachment_quota_transaction(
    transaction: &AttachmentQuotaTransaction,
) -> std::io::Result<()> {
    for victim_id in &transaction.victim_ids {
        apply_attachment_delete_transaction(&AttachmentDeleteTransaction {
            version: ATTACHMENT_DELETE_TRANSACTION_VERSION,
            tenant: transaction.tenant.clone(),
            id: victim_id.clone(),
        })?;
    }
    Ok(())
}
/// Recover one quota transaction while the caller holds the attachment quota mutex.
fn recover_attachment_quota_transaction() -> std::io::Result<bool> {
    let Some(transaction) = load_attachment_quota_transaction()? else {
        return Ok(false);
    };
    if attachment_quota_incoming_is_complete(&transaction)? {
        finalize_attachment_quota_transaction(&transaction)?;
    } else {
        rollback_attachment_quota_transaction(&transaction)?;
    }
    clear_attachment_mutation_transaction()?;
    Ok(true)
}
fn recover_attachment_mutation_transaction() -> std::io::Result<bool> {
    let Some(transaction) = load_attachment_mutation_transaction()? else {
        return Ok(false);
    };
    match transaction {
        AttachmentMutationTransaction::Write(transaction) => {
            if attachment_quota_incoming_is_complete(&transaction)? {
                finalize_attachment_quota_transaction(&transaction)?;
            } else {
                rollback_attachment_quota_transaction(&transaction)?;
            }
        }
        AttachmentMutationTransaction::Delete(transaction) => {
            apply_attachment_delete_transaction(&transaction)?;
        }
    }
    clear_attachment_mutation_transaction()?;
    Ok(true)
}
fn prepare_attachment_mutation_locked() -> std::io::Result<()> {
    recover_attachment_mutation_transaction()?;
    reconcile_attachment_entry_pairs_if_dirty()
}
fn hash_identity_hex(label: &str, value: &str) -> String {
    let mut buf = Vec::with_capacity(label.len() + 1 + value.len());
    buf.extend_from_slice(label.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(value.as_bytes());
    let hash = iroha_crypto::Hash::new(&buf);
    let digest: [u8; 32] = hash.into();
    hex::encode::<[u8; 32]>(digest)
}
/// Canonicalise a tenant key to lowercase hex, rejecting any other shape.
pub(crate) fn sanitize_tenant_key(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() != TENANT_KEY_HEX_LEN {
        return None;
    }
    if trimmed.bytes().any(|b| !b.is_ascii_hexdigit()) {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}
/// Canonicalise an attachment identifier to lowercase hex, rejecting any other shape.
pub(crate) fn sanitize_attachment_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() != ATTACHMENT_ID_HEX_LEN {
        return None;
    }
    if trimmed.bytes().any(|b| !b.is_ascii_hexdigit()) {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SanitizeRejectReason {
    Type,
    Expansion,
    Sandbox,
    Checksum,
}
impl SanitizeRejectReason {
    fn label(self) -> &'static str {
        match self {
            SanitizeRejectReason::Type => "type",
            SanitizeRejectReason::Expansion => "expansion",
            SanitizeRejectReason::Sandbox => "sandbox",
            SanitizeRejectReason::Checksum => "checksum",
        }
    }
    fn from_label(label: &str) -> Option<Self> {
        match label {
            "type" => Some(SanitizeRejectReason::Type),
            "expansion" => Some(SanitizeRejectReason::Expansion),
            "sandbox" => Some(SanitizeRejectReason::Sandbox),
            "checksum" => Some(SanitizeRejectReason::Checksum),
            _ => None,
        }
    }
    fn status_code(self) -> StatusCode {
        match self {
            SanitizeRejectReason::Type => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            SanitizeRejectReason::Expansion => StatusCode::PAYLOAD_TOO_LARGE,
            SanitizeRejectReason::Sandbox | SanitizeRejectReason::Checksum => {
                StatusCode::BAD_REQUEST
            }
        }
    }
}
#[derive(Debug)]
struct SanitizeError {
    reason: SanitizeRejectReason,
    message: String,
}
impl SanitizeError {
    fn new(reason: SanitizeRejectReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
    fn into_wire(self) -> SanitizeErrorWire {
        SanitizeErrorWire {
            reason: self.reason.label().to_string(),
            message: self.message,
        }
    }
    fn from_wire(wire: SanitizeErrorWire) -> Self {
        let reason =
            SanitizeRejectReason::from_label(&wire.reason).unwrap_or(SanitizeRejectReason::Sandbox);
        Self {
            reason,
            message: wire.message,
        }
    }
}
#[derive(Debug, Clone)]
struct SanitizerConfig {
    allowed_mime_types: Vec<String>,
    max_expanded_bytes: u64,
    max_archive_depth: u32,
    timeout: Duration,
    mode: AttachmentSanitizerMode,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::zk_attachments::SanitizerSummary")]
#[derive(Debug, Clone, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize)]
struct SanitizerSummary {
    sniffed_type: String,
    expanded_bytes: u64,
    archive_depth: u32,
    sandboxed: bool,
}
#[derive(Debug, Clone)]
struct SanitizerOutcome {
    summary: SanitizerSummary,
    sanitized_body: Vec<u8>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::zk_attachments::SanitizeErrorWire")]
#[derive(Debug, Clone, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize)]
struct SanitizeErrorWire {
    reason: String,
    message: String,
}
#[derive(
    Debug,
    Clone,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii::zk_attachments::SanitizerRequest")]
struct SanitizerRequest {
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    declared_type: Option<String>,
    body: Vec<u8>,
    allowed_mime_types: Vec<String>,
    max_expanded_bytes: u64,
    max_archive_depth: u32,
    timeout_ms: u64,
}
#[derive(
    Debug,
    Clone,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii::zk_attachments::SanitizerResponse")]
enum SanitizerResponse {
    /// Sanitization succeeded with one summary and exact replacement body.
    Accepted {
        summary: SanitizerSummary,
        sanitized_body: Vec<u8>,
    },
    /// Sanitization rejected the request.
    Rejected { error: SanitizeErrorWire },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SniffedFormat {
    Norito,
    Json,
    Zk1,
    Gzip,
    Zstd,
    Unknown,
}
#[cfg(test)]
struct SanitizerWorkerTestGate {
    entered: Arc<tokio::sync::Notify>,
    release: SyncMutex<mpsc::Receiver<()>>,
}
#[cfg(test)]
fn sanitizer_worker_test_gate() -> &'static SyncMutex<Option<Arc<SanitizerWorkerTestGate>>> {
    static GATE: OnceLock<SyncMutex<Option<Arc<SanitizerWorkerTestGate>>>> = OnceLock::new();
    GATE.get_or_init(|| SyncMutex::new(None))
}
#[cfg(test)]
pub(crate) struct SanitizerWorkerTestGateGuard;
#[cfg(test)]
impl Drop for SanitizerWorkerTestGateGuard {
    fn drop(&mut self) {
        *sanitizer_worker_test_gate().lock() = None;
    }
}
#[cfg(test)]
pub(crate) fn install_sanitizer_worker_test_gate(
    entered: Arc<tokio::sync::Notify>,
    release: mpsc::Receiver<()>,
) -> SanitizerWorkerTestGateGuard {
    let mut slot = sanitizer_worker_test_gate().lock();
    assert!(
        slot.is_none(),
        "sanitizer worker test gate already installed"
    );
    *slot = Some(Arc::new(SanitizerWorkerTestGate {
        entered,
        release: SyncMutex::new(release),
    }));
    SanitizerWorkerTestGateGuard
}
#[cfg(test)]
fn wait_for_sanitizer_worker_test_gate() {
    let gate = sanitizer_worker_test_gate().lock().clone();
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release
            .lock()
            .recv()
            .expect("release sanitizer worker test gate");
    }
}
#[derive(Debug, Clone, Copy)]
struct AttachmentQuotaLimits {
    per_tenant_max_count: u64,
    per_tenant_max_bytes: u64,
    global_max_count: u64,
    global_max_bytes: u64,
}
#[derive(Debug)]
struct AttachmentQuotaScanBudget {
    metadata_records: u64,
    child_entries: u64,
    child_entry_limit: u64,
}
impl AttachmentQuotaScanBudget {
    fn new(child_entry_limit: u64) -> Self {
        Self {
            metadata_records: 0,
            child_entries: 0,
            child_entry_limit,
        }
    }
}
fn quota_scan_entry_within_limit(scanned: &mut u64, limit: u64) -> bool {
    *scanned = (*scanned).saturating_add(1);
    *scanned <= limit
}
fn quota_metas_for_tenant(
    tenant: &AttachmentTenant,
    scan: &mut AttachmentQuotaScanBudget,
) -> std::io::Result<Vec<AttachmentMeta>> {
    let directory = attachments_dir(tenant);
    let Some(directory_handle) = open_pinned_direct_directory(&directory)? else {
        return Ok(Vec::new());
    };
    quota_metas_for_tenant_in(tenant, &directory, &directory_handle, scan)
}
fn quota_metas_for_tenant_in(
    tenant: &AttachmentTenant,
    directory: &Path,
    directory_handle: &fs::File,
    scan: &mut AttachmentQuotaScanBudget,
) -> std::io::Result<Vec<AttachmentMeta>> {
    let names = pinned_directory_names_at(
        directory,
        directory_handle,
        scan.child_entry_limit.saturating_sub(scan.child_entries),
    )?;
    let mut metas = Vec::new();
    for name in names {
        if !quota_scan_entry_within_limit(&mut scan.child_entries, scan.child_entry_limit) {
            return Err(invalid_attachment_file(format!(
                "attachment quota scan exceeds {} aggregate tenant child entries",
                scan.child_entry_limit
            )));
        }
        if open_direct_regular_file_in_pinned_directory(directory, directory_handle, &name)?
            .is_none()
        {
            return Err(invalid_attachment_file(format!(
                "attachment entry disappeared during quota scan: {}",
                directory.join(&name).display()
            )));
        }
        let Some(raw_id) = name.strip_suffix(".json") else {
            continue;
        };
        let id = sanitize_attachment_id(raw_id)
            .filter(|id| id == raw_id)
            .ok_or_else(|| {
                invalid_attachment_file(format!(
                    "attachment quota scan found a non-canonical metadata entry: {name}"
                ))
            })?;
        scan.metadata_records = scan.metadata_records.saturating_add(1);
        if scan.metadata_records > ATTACHMENT_META_SCAN_MAX_FILES {
            return Err(invalid_attachment_file(format!(
                "attachment quota scan exceeds {ATTACHMENT_META_SCAN_MAX_FILES} metadata records"
            )));
        }
        let meta = try_load_meta(tenant, &id)?.ok_or_else(|| {
            invalid_attachment_file(format!(
                "attachment quota scan found invalid metadata for {id}"
            ))
        })?;
        metas.push(meta);
    }
    verify_pinned_direct_directory(directory, directory_handle)?;
    Ok(metas)
}
fn other_tenants_quota_usage(
    submitting_tenant: &AttachmentTenant,
    scan: &mut AttachmentQuotaScanBudget,
) -> std::io::Result<(u64, u64)> {
    let root = attachments_root_dir();
    let Some((root_handle, root_names)) =
        open_pinned_directory_names(&root, ATTACHMENT_META_SCAN_MAX_FILES)?
    else {
        return Ok((0, 0));
    };
    let mut count = 0_u64;
    let mut bytes = 0_u64;
    let mut root_entries_scanned = 0_u64;
    for raw_tenant in root_names {
        if !quota_scan_entry_within_limit(&mut root_entries_scanned, ATTACHMENT_META_SCAN_MAX_FILES)
        {
            return Err(invalid_attachment_file(format!(
                "attachment quota root scan exceeds {ATTACHMENT_META_SCAN_MAX_FILES} entries"
            )));
        }
        let tenant_key = sanitize_tenant_key(&raw_tenant)
            .filter(|tenant| tenant == &raw_tenant)
            .ok_or_else(|| {
                invalid_attachment_file(format!(
                    "attachment root contains a non-canonical tenant entry: {raw_tenant}"
                ))
            })?;
        let tenant = AttachmentTenant(tenant_key);
        let directory = attachments_dir(&tenant);
        let Some(directory_handle) =
            open_direct_directory_in_pinned_directory(&root, &root_handle, &raw_tenant)?
        else {
            return Err(invalid_attachment_file(format!(
                "attachment tenant directory disappeared during quota scan: {}",
                directory.display()
            )));
        };
        if tenant.as_str() == submitting_tenant.as_str() {
            verify_pinned_direct_directory(&directory, &directory_handle)?;
            continue;
        }
        for meta in quota_metas_for_tenant_in(&tenant, &directory, &directory_handle, scan)? {
            count = count.saturating_add(1);
            bytes = bytes.saturating_add(meta.size);
        }
    }
    verify_pinned_direct_directory(&root, &root_handle)?;
    Ok((count, bytes))
}
fn plan_attachment_quota_admission(
    tenant: &AttachmentTenant,
    incoming_id: &str,
    incoming_size: u64,
) -> std::io::Result<Option<Vec<String>>> {
    let limits = quota_limits_cfg();
    let mut scan = AttachmentQuotaScanBudget::new(ATTACHMENT_TENANT_SCAN_MAX_ENTRIES);
    let mut metas = quota_metas_for_tenant(tenant, &mut scan)?;
    let current_count = metas.len();
    // A content-addressed repost replaces the same tenant-local entry. Do not
    // count or evict it as if another attachment were being added: doing so
    // would also discard the durable prover-processing reference for content
    // that remains live after this request.
    metas.retain(|meta| meta.id != incoming_id);
    metas.sort_by(|a, b| {
        a.created_ms
            .cmp(&b.created_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut total_bytes = metas
        .iter()
        .fold(0_u64, |total, meta| total.saturating_add(meta.size));
    let mut count_after_add = u64::try_from(metas.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let per_tenant_max_count = if limits.per_tenant_max_count == 0 {
        u64::MAX
    } else {
        limits.per_tenant_max_count
    };
    let per_tenant_max_bytes = if limits.per_tenant_max_bytes == 0 {
        u64::MAX
    } else {
        limits.per_tenant_max_bytes
    };
    let (other_tenants_count, other_tenants_bytes) = other_tenants_quota_usage(tenant, &mut scan)?;
    let mut idx = 0usize;
    let mut removed_ids: Vec<String> = Vec::new();
    while (count_after_add > per_tenant_max_count
        || total_bytes.saturating_add(incoming_size) > per_tenant_max_bytes
        || other_tenants_count.saturating_add(count_after_add) > limits.global_max_count
        || other_tenants_bytes
            .saturating_add(total_bytes)
            .saturating_add(incoming_size)
            > limits.global_max_bytes)
        && idx < metas.len()
    {
        let victim = &metas[idx];
        removed_ids.push(victim.id.clone());
        total_bytes = total_bytes.saturating_sub(victim.size);
        count_after_add = count_after_add.saturating_sub(1);
        idx += 1;
    }
    let exceeds_per_tenant = count_after_add > per_tenant_max_count
        || total_bytes.saturating_add(incoming_size) > per_tenant_max_bytes;
    let exceeds_global = other_tenants_count.saturating_add(count_after_add)
        > limits.global_max_count
        || other_tenants_bytes
            .saturating_add(total_bytes)
            .saturating_add(incoming_size)
            > limits.global_max_bytes;
    if exceeds_per_tenant || exceeds_global {
        warn!(
            tenant = tenant.as_str(),
            per_tenant_max_count,
            per_tenant_max_bytes,
            global_max_count = limits.global_max_count,
            global_max_bytes = limits.global_max_bytes,
            current_count,
            current_bytes = total_bytes,
            other_tenants_count,
            other_tenants_bytes,
            incoming_bytes = incoming_size,
            "rejecting attachment: unable to make room within attachment quotas"
        );
        return Ok(None);
    }
    // Feasibility is established without mutating retained state. The caller
    // must durably commit the incoming attachment before deleting these
    // tenant-local victims, so a later write failure or process stop cannot
    // discard old data while leaving no replacement.
    if !removed_ids.is_empty() {
        debug!(
            tenant = tenant.as_str(),
            planned_evictions = removed_ids.len(),
            per_tenant_max_count,
            per_tenant_max_bytes,
            global_max_count = limits.global_max_count,
            global_max_bytes = limits.global_max_bytes,
            count_after_add,
            bytes_after_removal = total_bytes,
            incoming_bytes = incoming_size,
            "planned tenant-local attachment evictions after durable commit"
        );
    }
    Ok(Some(removed_ids))
}
/// POST /v1/zk/attachments — store an attachment and return its metadata.
pub async fn handle_post_attachment(
    tenant: AttachmentTenant,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    handle_post_attachment_inner(tenant, headers, body, None).await
}
pub(crate) async fn handle_post_attachment_with_admission(
    tenant: AttachmentTenant,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
    admission: crate::ProofBodyAdmissionLease,
) -> axum::response::Response {
    handle_post_attachment_inner(tenant, headers, body, Some(admission)).await
}
async fn handle_post_attachment_inner(
    tenant: AttachmentTenant,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
    admission: Option<crate::ProofBodyAdmissionLease>,
) -> axum::response::Response {
    // Enforce size cap
    if body.len() > max_bytes_cfg() {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("attachment too large (>{} bytes)", max_bytes_cfg()),
        )
            .into_response();
    }
    let raw_hash = {
        let h = iroha_crypto::Hash::new(&body);
        hex::encode::<[u8; 32]>(h.into())
    };
    let declared_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(normalize_mime);
    let sanitize_start = Instant::now();
    let sanitize_result = sanitize_attachment(declared_type.clone(), body.clone(), admission).await;
    let sanitize_ms = sanitize_start.elapsed().as_millis() as u64;
    let telemetry = telemetry_handle();
    telemetry.with_metrics(|tel| tel.observe_torii_attachment_sanitize_ms(sanitize_ms));
    let sanitized = match sanitize_result {
        Ok(outcome) => outcome,
        Err(err) => {
            telemetry.with_metrics(|tel| tel.inc_torii_attachment_reject(err.reason.label()));
            info!(
                attachment_raw_hash = %raw_hash,
                reason = err.reason.label(),
                "rejecting attachment after sanitization"
            );
            debug!(
                attachment_raw_hash = %raw_hash,
                error = %err.message,
                "attachment sanitize detail"
            );
            return (err.reason.status_code(), err.message).into_response();
        }
    };
    let SanitizerOutcome {
        summary: sanitized_summary,
        sanitized_body,
    } = sanitized;
    let stored_size = sanitized_body.len() as u64;
    let max_bytes = max_bytes_u64_cfg();
    if stored_size > max_bytes {
        warn!(
            tenant = tenant.as_str(),
            limit_bytes = max_bytes,
            body_bytes = stored_size,
            "rejecting attachment: sanitized body exceeds per-item byte cap"
        );
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("sanitized attachment exceeds max bytes (>{max_bytes} bytes)"),
        )
            .into_response();
    }
    let per_tenant_max_bytes = per_tenant_max_bytes_cfg();
    if per_tenant_max_bytes > 0 && stored_size > per_tenant_max_bytes {
        warn!(
            tenant = tenant.as_str(),
            limit_bytes = per_tenant_max_bytes,
            body_bytes = stored_size,
            "rejecting attachment: exceeds per-tenant byte cap"
        );
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "attachment exceeds per-tenant max bytes (>{} bytes)",
                per_tenant_max_bytes
            ),
        )
            .into_response();
    }
    let global_max_bytes = global_max_bytes_cfg();
    if stored_size > global_max_bytes {
        warn!(
            tenant = tenant.as_str(),
            limit_bytes = global_max_bytes,
            body_bytes = stored_size,
            "rejecting attachment: exceeds node-global byte cap"
        );
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("attachment exceeds node-global max bytes (>{global_max_bytes} bytes)"),
        )
            .into_response();
    }
    let zk1_tags = if sanitized_body.starts_with(b"ZK1\0") {
        match parse_zk1_tags(&sanitized_body) {
            Ok(tags) => (!tags.is_empty()).then_some(tags),
            Err(error) => {
                telemetry.with_metrics(|tel| tel.inc_torii_attachment_reject("format"));
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid ZK1 envelope: {error}"),
                )
                    .into_response();
            }
        }
    } else {
        None
    };
    let id = {
        let h = iroha_crypto::Hash::new(&sanitized_body);
        hex::encode::<[u8; 32]>(h.into())
    };
    let _guard = quota_lock().lock().await;
    let _store_guard = attachment_store_write_lock();
    if let Err(error) = prepare_attachment_mutation_locked() {
        warn!(
            tenant = tenant.as_str(),
            %error,
            "rejecting attachment: persistence recovery failed"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "attachment persistence recovery failed".to_string(),
        )
            .into_response();
    }
    let previous_meta = match try_load_meta(&tenant, &id) {
        Ok(previous_meta) => previous_meta,
        Err(error) => {
            warn!(
                tenant = tenant.as_str(),
                attachment_id = %id,
                %error,
                "rejecting attachment: existing metadata could not be loaded"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "attachment storage is unavailable".to_string(),
            )
                .into_response();
        }
    };
    let eviction_ids = match plan_attachment_quota_admission(&tenant, &id, stored_size) {
        Ok(Some(eviction_ids)) => eviction_ids,
        Ok(None) => {
            warn!(
                tenant = tenant.as_str(),
                body_bytes = stored_size,
                "rejecting attachment: node-global quota exceeded"
            );
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "node-global attachment quota exceeded".to_string(),
            )
                .into_response();
        }
        Err(error) => {
            warn!(
                tenant = tenant.as_str(),
                body_bytes = stored_size,
                %error,
                "rejecting attachment: quota accounting failed"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "attachment quota accounting failed".to_string(),
            )
                .into_response();
        }
    };
    let sha256 = Sha256::digest(&sanitized_body);
    let hashes = AttachmentHashes {
        blake2b_256: id.clone(),
        sha256: hex::encode(sha256),
    };
    let meta = AttachmentMeta {
        id: id.clone(),
        content_type: sanitized_summary.sniffed_type.clone(),
        size: stored_size,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant.as_str().to_string()),
        provenance: Some(AttachmentProvenance {
            declared_type,
            sniffed_type: sanitized_summary.sniffed_type,
            hashes,
            sanitizer: AttachmentSanitizerVerdict {
                verdict: "accepted".to_string(),
                expanded_bytes: sanitized_summary.expanded_bytes,
                archive_depth: sanitized_summary.archive_depth,
                sandboxed: sanitized_summary.sandboxed,
            },
        }),
        zk1_tags,
    };
    if let Some(previous_meta) = &previous_meta {
        let previous_body =
            match read_bounded_attachment_regular_file(&bin_path(&tenant, &id), previous_meta.size)
            {
                Ok(body) => body,
                Err(error) => {
                    warn!(
                        tenant = tenant.as_str(),
                        attachment_id = %id,
                        %error,
                        "rejecting attachment: existing replacement body is not recoverable"
                    );
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "existing attachment is not recoverable".to_string(),
                    )
                        .into_response();
                }
            };
        if let Err(error) = validate_attachment_body_contract(previous_meta, &previous_body) {
            warn!(
                tenant = tenant.as_str(),
                attachment_id = %id,
                %error,
                "rejecting attachment: existing replacement body failed validation"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "existing attachment is not recoverable".to_string(),
            )
                .into_response();
        }
    }
    let write_transaction = AttachmentQuotaTransaction {
        version: ATTACHMENT_QUOTA_TRANSACTION_VERSION,
        tenant: tenant.as_str().to_owned(),
        incoming_meta: meta.clone(),
        previous_meta: previous_meta.clone(),
        victim_ids: eviction_ids.clone(),
    };
    if let Err(error) = persist_attachment_quota_transaction(&write_transaction) {
        warn!(
            tenant = tenant.as_str(),
            attachment_id = %id,
            %error,
            "rejecting attachment: failed to persist write transaction"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist attachment write transaction".to_string(),
        )
            .into_response();
    }
    if let Err(e) = persist_body(&tenant, &id, &sanitized_body) {
        if let Err(error) = recover_attachment_quota_transaction() {
            warn!(
                tenant = tenant.as_str(),
                attachment_id = %id,
                %error,
                "failed to roll back attachment write transaction after body persistence failure"
            );
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to persist body: {e}"),
        )
            .into_response();
    }
    if let Err(e) = save_meta(&tenant, &meta) {
        if let Err(error) = recover_attachment_quota_transaction() {
            warn!(
                tenant = tenant.as_str(),
                attachment_id = %id,
                %error,
                "failed to roll back attachment write transaction after metadata persistence failure"
            );
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to persist metadata: {e}"),
        )
            .into_response();
    }
    match recover_attachment_quota_transaction() {
        Ok(true) => {
            info!(
                tenant = tenant.as_str(),
                planned_evictions = eviction_ids.len(),
                "completed durable tenant-local attachment write transaction"
            );
        }
        Ok(false) => {
            error!(
                tenant = tenant.as_str(),
                attachment_id = %id,
                "durable attachment write transaction disappeared before completion"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "attachment write transaction was lost".to_string(),
            )
                .into_response();
        }
        Err(error) => {
            warn!(
                tenant = tenant.as_str(),
                attachment_id = %id,
                %error,
                "durable attachment committed but write transaction recovery failed"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "attachment write transaction completion failed".to_string(),
            )
                .into_response();
        }
    }
    let body = match json::to_json_pretty(&meta) {
        Ok(body) => body,
        Err(error) => {
            error!(
                tenant = tenant.as_str(),
                attachment_id = %id,
                %error,
                "attachment committed but its response could not be encoded"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    (
        StatusCode::CREATED,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}
/// GET /v1/zk/attachments — list stored attachments metadata.
pub async fn handle_list_attachments(tenant: AttachmentTenant) -> impl IntoResponse {
    handle_list_attachments_filtered(tenant, NoritoQuery(AttachmentListQuery::default())).await
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::zk_attachments::AttachmentListQuery")]
#[derive(
    Debug, Default, Clone, crate::json_macros::JsonDeserialize, norito::derive::NoritoDeserialize,
)]
/// Optional filters and projection for attachments listing
pub struct AttachmentListQuery {
    /// Exact id match (64-hex). If provided, only this id is returned if present.
    pub id: Option<String>,
    /// Substring match on content type (case-sensitive).
    pub content_type: Option<String>,
    /// Return only attachments with created_ms >= since_ms
    pub since_ms: Option<u64>,
    /// Return only attachments with created_ms <= before_ms
    pub before_ms: Option<u64>,
    /// Require a ZK1 tag to be present (e.g., "PROF").
    pub has_tag: Option<String>,
    /// Result limit (max 1000)
    pub limit: Option<u32>,
    /// Result offset (applied after sort)
    pub offset: Option<u32>,
    /// Sort order: asc|desc (by created_ms)
    pub order: Option<String>,
    /// If true, return only ids (array of strings)
    pub ids_only: Option<bool>,
}
/// GET /v1/zk/attachments with filters
pub async fn handle_list_attachments_filtered(
    tenant: AttachmentTenant,
    NoritoQuery(q): NoritoQuery<AttachmentListQuery>,
) -> impl IntoResponse {
    let _store_guard = attachment_store_read_lock();
    let mut metas: Vec<AttachmentMeta> = Vec::new();
    let mut scanned = 0_u64;
    let ids = if let Some(id) = q.id.as_deref() {
        let Some(clean) = sanitize_attachment_id(id) else {
            return (
                StatusCode::BAD_REQUEST,
                "invalid attachment id (expected 64 hex characters)",
            )
                .into_response();
        };
        vec![clean]
    } else {
        match try_list_all_ids(&tenant) {
            Ok(ids) => ids,
            Err(error) => {
                warn!(
                    tenant = tenant.as_str(),
                    %error,
                    "failed to enumerate attachment metadata"
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "attachment storage is unavailable",
                )
                    .into_response();
            }
        }
    };
    for id in ids {
        scanned = scanned.saturating_add(1);
        if scanned > ATTACHMENT_META_SCAN_MAX_FILES {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "too many attachment metadata records to scan (>{ATTACHMENT_META_SCAN_MAX_FILES}); narrow filters"
                ),
            )
                .into_response();
        }
        let meta = match try_load_meta(&tenant, &id) {
            Ok(Some(meta)) => meta,
            Ok(None) => continue,
            Err(error) => {
                warn!(
                    tenant = tenant.as_str(),
                    attachment_id = %id,
                    %error,
                    "failed to load attachment metadata while listing"
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "attachment storage is unavailable",
                )
                    .into_response();
            }
        };
        if let Some(ct) = q.content_type.as_deref() {
            if !meta.content_type.contains(ct) {
                continue;
            }
        }
        if !q.since_ms.map_or(true, |since| meta.created_ms >= since) {
            continue;
        }
        if !q.before_ms.map_or(true, |before| meta.created_ms <= before) {
            continue;
        }
        if let Some(tag) = q.has_tag.as_deref() {
            if !attachment_meta_has_tag(&meta, tag) {
                continue;
            }
        }
        metas.push(meta);
    }
    // Sort by created_ms asc (default)
    metas.sort_by_key(|m| m.created_ms);
    if matches!(q.order.as_deref(), Some("desc" | "DESC" | "Desc")) {
        metas.reverse();
    }
    // Offset/limit
    let start = (q.offset.unwrap_or(0) as usize).min(metas.len());
    let end = q.limit.map_or(metas.len(), |lim| {
        let cap = lim.min(1000) as usize;
        (start + cap).min(metas.len())
    });
    let slice = &metas[start..end];
    let body_result = if q.ids_only.unwrap_or(false) {
        let ids: Vec<String> = slice.iter().map(|m| m.id.clone()).collect();
        json::to_json_pretty(&ids)
    } else {
        // norito::json requires a sized type; serialize a Vec copy of the slice
        let owned: Vec<AttachmentMeta> = slice.to_vec();
        json::to_json_pretty(&owned)
    };
    let body = match body_result {
        Ok(body) => body,
        Err(error) => {
            error!(%error, "failed to encode attachment listing response");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}
/// GET /v1/zk/attachments/count — return number of attachments matching filters
pub async fn handle_count_attachments(
    tenant: AttachmentTenant,
    NoritoQuery(q): NoritoQuery<AttachmentListQuery>,
) -> impl IntoResponse {
    let _store_guard = attachment_store_read_lock();
    let mut count = 0u64;
    let mut scanned = 0_u64;
    let ids = if let Some(id) = q.id.as_deref() {
        let Some(clean) = sanitize_attachment_id(id) else {
            return (
                StatusCode::BAD_REQUEST,
                "invalid attachment id (expected 64 hex characters)",
            )
                .into_response();
        };
        vec![clean]
    } else {
        match try_list_all_ids(&tenant) {
            Ok(ids) => ids,
            Err(error) => {
                warn!(
                    tenant = tenant.as_str(),
                    %error,
                    "failed to enumerate attachment metadata for count"
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "attachment storage is unavailable",
                )
                    .into_response();
            }
        }
    };
    for id in ids {
        scanned = scanned.saturating_add(1);
        if scanned > ATTACHMENT_META_SCAN_MAX_FILES {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "too many attachment metadata records to scan (>{ATTACHMENT_META_SCAN_MAX_FILES}); narrow filters"
                ),
            )
                .into_response();
        }
        let meta = match try_load_meta(&tenant, &id) {
            Ok(Some(meta)) => meta,
            Ok(None) => continue,
            Err(error) => {
                warn!(
                    tenant = tenant.as_str(),
                    attachment_id = %id,
                    %error,
                    "failed to load attachment metadata while counting"
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "attachment storage is unavailable",
                )
                    .into_response();
            }
        };
        if let Some(ct) = q.content_type.as_deref() {
            if !meta.content_type.contains(ct) {
                continue;
            }
        }
        if !q.since_ms.map_or(true, |since| meta.created_ms >= since) {
            continue;
        }
        if !q.before_ms.map_or(true, |before| meta.created_ms <= before) {
            continue;
        }
        if let Some(tag) = q.has_tag.as_deref() {
            if !attachment_meta_has_tag(&meta, tag) {
                continue;
            }
        }
        count = count.saturating_add(1);
    }
    let s = match norito::json::to_json_pretty(&crate::json_object(vec![("count", count)])) {
        Ok(body) => body,
        Err(error) => {
            error!(%error, "failed to encode attachment count response");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(s))
        .unwrap()
}
fn attachment_meta_has_tag(meta: &AttachmentMeta, tag: &str) -> bool {
    meta.zk1_tags
        .as_ref()
        .is_some_and(|tags| tags.iter().any(|existing| existing == tag))
}
fn needs_export_sanitization(meta: &AttachmentMeta) -> bool {
    meta.provenance
        .as_ref()
        .map_or(true, |prov| prov.sanitizer.archive_depth > 0)
}
/// GET /v1/zk/attachments/{id} — return the stored attachment bytes.
pub async fn handle_get_attachment(
    tenant: AttachmentTenant,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    handle_get_attachment_inner(tenant, id, None).await
}
pub(crate) async fn handle_get_attachment_with_admission(
    tenant: AttachmentTenant,
    AxumPath(id): AxumPath<String>,
    admission: crate::ProofBodyAdmissionLease,
) -> axum::response::Response {
    handle_get_attachment_inner(tenant, id, Some(admission)).await
}
async fn handle_get_attachment_inner(
    tenant: AttachmentTenant,
    id: String,
    admission: Option<crate::ProofBodyAdmissionLease>,
) -> axum::response::Response {
    let Some(clean) = sanitize_attachment_id(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            "invalid attachment id (expected 64 hex characters)",
        )
            .into_response();
    };
    let store_guard = attachment_store_read_lock();
    let meta = match try_load_meta(&tenant, &clean) {
        Ok(Some(meta)) => meta,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            warn!(
                tenant = tenant.as_str(),
                attachment_id = %clean,
                %error,
                "failed to load attachment metadata"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let max_bytes = u64::try_from(max_bytes_cfg()).unwrap_or(u64::MAX);
    let bytes = match read_bounded_attachment_regular_file(&bin_path(&tenant, &clean), max_bytes) {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(
                tenant = tenant.as_str(),
                attachment_id = %clean,
                %error,
                "failed to load attachment body referenced by persisted metadata"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if let Err(error) = validate_attachment_body_contract(&meta, &bytes) {
        warn!(
            tenant = tenant.as_str(),
            attachment_id = %clean,
            %error,
            "attachment body does not match persisted metadata"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    drop(store_guard);
    if !needs_export_sanitization(&meta) {
        return axum::response::Response::builder()
            .header(axum::http::header::CONTENT_TYPE, meta.content_type)
            .body(axum::body::Body::from(bytes))
            .unwrap();
    }
    let sanitize_result = sanitize_attachment(
        Some(meta.content_type.clone()),
        axum::body::Bytes::from(bytes),
        admission,
    )
    .await;
    let sanitized = match sanitize_result {
        Ok(outcome) => outcome,
        Err(err) => {
            warn!(
                tenant = tenant.as_str(),
                attachment_id = %clean,
                reason = err.reason.label(),
                error = %err.message,
                "persisted attachment could not be re-sanitized for export"
            );
            let status = if err.reason == SanitizeRejectReason::Sandbox {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return status.into_response();
        }
    };
    if sanitized.summary.sniffed_type != meta.content_type {
        warn!(
            tenant = tenant.as_str(),
            attachment_id = %clean,
            declared = %meta.content_type,
            sniffed = %sanitized.summary.sniffed_type,
            "persisted attachment export content-type changed during sanitization"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, meta.content_type)
        .body(axum::body::Body::from(sanitized.sanitized_body))
        .unwrap()
}
/// DELETE /v1/zk/attachments/{id} — delete an attachment and its metadata.
pub async fn handle_delete_attachment(
    tenant: AttachmentTenant,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let Some(clean) = sanitize_attachment_id(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            "invalid attachment id (expected 64 hex characters)",
        )
            .into_response();
    };
    let _guard = quota_lock().lock().await;
    let _store_guard = attachment_store_write_lock();
    if let Err(error) = prepare_attachment_mutation_locked() {
        warn!(
            tenant = tenant.as_str(),
            attachment_id = %clean,
            %error,
            "failed to recover attachment persistence before deletion"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "attachment persistence recovery failed".to_string(),
        )
            .into_response();
    }
    let existed = match path_entry_exists(&meta_path(&tenant, &clean)).and_then(|metadata_exists| {
        path_entry_exists(&bin_path(&tenant, &clean))
            .map(|body_exists| metadata_exists || body_exists)
    }) {
        Ok(existed) => existed,
        Err(error) => {
            warn!(
                tenant = tenant.as_str(),
                attachment_id = %clean,
                %error,
                "failed to inspect attachment before deletion"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to inspect attachment".to_string(),
            )
                .into_response();
        }
    };
    if let Err(error) = delete_attachment_files(&tenant, &clean) {
        warn!(
            tenant = tenant.as_str(),
            attachment_id = %clean,
            %error,
            "failed to delete attachment safely"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to delete attachment".to_string(),
        )
            .into_response();
    }
    if existed {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
#[cfg(test)]
async fn delete_attachment_if_expired_with_before_lock(
    tenant: &AttachmentTenant,
    id: &str,
    ttl: Duration,
    before_lock: impl FnOnce(),
) -> std::io::Result<bool> {
    let id = sanitize_attachment_id(id)
        .filter(|clean| clean == id)
        .ok_or_else(|| invalid_attachment_file("invalid attachment id for TTL collection"))?;
    // POST, explicit DELETE, quota eviction, and TTL collection all mutate the
    // same content-addressed entry. Re-read its timestamp after acquiring the
    // common lock so an old GC observation cannot delete a successful repost.
    before_lock();
    let _guard = quota_lock().lock().await;
    let _store_guard = attachment_store_write_lock();
    prepare_attachment_mutation_locked()?;
    delete_attachment_if_expired_locked(tenant, &id, ttl)
}
fn delete_attachment_if_expired_locked(
    tenant: &AttachmentTenant,
    id: &str,
    ttl: Duration,
) -> std::io::Result<bool> {
    let Some(meta) = try_load_meta(tenant, id)? else {
        return Ok(false);
    };
    let meta_time = UNIX_EPOCH + Duration::from_millis(meta.created_ms);
    if SystemTime::now()
        .duration_since(meta_time)
        .unwrap_or_default()
        <= ttl
    {
        return Ok(false);
    }
    delete_attachment_files(tenant, id)?;
    Ok(true)
}
async fn collect_expired_attachments_once(
    shutdown: &ShutdownSignal,
    ttl: Duration,
) -> std::io::Result<()> {
    let _guard = tokio::select! {
        () = shutdown.receive() => return Ok(()),
        guard = quota_lock().lock() => guard,
    };
    let _store_guard = attachment_store_write_lock();
    prepare_attachment_mutation_locked()?;
    let root = attachments_root_dir();
    let (root_handle, root_names) =
        open_pinned_directory_names(&root, ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES)?.ok_or_else(
            || {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "attachment persistence root directory is missing",
                )
            },
        )?;
    let mut root_entries = 0_u64;
    let mut child_entries = 0_u64;
    for name in root_names {
        if shutdown.is_sent() {
            verify_pinned_direct_directory(&root, &root_handle)?;
            return Ok(());
        }
        root_entries = root_entries.saturating_add(1);
        if root_entries > ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES {
            return Err(invalid_attachment_file(format!(
                "attachment TTL scan exceeds {ATTACHMENT_ROOT_RECOVERY_MAX_ENTRIES} tenant entries"
            )));
        }
        let tenant_key = sanitize_tenant_key(&name)
            .filter(|clean| clean == &name)
            .ok_or_else(|| {
                invalid_attachment_file(format!(
                    "attachment TTL scan found a non-canonical tenant entry: {name}"
                ))
            })?;
        let tenant = AttachmentTenant(tenant_key);
        let tenant_dir = attachments_dir(&tenant);
        let Some(tenant_handle) =
            open_direct_directory_in_pinned_directory(&root, &root_handle, &name)?
        else {
            return Err(invalid_attachment_file(format!(
                "attachment tenant directory disappeared during TTL scan: {}",
                tenant_dir.display()
            )));
        };
        let tenant_names = pinned_directory_names_at(
            &tenant_dir,
            &tenant_handle,
            ATTACHMENT_CHILD_RECOVERY_MAX_ENTRIES.saturating_sub(child_entries),
        )?;
        let mut metadata_ids = BTreeSet::new();
        let mut body_ids = BTreeSet::new();
        for name in tenant_names {
            if shutdown.is_sent() {
                verify_pinned_direct_directory(&tenant_dir, &tenant_handle)?;
                verify_pinned_direct_directory(&root, &root_handle)?;
                return Ok(());
            }
            child_entries = child_entries.saturating_add(1);
            if child_entries > ATTACHMENT_CHILD_RECOVERY_MAX_ENTRIES {
                return Err(invalid_attachment_file(format!(
                    "attachment TTL scan exceeds {ATTACHMENT_CHILD_RECOVERY_MAX_ENTRIES} child entries"
                )));
            }
            if is_attachment_writer_temp_name(&name) {
                if open_direct_regular_file_in_pinned_directory(&tenant_dir, &tenant_handle, &name)?
                    .is_none()
                {
                    return Err(invalid_attachment_file(format!(
                        "attachment TTL temporary entry disappeared during scan: {}",
                        tenant_dir.join(&name).display()
                    )));
                }
                continue;
            }
            let (raw_id, is_metadata) = if let Some(raw_id) = name.strip_suffix(".json") {
                (raw_id, true)
            } else if let Some(raw_id) = name.strip_suffix(".bin") {
                (raw_id, false)
            } else {
                return Err(invalid_attachment_file(format!(
                    "attachment TTL scan found an unexpected entry: {name}"
                )));
            };
            let id = sanitize_attachment_id(raw_id)
                .filter(|clean| clean == raw_id)
                .ok_or_else(|| {
                    invalid_attachment_file(format!(
                        "attachment TTL scan found a non-canonical entry: {name}"
                    ))
                })?;
            if open_direct_regular_file_in_pinned_directory(&tenant_dir, &tenant_handle, &name)?
                .is_none()
            {
                return Err(invalid_attachment_file(format!(
                    "attachment entry disappeared during TTL scan: {}",
                    tenant_dir.join(&name).display()
                )));
            }
            if is_metadata {
                metadata_ids.insert(id);
            } else {
                body_ids.insert(id);
            }
        }
        verify_pinned_direct_directory(&tenant_dir, &tenant_handle)?;
        if let Some(id) = metadata_ids.difference(&body_ids).next() {
            return Err(invalid_attachment_file(format!(
                "attachment metadata has no body during TTL scan: {id}"
            )));
        }
        drop(tenant_handle);
        for id in body_ids.difference(&metadata_ids) {
            delete_attachment_files(&tenant, id)?;
        }
        for id in metadata_ids {
            if shutdown.is_sent() {
                verify_pinned_direct_directory(&root, &root_handle)?;
                return Ok(());
            }
            delete_attachment_if_expired_locked(&tenant, &id, ttl)?;
        }
    }
    verify_pinned_direct_directory(&root, &root_handle)
}
/// Start a background GC worker that removes expired attachments.
pub(crate) fn start_gc_worker(
    shutdown: ShutdownSignal,
) -> std::io::Result<tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit>> {
    ensure_root_dir()?;
    Ok(tokio::spawn(async move {
        let ttl = Duration::from_secs(ttl_secs_cfg());
        let interval = Duration::from_secs(GC_INTERVAL_SECS);
        loop {
            let result = tokio::select! {
                () = shutdown.receive() => {
                    return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                }
                result = collect_expired_attachments_once(&shutdown, ttl) => result,
            };
            if let Err(error) = result {
                error!(%error, "attachment garbage-collection worker stopped after a storage failure");
                return crate::ToriiCriticalWorkerExit::UnexpectedExit;
            }
            tokio::select! {
                () = shutdown.receive() => {
                    return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                }
                () = tokio::time::sleep(interval) => {}
            }
        }
    }))
}
#[derive(Debug, Clone)]
struct AttachConfig {
    ttl_secs: u64,
    max_bytes: u64,
    per_tenant_max_count: u64,
    per_tenant_max_bytes: u64,
    global_max_count: u64,
    global_max_bytes: u64,
    allowed_mime_types: Vec<String>,
    max_expanded_bytes: u64,
    max_archive_depth: u32,
    sanitizer_mode: AttachmentSanitizerMode,
    sanitize_timeout_ms: u64,
    sanitizer_exe_override: Option<PathBuf>,
    telemetry: MaybeTelemetry,
}
impl Default for AttachConfig {
    fn default() -> Self {
        Self {
            ttl_secs: ATTACHMENT_TTL_SECS_FALLBACK,
            max_bytes: MAX_ATTACHMENT_BYTES_FALLBACK as u64,
            per_tenant_max_count:
                iroha_config::parameters::defaults::torii::ATTACHMENTS_PER_TENANT_MAX_COUNT,
            per_tenant_max_bytes:
                iroha_config::parameters::defaults::torii::ATTACHMENTS_PER_TENANT_MAX_BYTES,
            global_max_count:
                iroha_config::parameters::defaults::torii::ATTACHMENTS_GLOBAL_MAX_COUNT,
            global_max_bytes:
                iroha_config::parameters::defaults::torii::ATTACHMENTS_GLOBAL_MAX_BYTES,
            allowed_mime_types:
                iroha_config::parameters::defaults::torii::attachments_allowed_mime_types()
                    .into_iter()
                    .filter_map(|entry| normalize_mime(&entry))
                    .collect(),
            max_expanded_bytes:
                iroha_config::parameters::defaults::torii::ATTACHMENTS_MAX_EXPANDED_BYTES,
            max_archive_depth:
                iroha_config::parameters::defaults::torii::ATTACHMENTS_MAX_ARCHIVE_DEPTH,
            sanitizer_mode: AttachmentSanitizerMode::Subprocess,
            sanitize_timeout_ms:
                iroha_config::parameters::defaults::torii::ATTACHMENTS_SANITIZE_TIMEOUT_MS,
            sanitizer_exe_override: None,
            telemetry: MaybeTelemetry::disabled(),
        }
    }
}
static ATTACH_CFG: OnceLock<RwLock<AttachConfig>> = OnceLock::new();
static ATTACH_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
fn attach_cfg() -> &'static RwLock<AttachConfig> {
    ATTACH_CFG.get_or_init(|| RwLock::new(AttachConfig::default()))
}
#[cfg(test)]
pub(crate) struct SanitizerModeTestGuard {
    previous_mode: AttachmentSanitizerMode,
    previous_executable: Option<PathBuf>,
}
#[cfg(test)]
impl Drop for SanitizerModeTestGuard {
    fn drop(&mut self) {
        let mut config = attach_cfg().write();
        config.sanitizer_mode = self.previous_mode;
        config.sanitizer_exe_override = self.previous_executable.take();
    }
}
#[cfg(test)]
pub(crate) fn set_sanitizer_mode_for_test(
    mode: AttachmentSanitizerMode,
    executable: Option<PathBuf>,
) -> SanitizerModeTestGuard {
    let mut config = attach_cfg().write();
    let guard = SanitizerModeTestGuard {
        previous_mode: config.sanitizer_mode,
        previous_executable: config.sanitizer_exe_override.clone(),
    };
    config.sanitizer_mode = mode;
    config.sanitizer_exe_override = executable;
    guard
}
/// Configure attachment retention and sanitization from Torii config.
/// The sanitizer executable override is intended for tests and tooling.
#[allow(clippy::too_many_arguments)]
pub fn configure(
    ttl_secs: u64,
    max_bytes: u64,
    per_tenant_max_count: u64,
    per_tenant_max_bytes: u64,
    global_max_count: u64,
    global_max_bytes: u64,
    allowed_mime_types: Vec<String>,
    max_expanded_bytes: u64,
    max_archive_depth: u32,
    sanitizer_mode: AttachmentSanitizerMode,
    sanitize_timeout_ms: u64,
    sanitizer_exe_override: Option<PathBuf>,
    telemetry: MaybeTelemetry,
) {
    let allowed_mime_types = allowed_mime_types
        .into_iter()
        .filter_map(|entry| normalize_mime(&entry))
        .collect();
    *attach_cfg().write() = AttachConfig {
        ttl_secs,
        max_bytes,
        per_tenant_max_count,
        per_tenant_max_bytes,
        global_max_count,
        global_max_bytes,
        allowed_mime_types,
        max_expanded_bytes,
        max_archive_depth,
        sanitizer_mode,
        sanitize_timeout_ms,
        sanitizer_exe_override,
        telemetry,
    };
}
pub(super) fn max_bytes_cfg() -> usize {
    let max_bytes = max_bytes_u64_cfg();
    usize::try_from(max_bytes).unwrap_or(usize::MAX)
}
fn max_bytes_u64_cfg() -> u64 {
    attach_cfg().read().max_bytes
}
fn ttl_secs_cfg() -> u64 {
    attach_cfg().read().ttl_secs
}
fn per_tenant_max_bytes_cfg() -> u64 {
    attach_cfg().read().per_tenant_max_bytes
}
fn global_max_bytes_cfg() -> u64 {
    attach_cfg().read().global_max_bytes
}
fn quota_limits_cfg() -> AttachmentQuotaLimits {
    let config = attach_cfg().read();
    AttachmentQuotaLimits {
        per_tenant_max_count: config.per_tenant_max_count,
        per_tenant_max_bytes: config.per_tenant_max_bytes,
        global_max_count: config.global_max_count,
        global_max_bytes: config.global_max_bytes,
    }
}
fn allowed_mime_types_cfg() -> Vec<String> {
    attach_cfg().read().allowed_mime_types.clone()
}
fn max_expanded_bytes_cfg() -> u64 {
    attach_cfg().read().max_expanded_bytes
}
fn max_archive_depth_cfg() -> u32 {
    attach_cfg().read().max_archive_depth
}
fn sanitizer_mode_cfg() -> AttachmentSanitizerMode {
    attach_cfg().read().sanitizer_mode
}
fn sanitize_timeout_cfg() -> Duration {
    let ms = attach_cfg().read().sanitize_timeout_ms.max(1);
    Duration::from_millis(ms)
}
/// Run the attachment sanitizer process if requested via environment.
pub fn sanitizer_process_exit_code_from_env() -> Option<i32> {
    if env::var_os(ATTACHMENT_SANITIZER_ENV).as_deref() != Some(OsStr::new("1")) {
        return None;
    }
    let exit_code = match run_sanitizer_process() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("attachment sanitizer failed: {}", err.message);
            1
        }
    };
    Some(exit_code)
}
fn run_sanitizer_process() -> Result<(), SanitizeError> {
    if env::var_os(ATTACHMENT_SANITIZER_SANDBOXED_ENV).as_deref() != Some(OsStr::new("1")) {
        return Err(SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            "attachment sanitizer refuses to run outside its OS sandbox",
        ));
    }
    let max_input = env::var(ATTACHMENT_SANITIZER_MAX_INPUT_ENV)
        .map_err(|_| {
            SanitizeError::new(
                SanitizeRejectReason::Sandbox,
                "attachment sanitizer max input limit is missing",
            )
        })?
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            SanitizeError::new(
                SanitizeRejectReason::Sandbox,
                "attachment sanitizer max input limit is invalid",
            )
        })?;
    let payload = read_stdin_limited(max_input)?;
    let request = match decode_sanitizer_request_bytes(&payload) {
        Ok(request) => request,
        Err(err) => {
            let response = SanitizerResponse::Rejected {
                error: err.into_wire(),
            };
            return write_sanitizer_response(&response);
        }
    };
    let cfg = SanitizerConfig {
        allowed_mime_types: request
            .allowed_mime_types
            .into_iter()
            .filter_map(|entry| normalize_mime(&entry))
            .collect(),
        max_expanded_bytes: request.max_expanded_bytes,
        max_archive_depth: request.max_archive_depth,
        timeout: Duration::from_millis(request.timeout_ms.max(1)),
        mode: AttachmentSanitizerMode::InProcess,
    };
    apply_sanitizer_limits(cfg.max_expanded_bytes, cfg.timeout)?;
    let response =
        match sanitize_attachment_sync(request.declared_type.as_deref(), &request.body, &cfg) {
            Ok(mut outcome) => {
                outcome.summary.sandboxed = true;
                SanitizerResponse::Accepted {
                    summary: outcome.summary,
                    sanitized_body: outcome.sanitized_body,
                }
            }
            Err(err) => SanitizerResponse::Rejected {
                error: err.into_wire(),
            },
        };
    write_sanitizer_response(&response)
}
fn decode_sanitizer_request_bytes(payload: &[u8]) -> Result<SanitizerRequest, SanitizeError> {
    norito::decode_canonical(payload).map_err(|err| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitizer request decode failed: {err}"),
        )
    })
}
fn sanitizer_cpu_limit_secs(timeout: Duration) -> u64 {
    let millis = timeout.as_millis().max(1) as u64;
    (millis.saturating_add(999) / 1000).max(1)
}
fn sanitizer_memory_limit_bytes(max_expanded_bytes: u64) -> u64 {
    const BASE_OVERHEAD_BYTES: u64 = 64 * 1024 * 1024;
    let scaled = max_expanded_bytes.saturating_mul(4);
    scaled
        .saturating_add(BASE_OVERHEAD_BYTES)
        .max(BASE_OVERHEAD_BYTES)
}
fn apply_sanitizer_limits(max_expanded_bytes: u64, timeout: Duration) -> Result<(), SanitizeError> {
    #[cfg(unix)]
    {
        let cpu_limit = sanitizer_cpu_limit_secs(timeout);
        let mem_limit = sanitizer_memory_limit_bytes(max_expanded_bytes);
        set_rlimit(libc::RLIMIT_CPU, cpu_limit)?;
        set_rlimit(libc::RLIMIT_AS, mem_limit)?;
    }
    Ok(())
}
#[cfg(unix)]
#[cfg(any(target_env = "gnu", target_env = "uclibc"))]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(unix)]
#[cfg(not(any(target_env = "gnu", target_env = "uclibc")))]
type RlimitResource = libc::c_int;
#[cfg(unix)]
#[allow(unsafe_code)]
fn set_rlimit(resource: RlimitResource, value: u64) -> Result<(), SanitizeError> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    let result = unsafe { libc::setrlimit(resource, &raw const limit) };
    if result != 0 {
        return Err(SanitizeError {
            reason: SanitizeRejectReason::Sandbox,
            message: format!(
                "setrlimit failed for resource {:?}: {}",
                resource,
                std::io::Error::last_os_error()
            ),
        });
    }
    Ok(())
}
fn write_sanitizer_response(response: &SanitizerResponse) -> Result<(), SanitizeError> {
    let bytes = norito::encode_canonical(response).map_err(|err| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitizer response encode failed: {err}"),
        )
    })?;
    let mut stdout = std::io::stdout();
    stdout.write_all(&bytes).map_err(|err| {
        SanitizeError::new(
            SanitizeRejectReason::Sandbox,
            format!("attachment sanitizer response write failed: {err}"),
        )
    })?;
    Ok(())
}
fn read_stdin_limited(max_bytes: usize) -> Result<Vec<u8>, SanitizeError> {
    let mut reader = std::io::stdin().lock();
    let mut buf = [0u8; 8 * 1024];
    let mut out = Vec::new();
    loop {
        let read = reader.read(&mut buf).map_err(|err| {
            SanitizeError::new(
                SanitizeRejectReason::Sandbox,
                format!("attachment sanitizer stdin read failed: {err}"),
            )
        })?;
        if read == 0 {
            break;
        }
        let next_len = out.len().saturating_add(read);
        if next_len > max_bytes {
            return Err(SanitizeError::new(
                SanitizeRejectReason::Sandbox,
                "attachment sanitizer request exceeds max bytes",
            ));
        }
        out.extend_from_slice(&buf[..read]);
    }
    Ok(out)
}
fn telemetry_handle() -> MaybeTelemetry {
    attach_cfg().read().telemetry.clone()
}
fn quota_lock() -> &'static Mutex<()> {
    ATTACH_MUTEX.get_or_init(|| Mutex::new(()))
}
#[cfg(test)]
mod tests;
