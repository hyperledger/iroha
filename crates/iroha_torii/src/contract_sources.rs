#![cfg(feature = "app_api")]
use crate::{Error, JsonBody, data_dir};
use axum::{http::StatusCode, response::IntoResponse};
use iroha_core::state::{State as CoreState, WorldReadOnly};
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId, ValidationFail,
    isi::{
        InstructionBox,
        smart_contract_code::{
            ActivateContractInstance, RegisterSmartContractBytes, RegisterSmartContractCode,
        },
    },
    query::error::QueryExecutionFail,
    smart_contract::ContractArtifactId,
    smart_contract::manifest::{
        ContractManifest, ContractPermissionDescriptorV1, ContractPermissionScopeV1,
        EntryPointKind, EntrypointAuthorizationV1, EntrypointDescriptor,
    },
    transaction::TransactionEntrypoint,
};
use ivm::analysis::ProgramAnalysis;
use mv::storage::StorageReadOnly;
#[cfg(unix)]
use std::fs::File;
#[cfg(any(unix, windows))]
use std::path::Component;
use std::{
    collections::HashMap,
    ffi::OsString,
    fmt::{self, Write as _},
    fs,
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};
const VERIFIED_SOURCE_VERSION: u32 = 1;
const VERIFIED_SOURCE_LANGUAGE_KOTODAMA: &str = "kotodama";
const FIXED_HEX_COMPONENT_BYTES_V1: usize = 32;
const FIXED_HEX_COMPONENT_CHARS_V1: usize = FIXED_HEX_COMPONENT_BYTES_V1 * 2;
const VERIFIED_SOURCE_JSON_MAX_ESCAPE_BYTES_PER_INPUT_BYTE_V1: usize = 6;
const VERIFIED_SOURCE_SUBMISSION_JSON_STRUCTURAL_BYTES_V1: usize = 1024 * 1024;
/// First-release HTTP envelope ceiling for a verified-source submission.
///
/// This derives from Kotodama's canonical source and logical-path limits and admits the worst-case
/// six-byte JSON escape for every UTF-8 input byte. The route therefore bounds transport memory
/// without reducing the language's V1 source surface.
pub(crate) const VERIFIED_SOURCE_SUBMISSION_MAX_HTTP_BODY_BYTES_V1: usize =
    VERIFIED_SOURCE_JSON_MAX_ESCAPE_BYTES_PER_INPUT_BYTE_V1
        * (kotodama_lang::linker::MAX_MODULE_GRAPH_SOURCE_BYTES
            + VERIFIED_SOURCE_NAME_MAX_BYTES_V1 * kotodama_lang::linker::MAX_MODULE_GRAPH_SOURCES
            + VERIFIED_SOURCE_LANGUAGE_MAX_BYTES_V1)
        + VERIFIED_SOURCE_SUBMISSION_JSON_STRUCTURAL_BYTES_V1;
const VERIFIED_SOURCE_TEXT_MAX_BYTES_V1: usize = kotodama_lang::source::MAX_SOURCE_BYTES;
const VERIFIED_SOURCE_NAME_MAX_BYTES_V1: usize =
    kotodama_lang::linker::MAX_LOGICAL_SOURCE_PATH_BYTES;
const VERIFIED_SOURCE_LANGUAGE_MAX_BYTES_V1: usize = 32;
const VERIFIED_SOURCE_RECORD_MAX_BYTES_V1: usize =
    VERIFIED_SOURCE_SUBMISSION_MAX_HTTP_BODY_BYTES_V1 + 256 * 1024;
const VERIFIED_SOURCE_JOB_MAX_BYTES_V1: usize = 256 * 1024;
const VERIFIED_SOURCE_JOB_MESSAGE_MAX_BYTES_V1: usize = 16 * 1024;
const VERIFIED_SOURCE_TIMESTAMP_MAX_BYTES_V1: usize = 64;
const VERIFIED_SOURCE_SECURE_TEMP_RETRIES_V1: usize = 16;
const RENDERED_SOURCE_VERIFIED: &str = "verified_source";
const RENDERED_SOURCE_PSEUDO: &str = "pseudo_source";
const RENDERED_SOURCE_MANIFEST_STUB: &str = "manifest_stub";
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractViewAccessHintsDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
pub struct ContractViewAccessHintsDto {
    pub read_keys: Vec<String>,
    pub write_keys: Vec<String>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractViewEntrypointParamDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
pub struct ContractViewEntrypointParamDto {
    pub name: String,
    pub type_name: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractViewEntrypointDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
pub struct ContractViewEntrypointDto {
    pub name: String,
    pub kind: String,
    pub params: Vec<ContractViewEntrypointParamDto>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub return_type: Option<String>,
    pub authorization: EntrypointAuthorizationV1,
    pub read_keys: Vec<String>,
    pub write_keys: Vec<String>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub access_hints_complete: Option<bool>,
    pub access_hints_skipped: Vec<String>,
    pub triggers: Vec<String>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractViewSyscallDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
pub struct ContractViewSyscallDto {
    pub number: u32,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub count: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractViewMemoryDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
pub struct ContractViewMemoryDto {
    pub load64: u64,
    pub store64: u64,
    pub load128: u64,
    pub store128: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractViewAnalysisDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
pub struct ContractViewAnalysisDto {
    pub instruction_count: u64,
    pub memory: ContractViewMemoryDto,
    pub syscalls: Vec<ContractViewSyscallDto>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractVerifiedSourceRefDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
)]
pub struct ContractVerifiedSourceRefDto {
    pub language: String,
    #[norito(default)]
    pub source_name: Option<String>,
    pub submitted_at: String,
    #[norito(default)]
    pub manifest_id_hex: Option<String>,
    #[norito(default)]
    pub payload_digest_hex: Option<String>,
    #[norito(default)]
    pub content_length: Option<u64>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractCodeViewDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
pub struct ContractCodeViewDto {
    pub network_id: NetworkId,
    pub artifact_id: ContractArtifactId,
    pub code_hash: String,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub declared_code_hash: Option<String>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub abi_hash: Option<String>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub compiler_fingerprint: Option<String>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub byte_len: Option<u64>,
    pub permissions: Vec<ContractPermissionDescriptorV1>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub access_hints: Option<ContractViewAccessHintsDto>,
    pub entrypoints: Vec<ContractViewEntrypointDto>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<ContractViewAnalysisDto>,
    pub warnings: Vec<String>,
    pub rendered_source_kind: String,
    pub rendered_source_text: String,
    /// Companion files belonging to the verified root, with original file identities.
    #[norito(default, skip_serializing_if = "Vec::is_empty")]
    pub source_files: Vec<ContractSourceFileDto>,
    /// Complete immutable root-owned interface artifacts needed for recompilation.
    pub source_artifacts: Vec<ContractSourceArtifactDto>,
    /// Exact root import bindings of the verified source bundle.
    #[norito(default, skip_serializing_if = "Vec::is_empty")]
    pub source_imports: Vec<ContractSourceImportDto>,
    /// Complete locked dependency packages needed to reproduce the artifact.
    #[norito(default, skip_serializing_if = "Vec::is_empty")]
    pub source_packages: Vec<ContractSourcePackageDto>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub verified_source_ref: Option<ContractVerifiedSourceRefDto>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::SubmitVerifiedContractSourceDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
)]

pub struct SubmitVerifiedContractSourceDto {
    pub language: String,
    #[norito(default)]
    pub source_name: Option<String>,
    pub source_text: String,
    /// Explicit companion files; compilation never reads server-local files.
    #[norito(default)]
    pub sources: Vec<ContractSourceFileDto>,
    /// Complete immutable imported interfaces, owned by this source set.
    pub artifacts: Vec<ContractSourceArtifactDto>,
    /// Exact root import bindings; no package resolution occurs on the server.
    #[norito(default)]
    pub imports: Vec<ContractSourceImportDto>,
    /// Complete locked dependency packages including their original files.
    #[norito(default)]
    pub packages: Vec<ContractSourcePackageDto>,
}
/// One original file in a submitted Kotodama source set.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::NoritoSchema,
    crate::json_macros::JsonDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::NoritoSerialize,
)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractSourceFileDto")]
pub struct ContractSourceFileDto {
    /// Portable path relative to the submitted source-set root.
    pub source_name: String,
    /// Complete bounded UTF-8 file contents.
    pub source_text: String,
}
/// Exact compiled contract interface supplied with its owning source set.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::NoritoSchema,
    crate::json_macros::JsonDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::NoritoSerialize,
)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractSourceArtifactDto")]
#[norito(deny_unknown_fields)]
pub struct ContractSourceArtifactDto {
    /// Canonical relative `.to` path; no server-local file resolution occurs.
    pub source_name: String,
    /// Complete immutable compiled bytes, authenticated by the compiler.
    pub artifact: Vec<u8>,
}
/// One exact package import binding in a verified source bundle.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::NoritoSchema,
    crate::json_macros::JsonDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::NoritoSerialize,
)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractSourceImportDto")]
pub struct ContractSourceImportDto {
    /// Source-visible package alias.
    pub alias: String,
    /// Exact locked package identity.
    pub package: String,
}
/// An immutable locked package supplied with a verified source request.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::NoritoSchema,
    crate::json_macros::JsonDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::NoritoSerialize,
)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractSourcePackageDto")]
pub struct ContractSourcePackageDto {
    /// Exact locked identity, including revision when applicable.
    pub identity: String,
    /// Explicit module entry files.
    pub modules: Vec<ContractSourceFileDto>,
    /// Companion files reached through module include/import declarations.
    #[norito(default)]
    pub sources: Vec<ContractSourceFileDto>,
    /// Complete immutable imported interfaces, owned by this source set.
    pub artifacts: Vec<ContractSourceArtifactDto>,
    /// Explicit exported symbol names.
    pub exports: Vec<String>,
    /// Exact transitive import bindings.
    pub imports: Vec<ContractSourceImportDto>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::ContractVerifiedSourceJobResponseDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
)]
pub struct ContractVerifiedSourceJobResponseDto {
    pub network_id: NetworkId,
    pub artifact_id: ContractArtifactId,
    pub job_id: String,
    pub code_hash: String,
    pub status: String,
    pub submitted_at: String,
    #[norito(default)]
    pub completed_at: Option<String>,
    #[norito(default)]
    pub message: Option<String>,
    #[norito(default)]
    pub actual_code_hash: Option<String>,
    #[norito(default)]
    pub verified_source_ref: Option<ContractVerifiedSourceRefDto>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::StoredVerifiedSourceRecord")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
)]
struct StoredVerifiedSourceRecord {
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
    version: u32,
    code_hash: String,
    #[norito(default)]
    abi_hash: Option<String>,
    #[norito(default)]
    compiler_fingerprint: Option<String>,
    language: String,
    #[norito(default)]
    source_name: Option<String>,
    source_text: String,
    sources: Vec<ContractSourceFileDto>,
    artifacts: Vec<ContractSourceArtifactDto>,
    imports: Vec<ContractSourceImportDto>,
    packages: Vec<ContractSourcePackageDto>,
    submitted_at: String,
    #[norito(default)]
    manifest_id_hex: Option<String>,
    #[norito(default)]
    payload_digest_hex: Option<String>,
    #[norito(default)]
    content_length: Option<u64>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::contract_sources::StoredVerifiedSourceJob")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
)]
struct StoredVerifiedSourceJob {
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
    version: u32,
    job_id: String,
    code_hash: String,
    status: String,
    submitted_at: String,
    #[norito(default)]
    completed_at: Option<String>,
    #[norito(default)]
    message: Option<String>,
    #[norito(default)]
    actual_code_hash: Option<String>,
    #[norito(default)]
    verified_source_ref: Option<ContractVerifiedSourceRefDto>,
}
struct ContractViewBuildInput {
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
    code_hash: Option<String>,
    declared_code_hash: Option<String>,
    manifest: Option<ContractManifest>,
    code_bytes: Option<Vec<u8>>,
    warnings: Vec<String>,
}
fn not_found() -> Error {
    Error::Query(ValidationFail::QueryFailed(QueryExecutionFail::NotFound))
}
fn conversion_error(message: impl Into<String>) -> Error {
    Error::Query(ValidationFail::QueryFailed(QueryExecutionFail::Conversion(
        message.into(),
    )))
}
fn storage_error(message: impl Into<String>) -> Error {
    Error::Query(ValidationFail::InternalError(message.into()))
}
fn map_io_error(error: io::Error, context: &str) -> Error {
    storage_error(format!("{context}: {error}"))
}
fn hash_hex(hash: &Hash) -> String {
    hex::encode(hash.as_ref())
}
fn canonical_code_hash(code_bytes: &[u8]) -> Result<Hash, Error> {
    let parsed = ivm::ProgramMetadata::parse(code_bytes)
        .map_err(|err| conversion_error(format!("invalid contract artifact header: {err}")))?;
    if parsed.header_len > code_bytes.len() {
        return Err(conversion_error(
            "contract artifact header length exceeds code length",
        ));
    }
    Ok(ivm::contract_code_hash(code_bytes))
}
fn canonical_verified_source_job_id(raw: &str) -> Result<String, Error> {
    if raw.len() != FIXED_HEX_COMPONENT_CHARS_V1 {
        return Err(conversion_error(format!(
            "invalid verified-source job id length {}; expected {FIXED_HEX_COMPONENT_CHARS_V1} hexadecimal characters",
            raw.len()
        )));
    }
    let mut bytes = [0_u8; FIXED_HEX_COMPONENT_BYTES_V1];
    hex::decode_to_slice(raw, &mut bytes)
        .map_err(|err| conversion_error(format!("invalid verified-source job id: {err}")))?;
    let canonical = hex::encode(bytes);
    if canonical != raw {
        return Err(conversion_error(
            "verified-source job id must use the exact canonical lowercase hexadecimal spelling",
        ));
    }
    Ok(canonical)
}
fn now_rfc3339() -> String {
    crate::explorer::now_rfc3339()
}
fn contracts_dir() -> PathBuf {
    data_dir::base_dir().join("contracts")
}
fn artifact_storage_key(network_id: NetworkId, artifact_id: ContractArtifactId) -> String {
    format!(
        "{}-{}-{}",
        hex::encode(network_id.as_bytes()),
        artifact_id.dataspace_id.as_u64(),
        hash_hex(&artifact_id.code_hash)
    )
}
fn verified_source_record_path(network_id: NetworkId, artifact_id: ContractArtifactId) -> PathBuf {
    contracts_dir().join("verified_sources").join(format!(
        "{}.json",
        artifact_storage_key(network_id, artifact_id)
    ))
}
fn verified_source_job_path(
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
    job_id: &str,
) -> PathBuf {
    contracts_dir()
        .join("verified_source_jobs")
        .join(artifact_storage_key(network_id, artifact_id))
        .join(format!("{job_id}.json"))
}
fn verified_source_mutation_locks() -> &'static Mutex<HashMap<String, Weak<Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Weak<Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}
fn verified_source_mutation_lock(
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
) -> Arc<Mutex<()>> {
    let key = artifact_storage_key(network_id, artifact_id);
    let mut locks = verified_source_mutation_locks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks.retain(|_, lock| lock.strong_count() != 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}
fn write_json_file_atomic<T: norito::json::JsonSerialize>(
    path: &Path,
    value: &T,
    maximum_bytes: usize,
    label: &str,
) -> Result<(), Error> {
    let encoded = crate::utils::encode_json_bounded(value, maximum_bytes).map_err(|error| {
        storage_error(format!(
            "failed to encode bounded {label} (maximum {maximum_bytes} bytes): {error}"
        ))
    })?;
    write_immutable_file(path, encoded.as_bytes(), maximum_bytes, label)
}

fn storage_parent(path: &Path) -> Result<(&Path, OsString), Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        conversion_error(format!(
            "contract source path has no file name: {}",
            path.display()
        ))
    })?;
    Ok((parent, name.to_os_string()))
}

#[cfg(unix)]
fn open_storage_parent(
    path: &Path,
    create: bool,
    label: &str,
) -> Result<Option<(File, OsString)>, Error> {
    use std::os::unix::fs::MetadataExt as _;

    let (parent, name) = storage_parent(path)?;
    if parent
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(conversion_error(format!(
            "{label} directory must not contain parent-directory components: {}",
            parent.display()
        )));
    }
    let candidate = if parent.is_absolute() {
        parent.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|error| map_io_error(error, "failed to resolve contract source directory"))?
            .join(parent)
    };
    let mut absolute = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::RootDir => absolute.push(Path::new("/")),
            Component::CurDir => {}
            Component::Normal(component) => absolute.push(component),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(conversion_error(format!(
                    "{label} directory is not an absolute normal path: {}",
                    candidate.display()
                )));
            }
        }
    }
    let mut directory = File::from(
        rustix::fs::open(
            "/",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            map_io_error(
                io::Error::from(error),
                "failed to open the contract source filesystem root",
            )
        })?,
    );
    let mut cursor = PathBuf::from("/");
    for component in absolute
        .components()
        .filter_map(|component| match component {
            Component::Normal(component) => Some(component),
            _ => None,
        })
    {
        cursor.push(component);
        let named = match rustix::fs::statat(
            &directory,
            component,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(metadata) => metadata,
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(rustix::io::Errno::NOENT) => {
                match rustix::fs::mkdirat(
                    &directory,
                    component,
                    rustix::fs::Mode::from_raw_mode(0o700),
                ) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => {
                        return Err(map_io_error(
                            io::Error::from(error),
                            "failed to create contract source directory",
                        ));
                    }
                }
                directory.sync_all().map_err(|error| {
                    map_io_error(
                        error,
                        "failed to sync a new contract source directory entry",
                    )
                })?;
                rustix::fs::statat(&directory, component, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|error| {
                        map_io_error(
                            io::Error::from(error),
                            "failed to inspect a new contract source directory",
                        )
                    })?
            }
            Err(error) => {
                return Err(map_io_error(
                    io::Error::from(error),
                    "failed to inspect contract source directory",
                ));
            }
        };
        let file_type = rustix::fs::FileType::from_raw_mode(named.st_mode);
        let current = directory.metadata().map_err(|error| {
            map_io_error(error, "failed to inspect a contract source path ancestor")
        })?;
        let trusted_system_symlink = file_type == rustix::fs::FileType::Symlink
            && named.st_uid == 0
            && current.uid() == 0
            && current.mode() & 0o022 == 0;
        if file_type != rustix::fs::FileType::Directory && !trusted_system_symlink {
            return Err(conversion_error(format!(
                "{label} directory contains a non-directory or untrusted symlink: {}",
                cursor.display()
            )));
        }
        let mut flags = rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC;
        if !trusted_system_symlink {
            flags |= rustix::fs::OFlags::NOFOLLOW;
        }
        let next = File::from(
            rustix::fs::openat(&directory, component, flags, rustix::fs::Mode::empty()).map_err(
                |error| {
                    map_io_error(
                        io::Error::from(error),
                        "failed to pin a contract source directory",
                    )
                },
            )?,
        );
        let opened = next.metadata().map_err(|error| {
            map_io_error(
                error,
                "failed to inspect a pinned contract source directory",
            )
        })?;
        if !opened.is_dir()
            || (!trusted_system_symlink
                && (named.st_dev as u64 != opened.dev() || named.st_ino as u64 != opened.ino()))
        {
            return Err(conversion_error(format!(
                "{label} directory changed while it was being opened: {}",
                cursor.display()
            )));
        }
        directory = next;
    }
    let opened = directory.metadata().map_err(|error| {
        map_io_error(error, "failed to inspect opened contract source directory")
    })?;
    if !opened.is_dir()
        || opened.uid() != rustix::process::geteuid().as_raw()
        || opened.mode() & 0o022 != 0
    {
        return Err(conversion_error(format!(
            "{label} directory must be current-user-owned without group/other write permission: {}",
            absolute.display()
        )));
    }
    let after = fs::metadata(&absolute)
        .map_err(|error| map_io_error(error, "failed to re-inspect contract source directory"))?;
    if !after.is_dir() || opened.dev() != after.dev() || opened.ino() != after.ino() {
        return Err(conversion_error(format!(
            "{label} directory changed while it was being opened: {}",
            absolute.display()
        )));
    }
    Ok(Some((directory, name)))
}

#[cfg(unix)]
fn read_bounded_relative(
    directory: &File,
    name: &std::ffi::OsStr,
    path: &Path,
    maximum_bytes: usize,
    label: &str,
) -> Result<Option<Vec<u8>>, Error> {
    use std::os::unix::fs::MetadataExt as _;

    let maximum_u64 = u64::try_from(maximum_bytes).map_err(|_| {
        conversion_error(format!(
            "{label} maximum does not fit the platform: {maximum_bytes}"
        ))
    })?;
    let before = match rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(map_io_error(
                io::Error::from(error),
                "failed to inspect contract source file",
            ));
        }
    };
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        || before.st_nlink != 1
        || u64::try_from(before.st_size)
            .ok()
            .is_none_or(|size| size > maximum_u64)
    {
        return Err(conversion_error(format!(
            "{label} must be a single-link bounded regular file: {}",
            path.display()
        )));
    }
    let mut file = File::from(
        rustix::fs::openat(
            directory,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            map_io_error(
                io::Error::from(error),
                "failed to open contract source file",
            )
        })?,
    );
    let opened = file
        .metadata()
        .map_err(|error| map_io_error(error, "failed to inspect contract source file"))?;
    if !opened.is_file()
        || opened.uid() != rustix::process::geteuid().as_raw()
        || opened.mode() & 0o7077 != 0
        || opened.nlink() != 1
        || u64::try_from(before.st_dev).ok() != Some(opened.dev())
        || u64::try_from(before.st_ino).ok() != Some(opened.ino())
        || opened.len() > maximum_u64
        || u64::try_from(before.st_size).ok() != Some(opened.len())
    {
        return Err(conversion_error(format!(
            "{label} is not a private current-user-owned regular file: {}",
            path.display()
        )));
    }
    let initial_capacity = usize::try_from(opened.len()).map_err(|_| {
        conversion_error(format!(
            "{label} at {} has a length that does not fit this platform",
            path.display()
        ))
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(initial_capacity).map_err(|error| {
        conversion_error(format!(
            "failed to reserve bounded {label} read ({initial_capacity} bytes): {error}"
        ))
    })?;
    (&mut file)
        .take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| map_io_error(error, "failed to read contract source file"))?;
    if bytes.len() > maximum_bytes {
        return Err(conversion_error(format!(
            "{label} at {} exceeds the first-release {maximum_bytes}-byte maximum",
            path.display()
        )));
    }
    let after = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| {
            map_io_error(
                io::Error::from(error),
                "failed to re-inspect contract source file",
            )
        })?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || rustix::fs::FileType::from_raw_mode(after.st_mode) != rustix::fs::FileType::RegularFile
        || after.st_uid != rustix::process::geteuid().as_raw()
        || after.st_mode & 0o7077 != 0
        || after.st_nlink != 1
        || after.st_size != before.st_size
        || after.st_mtime != before.st_mtime
        || after.st_mtime_nsec != before.st_mtime_nsec
        || after.st_ctime != before.st_ctime
        || after.st_ctime_nsec != before.st_ctime_nsec
        || u64::try_from(bytes.len()).ok() != Some(opened.len())
    {
        return Err(conversion_error(format!(
            "{label} changed while it was being read: {}",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn create_secure_temporary(
    directory: &File,
    destination: &std::ffi::OsStr,
) -> io::Result<(File, OsString)> {
    for _ in 0..VERIFIED_SOURCE_SECURE_TEMP_RETRIES_V1 {
        let mut suffix = [0_u8; 16];
        rand::rand_core::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut suffix)
            .map_err(|error| io::Error::other(format!("OS randomness unavailable: {error}")))?;
        let name = OsString::from(format!(
            ".{}.{}.tmp",
            destination.to_string_lossy(),
            hex::encode(suffix)
        ));
        match rustix::fs::openat(
            directory,
            &name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        ) {
            Ok(file) => {
                let file = File::from(file);
                use std::os::unix::fs::PermissionsExt as _;
                if let Err(error) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
                    let _ = rustix::fs::unlinkat(directory, &name, rustix::fs::AtFlags::empty());
                    return Err(error);
                }
                return Ok((file, name));
            }
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => return Err(io::Error::from(error)),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a collision-free contract-source temporary file",
    ))
}

#[cfg(unix)]
fn publish_noreplace(
    directory: &File,
    temporary: &std::ffi::OsStr,
    destination: &std::ffi::OsStr,
) -> io::Result<()> {
    rustix::fs::renameat_with(
        directory,
        temporary,
        directory,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)
}

#[cfg(unix)]
fn write_immutable_file(
    path: &Path,
    bytes: &[u8],
    maximum_bytes: usize,
    label: &str,
) -> Result<(), Error> {
    let Some((directory, name)) = open_storage_parent(path, true, label)? else {
        return Err(conversion_error(format!(
            "failed to create {label} directory"
        )));
    };
    if let Some(existing) = read_bounded_relative(&directory, &name, path, maximum_bytes, label)? {
        if existing != bytes {
            return Err(conversion_error(format!(
                "refusing to replace conflicting immutable {label}: {}",
                path.display()
            )));
        }
        directory.sync_all().map_err(|error| {
            map_io_error(error, "failed to sync existing contract source directory")
        })?;
        return Ok(());
    }
    let (mut temporary_file, temporary_name) = create_secure_temporary(&directory, &name)
        .map_err(|error| map_io_error(error, "failed to create contract source temporary file"))?;
    let publication = (|| {
        temporary_file
            .write_all(bytes)
            .and_then(|()| temporary_file.sync_all())
            .map_err(|error| {
                map_io_error(error, "failed to sync contract source temporary file")
            })?;
        let metadata = temporary_file.metadata().map_err(|error| {
            map_io_error(error, "failed to inspect contract source temporary file")
        })?;
        use std::os::unix::fs::MetadataExt as _;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(conversion_error(
                "contract source temporary file failed its private-file invariant",
            ));
        }
        drop(temporary_file);
        if let Err(error) = publish_noreplace(&directory, &temporary_name, &name) {
            if error.kind() != io::ErrorKind::AlreadyExists
                || !read_bounded_relative(&directory, &name, path, maximum_bytes, label)?
                    .is_some_and(|existing| existing == bytes)
            {
                return Err(map_io_error(
                    error,
                    "failed no-clobber contract source publication",
                ));
            }
        }
        directory
            .sync_all()
            .map_err(|error| map_io_error(error, "failed to sync contract source directory"))?;
        let readback = read_bounded_relative(&directory, &name, path, maximum_bytes, label)?
            .ok_or_else(|| conversion_error(format!("published {label} disappeared")))?;
        if readback != bytes {
            return Err(conversion_error(format!(
                "published {label} differs from its synced temporary file"
            )));
        }
        Ok(())
    })();
    let _ = rustix::fs::unlinkat(&directory, &temporary_name, rustix::fs::AtFlags::empty());
    publication
}

#[cfg(windows)]
type PinnedWindowsStorageDirectory = (PathBuf, crate::secure_file_metadata::SecureMetadata);

#[cfg(windows)]
fn revalidate_windows_storage_directories(
    directories: &[PinnedWindowsStorageDirectory],
    label: &str,
) -> Result<(), Error> {
    use crate::secure_file_metadata::{from_path, is_direct_directory, same_file};

    for (path, before) in directories {
        let after = from_path(path).map_err(|error| {
            map_io_error(error, "failed to re-inspect contract source directory")
        })?;
        if !is_direct_directory(&after) || !same_file(before, &after) {
            return Err(conversion_error(format!(
                "{label} directory changed while it was in use: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn prepare_windows_storage_parent(
    parent: &Path,
    create: bool,
    label: &str,
) -> Result<Option<(PathBuf, Vec<PinnedWindowsStorageDirectory>)>, Error> {
    use crate::secure_file_metadata::{from_path, is_direct_directory};

    let candidate = if parent.is_absolute() {
        parent.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|error| map_io_error(error, "failed to resolve contract source directory"))?
            .join(parent)
    };
    if !candidate.is_absolute() {
        return Err(conversion_error(format!(
            "{label} directory is not an absolute path: {}",
            candidate.display()
        )));
    }

    let mut cursor = PathBuf::new();
    let mut directories = Vec::new();
    for component in candidate.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                cursor.push(component.as_os_str());
            }
            Component::CurDir | Component::ParentDir => {
                return Err(conversion_error(format!(
                    "{label} directory contains a forbidden traversal component: {}",
                    candidate.display()
                )));
            }
            Component::Normal(component) => {
                let containing_directory = cursor.clone();
                cursor.push(component);
                let mut created = false;
                let metadata = match from_path(&cursor) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == io::ErrorKind::NotFound && !create => {
                        return Ok(None);
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        match fs::create_dir(&cursor) {
                            Ok(()) => created = true,
                            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                            Err(error) => {
                                return Err(map_io_error(
                                    error,
                                    "failed to create contract source directory",
                                ));
                            }
                        }
                        from_path(&cursor).map_err(|error| {
                            map_io_error(error, "failed to inspect contract source directory")
                        })?
                    }
                    Err(error) => {
                        return Err(map_io_error(
                            error,
                            "failed to inspect contract source directory",
                        ));
                    }
                };
                if !is_direct_directory(&metadata) {
                    return Err(conversion_error(format!(
                        "{label} directory contains a non-directory or reparse point: {}",
                        cursor.display()
                    )));
                }
                revalidate_windows_storage_directories(&directories, label)?;
                if created && !containing_directory.as_os_str().is_empty() {
                    crate::durable_fs::sync_direct_directory(&containing_directory).map_err(
                        |error| {
                            map_io_error(
                                error,
                                "failed to sync a new contract source directory entry",
                            )
                        },
                    )?;
                    revalidate_windows_storage_directories(&directories, label)?;
                }
                directories.push((cursor.clone(), metadata));
            }
        }
    }
    if directories
        .last()
        .is_none_or(|(path, _)| path != &candidate)
    {
        let metadata = from_path(&candidate)
            .map_err(|error| map_io_error(error, "failed to inspect contract source directory"))?;
        if !is_direct_directory(&metadata) {
            return Err(conversion_error(format!(
                "{label} directory is not a direct directory: {}",
                candidate.display()
            )));
        }
        directories.push((candidate.clone(), metadata));
    }
    revalidate_windows_storage_directories(&directories, label)?;
    Ok(Some((candidate, directories)))
}

#[cfg(windows)]
fn validate_windows_storage_file(
    metadata: &crate::secure_file_metadata::SecureMetadata,
    path: &Path,
    label: &str,
) -> Result<(), Error> {
    use crate::secure_file_metadata::{is_direct_file, number_of_links};

    if !is_direct_file(metadata) || number_of_links(metadata) != Some(1) {
        return Err(conversion_error(format!(
            "{label} must be a direct, single-link regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn write_immutable_file(
    path: &Path,
    bytes: &[u8],
    maximum_bytes: usize,
    label: &str,
) -> Result<(), Error> {
    if bytes.len() > maximum_bytes {
        return Err(conversion_error(format!(
            "{label} exceeds the first-release {maximum_bytes}-byte maximum"
        )));
    }
    let (parent, name) = storage_parent(path)?;
    let Some((parent, pinned_directories)) = prepare_windows_storage_parent(parent, true, label)?
    else {
        return Err(conversion_error(format!(
            "failed to create {label} directory"
        )));
    };
    let destination = parent.join(name);
    revalidate_windows_storage_directories(&pinned_directories, label)?;
    if let Some(existing) = read_bounded_file(&destination, maximum_bytes, label)? {
        if existing != bytes {
            return Err(storage_error(format!(
                "refusing to replace conflicting immutable {label}: {}",
                destination.display()
            )));
        }
        crate::durable_fs::sync_direct_directory(&parent).map_err(|error| {
            map_io_error(error, "failed to sync existing contract source directory")
        })?;
        revalidate_windows_storage_directories(&pinned_directories, label)?;
        return Ok(());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(&parent)
        .map_err(|error| map_io_error(error, "failed to create contract source temporary file"))?;
    let temporary_before = crate::secure_file_metadata::from_file(temporary.as_file())
        .map_err(|error| map_io_error(error, "failed to inspect contract source temporary file"))?;
    validate_windows_storage_file(&temporary_before, temporary.path(), label)?;
    if temporary_before.len() != 0 {
        return Err(conversion_error(
            "contract source temporary file was not empty at creation",
        ));
    }
    revalidate_windows_storage_directories(&pinned_directories, label)?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| map_io_error(error, "failed to sync contract source temporary file"))?;
    let temporary_ready =
        crate::secure_file_metadata::from_file(temporary.as_file()).map_err(|error| {
            map_io_error(
                error,
                "failed to inspect synced contract source temporary file",
            )
        })?;
    validate_windows_storage_file(&temporary_ready, temporary.path(), label)?;
    if !crate::secure_file_metadata::same_file(&temporary_before, &temporary_ready)
        || usize::try_from(temporary_ready.len()).ok() != Some(bytes.len())
    {
        return Err(conversion_error(
            "contract source temporary file changed unexpectedly while being written",
        ));
    }
    revalidate_windows_storage_directories(&pinned_directories, label)?;

    let published_file = match temporary.persist_noclobber(&destination) {
        Ok(file) => file,
        Err(error) => {
            if error.error.kind() == io::ErrorKind::AlreadyExists
                && read_bounded_file(&destination, maximum_bytes, label)?
                    .is_some_and(|existing| existing == bytes)
            {
                drop(temporary_ready);
                drop(error);
                crate::durable_fs::sync_direct_directory(&parent).map_err(|error| {
                    map_io_error(error, "failed to sync existing contract source directory")
                })?;
                revalidate_windows_storage_directories(&pinned_directories, label)?;
                return Ok(());
            }
            return Err(map_io_error(
                error.error,
                "failed no-clobber contract source publication",
            ));
        }
    };
    let published_before = crate::secure_file_metadata::from_file(&published_file)
        .map_err(|error| map_io_error(error, "failed to inspect published contract source file"))?;
    let named_after_publish = crate::secure_file_metadata::from_path(&destination)
        .map_err(|error| map_io_error(error, "failed to inspect named contract source file"))?;
    validate_windows_storage_file(&published_before, &destination, label)?;
    validate_windows_storage_file(&named_after_publish, &destination, label)?;
    if !crate::secure_file_metadata::same_file(&temporary_ready, &published_before)
        || !crate::secure_file_metadata::unchanged(&temporary_ready, &published_before)
        || !crate::secure_file_metadata::same_file(&published_before, &named_after_publish)
        || !crate::secure_file_metadata::unchanged(&published_before, &named_after_publish)
    {
        return Err(conversion_error(format!(
            "published {label} changed identity or revision: {}",
            destination.display()
        )));
    }
    revalidate_windows_storage_directories(&pinned_directories, label)?;
    crate::durable_fs::sync_direct_directory(&parent)
        .map_err(|error| map_io_error(error, "failed to sync contract source directory"))?;
    let published_after =
        crate::secure_file_metadata::from_file(&published_file).map_err(|error| {
            map_io_error(error, "failed to re-inspect published contract source file")
        })?;
    let named_after_sync = crate::secure_file_metadata::from_path(&destination)
        .map_err(|error| map_io_error(error, "failed to re-inspect named contract source file"))?;
    validate_windows_storage_file(&published_after, &destination, label)?;
    validate_windows_storage_file(&named_after_sync, &destination, label)?;
    if !crate::secure_file_metadata::same_file(&published_before, &published_after)
        || !crate::secure_file_metadata::unchanged(&published_before, &published_after)
        || !crate::secure_file_metadata::same_file(&published_after, &named_after_sync)
        || !crate::secure_file_metadata::unchanged(&published_after, &named_after_sync)
    {
        return Err(conversion_error(format!(
            "published {label} changed while its directory was synchronized: {}",
            destination.display()
        )));
    }
    revalidate_windows_storage_directories(&pinned_directories, label)?;
    let readback = read_bounded_file(&destination, maximum_bytes, label)?
        .ok_or_else(|| conversion_error(format!("published {label} disappeared")))?;
    revalidate_windows_storage_directories(&pinned_directories, label)?;
    if readback != bytes {
        return Err(conversion_error(format!(
            "published {label} differs from its synced temporary file"
        )));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn write_immutable_file(
    _path: &Path,
    _bytes: &[u8],
    _maximum_bytes: usize,
    label: &str,
) -> Result<(), Error> {
    Err(storage_error(format!(
        "secure immutable {label} storage is unsupported on this platform"
    )))
}

#[cfg(unix)]
fn read_bounded_file(
    path: &Path,
    maximum_bytes: usize,
    label: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let Some((directory, name)) = open_storage_parent(path, false, label)? else {
        return Ok(None);
    };
    read_bounded_relative(&directory, &name, path, maximum_bytes, label)
}

#[cfg(windows)]
fn read_bounded_file(
    path: &Path,
    maximum_bytes: usize,
    label: &str,
) -> Result<Option<Vec<u8>>, Error> {
    use crate::secure_file_metadata::{from_file, from_path, same_file, unchanged};

    let (parent, name) = storage_parent(path)?;
    let Some((parent, pinned_directories)) = prepare_windows_storage_parent(parent, false, label)?
    else {
        return Ok(None);
    };
    let path = parent.join(name);
    revalidate_windows_storage_directories(&pinned_directories, label)?;
    let maximum_u64 = u64::try_from(maximum_bytes).unwrap_or(u64::MAX);
    let before = match from_path(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(map_io_error(
                error,
                "failed to inspect contract source file",
            ));
        }
    };
    validate_windows_storage_file(&before, &path, label)?;
    revalidate_windows_storage_directories(&pinned_directories, label)?;
    if before.len() > maximum_u64 {
        return Err(conversion_error(format!(
            "{label} at {} exceeds the first-release {maximum_bytes}-byte maximum",
            path.display()
        )));
    }
    let mut file = match crate::secure_file_metadata::open_direct_file(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_io_error(error, "failed to open contract source file")),
    };
    let opened_before = from_file(&file)
        .map_err(|error| map_io_error(error, "failed to inspect contract source file"))?;
    let named_after_open = from_path(&path)
        .map_err(|error| map_io_error(error, "failed to re-inspect contract source file"))?;
    validate_windows_storage_file(&opened_before, &path, label)?;
    validate_windows_storage_file(&named_after_open, &path, label)?;
    if !same_file(&before, &opened_before)
        || !unchanged(&before, &opened_before)
        || !same_file(&opened_before, &named_after_open)
        || !unchanged(&opened_before, &named_after_open)
        || opened_before.len() > maximum_u64
    {
        return Err(conversion_error(format!(
            "{label} changed while it was being opened: {}",
            path.display()
        )));
    }
    revalidate_windows_storage_directories(&pinned_directories, label)?;
    let initial_capacity = usize::try_from(opened_before.len()).map_err(|_| {
        conversion_error(format!(
            "{label} at {} has a length that does not fit this platform",
            path.display()
        ))
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(initial_capacity).map_err(|error| {
        conversion_error(format!(
            "failed to reserve bounded {label} read ({initial_capacity} bytes): {error}"
        ))
    })?;
    (&mut file)
        .take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| map_io_error(error, "failed to read contract source file"))?;
    if bytes.len() > maximum_bytes {
        return Err(conversion_error(format!(
            "{label} at {} exceeds the first-release {maximum_bytes}-byte maximum",
            path.display()
        )));
    }
    let opened_after = from_file(&file)
        .map_err(|error| map_io_error(error, "failed to re-inspect contract source file"))?;
    let named_after_read = from_path(&path)
        .map_err(|error| map_io_error(error, "failed to re-inspect contract source file"))?;
    validate_windows_storage_file(&opened_after, &path, label)?;
    validate_windows_storage_file(&named_after_read, &path, label)?;
    if !same_file(&opened_before, &opened_after)
        || !unchanged(&opened_before, &opened_after)
        || !same_file(&opened_after, &named_after_read)
        || !unchanged(&opened_after, &named_after_read)
        || !same_file(&before, &named_after_read)
        || !unchanged(&before, &named_after_read)
        || u64::try_from(bytes.len()).ok() != Some(opened_before.len())
    {
        return Err(conversion_error(format!(
            "{label} changed while it was being read: {}",
            path.display()
        )));
    }
    revalidate_windows_storage_directories(&pinned_directories, label)?;
    Ok(Some(bytes))
}

#[cfg(not(any(unix, windows)))]
fn read_bounded_file(
    _path: &Path,
    _maximum_bytes: usize,
    label: &str,
) -> Result<Option<Vec<u8>>, Error> {
    Err(storage_error(format!(
        "secure bounded {label} reads are unsupported on this platform"
    )))
}

fn read_canonical_json_file<T>(
    path: &Path,
    maximum_bytes: usize,
    label: &str,
) -> Result<Option<T>, Error>
where
    T: norito::json::JsonDeserializeOwned + norito::json::JsonSerialize,
{
    let Some(bytes) = read_bounded_file(path, maximum_bytes, label)? else {
        return Ok(None);
    };
    let value: T = norito::json::from_slice(&bytes)
        .map_err(|error| storage_error(format!("failed to decode bounded {label}: {error}")))?;
    let canonical = crate::utils::encode_json_bounded(&value, maximum_bytes).map_err(|error| {
        storage_error(format!(
            "failed to re-encode bounded decoded {label}: {error}"
        ))
    })?;
    if canonical.as_bytes() != bytes {
        return Err(storage_error(format!(
            "stored {label} is not the exact canonical V1 encoding"
        )));
    }
    Ok(Some(value))
}

fn exact_fixed_hex(value: &str) -> bool {
    if value.len() != FIXED_HEX_COMPONENT_CHARS_V1 {
        return false;
    }
    let mut decoded = [0_u8; FIXED_HEX_COMPONENT_BYTES_V1];
    hex::decode_to_slice(value, &mut decoded).is_ok() && hex::encode(decoded) == value
}

fn exact_persisted_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= VERIFIED_SOURCE_TIMESTAMP_MAX_BYTES_V1
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn exact_provider_reference_fields(
    manifest_id_hex: Option<&str>,
    payload_digest_hex: Option<&str>,
    content_length: Option<u64>,
) -> bool {
    match (manifest_id_hex, payload_digest_hex, content_length) {
        (None, None, None) => true,
        (Some(manifest), Some(payload), Some(length)) => {
            exact_fixed_hex(manifest) && exact_fixed_hex(payload) && length != 0
        }
        _ => false,
    }
}

fn validate_verified_source_ref(reference: &ContractVerifiedSourceRefDto) -> Result<(), Error> {
    if reference.language != VERIFIED_SOURCE_LANGUAGE_KOTODAMA
        || reference.source_name.as_ref().is_some_and(|name| {
            name.is_empty()
                || name.len() > VERIFIED_SOURCE_NAME_MAX_BYTES_V1
                || name.chars().any(char::is_control)
        })
        || !exact_persisted_timestamp(&reference.submitted_at)
        || !exact_provider_reference_fields(
            reference.manifest_id_hex.as_deref(),
            reference.payload_digest_hex.as_deref(),
            reference.content_length,
        )
        || reference.manifest_id_hex.is_none()
    {
        return Err(storage_error(
            "stored verified-source reference violates the exact V1 schema",
        ));
    }
    Ok(())
}

fn validate_verified_source_record_schema(
    record: &StoredVerifiedSourceRecord,
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
) -> Result<(), Error> {
    let expected_code_hash = hash_hex(&artifact_id.code_hash);
    if record.network_id != network_id || record.artifact_id != artifact_id {
        return Err(storage_error(
            "stored verified-source record network or dataspace differs from its canonical path",
        ));
    }
    if record.version != VERIFIED_SOURCE_VERSION {
        return Err(storage_error(format!(
            "stored verified-source record advertises unsupported version {}; expected V{VERIFIED_SOURCE_VERSION}",
            record.version
        )));
    }
    if record.code_hash != expected_code_hash || !exact_fixed_hex(&record.code_hash) {
        return Err(storage_error(
            "stored verified-source record identity does not match its canonical path",
        ));
    }
    if record.language != VERIFIED_SOURCE_LANGUAGE_KOTODAMA
        || record.source_text.trim().is_empty()
        || record.source_text.len() > VERIFIED_SOURCE_TEXT_MAX_BYTES_V1
        || source_bundle_bound_error(
            record.source_name.as_deref(),
            &record.source_text,
            &record.sources,
            &record.imports,
            &record.packages,
            &record.artifacts,
        )
        .is_some()
        || record.source_name.as_ref().is_some_and(|name| {
            name.is_empty()
                || name.len() > VERIFIED_SOURCE_NAME_MAX_BYTES_V1
                || name.chars().any(char::is_control)
        })
        || !exact_persisted_timestamp(&record.submitted_at)
        || record
            .abi_hash
            .as_deref()
            .is_none_or(|digest| !exact_fixed_hex(digest))
        || !exact_provider_reference_fields(
            record.manifest_id_hex.as_deref(),
            record.payload_digest_hex.as_deref(),
            record.content_length,
        )
    {
        return Err(storage_error(
            "stored verified-source record violates the exact V1 schema",
        ));
    }
    Ok(())
}

fn validate_verified_source_record(
    record: &StoredVerifiedSourceRecord,
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
) -> Result<(), Error> {
    let expected_code_hash = hash_hex(&artifact_id.code_hash);
    validate_verified_source_record_schema(record, network_id, artifact_id)?;
    let compiled = compile_verified_source(
        record.source_name.as_deref(),
        &record.source_text,
        &record.sources,
        &record.imports,
        &record.packages,
        &record.artifacts,
    )
    .map_err(|_| {
        storage_error("stored verified-source record no longer compiles under Kotodama V1")
    })?;
    let actual_hash = canonical_code_hash(&compiled.artifact)?;
    if hash_hex(&actual_hash) != expected_code_hash {
        return Err(storage_error(
            "stored verified-source record does not compile to its canonical code hash",
        ));
    }
    let verified = ivm::verify_contract_artifact(&compiled.artifact).map_err(|_| {
        storage_error("stored verified-source record does not produce a valid IVM artifact")
    })?;
    let expected_abi_hash = hash_hex(&verified.abi_hash);
    if record.abi_hash.as_deref() != Some(expected_abi_hash.as_str())
        || record.compiler_fingerprint != verified.manifest.compiler_fingerprint
    {
        return Err(storage_error(
            "stored verified-source record ABI or compiler identity differs from its recompiled artifact",
        ));
    }
    Ok(())
}

fn validate_verified_source_job(
    job: &StoredVerifiedSourceJob,
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
    expected_job_id: &str,
) -> Result<(), Error> {
    let expected_hash = hash_hex(&artifact_id.code_hash);
    let expected_code_hash = expected_hash.as_str();
    if job.network_id != network_id || job.artifact_id != artifact_id {
        return Err(storage_error(
            "stored verified-source job network or dataspace differs from its canonical path",
        ));
    }
    if job.version != VERIFIED_SOURCE_VERSION {
        return Err(storage_error(format!(
            "stored verified-source job advertises unsupported version {}; expected V{VERIFIED_SOURCE_VERSION}",
            job.version
        )));
    }
    if job.code_hash != expected_code_hash
        || job.job_id != expected_job_id
        || !exact_fixed_hex(&job.code_hash)
        || !exact_fixed_hex(&job.job_id)
        || !exact_persisted_timestamp(&job.submitted_at)
        || job
            .completed_at
            .as_deref()
            .is_none_or(|timestamp| !exact_persisted_timestamp(timestamp))
        || job.message.as_ref().is_none_or(|message| {
            message.is_empty() || message.len() > VERIFIED_SOURCE_JOB_MESSAGE_MAX_BYTES_V1
        })
        || job
            .actual_code_hash
            .as_deref()
            .is_some_and(|hash| !exact_fixed_hex(hash))
    {
        return Err(storage_error(
            "stored verified-source job violates the exact V1 schema or canonical path identity",
        ));
    }
    match job.status.as_str() {
        "accepted" | "conflict" if job.actual_code_hash.as_deref() == Some(expected_code_hash) => {}
        "mismatch"
            if job
                .actual_code_hash
                .as_deref()
                .is_some_and(|hash| hash != expected_code_hash)
                && job.verified_source_ref.is_none() => {}
        "compile_error" | "error"
            if job.actual_code_hash.is_none() && job.verified_source_ref.is_none() => {}
        _ => {
            return Err(storage_error(
                "stored verified-source job has an inconsistent V1 status projection",
            ));
        }
    }
    if let Some(reference) = &job.verified_source_ref {
        validate_verified_source_ref(reference)?;
    }
    Ok(())
}

fn load_verified_source_record(
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
) -> Result<Option<StoredVerifiedSourceRecord>, Error> {
    let record = read_canonical_json_file(
        &verified_source_record_path(network_id, artifact_id),
        VERIFIED_SOURCE_RECORD_MAX_BYTES_V1,
        "verified-source record",
    )?;
    if let Some(record) = &record {
        validate_verified_source_record(record, network_id, artifact_id)?;
    }
    Ok(record)
}
fn load_verified_source_job(
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
    job_id: &str,
) -> Result<Option<ContractVerifiedSourceJobResponseDto>, Error> {
    let job = read_canonical_json_file::<StoredVerifiedSourceJob>(
        &verified_source_job_path(network_id, artifact_id, job_id),
        VERIFIED_SOURCE_JOB_MAX_BYTES_V1,
        "verified-source job",
    )?;
    if let Some(job) = &job {
        validate_verified_source_job(job, network_id, artifact_id, job_id)?;
    }
    Ok(job.map(Into::into))
}
fn persist_verified_source_record_locked(record: &StoredVerifiedSourceRecord) -> Result<(), Error> {
    validate_verified_source_record_schema(record, record.network_id, record.artifact_id)?;
    write_json_file_atomic(
        &verified_source_record_path(record.network_id, record.artifact_id),
        record,
        VERIFIED_SOURCE_RECORD_MAX_BYTES_V1,
        "verified-source record",
    )
}
#[cfg(test)]
fn persist_verified_source_record(record: &StoredVerifiedSourceRecord) -> Result<(), Error> {
    let mutation_lock = verified_source_mutation_lock(record.network_id, record.artifact_id);
    let _guard = mutation_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    persist_verified_source_record_locked(record)
}
fn persist_verified_source_job(job: &StoredVerifiedSourceJob) -> Result<(), Error> {
    validate_verified_source_job(job, job.network_id, job.artifact_id, &job.job_id)?;
    write_json_file_atomic(
        &verified_source_job_path(job.network_id, job.artifact_id, &job.job_id),
        job,
        VERIFIED_SOURCE_JOB_MAX_BYTES_V1,
        "verified-source job",
    )
}
fn verified_source_ref_from_record(
    record: &StoredVerifiedSourceRecord,
) -> Option<ContractVerifiedSourceRefDto> {
    if record.manifest_id_hex.is_none()
        && record.payload_digest_hex.is_none()
        && record.content_length.is_none()
    {
        return None;
    }
    Some(ContractVerifiedSourceRefDto {
        language: record.language.clone(),
        source_name: record.source_name.clone(),
        submitted_at: record.submitted_at.clone(),
        manifest_id_hex: record.manifest_id_hex.clone(),
        payload_digest_hex: record.payload_digest_hex.clone(),
        content_length: record.content_length,
    })
}
impl From<StoredVerifiedSourceJob> for ContractVerifiedSourceJobResponseDto {
    fn from(value: StoredVerifiedSourceJob) -> Self {
        Self {
            network_id: value.network_id,
            artifact_id: value.artifact_id,
            job_id: value.job_id,
            code_hash: value.code_hash,
            status: value.status,
            submitted_at: value.submitted_at,
            completed_at: value.completed_at,
            message: value.message,
            actual_code_hash: value.actual_code_hash,
            verified_source_ref: value.verified_source_ref,
        }
    }
}
fn persist_job_response(
    job: ContractVerifiedSourceJobResponseDto,
) -> Result<ContractVerifiedSourceJobResponseDto, Error> {
    let stored = StoredVerifiedSourceJob {
        network_id: job.network_id,
        artifact_id: job.artifact_id,
        version: VERIFIED_SOURCE_VERSION,
        job_id: job.job_id.clone(),
        code_hash: job.code_hash.clone(),
        status: job.status.clone(),
        submitted_at: job.submitted_at.clone(),
        completed_at: job.completed_at.clone(),
        message: job.message.clone(),
        actual_code_hash: job.actual_code_hash.clone(),
        verified_source_ref: job.verified_source_ref.clone(),
    };
    persist_verified_source_job(&stored)?;
    Ok(job)
}
fn entrypoint_kind_label(kind: EntryPointKind) -> &'static str {
    match kind {
        EntryPointKind::Kotoage => "kotoage",
        EntryPointKind::View => "view",
        EntryPointKind::Hajimari => "hajimari",
        EntryPointKind::Kaizen => "kaizen",
    }
}
fn kotodama_string_literal(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len().saturating_add(2));
    rendered.push('"');
    for character in value.chars() {
        match character {
            '\\' => rendered.push_str("\\\\"),
            '"' => rendered.push_str("\\\""),
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            '\t' => rendered.push_str("\\t"),
            '\0' => rendered.push_str("\\0"),
            character if character.is_control() => {
                rendered.push_str(&format!("\\u{{{:x}}}", u32::from(character)));
            }
            character => rendered.push(character),
        }
    }
    rendered.push('"');
    rendered
}
fn entrypoint_signature(entrypoint: &EntrypointDescriptor) -> Result<String, &'static str> {
    let params = entrypoint
        .params
        .iter()
        .map(|param| format!("{} {}", param.type_name, param.name))
        .collect::<Vec<_>>()
        .join(", ");
    let return_type = entrypoint
        .return_type
        .as_ref()
        .map(|value| format!(" -> {value}"))
        .unwrap_or_default();
    let authorization = match (&entrypoint.kind, &entrypoint.authorization) {
        (EntryPointKind::Kotoage | EntryPointKind::View, EntrypointAuthorizationV1::Anyone) => {
            " authorize(anyone)".to_owned()
        }
        (
            EntryPointKind::Kotoage | EntryPointKind::View,
            EntrypointAuthorizationV1::Permission(name),
        ) => format!(" authorize({name})"),
        (
            EntryPointKind::Hajimari | EntryPointKind::Kaizen,
            EntrypointAuthorizationV1::RuntimeLifecycle,
        ) => String::new(),
        _ => return Err("entrypoint kind and authorization policy do not match"),
    };
    Ok(match entrypoint.kind {
        EntryPointKind::Kotoage | EntryPointKind::View => format!(
            "{} fn {}({}){}{}",
            entrypoint_kind_label(entrypoint.kind),
            entrypoint.name,
            params,
            authorization,
            return_type
        ),
        EntryPointKind::Hajimari | EntryPointKind::Kaizen => format!(
            "{}({}){}",
            entrypoint_kind_label(entrypoint.kind),
            params,
            return_type
        ),
    })
}
fn render_program_syscalls(analysis: &ProgramAnalysis) -> String {
    if analysis.syscalls.is_empty() {
        return "none".to_owned();
    }
    analysis
        .syscalls
        .iter()
        .map(|entry| {
            let name = ivm::syscalls::syscall_name(entry.number).unwrap_or("UNKNOWN");
            format!("{name} x{}", entry.count)
        })
        .collect::<Vec<_>>()
        .join(", ")
}
fn trigger_label(
    trigger: &iroha_data_model::smart_contract::manifest::TriggerDescriptor,
) -> String {
    let callback = match &trigger.callback.namespace {
        Some(namespace) => format!("{namespace}.{}", trigger.callback.entrypoint),
        None => trigger.callback.entrypoint.clone(),
    };
    format!("{} -> {}", trigger.id, callback)
}
fn render_pseudo_source(
    code_hash: &str,
    manifest: Option<&ContractManifest>,
    analysis: Option<&ProgramAnalysis>,
) -> String {
    let seiyaku_name = format!(
        "Contract_{}",
        &code_hash.chars().take(8).collect::<String>()
    );
    let mut lines = Vec::new();
    lines.push(format!("seiyaku {seiyaku_name} {{"));
    lines.push(
        "  // Decompiled pseudo-source derived from contract bytes and manifest hints.".to_owned(),
    );
    lines.push(format!("  // code_hash: {code_hash}"));
    if let Some(manifest) = manifest {
        render_permission_declarations(manifest, &mut lines);
        if let Some(abi_hash) = manifest.abi_hash.as_ref() {
            lines.push(format!("  // abi_hash: {}", hash_hex(abi_hash)));
        }
        if let Some(compiler) = manifest.compiler_fingerprint.as_ref() {
            lines.push(format!("  // compiler_fingerprint: {compiler}"));
        }
        if let Some(features) = manifest.features_bitmap {
            lines.push(format!("  // features_bitmap: 0x{features:x}"));
        }
    }
    if let Some(analysis) = analysis {
        lines.push(format!(
            "  // static analysis: {} instructions; memory(load64={}, store64={}, load128={}, store128={})",
            analysis.instruction_count,
            analysis.memory.load64,
            analysis.memory.store64,
            analysis.memory.load128,
            analysis.memory.store128
        ));
        lines.push(format!(
            "  // static syscalls: {}",
            render_program_syscalls(analysis)
        ));
    }
    if let Some(manifest) = manifest {
        if let Some(entrypoints) = manifest.entrypoints.as_ref() {
            for entrypoint in entrypoints {
                let Ok(signature) = entrypoint_signature(entrypoint) else {
                    lines.push(String::new());
                    lines.push(
                        "  // Invalid entrypoint descriptor omitted from pseudo-source.".to_owned(),
                    );
                    continue;
                };
                lines.push(String::new());
                lines.push(format!("  {signature} {{"));
                if !entrypoint.read_keys.is_empty() {
                    lines.push(format!("    // reads: {}", entrypoint.read_keys.join(", ")));
                }
                if !entrypoint.write_keys.is_empty() {
                    lines.push(format!(
                        "    // writes: {}",
                        entrypoint.write_keys.join(", ")
                    ));
                }
                if !entrypoint.triggers.is_empty() {
                    let triggers = entrypoint
                        .triggers
                        .iter()
                        .map(trigger_label)
                        .collect::<Vec<_>>()
                        .join(", ");
                    lines.push(format!("    // triggers: {triggers}"));
                }
                if !entrypoint.access_hints_skipped.is_empty() {
                    lines.push(format!(
                        "    // skipped access hints: {}",
                        entrypoint.access_hints_skipped.join(", ")
                    ));
                }
                lines.push(
                    "    // body omitted; output reconstructed from static metadata.".to_owned(),
                );
                lines.push("  }".to_owned());
            }
        } else {
            lines.push(String::new());
            lines.push("  // No entrypoint metadata was embedded in the manifest.".to_owned());
        }
    } else {
        lines.push(String::new());
        lines.push("  // Manifest metadata is unavailable for this artifact.".to_owned());
    }
    lines.push("}".to_owned());
    lines.join("\n")
}
fn render_manifest_stub(
    code_hash: &str,
    manifest: Option<&ContractManifest>,
    warnings: &[String],
) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "seiyaku ManifestStub_{} {{",
        &code_hash[..code_hash.len().min(8)]
    ));
    lines.push(
        "  // Decompiled code bytes are unavailable; showing manifest-derived hints only."
            .to_owned(),
    );
    lines.push(format!("  // code_hash: {code_hash}"));
    if let Some(manifest) = manifest {
        render_permission_declarations(manifest, &mut lines);
        if let Some(abi_hash) = manifest.abi_hash.as_ref() {
            lines.push(format!("  // abi_hash: {}", hash_hex(abi_hash)));
        }
        if let Some(compiler) = manifest.compiler_fingerprint.as_ref() {
            lines.push(format!("  // compiler_fingerprint: {compiler}"));
        }
        if let Some(entrypoints) = manifest.entrypoints.as_ref() {
            for entrypoint in entrypoints {
                match entrypoint_signature(entrypoint) {
                    Ok(signature) => lines.push(format!("  // entrypoint: {signature}")),
                    Err(_) => lines.push(
                        "  // Invalid entrypoint descriptor omitted from manifest stub.".to_owned(),
                    ),
                }
            }
        }
    }
    for warning in warnings {
        lines.push(format!("  // warning: {warning}"));
    }
    lines.push("}".to_owned());
    lines.join("\n")
}
fn aggregate_permissions(
    manifest: Option<&ContractManifest>,
) -> Vec<ContractPermissionDescriptorV1> {
    manifest.map_or_else(Vec::new, |manifest| manifest.permissions.clone())
}
fn render_permission_declarations(manifest: &ContractManifest, lines: &mut Vec<String>) {
    for declaration in &manifest.permissions {
        lines.push(match &declaration.scope {
            ContractPermissionScopeV1::Instance => format!("  permission {};", declaration.name),
            ContractPermissionScopeV1::Chain { permission_name } => format!(
                "  import permission {} as {};",
                kotodama_string_literal(permission_name.as_ref()),
                declaration.name
            ),
        });
    }
}
fn to_entrypoint_dto(entrypoint: &EntrypointDescriptor) -> ContractViewEntrypointDto {
    ContractViewEntrypointDto {
        name: entrypoint.name.clone(),
        kind: entrypoint_kind_label(entrypoint.kind).to_owned(),
        params: entrypoint
            .params
            .iter()
            .map(|param| ContractViewEntrypointParamDto {
                name: param.name.clone(),
                type_name: param.type_name.clone(),
            })
            .collect(),
        return_type: entrypoint.return_type.clone(),
        authorization: entrypoint.authorization.clone(),
        read_keys: entrypoint.read_keys.clone(),
        write_keys: entrypoint.write_keys.clone(),
        access_hints_complete: entrypoint.access_hints_complete,
        access_hints_skipped: entrypoint.access_hints_skipped.clone(),
        triggers: entrypoint.triggers.iter().map(trigger_label).collect(),
    }
}
fn to_analysis_dto(analysis: &ProgramAnalysis) -> ContractViewAnalysisDto {
    ContractViewAnalysisDto {
        instruction_count: analysis.instruction_count as u64,
        memory: ContractViewMemoryDto {
            load64: analysis.memory.load64,
            store64: analysis.memory.store64,
            load128: analysis.memory.load128,
            store128: analysis.memory.store128,
        },
        syscalls: analysis
            .syscalls
            .iter()
            .map(|entry| ContractViewSyscallDto {
                number: entry.number,
                name: ivm::syscalls::syscall_name(entry.number).map(ToOwned::to_owned),
                count: entry.count,
            })
            .collect(),
    }
}
fn locate_instruction_box(
    state: &CoreState,
    transaction_hash: &str,
    index: u64,
) -> Result<InstructionBox, Error> {
    if state.emergency_fast_startup_enabled() {
        return Err(Error::AppServiceUnavailable {
            code: "emergency_fast_history_unavailable",
            message: "instruction contract view requires a historical transaction scan that emergency Fast mode deliberately disables; restart in Strict mode"
                .to_owned(),
        });
    }
    let target: iroha_crypto::HashOf<TransactionEntrypoint> = transaction_hash
        .trim()
        .parse()
        .map_err(|_| conversion_error("invalid transaction hash".to_owned()))?;
    let lookup_index: usize = index
        .try_into()
        .map_err(|_| conversion_error("instruction index exceeds host pointer width"))?;
    let height = state
        .committed_entrypoint_height(&target)
        .ok_or_else(not_found)?;
    let work = crate::routing::app_query_limits().max_fetch_size;
    let carrier = state
        .read_finalized_execution_carrier(
            height,
            work,
            iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work),
        )
        .map_err(crate::canonical_history::query_attempt_error)?;
    let mut instruction = None;
    let mut matched = false;
    for (source_hash, signed, _) in crate::canonical_history::signed_calls(carrier.block())
        .map_err(|error| conversion_error(error.to_string()))?
    {
        if !crate::signed_transaction_carrier_matches_indexed_identity(
            &source_hash,
            signed,
            &target,
        ) {
            continue;
        }
        if matched {
            return Err(conversion_error(
                "indexed transaction has duplicate Network sources",
            ));
        }
        matched = true;
        instruction = signed
            .instructions()
            .explicit_instructions()
            .nth(lookup_index)
            .cloned();
    }
    if state.committed_entrypoint_height(&target) != Some(height) {
        return Err(conversion_error(
            "transaction membership changed during instruction lookup",
        ));
    }
    instruction.ok_or_else(not_found)
}

fn build_contract_view(mut input: ContractViewBuildInput) -> Result<ContractCodeViewDto, Error> {
    let mut code_hash = input.code_hash.clone().unwrap_or_default();
    let mut declared_code_hash = input.declared_code_hash.clone();
    let mut manifest = input.manifest.take();
    let mut compiler_fingerprint = manifest
        .as_ref()
        .and_then(|value| value.compiler_fingerprint.clone());
    let mut abi_hash = manifest
        .as_ref()
        .and_then(|value| value.abi_hash.as_ref().map(hash_hex));
    let mut analysis = None;
    let byte_len = input.code_bytes.as_ref().map(|bytes| bytes.len() as u64);
    if let Some(code_bytes) = input.code_bytes.as_ref() {
        let canonical_hash = canonical_code_hash(code_bytes)?;
        match ivm::verify_contract_artifact(code_bytes) {
            Ok(verified) => {
                let verified_hash = hash_hex(&canonical_hash);
                if declared_code_hash.is_none() {
                    declared_code_hash = input.code_hash.clone();
                }
                if code_hash.is_empty() {
                    code_hash = verified_hash.clone();
                } else if code_hash != verified_hash {
                    input.warnings.push(format!(
                        "Declared code hash {code_hash} does not match verified artifact hash {verified_hash}; showing the verified artifact hash."
                    ));
                    declared_code_hash = Some(code_hash.clone());
                    code_hash = verified_hash.clone();
                }
                let verified_manifest = verified.manifest;
                match manifest.as_ref() {
                    Some(existing) if existing.same_signed_content(&verified_manifest) => {}
                    Some(_) => {
                        input.warnings.push(
                            "Stored manifest does not match the verified artifact; using metadata embedded in the contract bytes.".to_owned(),
                        );
                        manifest = Some(verified_manifest);
                    }
                    None => {
                        manifest = Some(verified_manifest);
                    }
                }
                abi_hash = Some(hash_hex(&verified.abi_hash));
                compiler_fingerprint = Some(verified.contract_interface.compiler_fingerprint);
                match ivm::analysis::analyze_program(code_bytes) {
                    Ok(value) => analysis = Some(value),
                    Err(err) => input
                        .warnings
                        .push(format!("Static analysis unavailable: {err}")),
                }
            }
            Err(err) => {
                input
                    .warnings
                    .push(format!("Contract artifact verification failed: {err}"));
            }
        }
    }
    if code_hash.is_empty() {
        if let Some(manifest_hash) = manifest
            .as_ref()
            .and_then(|value| value.code_hash.as_ref().map(hash_hex))
        {
            code_hash = manifest_hash;
        } else {
            return Err(not_found());
        }
    }
    input.artifact_id = crate::routing::parse_contract_artifact_path(
        &input.artifact_id.dataspace_id.as_u64().to_string(),
        &code_hash,
    )?;
    let verified_source_record = load_verified_source_record(input.network_id, input.artifact_id)?;
    let verified_source_ref = verified_source_record
        .as_ref()
        .and_then(verified_source_ref_from_record);
    let rendered_source_kind;
    let rendered_source_text;
    if let Some(record) = verified_source_record.as_ref() {
        rendered_source_kind = RENDERED_SOURCE_VERIFIED.to_owned();
        rendered_source_text = record.source_text.clone();
    } else if input.code_bytes.is_some() {
        rendered_source_kind = RENDERED_SOURCE_PSEUDO.to_owned();
        rendered_source_text =
            render_pseudo_source(&code_hash, manifest.as_ref(), analysis.as_ref());
    } else {
        rendered_source_kind = RENDERED_SOURCE_MANIFEST_STUB.to_owned();
        rendered_source_text = render_manifest_stub(&code_hash, manifest.as_ref(), &input.warnings);
    }
    Ok(ContractCodeViewDto {
        network_id: input.network_id,
        artifact_id: input.artifact_id,
        code_hash,
        declared_code_hash,
        abi_hash,
        compiler_fingerprint,
        byte_len,
        permissions: aggregate_permissions(manifest.as_ref()),
        access_hints: manifest
            .as_ref()
            .and_then(|value| value.access_set_hints.as_ref())
            .map(|hints| ContractViewAccessHintsDto {
                read_keys: hints.read_keys.clone(),
                write_keys: hints.write_keys.clone(),
            }),
        entrypoints: manifest
            .as_ref()
            .and_then(|value| value.entrypoints.as_ref())
            .map(|entrypoints| entrypoints.iter().map(to_entrypoint_dto).collect())
            .unwrap_or_default(),
        analysis: analysis.as_ref().map(to_analysis_dto),
        warnings: input.warnings,
        rendered_source_kind,
        rendered_source_text,
        source_artifacts: verified_source_record
            .as_ref()
            .map(|record| record.artifacts.clone())
            .unwrap_or_default(),
        source_files: verified_source_record
            .as_ref()
            .map(|record| record.sources.clone())
            .unwrap_or_default(),
        source_imports: verified_source_record
            .as_ref()
            .map(|record| record.imports.clone())
            .unwrap_or_default(),
        source_packages: verified_source_record
            .as_ref()
            .map(|record| record.packages.clone())
            .unwrap_or_default(),
        verified_source_ref,
    })
}
fn resolve_contract_view_input_for_artifact(
    state: &CoreState,
    artifact_id: ContractArtifactId,
) -> Result<ContractViewBuildInput, Error> {
    let code_hash_hex = hash_hex(&artifact_id.code_hash);
    let world = state.world_view();
    let manifest = world.contract_manifests().get(&artifact_id).cloned();
    let code_bytes = world.contract_code().get(&artifact_id).cloned();
    if manifest.is_none() && code_bytes.is_none() {
        return Err(not_found());
    }
    Ok(ContractViewBuildInput {
        network_id: *state.network_id_ref(),
        artifact_id,
        code_hash: Some(code_hash_hex),
        declared_code_hash: None,
        manifest,
        code_bytes,
        warnings: Vec::new(),
    })
}
fn resolve_contract_view_input_for_instruction(
    instruction: &InstructionBox,
    state: &CoreState,
) -> Result<ContractViewBuildInput, Error> {
    let any = instruction.as_any();
    if let Some(register_bytes) = any.downcast_ref::<RegisterSmartContractBytes>() {
        return Ok(ContractViewBuildInput {
            network_id: *state.network_id_ref(),
            artifact_id: register_bytes.artifact_id,
            code_hash: Some(hash_hex(&register_bytes.artifact_id.code_hash)),
            declared_code_hash: Some(hash_hex(&register_bytes.artifact_id.code_hash)),
            manifest: None,
            code_bytes: Some(register_bytes.code.clone()),
            warnings: vec![
                "This view was reconstructed from historical instruction bytes; the deployment may have been rejected and the artifact may not exist on-chain.".to_owned(),
            ],
        });
    }
    if let Some(register_code) = any.downcast_ref::<RegisterSmartContractCode>() {
        let declared = register_code.manifest.code_hash.as_ref().map(hash_hex);
        return Ok(ContractViewBuildInput {
            network_id: *state.network_id_ref(),
            artifact_id: register_code.artifact_id,
            code_hash: declared.clone(),
            declared_code_hash: declared,
            manifest: Some(register_code.manifest.clone()),
            code_bytes: None,
            warnings: vec![
                "Only manifest metadata is available for this instruction; on-chain contract bytes were not included.".to_owned(),
            ],
        });
    }
    if let Some(activate) = any.downcast_ref::<ActivateContractInstance>() {
        let artifact_id =
            ContractArtifactId::for_address(&activate.contract_address, activate.code_hash)
                .map_err(|error| conversion_error(error.to_string()))?;
        let mut input = resolve_contract_view_input_for_artifact(state, artifact_id)?;
        input.warnings.push(format!(
            "Showing the contract currently bound to {}.",
            activate.contract_address
        ));
        return Ok(input);
    }
    Err(not_found())
}
fn new_job_id() -> Result<String, Error> {
    let mut bytes = [0_u8; FIXED_HEX_COMPONENT_BYTES_V1];
    rand::rand_core::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut bytes).map_err(
        |error| {
            storage_error(format!(
                "failed to generate verified-source job id: {error}"
            ))
        },
    )?;
    Ok(hex::encode(bytes))
}
fn verified_source_request_bound_error(
    request: &SubmitVerifiedContractSourceDto,
) -> Option<&'static str> {
    if request.language.len() > VERIFIED_SOURCE_LANGUAGE_MAX_BYTES_V1 {
        return Some("language exceeds the first-release 32-byte maximum");
    }
    if let Some(name) = &request.source_name {
        if name.is_empty() {
            return Some("source_name must be omitted instead of empty");
        }
        if name.len() > VERIFIED_SOURCE_NAME_MAX_BYTES_V1 {
            return Some("source_name exceeds the Kotodama V1 4096-byte maximum");
        }
        if name.chars().any(char::is_control) {
            return Some("source_name must not contain control characters");
        }
    }
    if request.source_text.len() > VERIFIED_SOURCE_TEXT_MAX_BYTES_V1 {
        return Some("source_text exceeds the Kotodama V1 1048576-byte maximum");
    }
    source_bundle_bound_error(
        request.source_name.as_deref(),
        &request.source_text,
        &request.sources,
        &request.imports,
        &request.packages,
        &request.artifacts,
    )
}
fn source_bundle_bound_error(
    source_name: Option<&str>,
    source_text: &str,
    sources: &[ContractSourceFileDto],
    imports: &[ContractSourceImportDto],
    packages: &[ContractSourcePackageDto],
    artifacts: &[ContractSourceArtifactDto],
) -> Option<&'static str> {
    let count = packages.iter().fold(
        1usize
            .saturating_add(sources.len())
            .saturating_add(artifacts.len()),
        |count, package| {
            count
                .saturating_add(package.modules.len())
                .saturating_add(package.sources.len())
                .saturating_add(package.artifacts.len())
        },
    );
    if count > kotodama_lang::linker::MAX_MODULE_GRAPH_SOURCES
        || packages.len() > kotodama_lang::linker::MAX_MODULE_GRAPH_SOURCES
    {
        return Some("source set exceeds the 512-file maximum");
    }
    if (!sources.is_empty() || !artifacts.is_empty() || !imports.is_empty() || !packages.is_empty())
        && source_name.is_none()
    {
        return Some("source_name is required when companion sources are supplied");
    }
    let mut bytes = source_text.len();
    for source in sources.iter().chain(
        packages
            .iter()
            .flat_map(|package| package.modules.iter().chain(&package.sources)),
    ) {
        if source.source_name.is_empty()
            || source.source_name.len() > VERIFIED_SOURCE_NAME_MAX_BYTES_V1
            || source.source_name.chars().any(char::is_control)
        {
            return Some("companion source_name must be a bounded nonempty logical path");
        }
        if source.source_text.len() > VERIFIED_SOURCE_TEXT_MAX_BYTES_V1 {
            return Some("companion source_text exceeds the 1048576-byte maximum");
        }
        bytes = bytes.saturating_add(source.source_text.len());
    }
    for package in packages {
        if package
            .exports
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != package.exports.len()
        {
            return Some("locked package contains duplicate exports");
        }
    }
    for artifact in artifacts
        .iter()
        .chain(packages.iter().flat_map(|package| &package.artifacts))
    {
        if artifact.source_name.is_empty()
            || artifact.source_name.len() > VERIFIED_SOURCE_NAME_MAX_BYTES_V1
            || artifact.source_name.chars().any(char::is_control)
            || !artifact.source_name.ends_with(".to")
            || artifact.artifact.is_empty()
        {
            return Some(
                "interface artifact requires a bounded .to path and complete nonempty bytes",
            );
        }
        bytes = bytes.saturating_add(artifact.artifact.len());
    }
    if bytes > kotodama_lang::linker::MAX_MODULE_GRAPH_SOURCE_BYTES {
        return Some("source set exceeds the 16777216-byte maximum");
    }
    None
}
fn verified_source_link_request(
    name: &str,
    source_text: &str,
    sources: &[ContractSourceFileDto],
    imports: &[ContractSourceImportDto],
    packages: &[ContractSourcePackageDto],
    artifacts: &[ContractSourceArtifactDto],
) -> kotodama_lang::linker::SourceLinkRequest {
    kotodama_lang::linker::SourceLinkRequest {
        artifacts: artifacts.iter().map(source_artifact_unit).collect(),
        root: kotodama_lang::linker::SourceModuleUnit {
            source_name: name.into(),
            source: source_text.into(),
        },
        sources: sources
            .iter()
            .map(|source| kotodama_lang::linker::SourceModuleUnit {
                source_name: source.source_name.clone(),
                source: source.source_text.clone(),
            })
            .collect(),
        imports: imports
            .iter()
            .map(|binding| kotodama_lang::linker::ImportBinding {
                alias: binding.alias.clone(),
                package: binding.package.clone(),
            })
            .collect(),
        packages: packages
            .iter()
            .map(|package| kotodama_lang::linker::SourcePackageUnit {
                artifacts: package.artifacts.iter().map(source_artifact_unit).collect(),
                identity: package.identity.clone(),
                modules: package
                    .modules
                    .iter()
                    .map(|source| kotodama_lang::linker::SourceModuleUnit {
                        source_name: source.source_name.clone(),
                        source: source.source_text.clone(),
                    })
                    .collect(),
                sources: package
                    .sources
                    .iter()
                    .map(|source| kotodama_lang::linker::SourceModuleUnit {
                        source_name: source.source_name.clone(),
                        source: source.source_text.clone(),
                    })
                    .collect(),
                exports: package.exports.iter().cloned().collect(),
                imports: package
                    .imports
                    .iter()
                    .map(|binding| kotodama_lang::linker::ImportBinding {
                        alias: binding.alias.clone(),
                        package: binding.package.clone(),
                    })
                    .collect(),
            })
            .collect(),
    }
}
fn source_artifact_unit(
    artifact: &ContractSourceArtifactDto,
) -> kotodama_lang::linker::SourceContractArtifact {
    kotodama_lang::linker::SourceContractArtifact {
        source_name: artifact.source_name.clone(),
        artifact: artifact.artifact.clone(),
    }
}
fn source_artifact_dto(
    artifact: kotodama_lang::linker::SourceContractArtifact,
) -> ContractSourceArtifactDto {
    ContractSourceArtifactDto {
        source_name: artifact.source_name,
        artifact: artifact.artifact,
    }
}
fn source_file_dto(source: kotodama_lang::linker::SourceModuleUnit) -> ContractSourceFileDto {
    ContractSourceFileDto {
        source_name: source.source_name,
        source_text: source.source,
    }
}
fn source_import_dto(binding: kotodama_lang::linker::ImportBinding) -> ContractSourceImportDto {
    ContractSourceImportDto {
        alias: binding.alias,
        package: binding.package,
    }
}
fn source_package_dto(
    package: kotodama_lang::linker::SourcePackageUnit,
) -> ContractSourcePackageDto {
    ContractSourcePackageDto {
        artifacts: package
            .artifacts
            .into_iter()
            .map(source_artifact_dto)
            .collect(),
        identity: package.identity,
        modules: package.modules.into_iter().map(source_file_dto).collect(),
        sources: package.sources.into_iter().map(source_file_dto).collect(),
        exports: package.exports.into_iter().collect(),
        imports: package.imports.into_iter().map(source_import_dto).collect(),
    }
}
fn compile_verified_source(
    source_name: Option<&str>,
    source_text: &str,
    sources: &[ContractSourceFileDto],
    imports: &[ContractSourceImportDto],
    packages: &[ContractSourcePackageDto],
    artifacts: &[ContractSourceArtifactDto],
) -> Result<kotodama_lang::session::CompileOutput, kotodama_lang::diagnostic::DiagnosticBundle> {
    let session = kotodama_lang::session::CompilerSession::default();
    if sources.is_empty() && artifacts.is_empty() && imports.is_empty() && packages.is_empty() {
        return session.build(kotodama_lang::session::CompileRequest {
            source: source_text,
            source_name,
        });
    }
    let name = source_name.unwrap_or("main.ko");
    let graph =
        verified_source_link_request(name, source_text, sources, imports, packages, artifacts);
    kotodama_lang::driver::BuildDriver::new(session, "verified-source")
        .compile_project(graph, name)
        .map_err(|error| {
            error.into_diagnostics().unwrap_or_else(|error| {
                kotodama_lang::diagnostic::DiagnosticBundle::single(
                    kotodama_lang::diagnostic::Diagnostic::error(
                        "K0000",
                        kotodama_lang::diagnostic::DiagnosticPhase::Resolve,
                        error.to_string(),
                        None,
                    ),
                )
            })
        })
}
struct BoundedDiagnosticText {
    text: String,
    maximum_bytes: usize,
    truncated: bool,
}
impl BoundedDiagnosticText {
    fn try_new(maximum_bytes: usize) -> Result<Self, std::collections::TryReserveError> {
        let mut text = String::new();
        text.try_reserve_exact(maximum_bytes)?;
        Ok(Self {
            text,
            maximum_bytes,
            truncated: false,
        })
    }
    fn finish(mut self) -> String {
        if self.truncated {
            let ellipsis = '…';
            if self.maximum_bytes >= ellipsis.len_utf8() {
                let mut end = self
                    .text
                    .len()
                    .min(self.maximum_bytes - ellipsis.len_utf8());
                while !self.text.is_char_boundary(end) {
                    end = end.saturating_sub(1);
                }
                self.text.truncate(end);
                self.text.push(ellipsis);
            } else {
                self.text.clear();
            }
        }
        self.text
    }
}
impl fmt::Write for BoundedDiagnosticText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.truncated {
            return Err(fmt::Error);
        }
        let remaining = self.maximum_bytes.saturating_sub(self.text.len());
        if value.len() <= remaining {
            self.text.push_str(value);
            return Ok(());
        }
        let mut end = remaining;
        while !value.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        self.text.push_str(&value[..end]);
        self.truncated = true;
        Err(fmt::Error)
    }
}
fn write_diagnostic_source(
    output: &mut BoundedDiagnosticText,
    span: &kotodama_lang::diagnostic::SourceSpan,
) -> fmt::Result {
    if let Some(package) = span.package_identity.as_deref() {
        write!(output, "{package}::")?;
    }
    output.write_str(span.source.as_deref().unwrap_or("<source>"))
}
/// Render compiler diagnostics directly into a fixed-size UTF-8 buffer.
///
/// In particular, this must not call `DiagnosticBundle::to_string` or `render_human`: both first
/// allocate the complete attacker-influenced rendering before a caller can truncate it.
fn bounded_verified_source_diagnostic_message(
    bundle: &kotodama_lang::diagnostic::DiagnosticBundle,
) -> String {
    let Ok(mut output) = BoundedDiagnosticText::try_new(VERIFIED_SOURCE_JOB_MESSAGE_MAX_BYTES_V1)
    else {
        return "Kotodama compilation failed (diagnostic allocation failed)".to_owned();
    };
    for (index, diagnostic) in bundle.diagnostics.iter().enumerate() {
        let rendered = (|| -> fmt::Result {
            if index != 0 {
                output.write_char('\n')?;
            }
            write!(
                output,
                "{}[{}] {}: {}",
                diagnostic.severity.as_str(),
                diagnostic.code,
                diagnostic.phase.as_str(),
                diagnostic.message
            )?;
            if let Some(span) = &diagnostic.primary_span {
                output.write_str("\n  --> ")?;
                write_diagnostic_source(&mut output, span)?;
                write!(
                    output,
                    ":{}:{}-{}:{}",
                    span.start.line, span.start.column, span.end.line, span.end.column
                )?;
                if let Some(range) = span.byte_range {
                    write!(output, " [bytes {}..{}]", range.start, range.end)?;
                }
            }
            for label in &diagnostic.labels {
                output.write_str("\n  = label: ")?;
                write_diagnostic_source(&mut output, &label.span)?;
                write!(
                    output,
                    ":{}:{}-{}:{}: {}",
                    label.span.start.line,
                    label.span.start.column,
                    label.span.end.line,
                    label.span.end.column,
                    label.message
                )?;
                if let Some(range) = label.span.byte_range {
                    write!(output, " [bytes {}..{}]", range.start, range.end)?;
                }
            }
            for note in &diagnostic.notes {
                write!(output, "\n  = note: {note}")?;
            }
            if let Some(help) = &diagnostic.help {
                write!(output, "\n  = help: {help}")?;
            }
            if let Some(fix) = &diagnostic.fix {
                output.write_str("\n  = fix: replace ")?;
                write_diagnostic_source(&mut output, &fix.span)?;
                write!(
                    output,
                    ":{}:{}-{}:{} with {:?}",
                    fix.span.start.line,
                    fix.span.start.column,
                    fix.span.end.line,
                    fix.span.end.column,
                    fix.replacement
                )?;
                if let Some(range) = fix.span.byte_range {
                    write!(output, " [bytes {}..{}]", range.start, range.end)?;
                }
            }
            Ok(())
        })();
        if rendered.is_err() {
            break;
        }
    }
    if output.text.is_empty() {
        let _ = output.write_str("Kotodama compilation failed without diagnostics");
    }
    output.finish()
}
pub async fn handle_get_instruction_contract_view(
    state: Arc<CoreState>,
    transaction_hash: String,
    index: u64,
) -> Result<impl IntoResponse, Error> {
    let instruction = locate_instruction_box(state.as_ref(), &transaction_hash, index)?;
    let input = resolve_contract_view_input_for_instruction(&instruction, state.as_ref())?;
    let view = build_contract_view(input)?;
    Ok(JsonBody(view))
}
pub async fn handle_get_contract_code_view(
    state: Arc<CoreState>,
    artifact_id: ContractArtifactId,
) -> Result<impl IntoResponse, Error> {
    let input = resolve_contract_view_input_for_artifact(state.as_ref(), artifact_id)?;
    let view = build_contract_view(input)?;
    Ok(JsonBody(view))
}
pub fn handle_post_verified_source_job(
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
    request: SubmitVerifiedContractSourceDto,
    _sorafs_node: sorafs_node::NodeHandle,
) -> Result<(StatusCode, JsonBody<ContractVerifiedSourceJobResponseDto>), Error> {
    let requested_hash = artifact_id.code_hash;
    let code_hash_hex = hash_hex(&requested_hash);
    let submitted_at = now_rfc3339();
    let job_id = new_job_id()?;
    if let Some(message) = verified_source_request_bound_error(&request) {
        let response = ContractVerifiedSourceJobResponseDto {
            network_id,
            artifact_id,
            job_id,
            code_hash: code_hash_hex,
            status: "error".to_owned(),
            submitted_at,
            completed_at: Some(now_rfc3339()),
            message: Some(message.to_owned()),
            actual_code_hash: None,
            verified_source_ref: None,
        };
        let persisted = persist_job_response(response)?;
        return Ok((StatusCode::BAD_REQUEST, JsonBody(persisted)));
    }
    let language = request.language;
    if language != VERIFIED_SOURCE_LANGUAGE_KOTODAMA {
        let response = ContractVerifiedSourceJobResponseDto {
            network_id,
            artifact_id,
            job_id,
            code_hash: code_hash_hex.clone(),
            status: "error".to_owned(),
            submitted_at,
            completed_at: Some(now_rfc3339()),
            message: Some(format!(
                "unsupported verified source language; only the exact `{VERIFIED_SOURCE_LANGUAGE_KOTODAMA}` label is accepted"
            )),
            actual_code_hash: None,
            verified_source_ref: None,
        };
        let persisted = persist_job_response(response)?;
        return Ok((StatusCode::BAD_REQUEST, JsonBody(persisted)));
    }
    let mut source_name = request.source_name;
    let source_text = request.source_text;
    let mut artifacts = request.artifacts;
    artifacts.sort_by(|left, right| left.source_name.cmp(&right.source_name));
    let mut sources = request.sources;
    sources.sort_by(|left, right| left.source_name.cmp(&right.source_name));
    let mut imports = request.imports;
    imports.sort_by(|left, right| {
        left.alias
            .cmp(&right.alias)
            .then_with(|| left.package.cmp(&right.package))
    });
    let mut packages = request.packages;
    packages.sort_by(|left, right| left.identity.cmp(&right.identity));
    for package in &mut packages {
        package
            .artifacts
            .sort_by(|left, right| left.source_name.cmp(&right.source_name));
        package
            .modules
            .sort_by(|left, right| left.source_name.cmp(&right.source_name));
        package
            .sources
            .sort_by(|left, right| left.source_name.cmp(&right.source_name));
        package.exports.sort();
        package.imports.sort_by(|left, right| {
            left.alias
                .cmp(&right.alias)
                .then_with(|| left.package.cmp(&right.package))
        });
    }
    if source_text.trim().is_empty() {
        let response = ContractVerifiedSourceJobResponseDto {
            network_id,
            artifact_id,
            job_id,
            code_hash: code_hash_hex.clone(),
            status: "error".to_owned(),
            submitted_at,
            completed_at: Some(now_rfc3339()),
            message: Some("source_text must not be empty".to_owned()),
            actual_code_hash: None,
            verified_source_ref: None,
        };
        let persisted = persist_job_response(response)?;
        return Ok((StatusCode::BAD_REQUEST, JsonBody(persisted)));
    }
    let canonical_error = if sources.is_empty()
        && artifacts.is_empty()
        && imports.is_empty()
        && packages.is_empty()
    {
        None
    } else {
        let graph = verified_source_link_request(
            source_name
                .as_deref()
                .expect("source bundle requires root name"),
            &source_text,
            &sources,
            &imports,
            &packages,
            &artifacts,
        );
        match kotodama_lang::linker::ModuleBuildGraph::canonical_source_bundle(graph) {
            Ok(graph) => {
                source_name = Some(graph.root.source_name);
                sources = graph.sources.into_iter().map(source_file_dto).collect();
                artifacts = graph
                    .artifacts
                    .into_iter()
                    .map(source_artifact_dto)
                    .collect();
                imports = graph.imports.into_iter().map(source_import_dto).collect();
                packages = graph.packages.into_iter().map(source_package_dto).collect();
                None
            }
            Err(error) => Some(error.into_diagnostics()),
        }
    };
    let compile_result = match canonical_error {
        Some(error) => Err(error),
        None => compile_verified_source(
            source_name.as_deref(),
            &source_text,
            &sources,
            &imports,
            &packages,
            &artifacts,
        ),
    };
    let response = match compile_result {
        Ok(output) => {
            let kotodama_lang::session::CompileOutput {
                artifact: code_bytes,
                contract_interface,
                manifest,
                report,
            } = output;
            drop((contract_interface, manifest, report));
            let actual_hash = canonical_code_hash(&code_bytes)?;
            let verified = ivm::verify_contract_artifact(&code_bytes).map_err(|err| {
                conversion_error(format!(
                    "compiled source did not produce a valid contract artifact: {err}"
                ))
            })?;
            let actual_code_hash = hash_hex(&actual_hash);
            if actual_hash != requested_hash {
                ContractVerifiedSourceJobResponseDto {
                    network_id,
                    artifact_id,
                    job_id,
                    code_hash: code_hash_hex.clone(),
                    status: "mismatch".to_owned(),
                    submitted_at,
                    completed_at: Some(now_rfc3339()),
                    message: Some(
                        "compiled source does not match the requested code hash".to_owned(),
                    ),
                    actual_code_hash: Some(actual_code_hash),
                    verified_source_ref: None,
                }
            } else {
                let mutation_lock = verified_source_mutation_lock(network_id, artifact_id);
                let _guard = mutation_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(existing) = load_verified_source_record(network_id, artifact_id)? {
                    if existing.source_text == source_text
                        && existing.source_name == source_name
                        && existing.artifacts == artifacts
                        && existing.sources == sources
                        && existing.imports == imports
                        && existing.packages == packages
                    {
                        ContractVerifiedSourceJobResponseDto {
                            network_id,
                            artifact_id,
                            job_id,
                            code_hash: code_hash_hex.clone(),
                            status: "accepted".to_owned(),
                            submitted_at,
                            completed_at: Some(now_rfc3339()),
                            message: Some(
                                "verified source already stored for this code hash".to_owned(),
                            ),
                            actual_code_hash: Some(actual_code_hash),
                            verified_source_ref: verified_source_ref_from_record(&existing),
                        }
                    } else {
                        ContractVerifiedSourceJobResponseDto {
                            network_id,
                            artifact_id,
                            job_id,
                            code_hash: code_hash_hex.clone(),
                            status: "conflict".to_owned(),
                            submitted_at,
                            completed_at: Some(now_rfc3339()),
                            message: Some(
                                "a different verified source is already stored for this code hash"
                                    .to_owned(),
                            ),
                            actual_code_hash: Some(actual_code_hash),
                            verified_source_ref: verified_source_ref_from_record(&existing),
                        }
                    }
                } else {
                    // HTTP submission persists only the verified-source job record.
                    // Provider storage is populated exclusively by the finalized-ledger
                    // ingest outbox, never as a side effect of this route.
                    let verified_source_ref: Option<ContractVerifiedSourceRefDto> = None;
                    let record = StoredVerifiedSourceRecord {
                        network_id,
                        artifact_id,
                        version: VERIFIED_SOURCE_VERSION,
                        code_hash: code_hash_hex.clone(),
                        abi_hash: Some(hash_hex(&verified.abi_hash)),
                        compiler_fingerprint: verified.manifest.compiler_fingerprint.clone(),
                        language,
                        source_name: source_name.clone(),
                        source_text,
                        sources,
                        artifacts,
                        imports,
                        packages,
                        submitted_at: submitted_at.clone(),
                        manifest_id_hex: verified_source_ref
                            .as_ref()
                            .and_then(|value| value.manifest_id_hex.clone()),
                        payload_digest_hex: verified_source_ref
                            .as_ref()
                            .and_then(|value| value.payload_digest_hex.clone()),
                        content_length: verified_source_ref
                            .as_ref()
                            .and_then(|value| value.content_length),
                    };
                    persist_verified_source_record_locked(&record)?;
                    ContractVerifiedSourceJobResponseDto {
                        network_id,
                        artifact_id,
                        job_id,
                        code_hash: code_hash_hex.clone(),
                        status: "accepted".to_owned(),
                        submitted_at,
                        completed_at: Some(now_rfc3339()),
                        message: Some("verified source stored".to_owned()),
                        actual_code_hash: Some(actual_code_hash),
                        verified_source_ref,
                    }
                }
            }
        }
        Err(err) => ContractVerifiedSourceJobResponseDto {
            network_id,
            artifact_id,
            job_id,
            code_hash: code_hash_hex.clone(),
            status: "compile_error".to_owned(),
            submitted_at,
            completed_at: Some(now_rfc3339()),
            message: Some(bounded_verified_source_diagnostic_message(&err)),
            actual_code_hash: None,
            verified_source_ref: None,
        },
    };
    let status_code = match response.status.as_str() {
        "accepted" => StatusCode::ACCEPTED,
        "mismatch" | "compile_error" | "conflict" | "error" => StatusCode::BAD_REQUEST,
        _ => StatusCode::ACCEPTED,
    };
    let persisted = persist_job_response(response)?;
    Ok((status_code, JsonBody(persisted)))
}
pub async fn handle_get_verified_source_job(
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
    job_id: String,
) -> Result<impl IntoResponse, Error> {
    let job_id = canonical_verified_source_job_id(&job_id)?;
    let job = load_verified_source_job(network_id, artifact_id, &job_id)?.ok_or_else(not_found)?;
    Ok(JsonBody(job))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn source_network() -> NetworkId {
        crate::test_utils::signed_query_network_id()
    }
    fn source_artifact(hash: &str) -> ContractArtifactId {
        crate::routing::parse_contract_artifact_path("0", hash)
            .expect("canonical source fixture artifact")
    }
    use crate::test_utils::TestDataDirGuard;
    use iroha_core::{
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::Execute,
        smartcontracts::code::{activate_instance, register_code_bytes, register_manifest},
        state::{State, World},
        tx::AcceptedTransaction,
    };
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    use iroha_data_model::{account::AccountId, permission, prelude as dm};
    use iroha_executor_data_model::permission::{
        governance::CanEnactGovernance, smart_contract::CanManageSmartContractCode,
    };
    use std::{
        borrow::Cow,
        num::NonZeroU64,
        sync::{Arc, Barrier},
        time::Duration,
    };
    #[test]
    fn verified_source_request_bounds_accept_exact_and_reject_first_overflow() {
        assert_eq!(
            VERIFIED_SOURCE_TEXT_MAX_BYTES_V1,
            kotodama_lang::source::MAX_SOURCE_BYTES
        );
        assert_eq!(
            VERIFIED_SOURCE_NAME_MAX_BYTES_V1,
            kotodama_lang::linker::MAX_LOGICAL_SOURCE_PATH_BYTES
        );
        let mut request = SubmitVerifiedContractSourceDto {
            artifacts: Vec::new(),
            sources: Vec::new(),
            imports: Vec::new(),
            packages: Vec::new(),
            language: "k".repeat(VERIFIED_SOURCE_LANGUAGE_MAX_BYTES_V1),
            source_name: Some("n".repeat(VERIFIED_SOURCE_NAME_MAX_BYTES_V1)),
            source_text: "s".repeat(VERIFIED_SOURCE_TEXT_MAX_BYTES_V1),
        };
        assert_eq!(verified_source_request_bound_error(&request), None);
        request.source_text.push('s');
        assert_eq!(
            verified_source_request_bound_error(&request),
            Some("source_text exceeds the Kotodama V1 1048576-byte maximum")
        );
        request.source_text.pop();
        request.source_name.as_mut().expect("source name").push('n');
        assert_eq!(
            verified_source_request_bound_error(&request),
            Some("source_name exceeds the Kotodama V1 4096-byte maximum")
        );
        request.source_name.as_mut().expect("source name").pop();
        request.language.push('k');
        assert_eq!(
            verified_source_request_bound_error(&request),
            Some("language exceeds the first-release 32-byte maximum")
        );
        request.language.pop();
        request.source_name = Some(String::new());
        assert_eq!(
            verified_source_request_bound_error(&request),
            Some("source_name must be omitted instead of empty")
        );
        request.source_name = Some("bad\nname.ko".to_owned());
        assert_eq!(
            verified_source_request_bound_error(&request),
            Some("source_name must not contain control characters")
        );
    }
    #[test]
    fn verified_source_artifacts_share_the_count_and_byte_limits() {
        let mut request = SubmitVerifiedContractSourceDto {
            language: "kotodama".into(),
            source_name: Some("main.ko".into()),
            source_text: "seiyaku App {}".into(),
            sources: Vec::new(),
            imports: Vec::new(),
            packages: Vec::new(),
            artifacts: vec![ContractSourceArtifactDto {
                source_name: "interfaces/pool.to".into(),
                artifact: vec![1],
            }],
        };
        assert_eq!(verified_source_request_bound_error(&request), None);
        let encoded = norito::json::to_value(&request).unwrap();
        let mut retired = encoded.clone();
        retired.as_object_mut().unwrap().remove("artifacts");
        assert!(norito::json::from_value::<SubmitVerifiedContractSourceDto>(retired).is_err());
        let decoded: SubmitVerifiedContractSourceDto = norito::json::from_value(encoded).unwrap();
        assert_eq!(decoded.artifacts, request.artifacts);
        request.artifacts[0].artifact.resize(
            kotodama_lang::linker::MAX_MODULE_GRAPH_SOURCE_BYTES - request.source_text.len(),
            1,
        );
        assert_eq!(verified_source_request_bound_error(&request), None);
        request.artifacts[0].artifact.push(1);
        assert_eq!(
            verified_source_request_bound_error(&request),
            Some("source set exceeds the 16777216-byte maximum")
        );
        request.artifacts = (0..kotodama_lang::linker::MAX_MODULE_GRAPH_SOURCES)
            .map(|index| ContractSourceArtifactDto {
                source_name: format!("{index:04}.to"),
                artifact: vec![1],
            })
            .collect();
        assert_eq!(
            verified_source_request_bound_error(&request),
            Some("source set exceeds the 512-file maximum")
        );
        request.artifacts.truncate(1);
        request.artifacts[0].source_name = "pool.ko".into();
        assert_eq!(
            verified_source_request_bound_error(&request),
            Some("interface artifact requires a bounded .to path and complete nonempty bytes")
        );
    }

    #[test]
    fn verified_source_bundle_recompiles_local_and_locked_package_closures() {
        let root = "seiyaku App { include \"parts/view.ko\"; import \"local.ko\" as local; }";
        let sources = vec![
            ContractSourceFileDto {
                source_name: "parts/view.ko".into(),
                source_text: "view fn value() authorize(anyone) -> int { return local::value() + calc::value(); }"
                    .into(),
            },
            ContractSourceFileDto {
                source_name: "local.ko".into(),
                source_text: "module Local { export fn value() -> int { return 3; } }".into(),
            },
        ];
        let imports = vec![ContractSourceImportDto {
            alias: "calc".into(),
            package: "std/math@1".into(),
        }];
        let mut packages = vec![ContractSourcePackageDto {
            artifacts: Vec::new(),
            identity: "std/math@1".into(),
            modules: vec![ContractSourceFileDto {
                source_name: "src/math.ko".into(),
                source_text: "module Math { include \"body.ko\"; }".into(),
            }],
            sources: vec![ContractSourceFileDto {
                source_name: "src/body.ko".into(),
                source_text: "export fn value() -> int { return 4; }".into(),
            }],
            exports: vec!["value".into()],
            imports: Vec::new(),
        }];
        let original =
            compile_verified_source(Some("app.ko"), root, &sources, &imports, &packages, &[])
                .expect("complete immutable graph");
        let repeat =
            compile_verified_source(Some("app.ko"), root, &sources, &imports, &packages, &[])
                .expect("reproducible graph");
        assert_eq!(original.artifact, repeat.artifact);
        assert!(
            original
                .report
                .render_source_map_json()
                .expect("source map")
                .contains("parts/view.ko")
        );
        let verified =
            ivm::verify_contract_artifact(&original.artifact).expect("verified artifact");
        let code_hash = hash_hex(&canonical_code_hash(&original.artifact).expect("code hash"));
        let mut record = StoredVerifiedSourceRecord {
            artifacts: Vec::new(),
            network_id: source_network(),
            artifact_id: source_artifact(&code_hash),
            version: VERIFIED_SOURCE_VERSION,
            code_hash: code_hash.clone(),
            abi_hash: Some(hash_hex(&verified.abi_hash)),
            compiler_fingerprint: verified.manifest.compiler_fingerprint,
            language: "kotodama".into(),
            source_name: Some("app.ko".into()),
            source_text: root.into(),
            sources: sources.clone(),
            imports: imports.clone(),
            packages: packages.clone(),
            submitted_at: now_rfc3339(),
            manifest_id_hex: None,
            payload_digest_hex: None,
            content_length: None,
        };
        validate_verified_source_record(&record, record.network_id, record.artifact_id)
            .expect("full stored closure revalidates");
        record.packages[0].sources[0].source_text =
            "export fn value() -> int { return 100; }".into();
        assert!(
            validate_verified_source_record(&record, record.network_id, record.artifact_id)
                .is_err(),
            "tampered companion must fail record hash validation"
        );
        let encoded = norito::json::to_json(&record).expect("serialize complete record");
        let mut value: norito::json::Value = norito::json::from_str(&encoded).expect("record JSON");
        value
            .as_object_mut()
            .expect("record object")
            .remove("sources");
        assert!(
            norito::json::from_value::<StoredVerifiedSourceRecord>(value).is_err(),
            "retired persisted record shape must not decode"
        );
        packages[0].sources[0].source_text = "export fn value() -> int { return 5; }".into();
        let changed =
            compile_verified_source(Some("app.ko"), root, &sources, &imports, &packages, &[])
                .expect("changed graph");
        assert_ne!(original.artifact, changed.artifact);
        packages[0].sources.clear();
        assert!(
            compile_verified_source(Some("app.ko"), root, &sources, &imports, &packages, &[])
                .is_err()
        );
    }
    #[test]
    fn verified_source_bundle_bounds_include_package_companions() {
        let package = ContractSourcePackageDto {
            artifacts: Vec::new(),
            identity: "math@1".into(),
            modules: Vec::new(),
            sources: (0..512)
                .map(|index| ContractSourceFileDto {
                    source_name: format!("{index}.ko"),
                    source_text: String::new(),
                })
                .collect(),
            imports: Vec::new(),
            exports: Vec::new(),
        };
        assert_eq!(
            source_bundle_bound_error(Some("app.ko"), "seiyaku App {}", &[], &[], &[package], &[]),
            Some("source set exceeds the 512-file maximum")
        );
    }
    #[test]
    fn verified_source_diagnostic_message_is_utf8_safe_and_bounded() {
        let short = kotodama_lang::diagnostic::DiagnosticBundle::single(
            kotodama_lang::diagnostic::Diagnostic::error(
                "KTEST",
                kotodama_lang::diagnostic::DiagnosticPhase::Parse,
                "short diagnostic",
                None,
            ),
        );
        assert_eq!(
            bounded_verified_source_diagnostic_message(&short),
            short.render_human()
        );
        let long = kotodama_lang::diagnostic::DiagnosticBundle::single(
            kotodama_lang::diagnostic::Diagnostic::error(
                "KTEST",
                kotodama_lang::diagnostic::DiagnosticPhase::Parse,
                "界".repeat(VERIFIED_SOURCE_JOB_MESSAGE_MAX_BYTES_V1),
                None,
            ),
        );
        let bounded = bounded_verified_source_diagnostic_message(&long);
        assert!(bounded.len() <= VERIFIED_SOURCE_JOB_MESSAGE_MAX_BYTES_V1);
        assert!(bounded.ends_with('…'));
    }
    #[test]
    fn fixed_hex_path_components_require_exact_canonical_spelling() {
        let uppercase = "AB".repeat(FIXED_HEX_COMPONENT_BYTES_V1);
        assert!(crate::routing::parse_contract_artifact_path("0", &uppercase).is_err());
        assert!(canonical_verified_source_job_id(&uppercase).is_err());
        let lowercase = "ab".repeat(FIXED_HEX_COMPONENT_BYTES_V1);
        assert_eq!(
            hash_hex(
                &crate::routing::parse_contract_artifact_path("0", &lowercase)
                    .expect("canonical code hash")
                    .code_hash
            ),
            lowercase
        );
        assert_eq!(
            canonical_verified_source_job_id(&lowercase).expect("canonical job id"),
            lowercase
        );
        for invalid in [
            "a".repeat(FIXED_HEX_COMPONENT_CHARS_V1 - 1),
            "a".repeat(FIXED_HEX_COMPONENT_CHARS_V1 + 1),
            "g".repeat(FIXED_HEX_COMPONENT_CHARS_V1),
            format!("../{}", "a".repeat(FIXED_HEX_COMPONENT_CHARS_V1 - 3)),
        ] {
            assert!(crate::routing::parse_contract_artifact_path("0", &invalid).is_err());
            assert!(canonical_verified_source_job_id(&invalid).is_err());
        }
    }
    fn persisted_json_size_fixture() -> StoredVerifiedSourceRecord {
        StoredVerifiedSourceRecord {
            artifacts: Vec::new(),
            network_id: source_network(),
            artifact_id: source_artifact(&"ab".repeat(32)),
            sources: Vec::new(),
            imports: Vec::new(),
            packages: Vec::new(),
            version: VERIFIED_SOURCE_VERSION,
            code_hash: "ab".repeat(FIXED_HEX_COMPONENT_BYTES_V1),
            abi_hash: Some("\"\\\n界".to_owned()),
            compiler_fingerprint: None,
            language: VERIFIED_SOURCE_LANGUAGE_KOTODAMA.to_owned(),
            source_name: Some("\u{0001}/契約.ko".to_owned()),
            source_text: "seiyaku \"quoted\" { \\ }\n".to_owned(),
            submitted_at: "2026-08-11T00:00:00Z".to_owned(),
            manifest_id_hex: Some("cd".repeat(FIXED_HEX_COMPONENT_BYTES_V1)),
            payload_digest_hex: None,
            content_length: Some(u64::MAX),
        }
    }
    fn valid_verified_source_record(source: &str, source_name: &str) -> StoredVerifiedSourceRecord {
        let compiled = kotodama_lang::session::CompilerSession::default()
            .build(kotodama_lang::session::CompileRequest {
                source,
                source_name: Some(source_name),
            })
            .expect("compile verified-source record fixture");
        let verified = ivm::verify_contract_artifact(&compiled.artifact)
            .expect("verify source record fixture");
        StoredVerifiedSourceRecord {
            artifacts: Vec::new(),
            network_id: source_network(),
            artifact_id: ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                verified.code_hash,
            ),
            sources: Vec::new(),
            imports: Vec::new(),
            packages: Vec::new(),
            version: VERIFIED_SOURCE_VERSION,
            code_hash: hash_hex(
                &canonical_code_hash(&compiled.artifact).expect("hash source record fixture"),
            ),
            abi_hash: Some(hash_hex(&verified.abi_hash)),
            compiler_fingerprint: verified.manifest.compiler_fingerprint,
            language: VERIFIED_SOURCE_LANGUAGE_KOTODAMA.to_owned(),
            source_name: Some(source_name.to_owned()),
            source_text: source.to_owned(),
            submitted_at: now_rfc3339(),
            manifest_id_hex: None,
            payload_digest_hex: None,
            content_length: None,
        }
    }
    #[test]
    fn bounded_persisted_json_matches_compact_norito_encoding() {
        let record = persisted_json_size_fixture();
        let record_bytes = norito::json::to_vec(&record).expect("encode source record");
        assert_eq!(
            crate::utils::encode_json_bounded(&record, record_bytes.len())
                .expect("bounded source record")
                .as_bytes(),
            record_bytes
        );
        let job = StoredVerifiedSourceJob {
            network_id: record.network_id,
            artifact_id: record.artifact_id,
            version: VERIFIED_SOURCE_VERSION,
            job_id: "ef".repeat(FIXED_HEX_COMPONENT_BYTES_V1),
            code_hash: record.code_hash.clone(),
            status: "accepted".to_owned(),
            submitted_at: record.submitted_at.clone(),
            completed_at: Some(record.submitted_at.clone()),
            message: Some("stored\nwith warning".to_owned()),
            actual_code_hash: Some(record.code_hash.clone()),
            verified_source_ref: Some(ContractVerifiedSourceRefDto {
                language: record.language.clone(),
                source_name: record.source_name.clone(),
                submitted_at: record.submitted_at.clone(),
                manifest_id_hex: record.manifest_id_hex.clone(),
                payload_digest_hex: record.payload_digest_hex.clone(),
                content_length: record.content_length,
            }),
        };
        let job_bytes = norito::json::to_vec(&job).expect("encode source job");
        assert_eq!(
            crate::utils::encode_json_bounded(&job, job_bytes.len())
                .expect("bounded source job")
                .as_bytes(),
            job_bytes
        );
    }
    #[test]
    fn persisted_json_writer_rejects_overflow_before_filesystem_mutation() {
        let directory = tempfile::tempdir().expect("verified-source writer directory");
        let record = persisted_json_size_fixture();
        let encoded_len = norito::json::to_vec(&record)
            .expect("encode source record")
            .len();
        let exact_path = directory.path().join("exact").join("record.json");
        write_json_file_atomic(&exact_path, &record, encoded_len, "source writer test")
            .expect("exact-size record is admitted");
        assert_eq!(
            fs::read(&exact_path).expect("read persisted record").len(),
            encoded_len
        );
        let rejected_parent = directory.path().join("must-not-be-created");
        let rejected_path = rejected_parent.join("record.json");
        assert!(
            write_json_file_atomic(
                &rejected_path,
                &record,
                encoded_len - 1,
                "source writer test"
            )
            .is_err()
        );
        assert!(!rejected_parent.exists());
    }
    #[test]
    fn verified_source_file_reader_enforces_its_byte_bound() {
        let directory = tempfile::tempdir().expect("verified-source reader directory");
        let exact_path = directory.path().join("exact.json");
        fs::write(&exact_path, b"null").expect("write exact JSON");
        #[cfg(unix)]
        fs::set_permissions(
            &exact_path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .expect("make exact fixture private");
        let exact = read_bounded_file(&exact_path, 4, "verified-source reader test")
            .expect("exact-size file is admitted");
        assert_eq!(exact, Some(b"null".to_vec()));
        let overflow_path = directory.path().join("overflow.json");
        fs::write(&overflow_path, b"null ").expect("write oversized JSON");
        #[cfg(unix)]
        fs::set_permissions(
            &overflow_path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .expect("make overflow fixture private");
        assert!(read_bounded_file(&overflow_path, 4, "verified-source reader test").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn verified_source_file_reader_rejects_public_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("verified-source reader directory");
        let public_path = directory.path().join("public.json");
        fs::write(&public_path, b"null").expect("write public fixture");
        fs::set_permissions(&public_path, fs::Permissions::from_mode(0o644))
            .expect("make fixture public");
        assert!(read_bounded_file(&public_path, 4, "public source record").is_err());
    }
    #[cfg(any(unix, windows))]
    #[test]
    fn verified_source_file_reader_rejects_multiply_linked_files() {
        let directory = tempfile::tempdir().expect("verified-source reader directory");
        let source_path = directory.path().join("source.json");
        let linked_path = directory.path().join("linked.json");
        fs::write(&source_path, b"null").expect("write source fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600))
                .expect("make fixture private");
        }
        fs::hard_link(&source_path, &linked_path).expect("create second hard link");

        assert!(read_bounded_file(&source_path, 4, "linked source record").is_err());
    }
    #[test]
    fn verified_source_record_load_rejects_version_identity_and_source_corruption() {
        let _guard = TestDataDirGuard::new();
        let source = "seiyaku Exact { permission Run;  kotoage fn main() authorize(Run) {} }";
        let record = valid_verified_source_record(source, "exact.ko");
        let path = verified_source_record_path(record.network_id, record.artifact_id);
        persist_verified_source_record(&record).expect("persist valid source record");
        assert!(
            load_verified_source_record(record.network_id, record.artifact_id)
                .expect("load valid source record")
                .is_some()
        );

        let mut corrupt = record.clone();
        corrupt.version = VERIFIED_SOURCE_VERSION + 1;
        fs::write(
            &path,
            norito::json::to_vec(&corrupt).expect("encode wrong-version record"),
        )
        .expect("replace record with wrong version");
        assert!(load_verified_source_record(record.network_id, record.artifact_id).is_err());

        corrupt = record.clone();
        corrupt.code_hash = "ff".repeat(FIXED_HEX_COMPONENT_BYTES_V1);
        fs::write(
            &path,
            norito::json::to_vec(&corrupt).expect("encode wrong-identity record"),
        )
        .expect("replace record with wrong identity");
        assert!(load_verified_source_record(record.network_id, record.artifact_id).is_err());

        corrupt = record.clone();
        corrupt.source_text =
            "seiyaku Different { permission Run;  kotoage fn main() authorize(Run) {} }".to_owned();
        fs::write(
            &path,
            norito::json::to_vec(&corrupt).expect("encode wrong-source record"),
        )
        .expect("replace record with wrong source");
        assert!(load_verified_source_record(record.network_id, record.artifact_id).is_err());
    }
    #[test]
    fn verified_sources_are_isolated_by_network_and_full_dataspace_id() {
        let _guard = TestDataDirGuard::new();
        let mut record = valid_verified_source_record(
            "seiyaku Scoped { view fn value() authorize(anyone) -> int { return 1; } }",
            "scoped.ko",
        );
        record.artifact_id.dataspace_id = iroha_model_base::topology::DataSpaceId::new(u64::MAX);
        persist_verified_source_record(&record).expect("persist private source");
        let other_scope = ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            record.artifact_id.code_hash,
        );
        assert!(
            load_verified_source_record(record.network_id, other_scope)
                .unwrap()
                .is_none()
        );
        let other_network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"another source network"),
        ));
        assert!(
            load_verified_source_record(other_network, record.artifact_id)
                .unwrap()
                .is_none()
        );
        assert!(validate_verified_source_record(&record, record.network_id, other_scope).is_err());
        assert!(
            validate_verified_source_record(&record, other_network, record.artifact_id).is_err()
        );
        assert_eq!(
            load_verified_source_record(record.network_id, record.artifact_id)
                .unwrap()
                .unwrap()
                .source_text,
            record.source_text
        );
        assert_ne!(
            verified_source_record_path(record.network_id, record.artifact_id),
            verified_source_record_path(record.network_id, other_scope)
        );
    }
    #[test]
    fn verified_source_job_load_rejects_embedded_identity_corruption() {
        let _guard = TestDataDirGuard::new();
        let code_hash = "ab".repeat(FIXED_HEX_COMPONENT_BYTES_V1);
        let job_id = "cd".repeat(FIXED_HEX_COMPONENT_BYTES_V1);
        let mut job = StoredVerifiedSourceJob {
            network_id: source_network(),
            artifact_id: source_artifact(&code_hash),
            version: VERIFIED_SOURCE_VERSION,
            job_id: job_id.clone(),
            code_hash: code_hash.clone(),
            status: "error".to_owned(),
            submitted_at: now_rfc3339(),
            completed_at: Some(now_rfc3339()),
            message: Some("bounded validation error".to_owned()),
            actual_code_hash: None,
            verified_source_ref: None,
        };
        persist_verified_source_job(&job).expect("persist source job");
        let path = verified_source_job_path(source_network(), source_artifact(&code_hash), &job_id);
        job.job_id = "ef".repeat(FIXED_HEX_COMPONENT_BYTES_V1);
        fs::write(
            path,
            norito::json::to_vec(&job).expect("encode wrong-identity source job"),
        )
        .expect("replace source job with wrong identity");
        assert!(
            load_verified_source_job(source_network(), source_artifact(&code_hash), &job_id)
                .is_err()
        );
    }
    #[test]
    fn immutable_source_writer_never_replaces_a_concurrent_winner() {
        let directory = tempfile::tempdir().expect("verified-source writer directory");
        let path = Arc::new(directory.path().join("records").join("record.json"));
        let mut first = persisted_json_size_fixture();
        first.code_hash = "11".repeat(FIXED_HEX_COMPONENT_BYTES_V1);
        let mut second = persisted_json_size_fixture();
        second.code_hash = "22".repeat(FIXED_HEX_COMPONENT_BYTES_V1);
        let first_bytes = norito::json::to_vec(&first).expect("encode first contender");
        let second_bytes = norito::json::to_vec(&second).expect("encode second contender");
        let maximum = first_bytes.len().max(second_bytes.len());
        let barrier = Arc::new(Barrier::new(3));
        let contenders = [first, second]
            .into_iter()
            .map(|record| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    write_json_file_atomic(
                        &path,
                        &record,
                        maximum,
                        "concurrent verified-source test record",
                    )
                    .is_ok()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let successes = contenders
            .into_iter()
            .map(|contender| contender.join().expect("source writer thread"))
            .filter(|succeeded| *succeeded)
            .count();
        assert_eq!(successes, 1);
        let published = fs::read(&*path).expect("read immutable winner");
        assert!(published == first_bytes || published == second_bytes);
        let residue = fs::read_dir(path.parent().expect("record parent"))
            .expect("enumerate record parent")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(residue, 0, "failed contenders must clean temporary files");
    }
    #[cfg(unix)]
    #[test]
    fn immutable_source_writer_rejects_symlinked_destination_and_parent() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("verified-source writer directory");
        let real_parent = directory.path().join("real");
        fs::create_dir(&real_parent).expect("create real parent");
        let outside = directory.path().join("outside.json");
        fs::write(&outside, b"outside-sentinel").expect("write outside sentinel");
        let linked_destination = real_parent.join("record.json");
        symlink(&outside, &linked_destination).expect("link destination to sentinel");
        let record = persisted_json_size_fixture();
        assert!(
            write_json_file_atomic(
                &linked_destination,
                &record,
                VERIFIED_SOURCE_RECORD_MAX_BYTES_V1,
                "symlinked verified-source test record",
            )
            .is_err()
        );
        assert_eq!(
            fs::read(&outside).expect("read outside sentinel"),
            b"outside-sentinel"
        );

        let linked_parent = directory.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).expect("link source parent");
        assert!(
            write_json_file_atomic(
                &linked_parent.join("another.json"),
                &record,
                VERIFIED_SOURCE_RECORD_MAX_BYTES_V1,
                "symlink-parent verified-source test record",
            )
            .is_err()
        );
        assert!(
            write_json_file_atomic(
                &linked_parent.join("nested").join("another.json"),
                &record,
                VERIFIED_SOURCE_RECORD_MAX_BYTES_V1,
                "symlink-ancestor verified-source test record",
            )
            .is_err()
        );
        assert!(!real_parent.join("nested").exists());
    }
    #[test]
    fn verified_source_job_id_has_fixed_hex_size() {
        let job_id = new_job_id().expect("generate job id");
        assert_eq!(job_id.len(), FIXED_HEX_COMPONENT_CHARS_V1);
        assert!(
            job_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_ne!(job_id, new_job_id().expect("generate a second job id"));
    }
    fn checked_contract_sources_key_fixture(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm)
            .expect("generate checked contract source fixture key")
    }
    #[test]
    fn contract_sources_fixture_uses_checked_random_key_generation() {
        for algorithm in [Algorithm::Ed25519, Algorithm::BlsNormal] {
            let key_pair = checked_contract_sources_key_fixture(algorithm);
            let actual = key_pair
                .public_key()
                .try_algorithm()
                .expect("contract source fixture key advertises a valid algorithm");
            assert_eq!(actual, algorithm);
        }
    }
    #[test]
    fn pseudo_source_uses_branded_entrypoint_syntax_and_complete_permission_catalog() {
        let (_, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r#"
seiyaku Display {
  permission Run;
  permission Unused;
  import permission "GlobalRun" as Shared;
  kotoage fn run(quantity amount) authorize(Run) {}
  view fn read() authorize(anyone) -> int { return 1; }
  view fn shared() authorize(Shared) -> int { return 2; }
  hajimari() {}
  kaizen() {}
}
"#,
            )
            .unwrap();
        let entries = manifest.entrypoints.as_ref().unwrap();
        let entry = |name: &str| entries.iter().find(|entry| entry.name == name).unwrap();
        assert_eq!(
            entrypoint_signature(entry("run")).unwrap(),
            "kotoage fn run(quantity amount) authorize(Run) -> ()"
        );
        assert_eq!(
            entrypoint_signature(entry("read")).unwrap(),
            "view fn read() authorize(anyone) -> int"
        );
        assert_eq!(
            entrypoint_signature(entry("hajimari")).unwrap(),
            "hajimari() -> ()"
        );
        assert_eq!(
            entrypoint_signature(entry("kaizen")).unwrap(),
            "kaizen() -> ()"
        );
        for rendered in [
            render_pseudo_source("00", Some(&manifest), None),
            render_manifest_stub("00", Some(&manifest), &[]),
        ] {
            assert!(rendered.contains("permission Run;"));
            assert!(rendered.contains("permission Unused;"));
            assert!(rendered.contains("import permission \"GlobalRun\" as Shared;"));
            assert!(rendered.contains("view fn shared() authorize(Shared) -> int"));
        }
        assert_eq!(aggregate_permissions(Some(&manifest)), manifest.permissions);
        assert_eq!(
            to_entrypoint_dto(entry("run")).authorization,
            EntrypointAuthorizationV1::Permission("Run".parse().unwrap())
        );
        let mut invalid = entry("hajimari").clone();
        invalid.authorization = EntrypointAuthorizationV1::Anyone;
        assert!(entrypoint_signature(&invalid).is_err());
        invalid = entry("read").clone();
        invalid.authorization = EntrypointAuthorizationV1::RuntimeLifecycle;
        assert!(entrypoint_signature(&invalid).is_err());
    }
    fn build_state_with_single_transaction(
        instructions: Vec<dm::InstructionBox>,
    ) -> (Arc<State>, HashOf<TransactionEntrypoint>) {
        let mut chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(
            iroha_core::sumeragi::test_chain::TestChainConfig::new(
                World::default(),
                1_710_000_000_000,
            ),
        )
        .expect("original contract source query genesis");
        let state = Arc::clone(chain.state());
        let authority_key = checked_contract_sources_key_fixture(Algorithm::Ed25519);
        let authority = dm::AccountId::new(authority_key.public_key().clone());
        let mut builder = dm::TransactionBuilder::new(
            *state.network_id_ref(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(1_710_000_000_000));
        let signed = builder
            .with_instructions(instructions)
            .sign(authority_key.private_key());
        let target_hash = signed.hash_as_entrypoint();
        crate::test_utils::commit_native_accepted_inputs(
            &mut chain,
            vec![AcceptedTransaction::new_unchecked(Cow::Owned(signed))],
        );
        (state, target_hash)
    }
    fn install_contract_instance(
        state: &State,
        authority: &AccountId,
        authority_keypair: &KeyPair,
        contract_address: &dm::ContractAddress,
        code: Vec<u8>,
    ) -> Hash {
        let mut block = state.block(dm::BlockHeader::new(
            NonZeroU64::new(1).expect("height"),
            None,
            None,
            0,
            0,
        ));
        let mut stx = block.transaction();
        let register_permission: permission::Permission = CanManageSmartContractCode.into();
        dm::Grant::account_permission(register_permission, authority.clone())
            .execute(authority, &mut stx)
            .expect("grant CanManageSmartContractCode");
        let enact_permission: permission::Permission = CanEnactGovernance.into();
        dm::Grant::account_permission(enact_permission, authority.clone())
            .execute(authority, &mut stx)
            .expect("grant CanEnactGovernance");
        let verified = ivm::verify_contract_artifact(&code).expect("verify contract artifact");
        let code_hash = register_code_bytes(
            authority,
            contract_address.dataspace_id().expect("fixture scope"),
            code,
            &mut stx,
        )
        .expect("register contract bytes");
        let signing_owner = crate::history_producer::HistoryProducerOwner::for_test();
        let max_frame_bytes =
            usize::try_from(stx.world.parameters().transaction.ivm_bytecode_size.get())
                .expect("committed fixture manifest frame bound fits usize");
        let manifest = verified
            .manifest
            .try_signed(
                signing_owner.allocation_context(),
                max_frame_bytes,
                authority_keypair,
            )
            .expect("sign fixture manifest under original funded owner");
        register_manifest(
            authority,
            contract_address.dataspace_id().expect("fixture scope"),
            manifest,
            &mut stx,
        )
        .expect("register manifest");
        stx.world.bind_inactive_contract_subject_for_testing(
            contract_address.clone(),
            authority.clone(),
        );
        activate_instance(authority, contract_address.clone(), 1, code_hash, &mut stx)
            .expect("activate instance");
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit block");
        code_hash
    }
    #[tokio::test]
    async fn instruction_contract_view_renders_pseudo_source_for_register_bytes() {
        let _guard = TestDataDirGuard::new();
        let program = kotodama_lang::session::CompilerSession::default()
            .build(kotodama_lang::session::CompileRequest {
                source: "seiyaku Demo { view fn main() authorize(anyone) -> int { return 1; } }",
                source_name: Some("instruction_view.ko"),
            })
            .expect("compile callable source fixture")
            .artifact;
        let code_hash = canonical_code_hash(&program).expect("canonical hash");
        let instruction = dm::InstructionBox::from(RegisterSmartContractBytes {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                code_hash,
            ),
            code: program,
        });
        let (state, hash) = build_state_with_single_transaction(vec![instruction]);
        let response = handle_get_instruction_contract_view(state, hash.to_string(), 0)
            .await
            .expect("contract view response")
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let payload: ContractCodeViewDto =
            norito::json::from_slice(&body).expect("decode contract view");
        assert_eq!(payload.rendered_source_kind, RENDERED_SOURCE_PSEUDO);
        assert!(payload.rendered_source_text.contains("seiyaku Contract_"));
        assert!(payload.rendered_source_text.contains("view fn main()"));
        assert!(!payload.rendered_source_text.contains("public fn"));
        assert!(!payload.rendered_source_text.contains("main:"));
        assert!(!payload.entrypoints.is_empty());
    }
    #[tokio::test]
    async fn code_hash_contract_view_prefers_verified_source_record() {
        let _guard = TestDataDirGuard::new();
        let authority_keypair = checked_contract_sources_key_fixture(Algorithm::default());
        let authority = dm::AccountId::new(authority_keypair.public_key().clone());
        let world = crate::test_utils::world_with_authority(&authority);
        let state = Arc::new(State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        let source = "seiyaku Demo { permission Run;  kotoage fn main() authorize(Run) {} }";
        let source_name = "demo.ko";
        let compiled = kotodama_lang::session::CompilerSession::default()
            .build(kotodama_lang::session::CompileRequest {
                source,
                source_name: Some(source_name),
            })
            .expect("compile verified-source fixture");
        let verified = ivm::verify_contract_artifact(&compiled.artifact)
            .expect("verify compiled source fixture");
        let network_id = *state.network_id_ref();
        let contract_address = dm::ContractAddress::derive(
            &network_id,
            &authority,
            0,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let code_hash = install_contract_instance(
            state.as_ref(),
            &authority,
            &authority_keypair,
            &contract_address,
            compiled.artifact,
        );
        let code_hash_hex = hash_hex(&code_hash);
        let record = StoredVerifiedSourceRecord {
            artifacts: Vec::new(),
            network_id,
            artifact_id: source_artifact(&code_hash_hex),
            sources: Vec::new(),
            imports: Vec::new(),
            packages: Vec::new(),
            version: VERIFIED_SOURCE_VERSION,
            code_hash: code_hash_hex.clone(),
            abi_hash: Some(hash_hex(&verified.abi_hash)),
            compiler_fingerprint: verified.manifest.compiler_fingerprint,
            language: VERIFIED_SOURCE_LANGUAGE_KOTODAMA.to_owned(),
            source_name: Some(source_name.to_owned()),
            source_text: source.to_owned(),
            submitted_at: now_rfc3339(),
            manifest_id_hex: Some("aa".repeat(32)),
            payload_digest_hex: Some("bb".repeat(32)),
            content_length: Some(24),
        };
        persist_verified_source_record(&record).expect("persist verified source");
        let response = handle_get_contract_code_view(state, source_artifact(&code_hash_hex))
            .await
            .expect("contract view response")
            .into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let payload: ContractCodeViewDto =
            norito::json::from_slice(&body).expect("decode contract view");
        assert_eq!(payload.rendered_source_kind, RENDERED_SOURCE_VERIFIED);
        assert_eq!(payload.rendered_source_text, source);
        assert!(payload.verified_source_ref.is_some());
    }
    #[test]
    fn contract_view_never_labels_a_declared_hash_source_as_verified_for_other_code() {
        let _guard = TestDataDirGuard::new();
        let declared_source = "seiyaku Declared { permission InvokeDeclared;  kotoage fn main() authorize(InvokeDeclared) {} }";
        let declared = valid_verified_source_record(declared_source, "declared.ko");
        persist_verified_source_record(&declared).expect("persist declared-hash source");

        let actual_source = "seiyaku Actual { permission InvokeActual;  kotoage fn main() authorize(InvokeActual) {} }";
        let actual = kotodama_lang::session::CompilerSession::default()
            .build(kotodama_lang::session::CompileRequest {
                source: actual_source,
                source_name: Some("actual.ko"),
            })
            .expect("compile different actual contract");
        let actual_hash = hash_hex(
            &canonical_code_hash(&actual.artifact).expect("hash different actual contract"),
        );
        assert_ne!(declared.code_hash, actual_hash);

        let view = build_contract_view(ContractViewBuildInput {
            network_id: declared.network_id,
            artifact_id: declared.artifact_id,
            code_hash: Some(declared.code_hash.clone()),
            declared_code_hash: Some(declared.code_hash),
            manifest: None,
            code_bytes: Some(actual.artifact),
            warnings: Vec::new(),
        })
        .expect("build mismatched contract view");
        assert_eq!(view.code_hash, actual_hash);
        assert_eq!(view.rendered_source_kind, RENDERED_SOURCE_PSEUDO);
        assert_ne!(view.rendered_source_text, declared_source);
        assert!(view.verified_source_ref.is_none());
    }
    #[test]
    fn verified_source_job_accepts_exact_match_and_persists_record() {
        let _guard = TestDataDirGuard::new();
        let source = r#"
seiyaku Demo { permission Run;  kotoage fn main() authorize(Run) {} }
"#;
        let (compiled, _, _) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest_and_report(source)
            .expect("compile contract");
        let code_hash_hex = hash_hex(&canonical_code_hash(&compiled).expect("canonical hash"));
        let node = sorafs_node::NodeHandle::new(
            sorafs_node::config::StorageConfig::builder()
                .enabled(true)
                .data_dir(_guard.path().join("sorafs"))
                .build(),
        );
        let request = SubmitVerifiedContractSourceDto {
            artifacts: Vec::new(),
            sources: Vec::new(),
            imports: Vec::new(),
            packages: Vec::new(),
            language: VERIFIED_SOURCE_LANGUAGE_KOTODAMA.to_owned(),
            source_name: Some("demo.ko".to_owned()),
            source_text: source.to_owned(),
        };
        crate::frame_test_support::assert_current_frame(
            &request,
            "iroha_torii::contract_sources::SubmitVerifiedContractSourceDto",
        );
        let (status, JsonBody(response)) = handle_post_verified_source_job(
            source_network(),
            source_artifact(&code_hash_hex),
            request,
            node,
        )
        .expect("submit verified source");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(response.status, "accepted");
        assert!(response.verified_source_ref.is_none());
        let record = load_verified_source_record(source_network(), source_artifact(&code_hash_hex))
            .expect("load record")
            .expect("record exists");
        assert_eq!(record.source_text.trim(), source.trim());
        assert_eq!(record.language, VERIFIED_SOURCE_LANGUAGE_KOTODAMA);
    }
    #[test]
    fn verified_source_job_rejects_language_aliases() {
        let _guard = TestDataDirGuard::new();
        let code_hash = "11".repeat(FIXED_HEX_COMPONENT_BYTES_V1);
        let node = sorafs_node::NodeHandle::new(
            sorafs_node::config::StorageConfig::builder()
                .data_dir(_guard.path().join("sorafs"))
                .build(),
        );
        let (status, JsonBody(response)) = handle_post_verified_source_job(
            source_network(),
            source_artifact(&code_hash),
            SubmitVerifiedContractSourceDto {
                artifacts: Vec::new(),
                sources: Vec::new(),
                imports: Vec::new(),
                packages: Vec::new(),
                language: "Kotodama".to_owned(),
                source_name: None,
                source_text: "seiyaku Demo {}".to_owned(),
            },
            node,
        )
        .expect("reject language alias");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response.status, "error");
        let stored = load_verified_source_job(
            source_network(),
            source_artifact(&code_hash),
            &response.job_id,
        )
        .expect("load language error job")
        .expect("language error job exists");
        assert_eq!(stored.status, "error");
    }
    #[test]
    fn verified_source_job_does_not_mutate_provider_storage() {
        let _guard = TestDataDirGuard::new();
        let source = "seiyaku Demo { permission Run;  kotoage fn main() authorize(Run) {} }";
        let (compiled, _, _) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest_and_report(source)
            .expect("compile contract");
        let code_hash_hex = hash_hex(&canonical_code_hash(&compiled).expect("canonical hash"));
        let node = sorafs_node::NodeHandle::new(
            sorafs_node::config::StorageConfig::builder()
                .enabled(true)
                .data_dir(_guard.path().join("sorafs"))
                .build(),
        );
        let inspect_node = node.clone();
        let (status, JsonBody(response)) = handle_post_verified_source_job(
            source_network(),
            source_artifact(&code_hash_hex),
            SubmitVerifiedContractSourceDto {
                artifacts: Vec::new(),
                sources: Vec::new(),
                imports: Vec::new(),
                packages: Vec::new(),
                language: VERIFIED_SOURCE_LANGUAGE_KOTODAMA.to_owned(),
                source_name: Some("demo.ko".to_owned()),
                source_text: source.to_owned(),
            },
            node,
        )
        .expect("submit verified source");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(response.verified_source_ref.is_none());
        assert!(
            inspect_node
                .stored_manifests()
                .expect("inspect provider storage")
                .is_empty(),
            "HTTP verified-source submission must not mutate provider storage"
        );
    }
    #[test]
    fn verified_source_job_reports_hash_mismatch() {
        let _guard = TestDataDirGuard::new();
        let source = "seiyaku Demo { permission Run;  kotoage fn main() authorize(Run) {} }";
        let wrong_hash = "11".repeat(32);
        let node = sorafs_node::NodeHandle::new(
            sorafs_node::config::StorageConfig::builder()
                .data_dir(_guard.path().join("sorafs"))
                .build(),
        );
        let (status, JsonBody(response)) = handle_post_verified_source_job(
            source_network(),
            source_artifact(&wrong_hash),
            SubmitVerifiedContractSourceDto {
                artifacts: Vec::new(),
                sources: Vec::new(),
                imports: Vec::new(),
                packages: Vec::new(),
                language: VERIFIED_SOURCE_LANGUAGE_KOTODAMA.to_owned(),
                source_name: None,
                source_text: source.to_owned(),
            },
            node,
        )
        .expect("submit mismatch");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response.status, "mismatch");
        assert!(response.actual_code_hash.is_some());
        let stored = load_verified_source_job(
            source_network(),
            source_artifact(&wrong_hash),
            &response.job_id,
        )
        .expect("load job")
        .expect("job exists");
        assert_eq!(stored.status, "mismatch");
    }
}
