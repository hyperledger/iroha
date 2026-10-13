//! Provider advert ingestion and validation for Torii's SoraFS discovery pipeline.
#[cfg(test)]
mod finalized_admission_tests;
use super::admission::{
    AdmissionRegistry, ProviderAdmissionAdvertError, verify_advert_against_envelope,
};
use crate::secure_file_metadata::{self, SecureMetadata};
use blake3::hash as blake3_hash;
use norito::{
    derive::{NoritoDeserialize, NoritoSerialize},
    to_bytes,
};
use sorafs_manifest::{
    AdvertSignatureError, AdvertValidationError, CapabilityType, ProviderAdvertV1,
    SignatureAlgorithm,
};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use thiserror::Error;
/// Fingerprint size for stored adverts (BLAKE3-256).
pub const FINGERPRINT_LEN: usize = 32;
const REPLAY_CHECKPOINT_VERSION_V1: u8 = 1;
const REPLAY_CHECKPOINT_HARD_MAX_ENTRIES: usize = 65_536;
const REPLAY_CHECKPOINT_BASE_MAX_BYTES: u64 = 4 * 1024;
const REPLAY_CHECKPOINT_MAX_BYTES_PER_ENTRY: u64 = 128;
static REPLAY_CHECKPOINT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdvertReplayHighWater {
    issued_at: u64,
    fingerprint: [u8; FINGERPRINT_LEN],
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::discovery::ProviderAdvertReplayEntryV1")]
struct ProviderAdvertReplayEntryV1 {
    version: u8,
    network_id: [u8; 32],
    provider_id: [u8; 32],
    issued_at: u64,
    fingerprint: [u8; FINGERPRINT_LEN],
}
#[derive(Debug)]
struct ReplayCheckpointStore {
    path: PathBuf,
    network_id: [u8; 32],
    max_entries: usize,
    // Retained for the full cache lifetime; dropping the cache releases the
    // operating-system advisory lock.
    _lock_file: fs::File,
}
/// Outcome of ingesting a provider advert into the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertIngest {
    /// A brand new advert was stored.
    Stored {
        /// BLAKE3 fingerprint of the stored advert.
        fingerprint: [u8; FINGERPRINT_LEN],
    },
    /// An advert replaced a previous version from the same provider.
    Replaced {
        /// BLAKE3 fingerprint of the updated advert.
        fingerprint: [u8; FINGERPRINT_LEN],
    },
    /// The advert matched an existing fingerprint and was ignored.
    Duplicate {
        /// BLAKE3 fingerprint of the existing advert.
        fingerprint: [u8; FINGERPRINT_LEN],
    },
}
/// Metadata downgrade warnings emitted during advert ingestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertWarning {
    /// Provider advert omitted the required `chunk_range_fetch` capability.
    ChunkRangeCapability,
    /// Provider advert omitted the required stream budget for range fetch.
    StreamBudget,
    /// Provider advert omitted transport hints for range fetch.
    TransportHints,
}
impl AdvertWarning {
    /// Returns the canonical telemetry reason label.
    #[must_use]
    pub fn telemetry_reason(self) -> &'static str {
        match self {
            AdvertWarning::ChunkRangeCapability => "missing_chunk_range",
            AdvertWarning::StreamBudget => "missing_stream_budget",
            AdvertWarning::TransportHints => "missing_transport_hints",
        }
    }
    /// Returns a short identifier suitable for JSON responses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.telemetry_reason()
    }
}
/// Result of an advert ingestion attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertIngestResult {
    /// Outcome of the ingestion (stored/replaced/duplicate).
    pub outcome: AdvertIngest,
    /// Downgrade warnings detected during ingestion.
    pub warnings: Vec<AdvertWarning>,
}
/// Immutable inputs needed to authenticate and normalize a provider advert.
///
/// A policy snapshot can be cloned while briefly holding the cache read lock,
/// then used for signature and admission verification after that lock has been
/// released. The resulting [`PreparedProviderAdvert`] is opaque, so the cache
/// commit path cannot be reached with unverified wire data.
#[derive(Debug, Clone)]
pub struct ProviderAdvertValidationPolicy {
    known_capabilities: Vec<CapabilityType>,
    admission: Arc<AdmissionRegistry>,
}
/// Provider advert that passed structural, signature, capability, and
/// admission-envelope validation against one cache policy snapshot.
#[derive(Debug)]
pub struct PreparedProviderAdvert {
    advert: ProviderAdvertV1,
    known_capabilities: Vec<CapabilityType>,
    warnings: Vec<AdvertWarning>,
    fingerprint: [u8; FINGERPRINT_LEN],
    policy_capabilities: Vec<CapabilityType>,
    policy_admission: Arc<AdmissionRegistry>,
}
impl ProviderAdvertValidationPolicy {
    /// Validate an advert without acquiring or retaining the provider-cache lock.
    ///
    /// # Errors
    ///
    /// Returns an [`AdvertError`] when the advert is malformed, expired, unsigned, outside the
    /// configured capability policy, or not authorized by its provider admission envelope.
    pub fn prepare(
        &self,
        advert: ProviderAdvertV1,
        now: u64,
    ) -> Result<PreparedProviderAdvert, AdvertError> {
        advert.validate_with_body(now)?;
        if !advert.signature_strict {
            return Err(AdvertError::SignaturePolicyDisabled);
        }
        verify_signature(&advert)?;
        let unknown_capabilities = advert
            .body
            .capabilities
            .iter()
            .map(|tlv| tlv.cap_type)
            .filter(|capability| !self.known_capabilities.contains(capability))
            .collect::<Vec<_>>();
        if !unknown_capabilities.is_empty() && !advert.allow_unknown_capabilities {
            return Err(AdvertError::UnknownCapabilities {
                capabilities: unknown_capabilities,
            });
        }
        let known_capabilities = advert
            .body
            .capabilities
            .iter()
            .filter_map(|tlv| {
                self.known_capabilities
                    .contains(&tlv.cap_type)
                    .then_some(tlv.cap_type)
            })
            .collect();
        let provider_id = advert.body.provider_id;
        let admission_entry = self
            .admission
            .entry(&provider_id)
            .ok_or(AdvertError::AdmissionMissing { provider_id })?;
        verify_advert_against_envelope(&advert, &admission_entry).map_err(|error| {
            AdvertError::AdmissionFailed {
                provider_id,
                error: Box::new(error),
            }
        })?;
        let warnings = collect_warnings(&advert);
        let fingerprint = fingerprint(&advert)?;
        Ok(PreparedProviderAdvert {
            advert,
            known_capabilities,
            warnings,
            fingerprint,
            policy_capabilities: self.known_capabilities.clone(),
            policy_admission: Arc::clone(&self.admission),
        })
    }
}
/// Errors raised while loading or atomically updating the durable provider
/// advert replay checkpoint.
#[derive(Debug, Error)]
pub enum ReplayCheckpointError {
    /// The admitted provider registry exceeds the configured checkpoint bound.
    #[error(
        "admission registry contains {admitted} providers, exceeding replay checkpoint limit {max_entries}"
    )]
    AdmissionRegistryTooLarge {
        /// Number of providers in the admission registry.
        admitted: usize,
        /// Configured maximum checkpoint entries.
        max_entries: usize,
    },
    /// The configured checkpoint limit exceeds the implementation's hard
    /// allocation and file-size ceiling.
    #[error("configured replay checkpoint limit {configured} exceeds hard maximum {hard_maximum}")]
    ConfiguredLimitTooLarge {
        /// Operator-configured entry limit.
        configured: usize,
        /// Hard first-release entry limit.
        hard_maximum: usize,
    },
    /// A checkpoint read or write failed.
    #[error("provider advert replay checkpoint I/O failed at {path:?}: {source}")]
    Io {
        /// Checkpoint path involved in the failed operation.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// The checkpoint rename completed but syncing its directory failed, so
    /// further ingestion must remain disabled until restart and repair.
    #[error("provider advert replay checkpoint durability is uncertain at {path:?}: {source}")]
    DurabilityUncertain {
        /// Checkpoint whose rename could not be durably confirmed.
        path: PathBuf,
        /// Underlying directory-sync error.
        #[source]
        source: io::Error,
    },
    /// A prior ambiguous durability failure poisoned this cache instance.
    #[error("provider advert replay checkpoint is poisoned after an uncertain commit")]
    Poisoned,
    /// Another Torii process already owns the checkpoint lock.
    #[error("provider advert replay checkpoint is already locked at {path:?}")]
    LockHeld {
        /// Lock file held by the competing process.
        path: PathBuf,
    },
    /// Checkpoint bytes could not be encoded or decoded with Norito.
    #[error("provider advert replay checkpoint codec failure: {0}")]
    Codec(String),
    /// The persisted checkpoint version is unsupported.
    #[error("unsupported provider advert replay checkpoint version {version}")]
    UnsupportedVersion {
        /// Version found in the persisted checkpoint.
        version: u8,
    },
    /// A persisted checkpoint must contain at least one provider high-water mark.
    #[error("provider advert replay checkpoint is empty")]
    Empty,
    /// The checkpoint is larger than the configured size bound.
    #[error("provider advert replay checkpoint is {actual} bytes; maximum is {maximum}")]
    TooLarge {
        /// Observed checkpoint length.
        actual: u64,
        /// Maximum permitted checkpoint length.
        maximum: u64,
    },
    /// The checkpoint contains more entries than configured.
    #[error("provider advert replay checkpoint has {actual} entries; maximum is {maximum}")]
    TooManyEntries {
        /// Observed number of entries.
        actual: usize,
        /// Maximum permitted number of entries.
        maximum: usize,
    },
    /// The checkpoint does not use the canonical Norito encoding.
    #[error("provider advert replay checkpoint is not canonically encoded")]
    NonCanonicalEncoding,
    /// A persisted high-water mark belongs to a different genesis network.
    #[error(
        "provider advert replay checkpoint network {provided:02x?} differs from local network {expected:02x?}"
    )]
    NetworkMismatch {
        /// Exact genesis network configured for this cache.
        expected: [u8; 32],
        /// Genesis network recorded in the checkpoint.
        provided: [u8; 32],
    },
    /// Checkpoint provider identifiers are not strictly increasing.
    #[error("provider advert replay checkpoint entries are not strictly sorted and unique")]
    NonCanonicalOrder,
    /// A checkpoint entry is no longer backed by the configured admission registry.
    #[error("provider advert replay checkpoint contains unadmitted provider {provider_id:02x?}")]
    ProviderNotAdmitted {
        /// Provider identifier absent from the admission registry.
        provider_id: [u8; 32],
    },
    /// A new admitted provider would exceed the configured high-water bound.
    #[error("provider advert replay high-water limit {maximum} reached")]
    CapacityExceeded {
        /// Maximum permitted number of provider high-water entries.
        maximum: usize,
    },
}
/// Errors surfaced while processing provider adverts.
#[derive(Debug, Error)]
pub enum AdvertError {
    /// Provider advert could not be decoded with the Norito codec.
    #[error("decode provider advert: {0}")]
    Decode(#[from] norito::Error),
    /// Structural validation of the advert failed.
    #[error("provider advert validation failed: {0}")]
    Validation(#[from] AdvertValidationError),
    /// The advert declared a signature algorithm Torii does not support.
    #[error("unsupported signature algorithm: {0:?}")]
    UnsupportedSignature(SignatureAlgorithm),
    /// Mandatory signature verification failed.
    #[error("signature verification failed: {0}")]
    Signature(String),
    /// Torii requires signature verification for all remotely supplied adverts.
    #[error("provider advert disabled mandatory signature verification")]
    SignaturePolicyDisabled,
    /// A prepared advert came from a different cache validation policy.
    #[error("prepared provider advert does not match the active validation policy")]
    ValidationPolicyChanged,
    /// A provider attempted to replace a newer advert with an older or conflicting advert.
    #[error(
        "provider advert issued_at is not monotonic for {provider_id:02x?} (current={current_issued_at}, incoming={incoming_issued_at})"
    )]
    NonMonotonicIssuedAt {
        /// Provider whose cached advert would have been replaced.
        provider_id: [u8; 32],
        /// Issuance timestamp already stored in the cache.
        current_issued_at: u64,
        /// Issuance timestamp supplied by the rejected advert.
        incoming_issued_at: u64,
    },
    /// Persisting the provider's replay high-water mark failed. The cache is left unchanged.
    #[error("provider advert replay checkpoint rejected update: {0}")]
    ReplayCheckpoint(#[from] ReplayCheckpointError),
    /// The advert referenced capability TLVs not present in the allow-list.
    #[error("unknown capabilities rejected: {capabilities:?}")]
    UnknownCapabilities {
        /// Capability identifiers rejected during validation.
        capabilities: Vec<CapabilityType>,
    },
    /// No admission envelope matched the provider identifier.
    #[error("missing admission envelope for provider {provider_id:02x?}")]
    AdmissionMissing {
        /// Provider identifier lacking an admission envelope.
        provider_id: [u8; 32],
    },
    /// Admission verification failed for the advert.
    #[error("admission verification failed for provider {provider_id:02x?}: {error}")]
    AdmissionFailed {
        /// Provider identifier whose admission failed.
        provider_id: [u8; 32],
        /// Reason the admission check rejected the advert.
        error: Box<ProviderAdmissionAdvertError>,
    },
}
impl ReplayCheckpointStore {
    fn new(
        path: PathBuf,
        network_id: [u8; 32],
        max_entries: NonZeroUsize,
    ) -> Result<Self, ReplayCheckpointError> {
        let lock_file = acquire_checkpoint_lock(&path)?;
        Ok(Self {
            path,
            network_id,
            max_entries: max_entries.get(),
            _lock_file: lock_file,
        })
    }
    fn maximum_bytes(&self) -> u64 {
        u64::try_from(self.max_entries)
            .unwrap_or(u64::MAX)
            .saturating_mul(REPLAY_CHECKPOINT_MAX_BYTES_PER_ENTRY)
            .saturating_add(REPLAY_CHECKPOINT_BASE_MAX_BYTES)
    }
    fn load(
        &self,
        admission: &AdmissionRegistry,
    ) -> Result<HashMap<[u8; 32], AdvertReplayHighWater>, ReplayCheckpointError> {
        let Some(bytes) = read_checkpoint_bounded(&self.path, self.maximum_bytes())? else {
            return Ok(HashMap::new());
        };
        // Preflight the top-level sequence length before generic decoding. This
        // prevents a corrupt length prefix from requesting an attacker-chosen
        // allocation even when the checkpoint file itself is bounded.
        let view = norito::core::from_bytes_view(&bytes)
            .map_err(|err| ReplayCheckpointError::Codec(err.to_string()))?;
        let (declared_entries, _) = norito::core::read_seq_len_slice(view.as_bytes())
            .map_err(|err| ReplayCheckpointError::Codec(err.to_string()))?;
        if declared_entries > self.max_entries {
            return Err(ReplayCheckpointError::TooManyEntries {
                actual: declared_entries,
                maximum: self.max_entries,
            });
        }
        let entries: Vec<ProviderAdvertReplayEntryV1> = norito::decode_from_bytes(&bytes)
            .map_err(|err| ReplayCheckpointError::Codec(err.to_string()))?;
        if entries.is_empty() {
            return Err(ReplayCheckpointError::Empty);
        }
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.version != REPLAY_CHECKPOINT_VERSION_V1)
        {
            return Err(ReplayCheckpointError::UnsupportedVersion {
                version: entry.version,
            });
        }
        if entries
            .windows(2)
            .any(|pair| pair[0].provider_id >= pair[1].provider_id)
        {
            return Err(ReplayCheckpointError::NonCanonicalOrder);
        }
        let canonical =
            to_bytes(&entries).map_err(|err| ReplayCheckpointError::Codec(err.to_string()))?;
        if canonical != bytes {
            return Err(ReplayCheckpointError::NonCanonicalEncoding);
        }
        let mut high_water = HashMap::with_capacity(entries.len());
        for entry in entries {
            if entry.network_id != self.network_id {
                return Err(ReplayCheckpointError::NetworkMismatch {
                    expected: self.network_id,
                    provided: entry.network_id,
                });
            }
            if !admission.retains_identity(&entry.provider_id) {
                return Err(ReplayCheckpointError::ProviderNotAdmitted {
                    provider_id: entry.provider_id,
                });
            }
            high_water.insert(
                entry.provider_id,
                AdvertReplayHighWater {
                    issued_at: entry.issued_at,
                    fingerprint: entry.fingerprint,
                },
            );
        }
        Ok(high_water)
    }
    fn persist(
        &self,
        high_water: &HashMap<[u8; 32], AdvertReplayHighWater>,
    ) -> Result<(), ReplayCheckpointError> {
        if high_water.len() > self.max_entries {
            return Err(ReplayCheckpointError::CapacityExceeded {
                maximum: self.max_entries,
            });
        }
        let mut entries = high_water
            .iter()
            .map(|(provider_id, high_water)| ProviderAdvertReplayEntryV1 {
                version: REPLAY_CHECKPOINT_VERSION_V1,
                network_id: self.network_id,
                provider_id: *provider_id,
                issued_at: high_water.issued_at,
                fingerprint: high_water.fingerprint,
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|entry| entry.provider_id);
        let bytes =
            to_bytes(&entries).map_err(|err| ReplayCheckpointError::Codec(err.to_string()))?;
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let maximum = self.maximum_bytes();
        if actual > maximum {
            return Err(ReplayCheckpointError::TooLarge { actual, maximum });
        }
        write_checkpoint_atomic(&self.path, &bytes)
    }
}
fn acquire_checkpoint_lock(checkpoint_path: &Path) -> Result<fs::File, ReplayCheckpointError> {
    validate_checkpoint_path(checkpoint_path)?;
    let parent = checkpoint_parent(checkpoint_path);
    fs::create_dir_all(parent).map_err(|source| ReplayCheckpointError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    validate_checkpoint_path(checkpoint_path)?;
    let lock_path = checkpoint_path.with_added_extension("lock");
    validate_checkpoint_path(&lock_path)?;
    let before_open = match secure_file_metadata::from_path(&lock_path) {
        Ok(metadata) => Some(metadata),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(ReplayCheckpointError::Io {
                path: lock_path,
                source,
            });
        }
    };
    if let Some(metadata) = before_open.as_ref() {
        validate_lock_file_metadata(&lock_path, metadata)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_no_follow_flag(&mut options);
    set_lock_share_mode(&mut options);
    set_private_create_mode(&mut options);
    let file = options
        .open(&lock_path)
        .map_err(|source| ReplayCheckpointError::Io {
            path: lock_path.clone(),
            source,
        })?;
    let opened_metadata =
        secure_file_metadata::from_file(&file).map_err(|source| ReplayCheckpointError::Io {
            path: lock_path.clone(),
            source,
        })?;
    validate_lock_file_metadata(&lock_path, &opened_metadata)?;
    if before_open
        .as_ref()
        .is_some_and(|metadata| !secure_file_metadata::same_file(metadata, &opened_metadata))
    {
        return Err(checkpoint_io_error(
            &lock_path,
            "checkpoint lock changed between inspection and open",
        ));
    }
    let after_open = secure_file_metadata::from_path(&lock_path).map_err(|source| {
        ReplayCheckpointError::Io {
            path: lock_path.clone(),
            source,
        }
    })?;
    validate_lock_file_metadata(&lock_path, &after_open)?;
    if !secure_file_metadata::same_file(&opened_metadata, &after_open) {
        return Err(checkpoint_io_error(
            &lock_path,
            "checkpoint lock path changed while opening",
        ));
    }
    validate_checkpoint_path(&lock_path)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            return Err(ReplayCheckpointError::LockHeld { path: lock_path });
        }
        Err(fs::TryLockError::Error(source)) => {
            return Err(ReplayCheckpointError::Io {
                path: lock_path,
                source,
            });
        }
    }
    let locked_open_metadata =
        secure_file_metadata::from_file(&file).map_err(|source| ReplayCheckpointError::Io {
            path: lock_path.clone(),
            source,
        })?;
    let locked_path_metadata = secure_file_metadata::from_path(&lock_path).map_err(|source| {
        ReplayCheckpointError::Io {
            path: lock_path.clone(),
            source,
        }
    })?;
    validate_lock_file_metadata(&lock_path, &locked_open_metadata)?;
    validate_lock_file_metadata(&lock_path, &locked_path_metadata)?;
    if !secure_file_metadata::same_file(&opened_metadata, &locked_open_metadata)
        || !secure_file_metadata::same_file(&locked_open_metadata, &locked_path_metadata)
    {
        return Err(checkpoint_io_error(
            &lock_path,
            "checkpoint lock path changed while acquiring ownership",
        ));
    }
    validate_checkpoint_path(&lock_path)?;
    Ok(file)
}
fn validate_lock_file_metadata(
    path: &Path,
    metadata: &SecureMetadata,
) -> Result<(), ReplayCheckpointError> {
    if !secure_file_metadata::is_direct_file(metadata)
        || secure_file_metadata::number_of_links(metadata) != Some(1)
    {
        return Err(checkpoint_io_error(
            path,
            "checkpoint lock must be a single-link direct regular file",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(checkpoint_io_error(
            path,
            "checkpoint lock permissions must not grant group or other access",
        ));
    }
    Ok(())
}
fn read_checkpoint_bounded(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Option<Vec<u8>>, ReplayCheckpointError> {
    let path_metadata = match secure_file_metadata::from_path(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ReplayCheckpointError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    validate_checkpoint_file_metadata(path, &path_metadata, maximum_bytes)?;
    validate_checkpoint_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    set_no_follow_flag(&mut options);
    set_stable_read_share_mode(&mut options);
    let mut file = options
        .open(path)
        .map_err(|source| ReplayCheckpointError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let opened_metadata =
        secure_file_metadata::from_file(&file).map_err(|source| ReplayCheckpointError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    validate_checkpoint_file_metadata(path, &opened_metadata, maximum_bytes)?;
    let opened_path_metadata =
        secure_file_metadata::from_path(path).map_err(|source| ReplayCheckpointError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    validate_checkpoint_file_metadata(path, &opened_path_metadata, maximum_bytes)?;
    if !secure_file_metadata::unchanged(&path_metadata, &opened_metadata)
        || !secure_file_metadata::unchanged(&opened_metadata, &opened_path_metadata)
    {
        return Err(checkpoint_io_error(
            path,
            "checkpoint changed between inspection and open",
        ));
    }
    let capacity = usize::try_from(opened_metadata.len()).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(capacity.min(64 * 1024));
    (&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ReplayCheckpointError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > maximum_bytes {
        return Err(ReplayCheckpointError::TooLarge {
            actual,
            maximum: maximum_bytes,
        });
    }
    let final_opened_metadata =
        secure_file_metadata::from_file(&file).map_err(|source| ReplayCheckpointError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let final_path_metadata =
        secure_file_metadata::from_path(path).map_err(|source| ReplayCheckpointError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    validate_checkpoint_file_metadata(path, &final_opened_metadata, maximum_bytes)?;
    validate_checkpoint_file_metadata(path, &final_path_metadata, maximum_bytes)?;
    if opened_metadata.len() != actual
        || !secure_file_metadata::unchanged(&opened_metadata, &final_opened_metadata)
        || !secure_file_metadata::unchanged(&final_opened_metadata, &final_path_metadata)
    {
        return Err(checkpoint_io_error(
            path,
            "checkpoint changed while reading",
        ));
    }
    validate_checkpoint_path(path)?;
    Ok(Some(bytes))
}
fn validate_checkpoint_file_metadata(
    path: &Path,
    metadata: &SecureMetadata,
    maximum_bytes: u64,
) -> Result<(), ReplayCheckpointError> {
    if !secure_file_metadata::is_direct_file(metadata)
        || secure_file_metadata::number_of_links(metadata) != Some(1)
    {
        return Err(checkpoint_io_error(
            path,
            "checkpoint must be a single-link direct regular file",
        ));
    }
    if metadata.len() > maximum_bytes {
        return Err(ReplayCheckpointError::TooLarge {
            actual: metadata.len(),
            maximum: maximum_bytes,
        });
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(checkpoint_io_error(
            path,
            "checkpoint permissions must not grant group or other access",
        ));
    }
    Ok(())
}
fn write_checkpoint_atomic(path: &Path, bytes: &[u8]) -> Result<(), ReplayCheckpointError> {
    validate_checkpoint_path(path)?;
    let parent = checkpoint_parent(path);
    fs::create_dir_all(parent).map_err(|source| ReplayCheckpointError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    validate_checkpoint_path(path)?;
    let counter = REPLAY_CHECKPOINT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = path.with_added_extension(format!("tmp.{}.{}", std::process::id(), counter));
    let mut renamed = false;
    let write_result = (|| {
        let expected_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_no_follow_flag(&mut options);
        set_writer_share_mode(&mut options);
        set_private_create_mode(&mut options);
        let mut file = options
            .open(&temp_path)
            .map_err(|source| ReplayCheckpointError::Io {
                path: temp_path.clone(),
                source,
            })?;
        let opened_before =
            secure_file_metadata::from_file(&file).map_err(|source| ReplayCheckpointError::Io {
                path: temp_path.clone(),
                source,
            })?;
        let named_before = secure_file_metadata::from_path(&temp_path).map_err(|source| {
            ReplayCheckpointError::Io {
                path: temp_path.clone(),
                source,
            }
        })?;
        validate_checkpoint_file_metadata(&temp_path, &opened_before, expected_len)?;
        validate_checkpoint_file_metadata(&temp_path, &named_before, expected_len)?;
        if !secure_file_metadata::same_file(&opened_before, &named_before) {
            return Err(checkpoint_io_error(
                &temp_path,
                "atomic checkpoint temporary path changed while opening",
            ));
        }
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| ReplayCheckpointError::Io {
                path: temp_path.clone(),
                source,
            })?;
        let opened_after =
            secure_file_metadata::from_file(&file).map_err(|source| ReplayCheckpointError::Io {
                path: temp_path.clone(),
                source,
            })?;
        let named_after = secure_file_metadata::from_path(&temp_path).map_err(|source| {
            ReplayCheckpointError::Io {
                path: temp_path.clone(),
                source,
            }
        })?;
        validate_checkpoint_file_metadata(&temp_path, &opened_after, expected_len)?;
        validate_checkpoint_file_metadata(&temp_path, &named_after, expected_len)?;
        if !secure_file_metadata::same_file(&opened_before, &opened_after)
            || !secure_file_metadata::same_file(&opened_after, &named_after)
            || opened_after.len() != expected_len
            || named_after.len() != expected_len
        {
            return Err(checkpoint_io_error(
                &temp_path,
                "atomic checkpoint temporary path changed while writing",
            ));
        }
        validate_checkpoint_path(path)?;
        fs::rename(&temp_path, path).map_err(|source| ReplayCheckpointError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        renamed = true;
        let persisted_metadata = secure_file_metadata::from_path(path).map_err(|source| {
            ReplayCheckpointError::DurabilityUncertain {
                path: path.to_path_buf(),
                source,
            }
        })?;
        validate_checkpoint_file_metadata(path, &persisted_metadata, expected_len).map_err(
            |error| ReplayCheckpointError::DurabilityUncertain {
                path: path.to_path_buf(),
                source: io::Error::other(error.to_string()),
            },
        )?;
        if !secure_file_metadata::same_file(&opened_after, &persisted_metadata)
            || persisted_metadata.len() != expected_len
        {
            return Err(ReplayCheckpointError::DurabilityUncertain {
                path: path.to_path_buf(),
                source: io::Error::other(
                    "checkpoint path changed identity or revision after atomic replacement",
                ),
            });
        }
        sync_checkpoint_parent(parent).map_err(|source| {
            ReplayCheckpointError::DurabilityUncertain {
                path: path.to_path_buf(),
                source,
            }
        })?;
        let durable_metadata = secure_file_metadata::from_path(path).map_err(|source| {
            ReplayCheckpointError::DurabilityUncertain {
                path: path.to_path_buf(),
                source,
            }
        })?;
        validate_checkpoint_file_metadata(path, &durable_metadata, expected_len).map_err(
            |error| ReplayCheckpointError::DurabilityUncertain {
                path: path.to_path_buf(),
                source: io::Error::other(error.to_string()),
            },
        )?;
        if !secure_file_metadata::unchanged(&persisted_metadata, &durable_metadata)
            || durable_metadata.len() != expected_len
        {
            return Err(ReplayCheckpointError::DurabilityUncertain {
                path: path.to_path_buf(),
                source: io::Error::other(
                    "checkpoint changed while its directory entry was synchronized",
                ),
            });
        }
        Ok(())
    })();
    if write_result.is_err() && !renamed {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}
fn checkpoint_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}
fn sync_checkpoint_parent(parent: &Path) -> io::Result<()> {
    crate::durable_fs::sync_direct_directory(parent)
}
fn validate_checkpoint_path(path: &Path) -> Result<(), ReplayCheckpointError> {
    match secure_file_metadata::from_path(path) {
        Ok(metadata) => {
            if !secure_file_metadata::is_direct_file(&metadata)
                || secure_file_metadata::number_of_links(&metadata) != Some(1)
            {
                return Err(checkpoint_io_error(
                    path,
                    "checkpoint output must be a single-link direct regular file",
                ));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ReplayCheckpointError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    let parent = checkpoint_parent(path);
    for ancestor in std::iter::once(parent).chain(parent.ancestors().skip(1)) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match secure_file_metadata::from_path(ancestor) {
            Ok(metadata) => {
                if !secure_file_metadata::is_direct_directory(&metadata) {
                    return Err(checkpoint_io_error(
                        ancestor,
                        "checkpoint parent must be a direct directory",
                    ));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ReplayCheckpointError::Io {
                    path: ancestor.to_path_buf(),
                    source,
                });
            }
        }
    }
    Ok(())
}
fn checkpoint_io_error(path: &Path, message: &'static str) -> ReplayCheckpointError {
    ReplayCheckpointError::Io {
        path: path.to_path_buf(),
        source: io::Error::other(message),
    }
}
#[cfg(unix)]
fn set_no_follow_flag(options: &mut OpenOptions) {
    options.custom_flags(libc::O_NOFOLLOW);
}
#[cfg(windows)]
fn set_no_follow_flag(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}
#[cfg(not(any(unix, windows)))]
fn set_no_follow_flag(_options: &mut OpenOptions) {}
#[cfg(windows)]
fn set_lock_share_mode(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
}
#[cfg(not(windows))]
fn set_lock_share_mode(_options: &mut OpenOptions) {}
#[cfg(windows)]
fn set_stable_read_share_mode(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
}
#[cfg(not(windows))]
fn set_stable_read_share_mode(_options: &mut OpenOptions) {}
#[cfg(windows)]
fn set_writer_share_mode(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
}
#[cfg(not(windows))]
fn set_writer_share_mode(_options: &mut OpenOptions) {}
#[cfg(unix)]
fn set_private_create_mode(options: &mut OpenOptions) {
    options.mode(0o600);
}
#[cfg(not(unix))]
fn set_private_create_mode(_options: &mut OpenOptions) {}
/// Sanitised provider advert stored by the cache.
#[derive(Debug, Clone)]
pub struct AdvertRecord {
    fingerprint: [u8; FINGERPRINT_LEN],
    advert: ProviderAdvertV1,
    known_capabilities: Vec<CapabilityType>,
    warnings: Vec<AdvertWarning>,
}
impl AdvertRecord {
    /// Returns the stored advert.
    #[must_use]
    pub fn advert(&self) -> &ProviderAdvertV1 {
        &self.advert
    }
    /// Returns the filtered capability list recognised by the cache.
    #[must_use]
    pub fn known_capabilities(&self) -> &[CapabilityType] {
        self.known_capabilities.as_slice()
    }
    /// Returns the downgrade warnings observed while ingesting the advert.
    #[must_use]
    pub fn warnings(&self) -> &[AdvertWarning] {
        &self.warnings
    }
    /// Returns the advert fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.fingerprint
    }
}
/// Provider advert cache propagated through Torii, with optional durable replay high-water storage.
#[derive(Debug)]
pub struct ProviderAdvertCache {
    known_capabilities: Vec<CapabilityType>,
    records: HashMap<[u8; FINGERPRINT_LEN], AdvertRecord>,
    by_provider: HashMap<[u8; 32], [u8; FINGERPRINT_LEN]>,
    // Retained after record pruning so a shorter-lived replacement cannot be
    // followed by replaying an older advert that remains within its own TTL.
    // Entries are added only after governance admission succeeds, bounding
    // cardinality to admitted provider identities.
    replay_high_water: HashMap<[u8; 32], AdvertReplayHighWater>,
    replay_checkpoint: Option<ReplayCheckpointStore>,
    replay_checkpoint_poisoned: bool,
    admission: Arc<AdmissionRegistry>,
}
impl ProviderAdvertCache {
    /// Construct a new cache with the provided capability allow-list.
    #[must_use]
    pub fn new<I>(known_capabilities: I, admission: Arc<AdmissionRegistry>) -> Self
    where
        I: IntoIterator<Item = CapabilityType>,
    {
        Self {
            known_capabilities: known_capabilities.into_iter().collect(),
            records: HashMap::new(),
            by_provider: HashMap::new(),
            replay_high_water: HashMap::new(),
            replay_checkpoint: None,
            replay_checkpoint_poisoned: false,
            admission,
        }
    }
    /// Construct a cache backed by an atomic, bounded Norito replay checkpoint.
    ///
    /// The constructor fails closed when the checkpoint is corrupt, non-canonical, oversized,
    /// symlink-backed, or contains an identity absent from the admission registry.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayCheckpointError`] if the admission registry exceeds the
    /// configured bound or the checkpoint cannot be loaded securely.
    pub fn new_persistent<I>(
        known_capabilities: I,
        admission: Arc<AdmissionRegistry>,
        checkpoint_path: PathBuf,
        max_entries: NonZeroUsize,
    ) -> Result<Self, ReplayCheckpointError>
    where
        I: IntoIterator<Item = CapabilityType>,
    {
        if max_entries.get() > REPLAY_CHECKPOINT_HARD_MAX_ENTRIES {
            return Err(ReplayCheckpointError::ConfiguredLimitTooLarge {
                configured: max_entries.get(),
                hard_maximum: REPLAY_CHECKPOINT_HARD_MAX_ENTRIES,
            });
        }
        if admission.len() > max_entries.get() {
            return Err(ReplayCheckpointError::AdmissionRegistryTooLarge {
                admitted: admission.len(),
                max_entries: max_entries.get(),
            });
        }
        let replay_checkpoint =
            ReplayCheckpointStore::new(checkpoint_path, *admission.network_id(), max_entries)?;
        let replay_high_water = replay_checkpoint.load(&admission)?;
        Ok(Self {
            known_capabilities: known_capabilities.into_iter().collect(),
            records: HashMap::new(),
            by_provider: HashMap::new(),
            replay_high_water,
            replay_checkpoint: Some(replay_checkpoint),
            replay_checkpoint_poisoned: false,
            admission,
        })
    }
    /// Snapshot the immutable validation policy for lock-free advert verification.
    #[must_use]
    pub fn validation_policy(&self) -> ProviderAdvertValidationPolicy {
        ProviderAdvertValidationPolicy {
            known_capabilities: self.known_capabilities.clone(),
            admission: Arc::clone(&self.admission),
        }
    }
    /// Atomically commit a provider advert that was authenticated outside the cache lock.
    ///
    /// The active policy identity, current-time validity, admission envelope, replay high-water
    /// mark, and cache freshness are rechecked before any mutation. Signature verification is
    /// deliberately absent from this critical section and can only be represented by the opaque
    /// [`PreparedProviderAdvert`] value.
    ///
    /// # Errors
    ///
    /// Returns an [`AdvertError`] if the validation policy changed, the advert
    /// expired while waiting to commit, its admission record no longer
    /// matches, or replay/durability checks reject the update.
    pub fn commit_prepared(
        &mut self,
        prepared: PreparedProviderAdvert,
        now: u64,
    ) -> Result<AdvertIngestResult, AdvertError> {
        if self.replay_checkpoint_poisoned {
            return Err(ReplayCheckpointError::Poisoned.into());
        }
        if prepared.policy_capabilities != self.known_capabilities
            || !Arc::ptr_eq(&prepared.policy_admission, &self.admission)
        {
            return Err(AdvertError::ValidationPolicyChanged);
        }
        let PreparedProviderAdvert {
            advert,
            known_capabilities,
            warnings,
            fingerprint,
            policy_capabilities: _,
            policy_admission: _,
        } = prepared;
        advert.validate_with_body(now)?;
        let provider_id = advert.body.provider_id;
        let issued_at = advert.issued_at;
        if !advert.signature_strict {
            return Err(AdvertError::SignaturePolicyDisabled);
        }
        let admission_entry = self
            .admission
            .entry(&provider_id)
            .ok_or(AdvertError::AdmissionMissing { provider_id })?;
        verify_advert_against_envelope(&advert, &admission_entry).map_err(|error| {
            AdvertError::AdmissionFailed {
                provider_id,
                error: Box::new(error),
            }
        })?;
        let previous = self.by_provider.get(&provider_id).copied();
        if let Some(prev_fp) = previous {
            if prev_fp == fingerprint {
                return Ok(AdvertIngestResult {
                    outcome: AdvertIngest::Duplicate { fingerprint },
                    warnings,
                });
            }
        }
        let already_durable = match self.replay_high_water.get(&provider_id).copied() {
            Some(current)
                if issued_at < current.issued_at
                    || (issued_at == current.issued_at && fingerprint != current.fingerprint) =>
            {
                return Err(AdvertError::NonMonotonicIssuedAt {
                    provider_id,
                    current_issued_at: current.issued_at,
                    incoming_issued_at: issued_at,
                });
            }
            Some(current) if issued_at == current.issued_at => true,
            Some(_) | None => false,
        };
        if !already_durable {
            let previous_high_water = self.replay_high_water.insert(
                provider_id,
                AdvertReplayHighWater {
                    issued_at,
                    fingerprint,
                },
            );
            if let Some(checkpoint) = &self.replay_checkpoint
                && let Err(err) = checkpoint.persist(&self.replay_high_water)
            {
                if matches!(&err, ReplayCheckpointError::DurabilityUncertain { .. }) {
                    // Keep the candidate high-water and poison this cache. If
                    // the rename committed, rolling back memory could let a
                    // lower timestamp overwrite the newer checkpoint.
                    self.replay_checkpoint_poisoned = true;
                } else {
                    match previous_high_water {
                        Some(previous) => {
                            self.replay_high_water.insert(provider_id, previous);
                        }
                        None => {
                            self.replay_high_water.remove(&provider_id);
                        }
                    }
                }
                return Err(AdvertError::ReplayCheckpoint(err));
            }
        }
        if let Some(prev_fp) = previous {
            self.records.remove(&prev_fp);
        }
        let record = AdvertRecord {
            fingerprint,
            advert,
            known_capabilities,
            warnings: warnings.clone(),
        };
        self.records.insert(fingerprint, record);
        self.by_provider.insert(provider_id, fingerprint);
        let outcome = match previous {
            Some(_) => AdvertIngest::Replaced { fingerprint },
            None => AdvertIngest::Stored { fingerprint },
        };
        Ok(AdvertIngestResult { outcome, warnings })
    }
    /// Return the number of cached adverts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }
    /// Returns `true` when the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    /// Look up the advert stored for the given provider id.
    #[must_use]
    pub fn record_by_provider(&self, provider_id: &[u8; 32]) -> Option<&AdvertRecord> {
        self.by_provider
            .get(provider_id)
            .and_then(|fp| self.records.get(fp))
    }
    /// Borrow an unverified candidate for an independent complete native proof.
    ///
    /// Replay-store poisoning still refuses. This deliberately performs no admission/history
    /// lookup and may return expired or revoked material. The caller must authenticate the
    /// complete candidate and current admission under its own same-cut native verifier before
    /// using any endpoint, key or provider claim; this accessor grants no authority.
    #[must_use]
    pub fn unverified_record_for_native_proof(
        &self,
        provider_id: &[u8; 32],
    ) -> Option<&AdvertRecord> {
        if self.replay_checkpoint_poisoned {
            return None;
        }
        self.record_by_provider(provider_id)
    }

    /// Return an advert only while its retained council admission and signed payload are valid.
    ///
    /// A cache hit alone is insufficient after expiry or an admission-record replacement. The
    /// caller must still bind this advert to its own network, finalized State provider and exact
    /// transport origin before using it for a provider-specific operation.
    #[must_use]
    pub fn admitted_record_by_provider(
        &self,
        provider_id: &[u8; 32],
        now_unix_seconds: u64,
    ) -> Option<&AdvertRecord> {
        if self.replay_checkpoint_poisoned {
            return None;
        }
        let record = self.record_by_provider(provider_id)?;
        let advert = record.advert();
        let admission = self.admission.entry(provider_id)?;
        // The registry selects current native authority, including signed-genesis
        // admissions. Council signature presence is not a substitute for that source.
        (advert.signature_strict
            && advert.validate_with_body(now_unix_seconds).is_ok()
            && verify_signature(advert).is_ok()
            && verify_advert_against_envelope(advert, &admission).is_ok())
        .then_some(record)
    }
    /// Iterate over all stored adverts.
    pub fn records(&self) -> impl Iterator<Item = &AdvertRecord> {
        self.records.values()
    }
    /// Revalidate cached adverts and drop entries that no longer pass admission checks.
    ///
    /// Provider issuance high-water marks are retained so pruning cannot reopen
    /// a replay window for older adverts.
    pub fn prune_stale(&mut self, now: u64) -> usize {
        let mut to_remove = Vec::new();
        for (&fingerprint, record) in &self.records {
            let advert = record.advert();
            let provider_id = advert.body.provider_id;
            let mut drop = advert.validate_with_body(now).is_err();
            if !drop {
                match self.admission.entry(&provider_id) {
                    Some(entry) => {
                        if verify_advert_against_envelope(advert, &entry).is_err() {
                            drop = true;
                        }
                    }
                    None => {
                        drop = true;
                    }
                }
            }
            if drop {
                to_remove.push((fingerprint, provider_id));
            }
        }
        for (fingerprint, provider_id) in &to_remove {
            self.records.remove(fingerprint);
            self.by_provider.remove(provider_id);
        }
        to_remove.len()
    }
}
fn fingerprint(advert: &ProviderAdvertV1) -> Result<[u8; FINGERPRINT_LEN], AdvertError> {
    let bytes = to_bytes(advert)?;
    let digest = blake3_hash(&bytes);
    Ok(digest.into())
}
fn verify_signature(advert: &ProviderAdvertV1) -> Result<(), AdvertError> {
    advert.verify_signature().map_err(|err| match err {
        AdvertSignatureError::UnsupportedAlgorithm(other) => {
            AdvertError::UnsupportedSignature(other)
        }
        other => AdvertError::Signature(other.to_string()),
    })
}
/// Return the canonical capability name used in configuration and responses.
#[must_use]
pub fn capability_name(capability: CapabilityType) -> &'static str {
    match capability {
        CapabilityType::ToriiGateway => "torii_gateway",
        CapabilityType::QuicNoise => "quic_noise",
        CapabilityType::ChunkRangeFetch => "chunk_range_fetch",
        CapabilityType::SoraNetHybridPq => "soranet_pq",
        CapabilityType::PotrMlDsa => "potr_mldsa",
        CapabilityType::RegisteredAccountRead => "registered_account_read",
        CapabilityType::VendorReserved => "vendor_reserved",
    }
}
/// Parse a capability name used in configuration into the corresponding enum value.
#[must_use]
pub fn parse_capability_name(name: &str) -> Option<CapabilityType> {
    match name {
        "torii_gateway" => Some(CapabilityType::ToriiGateway),
        "quic_noise" => Some(CapabilityType::QuicNoise),
        "chunk_range_fetch" => Some(CapabilityType::ChunkRangeFetch),
        "soranet_pq" => Some(CapabilityType::SoraNetHybridPq),
        "potr_mldsa" => Some(CapabilityType::PotrMlDsa),
        "registered_account_read" => Some(CapabilityType::RegisteredAccountRead),
        "vendor_reserved" => Some(CapabilityType::VendorReserved),
        _ => None,
    }
}
fn collect_warnings(advert: &ProviderAdvertV1) -> Vec<AdvertWarning> {
    let mut warnings = Vec::new();
    let has_chunk_range = advert
        .body
        .capabilities
        .iter()
        .any(|cap| cap.cap_type == CapabilityType::ChunkRangeFetch);
    if !has_chunk_range {
        warnings.push(AdvertWarning::ChunkRangeCapability);
    } else {
        if advert.body.stream_budget.is_none() {
            warnings.push(AdvertWarning::StreamBudget);
        }
        if advert
            .body
            .transport_hints
            .as_ref()
            .map_or(true, Vec::is_empty)
        {
            warnings.push(AdvertWarning::TransportHints);
        }
    }
    warnings
}
#[cfg(test)]
mod capability_name_tests {
    use super::*;
    #[test]
    fn capability_names_round_trip_only_the_v1_canonical_labels() {
        let canonical = [
            ("torii_gateway", CapabilityType::ToriiGateway),
            ("quic_noise", CapabilityType::QuicNoise),
            ("chunk_range_fetch", CapabilityType::ChunkRangeFetch),
            ("soranet_pq", CapabilityType::SoraNetHybridPq),
            ("potr_mldsa", CapabilityType::PotrMlDsa),
            ("vendor_reserved", CapabilityType::VendorReserved),
        ];
        for (name, capability) in canonical {
            assert_eq!(parse_capability_name(name), Some(capability));
            assert_eq!(capability_name(capability), name);
        }
        for alias in [
            "torii",
            "quic",
            "range",
            "soranet",
            "soranet-pq",
            "soranet-hybrid-pq",
            "potr-mldsa",
            "vendor",
            "TORII_GATEWAY",
            " torii_gateway",
            "torii_gateway ",
        ] {
            assert_eq!(
                parse_capability_name(alias),
                None,
                "alias {alias:?} must fail"
            );
        }
    }
}
#[cfg(test)]
mod replay_checkpoint_tests {
    use super::*;
    fn private_tempdir() -> tempfile::TempDir {
        // Resolve only the operating system's temporary root. Keep deliberate checkpoint
        // and parent symlinks intact so the no-follow tests exercise the actual boundary.
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        tempfile::tempdir_in(root).expect("private temporary directory")
    }
    fn max_entries(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("test checkpoint capacity is non-zero")
    }
    fn checkpoint_store(path: PathBuf, capacity: usize) -> ReplayCheckpointStore {
        ReplayCheckpointStore::new(path, [0xA1; 32], max_entries(capacity))
            .expect("acquire test replay checkpoint lock")
    }
    fn entry(provider_byte: u8, issued_at: u64) -> ProviderAdvertReplayEntryV1 {
        ProviderAdvertReplayEntryV1 {
            version: REPLAY_CHECKPOINT_VERSION_V1,
            network_id: [0xA1; 32],
            provider_id: [provider_byte; 32],
            issued_at,
            fingerprint: [provider_byte.wrapping_add(1); FINGERPRINT_LEN],
        }
    }
    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write checkpoint fixture");
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set private checkpoint fixture permissions");
    }
    #[test]
    fn checkpoint_rejects_empty_payload() {
        crate::frame_test_support::assert_current_frame(
            &entry(0x42, 7),
            "iroha_torii::sorafs::discovery::ProviderAdvertReplayEntryV1",
        );
        let temp = private_tempdir();
        let path = temp.path().join("replay.to");
        write_private(
            &path,
            &to_bytes(&Vec::<ProviderAdvertReplayEntryV1>::new()).unwrap(),
        );
        let store = checkpoint_store(path, 4);
        assert!(matches!(
            store.load(&AdmissionRegistry::empty([0xA1; 32])),
            Err(ReplayCheckpointError::Empty)
        ));
    }
    #[test]
    fn persistent_cache_rejects_configured_limit_above_hard_bound() {
        let temp = private_tempdir();
        let err = ProviderAdvertCache::new_persistent(
            [],
            Arc::new(AdmissionRegistry::empty([0xA1; 32])),
            temp.path().join("replay.to"),
            max_entries(REPLAY_CHECKPOINT_HARD_MAX_ENTRIES + 1),
        )
        .expect_err("configured limit must remain absolutely bounded");
        assert!(matches!(
            err,
            ReplayCheckpointError::ConfiguredLimitTooLarge {
                configured,
                hard_maximum
            } if configured == REPLAY_CHECKPOINT_HARD_MAX_ENTRIES + 1
                && hard_maximum == REPLAY_CHECKPOINT_HARD_MAX_ENTRIES
        ));
    }
    #[test]
    fn checkpoint_lock_rejects_second_owner_until_first_drops() {
        let temp = private_tempdir();
        let path = temp.path().join("replay.to");
        let first = checkpoint_store(path.clone(), 4);
        assert!(matches!(
            ReplayCheckpointStore::new(path.clone(), [0xA1; 32], max_entries(4)),
            Err(ReplayCheckpointError::LockHeld { path: lock_path })
                if lock_path == path.with_added_extension("lock")
        ));
        drop(first);
        ReplayCheckpointStore::new(path, [0xA1; 32], max_entries(4))
            .expect("dropping first cache releases replay checkpoint lock");
    }
    #[cfg(any(unix, windows))]
    #[test]
    fn checkpoint_lock_refuses_hard_links() {
        let temp = private_tempdir();
        let path = temp.path().join("replay.to");
        let lock_path = path.with_added_extension("lock");
        let alias = temp.path().join("replay.lock.alias");
        write_private(&lock_path, b"");
        fs::hard_link(&lock_path, &alias).expect("hardlink checkpoint lock fixture");

        assert!(matches!(
            ReplayCheckpointStore::new(path, [0xA1; 32], max_entries(4)),
            Err(ReplayCheckpointError::Io { .. })
        ));
    }
    #[test]
    fn checkpoint_preflights_declared_entry_count() {
        let temp = private_tempdir();
        let path = temp.path().join("replay.to");
        write_private(&path, &to_bytes(&vec![entry(1, 10), entry(2, 20)]).unwrap());
        let store = checkpoint_store(path, 1);
        assert!(matches!(
            store.load(&AdmissionRegistry::empty([0xA1; 32])),
            Err(ReplayCheckpointError::TooManyEntries {
                actual: 2,
                maximum: 1
            })
        ));
    }
    #[test]
    fn checkpoint_rejects_oversized_file_before_decode() {
        let temp = private_tempdir();
        let path = temp.path().join("replay.to");
        let store = checkpoint_store(path.clone(), 1);
        let oversized = vec![0u8; usize::try_from(store.maximum_bytes()).unwrap() + 1];
        write_private(&path, &oversized);
        assert!(matches!(
            store.load(&AdmissionRegistry::empty([0xA1; 32])),
            Err(ReplayCheckpointError::TooLarge { actual, maximum })
                if actual == maximum + 1 && maximum == store.maximum_bytes()
        ));
    }
    #[cfg(any(unix, windows))]
    #[test]
    fn checkpoint_read_and_write_refuse_hard_links() {
        let temp = private_tempdir();
        let path = temp.path().join("replay.to");
        let alias = temp.path().join("replay.alias.to");
        let store = checkpoint_store(path.clone(), 4);
        write_private(&path, &to_bytes(&vec![entry(1, 10)]).unwrap());
        fs::hard_link(&path, &alias).expect("hardlink checkpoint fixture");

        assert!(matches!(
            store.load(&AdmissionRegistry::empty([0xA1; 32])),
            Err(ReplayCheckpointError::Io { .. })
        ));
        assert!(matches!(
            store.persist(&HashMap::from([(
                [1; 32],
                AdvertReplayHighWater {
                    issued_at: 10,
                    fingerprint: [2; FINGERPRINT_LEN]
                }
            )])),
            Err(ReplayCheckpointError::Io { .. })
        ));
    }
    #[test]
    fn checkpoint_rejects_unknown_version_before_admission_lookup() {
        let temp = private_tempdir();
        let path = temp.path().join("replay.to");
        let mut unsupported = entry(1, 10);
        unsupported.version = REPLAY_CHECKPOINT_VERSION_V1 + 1;
        write_private(&path, &to_bytes(&vec![unsupported]).unwrap());
        let store = checkpoint_store(path, 4);
        assert!(matches!(
            store.load(&AdmissionRegistry::empty([0xA1; 32])),
            Err(ReplayCheckpointError::UnsupportedVersion { version: 2 })
        ));
    }
    #[test]
    fn checkpoint_rejects_unsorted_and_duplicate_provider_ids() {
        let temp = private_tempdir();
        let store = checkpoint_store(temp.path().join("replay.to"), 4);
        for entries in [
            vec![entry(2, 10), entry(1, 20)],
            vec![entry(1, 10), entry(1, 20)],
        ] {
            write_private(&store.path, &to_bytes(&entries).unwrap());
            assert!(matches!(
                store.load(&AdmissionRegistry::empty([0xA1; 32])),
                Err(ReplayCheckpointError::NonCanonicalOrder)
            ));
        }
    }
    #[test]
    fn checkpoint_rejects_decodable_noncanonical_layout() {
        let temp = private_tempdir();
        let path = temp.path().join("replay.to");
        let entries = vec![entry(1, 10)];
        let canonical = to_bytes(&entries).unwrap();
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let guard = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let alternate = to_bytes(&entries).unwrap();
        drop(guard);
        assert_ne!(
            alternate, canonical,
            "test requires a distinct valid layout"
        );
        write_private(&path, &alternate);
        let store = checkpoint_store(path, 4);
        assert!(matches!(
            store.load(&AdmissionRegistry::empty([0xA1; 32])),
            Err(ReplayCheckpointError::NonCanonicalEncoding)
        ));
    }
    #[test]
    fn checkpoint_rejects_unadmitted_identity() {
        let temp = private_tempdir();
        let path = temp.path().join("replay.to");
        write_private(&path, &to_bytes(&vec![entry(3, 10)]).unwrap());
        let store = checkpoint_store(path, 4);
        assert!(matches!(
            store.load(&AdmissionRegistry::empty([0xA1; 32])),
            Err(ReplayCheckpointError::ProviderNotAdmitted {
                provider_id
            }) if provider_id == [3; 32]
        ));
    }
    #[cfg(unix)]
    #[test]
    fn checkpoint_read_and_write_refuse_symlinks() {
        use std::os::unix::fs::symlink;
        let temp = private_tempdir();
        let external = temp.path().join("external.to");
        let checkpoint = temp.path().join("replay.to");
        let sentinel = b"do not replace";
        write_private(&external, sentinel);
        let store = checkpoint_store(checkpoint.clone(), 4);
        symlink(&external, &checkpoint).expect("create checkpoint symlink after locking");
        assert!(matches!(
            store.load(&AdmissionRegistry::empty([0xA1; 32])),
            Err(ReplayCheckpointError::Io { .. })
        ));
        assert!(matches!(
            store.persist(&HashMap::from([(
                [1; 32],
                AdvertReplayHighWater {
                    issued_at: 10,
                    fingerprint: [2; FINGERPRINT_LEN]
                }
            )])),
            Err(ReplayCheckpointError::Io { .. })
        ));
        assert_eq!(fs::read(external).unwrap(), sentinel);
    }
    #[cfg(unix)]
    #[test]
    fn checkpoint_write_refuses_symlinked_parent() {
        use std::os::unix::fs::symlink;
        let temp = private_tempdir();
        let real_parent = temp.path().join("real-parent");
        let linked_parent = temp.path().join("linked-parent");
        fs::create_dir(&real_parent).expect("create real checkpoint parent");
        symlink(&real_parent, &linked_parent).expect("create parent symlink");
        assert!(matches!(
            ReplayCheckpointStore::new(linked_parent.join("replay.to"), [0xA1; 32], max_entries(4)),
            Err(ReplayCheckpointError::Io { .. })
        ));
        assert!(
            !real_parent.join("replay.to").exists(),
            "symlinked parent must not receive checkpoint data"
        );
    }
    #[cfg(unix)]
    #[test]
    fn checkpoint_rejects_permissive_file_mode() {
        let temp = private_tempdir();
        let path = temp.path().join("replay.to");
        fs::write(&path, to_bytes(&vec![entry(1, 10)]).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let store = checkpoint_store(path, 4);
        assert!(matches!(
            store.load(&AdmissionRegistry::empty([0xA1; 32])),
            Err(ReplayCheckpointError::Io { .. })
        ));
    }
}
