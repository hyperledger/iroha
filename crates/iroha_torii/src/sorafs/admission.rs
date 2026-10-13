//! Finalized native provider admission, with isolated offline envelope verification helpers.
use crate::secure_file_metadata;
use iroha_logger::{trace, warn};
pub use sorafs_manifest::ProviderAdmissionAdvertError;
use sorafs_manifest::{
    AdmissionRecord, ProviderAdmissionCouncilPolicy, ProviderAdmissionEnvelopeError,
    ProviderAdmissionEnvelopeV1, ProviderAdmissionRenewalError, ProviderAdmissionRenewalV1,
    ProviderAdmissionRevocationError, ProviderAdmissionRevocationV1, ProviderAdvertV1,
    verify_advert_against_record,
};
#[cfg(not(windows))]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{
    collections::HashMap,
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
/// Maximum number of admission envelopes loaded from one registry directory.
pub const MAX_ADMISSION_ENVELOPES: usize = 4_096;
/// Maximum canonical Norito size of one admission envelope (1 MiB).
pub const MAX_ADMISSION_ENVELOPE_BYTES: u64 = 1024 * 1024;
/// Admission registry loaded from governance envelopes.
#[derive(Clone)]
pub struct AdmissionRegistry {
    network_id: [u8; 32],
    policy: Option<Arc<ProviderAdmissionCouncilPolicy>>,
    by_provider: HashMap<[u8; 32], Arc<AdmissionRecord>>,
    native_state: Option<Arc<iroha_core::state::State>>,
}
impl std::fmt::Debug for AdmissionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionRegistry")
            .field("network_id", &self.network_id)
            .field("finalized", &self.native_state.is_some())
            .finish_non_exhaustive()
    }
}
impl AdmissionRegistry {
    /// Bind production admission to Torii's exact Core State and durable finalized history.
    /// Local envelope directories and configured council keys cannot authorize this registry.
    #[must_use]
    pub fn from_state(state: Arc<iroha_core::state::State>) -> Self {
        use iroha_core::state::StateReadOnly;
        let network_id = *state.view().network_id().as_bytes();
        Self {
            network_id,
            policy: None,
            by_provider: HashMap::new(),
            native_state: Some(state),
        }
    }
    /// Construct an empty registry (used when admission is optional).
    #[must_use]
    pub fn empty(network_id: [u8; 32]) -> Self {
        Self {
            network_id,
            policy: None,
            by_provider: HashMap::new(),
            native_state: None,
        }
    }
    /// Construct an isolated offline verifier capable of accepting records under `policy`.
    /// Runtime constructors use `from_state` instead.
    #[cfg(test)]
    #[must_use]
    pub fn with_policy(network_id: [u8; 32], policy: ProviderAdmissionCouncilPolicy) -> Self {
        Self {
            network_id,
            policy: Some(Arc::new(policy)),
            by_provider: HashMap::new(),
            native_state: None,
        }
    }
    /// Read the current finalized council policy, or an explicit offline verification policy.
    ///
    /// Empty optional registries have no trust policy and therefore cannot be
    /// used to authorize alias proofs or other governance-signed payloads.
    #[must_use]
    pub fn council_policy(&self) -> Option<Arc<ProviderAdmissionCouncilPolicy>> {
        if let Some(state) = &self.native_state {
            return iroha_core::query::provider_admission::read_finalized_admission_council_v1(
                &state.view(),
            )
            .ok()
            .flatten()
            .map(Arc::new);
        }
        self.policy.clone()
    }
    /// Return the exact genesis network identity enforced for every admitted envelope.
    #[must_use]
    pub fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }
    /// Construct a registry from an iterator of admission envelopes.
    ///
    /// # Errors
    ///
    /// Returns a [`SingleEnvelopeError`] when any envelope is invalid or when
    /// multiple envelopes declare the same provider identifier.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn from_envelopes<I>(
        network_id: [u8; 32],
        policy: ProviderAdmissionCouncilPolicy,
        envelopes: I,
    ) -> Result<Self, SingleEnvelopeError>
    where
        I: IntoIterator<Item = ProviderAdmissionEnvelopeV1>,
    {
        let mut by_provider = HashMap::new();
        for envelope in envelopes {
            let (provider_id, record) = prepare_entry(envelope, &network_id, &policy)?;
            if by_provider.insert(provider_id, Arc::new(record)).is_some() {
                return Err(SingleEnvelopeError::DuplicateProvider { provider_id });
            }
        }
        Ok(Self {
            network_id,
            policy: Some(Arc::new(policy)),
            by_provider,
            native_state: None,
        })
    }
    /// Populate the registry from the provided directory.
    ///
    /// # Errors
    ///
    /// Returns an [`AdmissionRegistryError`] when the directory cannot be read, an envelope fails
    /// to decode, or multiple envelopes declare the same provider identifier.
    pub fn load_from_dir(
        dir: &Path,
        network_id: [u8; 32],
        policy: ProviderAdmissionCouncilPolicy,
    ) -> Result<Self, AdmissionRegistryError> {
        let mut by_provider = HashMap::new();
        let directory_metadata =
            fs::symlink_metadata(dir).map_err(|err| AdmissionRegistryError::DirectoryMetadata {
                dir: dir.into(),
                err,
            })?;
        if directory_metadata.file_type().is_symlink() {
            return Err(AdmissionRegistryError::SymlinkDirectory { dir: dir.into() });
        }
        if !directory_metadata.file_type().is_dir() {
            return Err(AdmissionRegistryError::NotDirectory { dir: dir.into() });
        }
        let read_dir = fs::read_dir(dir).map_err(|err| AdmissionRegistryError::ReadDir {
            dir: dir.into(),
            err,
        })?;
        let mut paths = Vec::new();
        for entry in read_dir {
            let entry = entry.map_err(|err| AdmissionRegistryError::ReadDirEntry {
                dir: dir.into(),
                err,
            })?;
            if paths.len() == MAX_ADMISSION_ENVELOPES.saturating_add(1) {
                return Err(AdmissionRegistryError::TooManyEntries {
                    dir: dir.into(),
                    limit: MAX_ADMISSION_ENVELOPES,
                });
            }
            paths.push(entry.path());
        }
        paths.sort_unstable();
        // Admit the complete bounded inventory before reading or decoding any envelope.
        // Enumeration permits one additional entry for README.md, not another envelope.
        let mut envelope_paths = Vec::new();
        for path in paths {
            if !validate_registry_entry(&path)? {
                continue;
            }
            if envelope_paths.len() == MAX_ADMISSION_ENVELOPES {
                return Err(AdmissionRegistryError::TooManyEntries {
                    dir: dir.into(),
                    limit: MAX_ADMISSION_ENVELOPES,
                });
            }
            envelope_paths.push(path);
        }
        for path in envelope_paths {
            match load_single_envelope(&path, &network_id, &policy) {
                Ok((provider_id, record)) => {
                    trace!(?path, "loaded provider admission envelope");
                    if by_provider.insert(provider_id, Arc::new(record)).is_some() {
                        return Err(AdmissionRegistryError::DuplicateProvider {
                            provider_id,
                            path,
                        });
                    }
                }
                Err(err) => {
                    return Err(AdmissionRegistryError::LoadEnvelope {
                        path,
                        source: Box::new(err),
                    });
                }
            }
        }
        if by_provider.is_empty() {
            warn!(
                ?dir,
                "provider admission registry directory contains no envelopes"
            );
        }
        Ok(Self {
            network_id,
            policy: Some(Arc::new(policy)),
            by_provider,
            native_state: None,
        })
    }
    /// Atomically replace this registry with a freshly loaded trust store and council policy.
    ///
    /// The current registry remains untouched unless every directory entry decodes canonically
    /// and satisfies the replacement policy. This permits deliberate council-key rotation without
    /// exposing a partially reloaded registry.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRegistryError`] on any directory, decoding, canonical-encoding,
    /// signature, trust, quorum, or duplicate-provider failure.
    #[cfg(test)]
    pub fn reload_from_dir(
        &mut self,
        dir: &Path,
        policy: ProviderAdmissionCouncilPolicy,
    ) -> Result<(), AdmissionRegistryError> {
        if self.native_state.is_some() {
            return Err(AdmissionRegistryError::FinalizedAuthority);
        }
        let replacement = Self::load_from_dir(dir, self.network_id, policy)?;
        *self = replacement;
        Ok(())
    }
    /// Register a newly approved envelope under this registry's council policy.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRegistryUpdateError`] when the registry is a deny-all registry without
    /// a trust policy, the envelope is invalid or untrusted, or the provider already exists.
    pub fn register(
        &mut self,
        envelope: ProviderAdmissionEnvelopeV1,
    ) -> Result<(), AdmissionRegistryUpdateError> {
        let policy = self
            .policy
            .as_deref()
            .ok_or(AdmissionRegistryUpdateError::PolicyUnavailable)?;
        let (provider_id, record) = prepare_entry(envelope, &self.network_id, policy)
            .map_err(AdmissionRegistryUpdateError::Envelope)?;
        if self.by_provider.contains_key(&provider_id) {
            return Err(AdmissionRegistryUpdateError::DuplicateProvider { provider_id });
        }
        self.by_provider.insert(provider_id, Arc::new(record));
        Ok(())
    }
    /// Apply a council-approved renewal atomically to an existing provider.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRegistryUpdateError`] when policy is unavailable, the provider is not
    /// admitted, or the renewal fails its chain, invariant, trust, or quorum checks.
    pub fn apply_renewal(
        &mut self,
        renewal: &ProviderAdmissionRenewalV1,
    ) -> Result<(), AdmissionRegistryUpdateError> {
        let policy = self
            .policy
            .as_deref()
            .ok_or(AdmissionRegistryUpdateError::PolicyUnavailable)?;
        let provider_id = *renewal.provider_id();
        let current = self
            .by_provider
            .get(&provider_id)
            .ok_or(AdmissionRegistryUpdateError::UnknownProvider { provider_id })?;
        let updated = current
            .apply_renewal(renewal, policy)
            .map_err(AdmissionRegistryUpdateError::Renewal)?;
        self.by_provider.insert(provider_id, Arc::new(updated));
        Ok(())
    }
    /// Verify and apply a council-approved revocation atomically.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRegistryUpdateError`] when policy is unavailable, the provider is not
    /// admitted, or the revocation fails its binding, trust, or quorum checks.
    pub fn revoke(
        &mut self,
        revocation: &ProviderAdmissionRevocationV1,
    ) -> Result<Arc<AdmissionRecord>, AdmissionRegistryUpdateError> {
        let policy = self
            .policy
            .as_deref()
            .ok_or(AdmissionRegistryUpdateError::PolicyUnavailable)?;
        let provider_id = revocation.provider_id;
        let current = self
            .by_provider
            .get(&provider_id)
            .ok_or(AdmissionRegistryUpdateError::UnknownProvider { provider_id })?;
        current
            .verify_revocation(revocation, policy)
            .map_err(AdmissionRegistryUpdateError::Revocation)?;
        self.by_provider
            .remove(&provider_id)
            .ok_or(AdmissionRegistryUpdateError::UnknownProvider { provider_id })
    }
    /// Look up an admission entry for the given provider identifier.
    #[must_use]
    pub fn entry(&self, provider_id: &[u8; 32]) -> Option<Arc<AdmissionRecord>> {
        if let Some(state) = &self.native_state {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs();
            return iroha_core::query::provider_admission::read_finalized_provider_admission_v1(
                &state.view(),
                iroha_data_model::sorafs::capacity::ProviderId::new(*provider_id),
                now,
            )
            .ok()
            .flatten()
            .map(Arc::new);
        }
        self.by_provider.get(provider_id).cloned()
    }
    /// Return the number of governance-admitted provider identities.
    #[must_use]
    pub fn len(&self) -> usize {
        if let Some(state) = &self.native_state {
            return iroha_core::query::provider_admission::retained_provider_count_v1(&state.view())
                .unwrap_or(MAX_ADMISSION_ENVELOPES as u64) as usize;
        }
        self.by_provider.len()
    }
    /// Return whether the registry contains no governance-admitted providers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the native history retains this identity, including a terminal tombstone.
    /// Replay checkpoints preserve revoked identities so restart cannot reopen old advert windows.
    pub fn retains_identity(&self, provider_id: &[u8; 32]) -> bool {
        if let Some(state) = &self.native_state {
            return iroha_core::query::provider_admission::retains_provider_identity_v1(
                &state.view(),
                iroha_data_model::sorafs::capacity::ProviderId::new(*provider_id),
            )
            .unwrap_or(false);
        }
        self.by_provider.contains_key(provider_id)
    }
}
fn load_single_envelope(
    path: &Path,
    network_id: &[u8; 32],
    policy: &ProviderAdmissionCouncilPolicy,
) -> Result<([u8; 32], AdmissionRecord), SingleEnvelopeError> {
    let bytes = read_bounded_envelope(path)?;
    let envelope = decode_envelope(&bytes).map_err(SingleEnvelopeError::Decode)?;
    let canonical = norito::to_bytes(&envelope)
        .map_err(|source| SingleEnvelopeError::CanonicalEncoding { source })?;
    if canonical != bytes {
        return Err(SingleEnvelopeError::NonCanonicalEncoding);
    }
    prepare_entry(envelope, network_id, policy)
}
fn validate_registry_entry(path: &Path) -> Result<bool, AdmissionRegistryError> {
    let metadata = fs::symlink_metadata(path).map_err(|err| AdmissionRegistryError::Metadata {
        path: path.into(),
        err,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(AdmissionRegistryError::SymlinkEntry { path: path.into() });
    }
    if !metadata.file_type().is_file() {
        return Err(AdmissionRegistryError::NonRegularEntry { path: path.into() });
    }
    if path.file_name().and_then(std::ffi::OsStr::to_str) == Some("README.md") {
        return Ok(false);
    }
    if path.extension().and_then(std::ffi::OsStr::to_str) != Some("to") {
        return Err(AdmissionRegistryError::UnexpectedEntry { path: path.into() });
    }
    Ok(true)
}
fn read_bounded_envelope(path: &Path) -> Result<Vec<u8>, SingleEnvelopeError> {
    let path_metadata = secure_file_metadata::from_path(path)
        .map_err(|err| SingleEnvelopeError::Metadata { err })?;
    if !secure_file_metadata::is_direct_file(&path_metadata)
        || secure_file_metadata::number_of_links(&path_metadata) != Some(1)
    {
        return Err(SingleEnvelopeError::NotRegularFile);
    }
    #[cfg(windows)]
    let mut file = secure_file_metadata::open_direct_file(path)
        .map_err(|err| SingleEnvelopeError::Open { err })?;
    #[cfg(not(windows))]
    let mut file = {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options
            .open(path)
            .map_err(|err| SingleEnvelopeError::Open { err })?
    };
    let opened_metadata = secure_file_metadata::from_file(&file)
        .map_err(|err| SingleEnvelopeError::Metadata { err })?;
    if !secure_file_metadata::is_direct_file(&opened_metadata)
        || secure_file_metadata::number_of_links(&opened_metadata) != Some(1)
    {
        return Err(SingleEnvelopeError::NotRegularFile);
    }
    if opened_metadata.len() > MAX_ADMISSION_ENVELOPE_BYTES {
        return Err(SingleEnvelopeError::TooLarge {
            size: opened_metadata.len(),
            limit: MAX_ADMISSION_ENVELOPE_BYTES,
        });
    }
    if !secure_file_metadata::unchanged(&path_metadata, &opened_metadata) {
        return Err(SingleEnvelopeError::EntryChangedDuringLoad);
    }
    let allocation = usize::try_from(opened_metadata.len())
        .unwrap_or(usize::MAX)
        .min(usize::try_from(MAX_ADMISSION_ENVELOPE_BYTES).unwrap_or(usize::MAX));
    let mut bytes = Vec::with_capacity(allocation);
    file.by_ref()
        .take(MAX_ADMISSION_ENVELOPE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| SingleEnvelopeError::Read { err })?;
    let observed_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if observed_size > MAX_ADMISSION_ENVELOPE_BYTES {
        return Err(SingleEnvelopeError::TooLarge {
            size: observed_size,
            limit: MAX_ADMISSION_ENVELOPE_BYTES,
        });
    }
    let opened_after = secure_file_metadata::from_file(&file)
        .map_err(|err| SingleEnvelopeError::Metadata { err })?;
    let named_after = secure_file_metadata::from_path(path)
        .map_err(|err| SingleEnvelopeError::Metadata { err })?;
    if !secure_file_metadata::is_direct_file(&opened_after)
        || !secure_file_metadata::is_direct_file(&named_after)
        || secure_file_metadata::number_of_links(&opened_after) != Some(1)
        || secure_file_metadata::number_of_links(&named_after) != Some(1)
        || !secure_file_metadata::unchanged(&opened_metadata, &opened_after)
        || !secure_file_metadata::unchanged(&opened_after, &named_after)
        || observed_size != opened_metadata.len()
    {
        return Err(SingleEnvelopeError::EntryChangedDuringLoad);
    }
    Ok(bytes)
}
fn prepare_entry(
    envelope: ProviderAdmissionEnvelopeV1,
    network_id: &[u8; 32],
    policy: &ProviderAdmissionCouncilPolicy,
) -> Result<([u8; 32], AdmissionRecord), SingleEnvelopeError> {
    if envelope.network_id != *network_id {
        return Err(SingleEnvelopeError::NetworkMismatch {
            expected: *network_id,
            provided: envelope.network_id,
        });
    }
    let record = AdmissionRecord::new(envelope, policy).map_err(SingleEnvelopeError::Verify)?;
    let provider_id = *record.provider_id();
    Ok((provider_id, record))
}
/// Verify that the given advert is authorised by the provided admission entry.
///
/// # Errors
///
/// Returns [`ProviderAdmissionAdvertError`] when the advert metadata does not match the admission record.
pub fn verify_advert_against_envelope(
    advert: &ProviderAdvertV1,
    record: &AdmissionRecord,
) -> Result<(), ProviderAdmissionAdvertError> {
    verify_advert_against_record(advert, record)
}
fn decode_envelope(bytes: &[u8]) -> Result<ProviderAdmissionEnvelopeV1, EnvelopeDecodeError> {
    norito::decode_from_bytes(bytes).map_err(EnvelopeDecodeError::Norito)
}
/// Errors raised while constructing the admission registry.
#[derive(Debug, Error)]
pub enum AdmissionRegistryError {
    /// A production registry can change only through finalized Parliament effects.
    #[error("provider admission is governed by finalized native state")]
    FinalizedAuthority,
    /// Inspecting the configured trust-store directory failed.
    #[error("failed to inspect admission directory {dir:?}: {err}")]
    DirectoryMetadata {
        /// Configured registry directory.
        dir: PathBuf,
        /// Underlying I/O error.
        err: std::io::Error,
    },
    /// A symbolic-link root could redirect the complete trust store.
    #[error("provider admission directory {dir:?} must not be a symbolic link")]
    SymlinkDirectory {
        /// Rejected registry directory.
        dir: PathBuf,
    },
    /// The configured trust-store root is not a directory.
    #[error("provider admission path {dir:?} is not a directory")]
    NotDirectory {
        /// Rejected registry path.
        dir: PathBuf,
    },
    /// Reading the admission directory failed.
    #[error("failed to read admission directory {dir:?}: {err}")]
    ReadDir {
        /// Directory whose contents could not be read.
        dir: PathBuf,
        /// Underlying I/O error.
        err: std::io::Error,
    },
    /// Iterating over directory entries failed.
    #[error("failed to list admission directory {dir:?}: {err}")]
    ReadDirEntry {
        /// Directory whose entries could not be enumerated.
        dir: PathBuf,
        /// Underlying I/O error.
        err: std::io::Error,
    },
    /// The directory contains more entries than the bounded startup loader accepts.
    #[error("provider admission directory {dir:?} exceeds the {limit}-entry limit")]
    TooManyEntries {
        /// Registry directory.
        dir: PathBuf,
        /// Configured hard limit.
        limit: usize,
    },
    /// Entry metadata could not be inspected without following links.
    #[error("failed to inspect provider admission entry {path:?}: {err}")]
    Metadata {
        /// Rejected entry path.
        path: PathBuf,
        /// Underlying I/O error.
        err: std::io::Error,
    },
    /// Symbolic links are forbidden in the trust store.
    #[error("provider admission entry {path:?} is a symbolic link")]
    SymlinkEntry {
        /// Rejected entry path.
        path: PathBuf,
    },
    /// Directories, devices, sockets, and other non-regular entries are forbidden.
    #[error("provider admission entry {path:?} is not a regular file")]
    NonRegularEntry {
        /// Rejected entry path.
        path: PathBuf,
    },
    /// Only canonical `.to` envelope files and the documented README may appear in the directory.
    #[error(
        "unexpected provider admission registry entry {path:?}; only .to files and README.md are allowed"
    )]
    UnexpectedEntry {
        /// Rejected entry path.
        path: PathBuf,
    },
    /// A second envelope for the same provider was encountered.
    #[error("duplicate provider admission envelope for {provider_id:?} at {path:?}")]
    DuplicateProvider {
        /// Identifier of the provider with duplicate envelope.
        provider_id: [u8; 32],
        /// Path to the conflicting envelope file.
        path: PathBuf,
    },
    /// Loading or verifying an individual envelope failed.
    #[error("failed to load admission envelope {path:?}: {source}")]
    LoadEnvelope {
        /// Path to the envelope being processed.
        path: PathBuf,
        /// Reason the envelope could not be loaded or verified.
        source: Box<SingleEnvelopeError>,
    },
}
/// Errors raised while mutating an in-memory provider admission registry.
#[derive(Debug, Error)]
pub enum AdmissionRegistryUpdateError {
    /// The registry was created as deny-all and therefore has no trust roots.
    #[error("provider admission council policy is unavailable")]
    PolicyUnavailable,
    /// A new envelope failed structural, cryptographic, trust, or quorum verification.
    #[error("provider admission envelope rejected: {0}")]
    Envelope(SingleEnvelopeError),
    /// A provider cannot be registered twice.
    #[error("duplicate provider admission envelope for {provider_id:02x?}")]
    DuplicateProvider {
        /// Identifier already present in the registry.
        provider_id: [u8; 32],
    },
    /// A renewal or revocation referenced a provider absent from the registry.
    #[error("provider {provider_id:02x?} is not present in the admission registry")]
    UnknownProvider {
        /// Missing provider identifier.
        provider_id: [u8; 32],
    },
    /// A renewal failed its chain, invariant, signature, trust, or quorum checks.
    #[error("provider admission renewal rejected: {0}")]
    Renewal(ProviderAdmissionRenewalError),
    /// A revocation failed its binding, signature, trust, or quorum checks.
    #[error("provider admission revocation rejected: {0}")]
    Revocation(ProviderAdmissionRevocationError),
}
/// Errors emitted while loading a single envelope.
#[derive(Debug, Error)]
pub enum SingleEnvelopeError {
    /// Failed to open the envelope without following symbolic links.
    #[error("failed to open envelope: {err}")]
    Open {
        /// Underlying I/O error.
        err: std::io::Error,
    },
    /// Failed to inspect the opened envelope.
    #[error("failed to inspect opened envelope: {err}")]
    Metadata {
        /// Underlying I/O error.
        err: std::io::Error,
    },
    /// The opened entry was not a regular file.
    #[error("opened envelope is not a regular file")]
    NotRegularFile,
    /// The directory entry was replaced between inspection and opening.
    #[error("provider admission entry changed while it was being loaded")]
    EntryChangedDuringLoad,
    /// The envelope exceeds the bounded startup allocation.
    #[error("provider admission envelope is {size} bytes, exceeding the {limit}-byte limit")]
    TooLarge {
        /// Observed size.
        size: u64,
        /// Hard byte limit.
        limit: u64,
    },
    /// Failed to read the bounded envelope file.
    #[error("failed to read envelope: {err}")]
    Read {
        /// Underlying I/O error.
        err: std::io::Error,
    },
    /// Envelope contents could not be decoded.
    #[error("failed to decode envelope: {0}")]
    Decode(EnvelopeDecodeError),
    /// A decoded envelope could not be encoded canonically.
    #[error("failed to compute canonical envelope encoding: {source}")]
    CanonicalEncoding {
        /// Norito encoding failure.
        source: norito::core::Error,
    },
    /// Input bytes had trailing, alternate, or otherwise non-canonical encoding.
    #[error("provider admission envelope is not canonically encoded")]
    NonCanonicalEncoding,
    /// A signed envelope belongs to a different genesis network.
    #[error(
        "provider admission envelope network {provided:02x?} differs from local network {expected:02x?}"
    )]
    NetworkMismatch {
        /// Network configured by the authoritative local state.
        expected: [u8; 32],
        /// Network committed in the council-signed envelope.
        provided: [u8; 32],
    },
    /// Envelope verification failed.
    #[error("envelope verification failed: {0}")]
    Verify(ProviderAdmissionEnvelopeError),
    /// The envelope duplicates an existing provider identifier.
    #[error("duplicate provider identifier {provider_id:02x?} in admission registry")]
    DuplicateProvider {
        /// Conflicting provider identifier.
        provider_id: [u8; 32],
    },
}
/// Errors that occur while decoding a provider admission envelope.
#[derive(Debug, Error)]
pub enum EnvelopeDecodeError {
    /// Decoding the envelope with the Norito codec failed.
    #[error("failed to decode provider admission envelope: {0}")]
    Norito(#[from] norito::core::Error),
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use sorafs_manifest::{
        CouncilSignature, ProviderAdmissionEnvelopeV1, ProviderAdmissionRenewalV1,
        ProviderAdmissionRevocationV1, ProviderAdmissionSignatureError,
        compute_envelope_authorization_digest,
    };
    use std::{fs::File, path::Path};
    use tempfile::TempDir;
    fn fixture_bytes(name: &str) -> Vec<u8> {
        fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/sorafs_manifest/provider_admission")
                .join(name),
        )
        .expect("read provider admission fixture")
    }
    fn fixture_envelope() -> ProviderAdmissionEnvelopeV1 {
        norito::decode_from_bytes(&fixture_bytes("envelope_v1.to"))
            .expect("decode provider admission fixture")
    }
    fn fixture_policy() -> ProviderAdmissionCouncilPolicy {
        let key = SigningKey::from_bytes(&[0x45; 32]);
        ProviderAdmissionCouncilPolicy::new([*key.verifying_key().as_bytes()], 1)
            .expect("valid fixture policy")
    }
    fn write_fixture(dir: &Path, name: &str) {
        fs::write(dir.join(name), fixture_bytes("envelope_v1.to"))
            .expect("write provider admission fixture");
    }
    #[test]
    fn registry_exposes_only_explicit_council_policy() {
        assert!(
            AdmissionRegistry::empty([0xA1; 32])
                .council_policy()
                .is_none()
        );
        let registry = AdmissionRegistry::with_policy([0xA1; 32], fixture_policy());
        let policy = registry
            .council_policy()
            .expect("explicit registry policy must remain available");
        assert_eq!(policy.trusted_signer_count(), 1);
        assert_eq!(policy.signature_threshold().get(), 1);
    }
    #[test]
    fn registry_loads_canonical_envelope_under_explicit_policy() {
        let temp = TempDir::new().expect("temp directory");
        let envelope = fixture_envelope();
        let policy = fixture_policy();
        write_fixture(temp.path(), "provider.to");
        let registry = AdmissionRegistry::load_from_dir(temp.path(), [0xA1; 32], policy)
            .expect("load registry");
        assert_eq!(registry.len(), 1);
        assert!(registry.entry(&envelope.proposal.provider_id).is_some());
    }
    #[test]
    fn registry_rejects_fully_signed_foreign_network_at_every_entry_point() {
        let envelope = fixture_envelope();
        let policy = fixture_policy();
        assert!(
            AdmissionRecord::new(envelope.clone(), &policy).is_ok(),
            "foreign envelope must otherwise carry valid council signatures"
        );
        let local_network = [0xB3; 32];
        assert!(matches!(
            AdmissionRegistry::from_envelopes(local_network, policy.clone(), [envelope.clone()]),
            Err(SingleEnvelopeError::NetworkMismatch { expected, provided })
                if expected == local_network && provided == envelope.network_id
        ));
        let temp = TempDir::new().expect("temp directory");
        write_fixture(temp.path(), "provider.to");
        assert!(matches!(
            AdmissionRegistry::load_from_dir(temp.path(), local_network, policy.clone()),
            Err(AdmissionRegistryError::LoadEnvelope {
                source,
                ..
            }) if matches!(*source, SingleEnvelopeError::NetworkMismatch { expected, provided }
                if expected == local_network && provided == envelope.network_id)
        ));
        let mut registry = AdmissionRegistry::with_policy(local_network, policy);
        assert!(matches!(
            registry.register(envelope.clone()),
            Err(AdmissionRegistryUpdateError::Envelope(
                SingleEnvelopeError::NetworkMismatch { expected, provided }
            )) if expected == local_network && provided == envelope.network_id
        ));
        assert!(
            registry.is_empty(),
            "foreign registration must not mutate the registry"
        );
    }
    #[test]
    fn registry_rejects_duplicate_and_corrupt_entries_fail_closed() {
        let policy = fixture_policy();
        let duplicates = TempDir::new().expect("temp directory");
        write_fixture(duplicates.path(), "a.to");
        write_fixture(duplicates.path(), "b.to");
        assert!(matches!(
            AdmissionRegistry::load_from_dir(duplicates.path(), [0xA1; 32], policy.clone()),
            Err(AdmissionRegistryError::DuplicateProvider { .. })
        ));
        let corrupt = TempDir::new().expect("temp directory");
        write_fixture(corrupt.path(), "a.to");
        fs::write(corrupt.path().join("b.to"), b"not-norito").expect("write corrupt entry");
        assert!(matches!(
            AdmissionRegistry::load_from_dir(corrupt.path(), [0xA1; 32], policy),
            Err(AdmissionRegistryError::LoadEnvelope { .. })
        ));
    }
    #[test]
    fn registry_rejects_unknown_nonregular_and_oversized_entries() {
        let policy = fixture_policy();
        let unknown = TempDir::new().expect("temp directory");
        fs::write(
            unknown.path().join("unexpected.json"),
            b"ignored trust roots are unsafe",
        )
        .expect("write unknown entry");
        assert!(matches!(
            AdmissionRegistry::load_from_dir(unknown.path(), [0xA1; 32], policy.clone()),
            Err(AdmissionRegistryError::UnexpectedEntry { .. })
        ));
        let nonregular = TempDir::new().expect("temp directory");
        fs::create_dir(nonregular.path().join("nested.to")).expect("create nested directory");
        assert!(matches!(
            AdmissionRegistry::load_from_dir(nonregular.path(), [0xA1; 32], policy.clone()),
            Err(AdmissionRegistryError::NonRegularEntry { .. })
        ));
        let oversized = TempDir::new().expect("temp directory");
        let file = File::create(oversized.path().join("oversized.to")).expect("create envelope");
        file.set_len(MAX_ADMISSION_ENVELOPE_BYTES + 1)
            .expect("extend envelope");
        assert!(matches!(
            AdmissionRegistry::load_from_dir(oversized.path(), [0xA1; 32], policy),
            Err(AdmissionRegistryError::LoadEnvelope {
                source,
                ..
            }) if matches!(*source, SingleEnvelopeError::TooLarge { .. })
        ));
    }
    #[test]
    fn registry_rejects_hard_linked_envelope() {
        let temp = TempDir::new().expect("temp directory");
        let envelope = temp.path().join("provider.to");
        write_fixture(temp.path(), "provider.to");
        fs::hard_link(&envelope, temp.path().join("provider-copy.bin"))
            .expect("create second name for envelope");

        assert!(matches!(
            read_bounded_envelope(&envelope),
            Err(SingleEnvelopeError::NotRegularFile)
        ));
    }
    #[cfg(unix)]
    #[test]
    fn registry_rejects_symlinked_envelope() {
        use std::os::unix::fs::symlink;
        let policy = fixture_policy();
        let temp = TempDir::new().expect("temp directory");
        let target = temp.path().join("target.bin");
        fs::write(&target, fixture_bytes("envelope_v1.to")).expect("write target");
        symlink(&target, temp.path().join("provider.to")).expect("create symlink");
        assert!(matches!(
            AdmissionRegistry::load_from_dir(temp.path(), [0xA1; 32], policy),
            Err(AdmissionRegistryError::SymlinkEntry { .. })
        ));
        let root_parent = TempDir::new().expect("root parent");
        let registry_target = root_parent.path().join("registry-target");
        fs::create_dir(&registry_target).expect("create target directory");
        let registry_link = root_parent.path().join("registry-link");
        symlink(&registry_target, &registry_link).expect("create directory symlink");
        let policy = fixture_policy();
        assert!(matches!(
            AdmissionRegistry::load_from_dir(&registry_link, [0xA1; 32], policy),
            Err(AdmissionRegistryError::SymlinkDirectory { .. })
        ));
    }
    #[test]
    fn registry_bounds_entry_count_before_decoding() {
        let policy = fixture_policy();
        let temp = TempDir::new().expect("temp directory");
        for index in 0..=MAX_ADMISSION_ENVELOPES {
            File::create(temp.path().join(format!("{index:04}.to"))).expect("create entry");
        }
        assert!(matches!(
            AdmissionRegistry::load_from_dir(temp.path(), [0xA1; 32], policy.clone()),
            Err(AdmissionRegistryError::TooManyEntries { .. })
        ));
        fs::write(
            temp.path().join("README.md"),
            b"offline admission inventory",
        )
        .expect("write documented README");
        assert!(matches!(
            AdmissionRegistry::load_from_dir(temp.path(), [0xA1; 32], policy.clone()),
            Err(AdmissionRegistryError::TooManyEntries { .. })
        ));
        fs::remove_file(temp.path().join(format!("{MAX_ADMISSION_ENVELOPES:04}.to")))
            .expect("remove excess envelope");
        assert!(
            matches!(
                AdmissionRegistry::load_from_dir(temp.path(), [0xA1; 32], policy),
                Err(AdmissionRegistryError::LoadEnvelope { .. })
            ),
            "exactly the envelope limit plus README must pass inventory admission before rejecting the malformed envelope"
        );
    }
    #[test]
    fn registry_mutations_require_policy_and_verify_renewal_and_revocation() {
        let envelope = fixture_envelope();
        let policy = fixture_policy();
        let mut deny_all = AdmissionRegistry::empty([0xA1; 32]);
        assert!(matches!(
            deny_all.register(envelope.clone()),
            Err(AdmissionRegistryUpdateError::PolicyUnavailable)
        ));
        let renewal: ProviderAdmissionRenewalV1 =
            norito::decode_from_bytes(&fixture_bytes("renewal_v1.to")).expect("decode renewal");
        let mut renewal_registry =
            AdmissionRegistry::from_envelopes([0xA1; 32], policy.clone(), [envelope.clone()])
                .expect("build registry");
        renewal_registry
            .apply_renewal(&renewal)
            .expect("apply trusted renewal");
        assert_eq!(
            renewal_registry
                .entry(&envelope.proposal.provider_id)
                .expect("renewed entry")
                .envelope_digest(),
            &renewal.envelope_digest
        );
        let revocation: ProviderAdmissionRevocationV1 =
            norito::decode_from_bytes(&fixture_bytes("revocation_v1.to"))
                .expect("decode revocation");
        let mut revocation_registry =
            AdmissionRegistry::from_envelopes([0xA1; 32], policy, [envelope.clone()])
                .expect("build registry");
        revocation_registry
            .revoke(&revocation)
            .expect("apply trusted revocation");
        assert!(revocation_registry.is_empty());
    }
    #[test]
    fn registry_reload_is_atomic_and_supports_explicit_council_rotation() {
        let envelope = fixture_envelope();
        let provider_id = envelope.proposal.provider_id;
        let mut registry =
            AdmissionRegistry::from_envelopes([0xA1; 32], fixture_policy(), [envelope.clone()])
                .expect("build initial registry");
        let initial_digest = *registry
            .entry(&provider_id)
            .expect("initial entry")
            .envelope_digest();
        let replacement = SigningKey::from_bytes(&[0xa6; 32]);
        let rotated_policy =
            ProviderAdmissionCouncilPolicy::new([*replacement.verifying_key().as_bytes()], 1)
                .expect("replacement policy");
        let temp = TempDir::new().expect("temp directory");
        write_fixture(temp.path(), "provider.to");
        let error = registry
            .reload_from_dir(temp.path(), rotated_policy.clone())
            .unwrap_err();
        assert!(matches!(
            error,
            AdmissionRegistryError::LoadEnvelope {
                source,
                ..
            } if matches!(*source, SingleEnvelopeError::Verify(ProviderAdmissionEnvelopeError::Signature(
                    ProviderAdmissionSignatureError::UntrustedSigner { .. }
                )))
        ));
        assert_eq!(
            registry
                .entry(&provider_id)
                .expect("failed reload preserves initial entry")
                .envelope_digest(),
            &initial_digest
        );
        let mut rotated_envelope = envelope;
        rotated_envelope.council_signatures.clear();
        let digest = compute_envelope_authorization_digest(&rotated_envelope)
            .expect("compute rotated authorization digest");
        rotated_envelope.council_signatures.push(CouncilSignature {
            signer: *replacement.verifying_key().as_bytes(),
            signature: replacement.sign(&digest).to_bytes().to_vec(),
        });
        fs::write(
            temp.path().join("provider.to"),
            norito::to_bytes(&rotated_envelope).expect("encode rotated envelope"),
        )
        .expect("write rotated envelope");
        registry
            .reload_from_dir(temp.path(), rotated_policy)
            .expect("reload explicitly rotated trust store");
        let rotated_record = registry.entry(&provider_id).expect("rotated entry");
        assert_eq!(
            rotated_record.envelope().council_signatures[0].signer,
            *replacement.verifying_key().as_bytes()
        );
        assert_ne!(rotated_record.envelope_digest(), &initial_digest);
    }
}
