//! Rollback-resistant encrypted holder custody for Bootle/Lantern issuance.
//!
//! A holder must retain the masking randomness and private attributes after
//! producing `ILQ1`; losing them makes a subsequently returned `ILR1`
//! impossible to finalize.  This module therefore makes durable custody part
//! of the producer API: it publishes an immutable encrypted object, fsyncs it,
//! and advances an externally sealed monotonic manifest before returning any
//! `ILQ1` bytes.  The same state machine caches `ILR1` before finalization and
//! retains only encrypted finalized credentials for later local presentation.
//!
//! Files alone cannot detect restoration of an older, otherwise authentic
//! directory snapshot.  The injected sealed-head provider is consequently a
//! mandatory production dependency, not an optional hardening layer.  It must
//! provide linearizable compare-and-swap and rollback-resistant storage.
#[cfg(test)]
use super::{
    codec::PROOF_BYTES_V1,
    issuer::{
        BootleLanternBlindIssuanceStateV1, BootleLanternCredentialV1,
        BootleLanternIssuanceAuthorizationV1, holder_finalize_blind_issuance_v1,
        holder_prepare_blind_issuance_with_rng_v1,
    },
    scope::BootleLanternCredentialScopeV1,
};
use super::{
    codec::{BLIND_ISSUANCE_REQUEST_BYTES_V1, BLIND_ISSUANCE_RESPONSE_BYTES_V1},
    issuer::{
        BootleLanternBlindIssuanceRequestV1, BootleLanternBlindIssuanceResponseV1,
        BootleLanternIssuanceErrorV1,
    },
    params::{APPLICATION_MODULUS_V1, APPLICATION_RING_DEGREE_V1},
    ring::ApplicationPolynomialV1,
};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead as _, KeyInit as _, Payload},
};
use iroha_data_model::privacy::BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1;
#[cfg(test)]
use iroha_data_model::privacy::{
    BootleLanternIssuerPolicyV1, IrohaBootleLanternAnoncredStatementV1, PrivacyStatementContextV1,
};
#[cfg(test)]
use rand_core_06::{CryptoRng, OsRng, RngCore};
use sha2::{Digest as _, Sha256};
#[cfg(unix)]
use std::io::Read as _;
#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
const HOLDER_ENVELOPE_MAGIC_V1: [u8; 4] = *b"ILV1";
const HOLDER_MANIFEST_MAGIC_V1: [u8; 4] = *b"ILM1";
const HOLDER_PENDING_MAGIC_V1: [u8; 4] = *b"ILP1";
const HOLDER_CACHED_MAGIC_V1: [u8; 4] = *b"ILC1";
const HOLDER_FINALIZED_MAGIC_V1: [u8; 4] = *b"ILF1";
const HOLDER_REJECTED_MAGIC_V1: [u8; 4] = *b"ILX1";
const HOLDER_VERSION_V1: u8 = 1;
const HOLDER_PENDING_TAG_V1: u8 = 0;
const HOLDER_RESPONSE_CACHED_TAG_V1: u8 = 1;
const HOLDER_FINALIZED_TAG_V1: u8 = 2;
const HOLDER_REJECTED_TAG_V1: u8 = 3;
#[cfg(any(unix, test))]
const HOLDER_OBJECTS_DIRECTORY_V1: &str = "objects";
#[cfg(any(unix, test))]
const HOLDER_TEMP_DIRECTORY_V1: &str = ".tmp";
#[cfg(any(unix, test))]
const HOLDER_WRITER_LOCK_FILE_V1: &str = ".writer.lock";
const HOLDER_OBJECT_EXTENSION_V1: &str = ".blh1";
const HOLDER_TEMP_EXTENSION_V1: &str = ".tmp";
const HOLDER_SECRET_HEADER_BYTES_V1: usize = 8;
const HOLDER_BINDING_DIGESTS_V1: usize = 5;
const HOLDER_POLYNOMIAL_BYTES_V1: usize = APPLICATION_RING_DEGREE_V1 * 2;
const HOLDER_RANDOMNESS_POLYNOMIALS_V1: usize = 16;
const HOLDER_CREDENTIAL_POLYNOMIALS_V1: usize = 40;
const HOLDER_ATTRIBUTES_BYTES_V1: usize = BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1 * 8;
const HOLDER_ENVELOPE_HEADER_BYTES_V1: usize = 276;
const HOLDER_MANIFEST_HEADER_BYTES_V1: usize = 84;
const HOLDER_MANIFEST_ENTRY_BYTES_V1: usize = 208;
const HOLDER_MANIFEST_REVISION_BYTES_V1: usize = 32;
const HOLDER_AEAD_TAG_BYTES_V1: usize = 16;
const HOLDER_NONCE_BYTES_V1: usize = 24;
#[cfg(test)]
const HOLDER_DEK_BYTES_V1: usize = 32;
const HOLDER_KEY_ID_MAX_BYTES_V1: usize = 255;
const HOLDER_WRAPPED_DEK_MAX_BYTES_V1: usize = 4_096;
const HOLDER_HARD_MAX_RECORDS_V1: usize = 4_096;
const HOLDER_DEFAULT_MAX_RECORDS_V1: usize = 256;
const HOLDER_ENVELOPE_AAD_DOMAIN_V1: &[u8] = b"iroha.privacy.bootle-lantern.holder-envelope-aad.v1";
const HOLDER_DEK_CONTEXT_DOMAIN_V1: &[u8] = b"iroha.privacy.bootle-lantern.holder-dek-context.v1";
const HOLDER_RESPONSE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.privacy.bootle-lantern.holder-response-digest.v1";
const HOLDER_ENVELOPE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.privacy.bootle-lantern.holder-envelope-digest.v1";
const HOLDER_MANIFEST_REVISION_DOMAIN_V1: &[u8] =
    b"iroha.privacy.bootle-lantern.holder-manifest-revision.v1";
/// Exact plaintext bytes in one pending holder object.
pub const BOOTLE_LANTERN_HOLDER_PENDING_PLAINTEXT_BYTES_V1: usize = HOLDER_SECRET_HEADER_BYTES_V1
    + HOLDER_BINDING_DIGESTS_V1 * 32
    + BLIND_ISSUANCE_REQUEST_BYTES_V1
    + HOLDER_RANDOMNESS_POLYNOMIALS_V1 * HOLDER_POLYNOMIAL_BYTES_V1
    + HOLDER_ATTRIBUTES_BYTES_V1;
/// Exact plaintext bytes after the canonical issuer response is cached.
pub const BOOTLE_LANTERN_HOLDER_CACHED_PLAINTEXT_BYTES_V1: usize =
    BOOTLE_LANTERN_HOLDER_PENDING_PLAINTEXT_BYTES_V1 + BLIND_ISSUANCE_RESPONSE_BYTES_V1;
/// Exact plaintext bytes in one finalized credential object.
pub const BOOTLE_LANTERN_HOLDER_FINALIZED_PLAINTEXT_BYTES_V1: usize = HOLDER_SECRET_HEADER_BYTES_V1
    + HOLDER_BINDING_DIGESTS_V1 * 32
    + HOLDER_CREDENTIAL_POLYNOMIALS_V1 * HOLDER_POLYNOMIAL_BYTES_V1
    + HOLDER_ATTRIBUTES_BYTES_V1;
/// Exact plaintext bytes in a secret-free terminal rejection object.
pub const BOOTLE_LANTERN_HOLDER_REJECTED_PLAINTEXT_BYTES_V1: usize =
    HOLDER_SECRET_HEADER_BYTES_V1 + HOLDER_BINDING_DIGESTS_V1 * 32 + 8;
/// Largest complete encrypted holder object under the fixed public caps.
pub const BOOTLE_LANTERN_HOLDER_MAX_ENVELOPE_BYTES_V1: u64 = (HOLDER_ENVELOPE_HEADER_BYTES_V1
    + HOLDER_KEY_ID_MAX_BYTES_V1
    + HOLDER_WRAPPED_DEK_MAX_BYTES_V1
    + BOOTLE_LANTERN_HOLDER_CACHED_PLAINTEXT_BYTES_V1
    + HOLDER_AEAD_TAG_BYTES_V1) as u64;
/// Largest canonical sealed manifest under the fixed record cap.
pub const BOOTLE_LANTERN_HOLDER_MAX_MANIFEST_BYTES_V1: u64 = (HOLDER_MANIFEST_HEADER_BYTES_V1
    + HOLDER_HARD_MAX_RECORDS_V1 * HOLDER_MANIFEST_ENTRY_BYTES_V1
    + HOLDER_MANIFEST_REVISION_BYTES_V1)
    as u64;
/// Public lifecycle of one holder authorization record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BootleLanternHolderPhaseV1 {
    /// The exact `ILQ1` and its holder state are durable and may be sent.
    Pending,
    /// The exact `ILR1` is durable and will be finalized after reopen.
    ResponseCached,
    /// A reusable credential is durably available for local presentation.
    Finalized,
    /// Holder-owned semantic state was deterministically invalid; no secret
    /// material remains. Untrusted invalid responses never enter this phase.
    Rejected,
}
impl BootleLanternHolderPhaseV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Pending => HOLDER_PENDING_TAG_V1,
            Self::ResponseCached => HOLDER_RESPONSE_CACHED_TAG_V1,
            Self::Finalized => HOLDER_FINALIZED_TAG_V1,
            Self::Rejected => HOLDER_REJECTED_TAG_V1,
        }
    }
    fn from_tag(tag: u8) -> Result<Self, BootleLanternHolderStoreErrorV1> {
        match tag {
            HOLDER_PENDING_TAG_V1 => Ok(Self::Pending),
            HOLDER_RESPONSE_CACHED_TAG_V1 => Ok(Self::ResponseCached),
            HOLDER_FINALIZED_TAG_V1 => Ok(Self::Finalized),
            HOLDER_REJECTED_TAG_V1 => Ok(Self::Rejected),
            _ => Err(BootleLanternHolderStoreErrorV1::Corrupt),
        }
    }
}
/// Non-secret stable handle for one authorization and its eventual credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BootleLanternHolderHandleV1([u8; 32]);
impl BootleLanternHolderHandleV1 {
    /// Construct a handle from the exact non-zero issuance-authorization digest.
    pub fn new(bytes: [u8; 32]) -> Result<Self, BootleLanternHolderStoreErrorV1> {
        if bytes == [0; 32] {
            return Err(BootleLanternHolderStoreErrorV1::InvalidInput);
        }
        Ok(Self(bytes))
    }
    /// Borrow the canonical handle bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
#[cfg(test)]
/// Result released only after pending holder state is durably authoritative.
#[derive(Debug, PartialEq, Eq)]
pub struct BootleLanternPreparedRequestV1 {
    handle: BootleLanternHolderHandleV1,
    request_bytes: Vec<u8>,
}
#[cfg(test)]
impl BootleLanternPreparedRequestV1 {
    /// Stable recovery handle, equal to the authorization digest.
    #[must_use]
    pub const fn handle(&self) -> BootleLanternHolderHandleV1 {
        self.handle
    }
    /// Exact canonical `ILQ1` bytes safe to release to the issuer.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.request_bytes
    }
}
/// Public, non-secret qualification of one runtime custody provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootleLanternHolderProviderQualificationV1 {
    /// Provider contract version; exactly one in the first release.
    pub version: u8,
    /// Non-zero monotonic provider/policy revision.
    pub revision: u64,
    /// Non-zero digest of the exact public provider policy.
    pub policy_digest: [u8; 32],
}
impl BootleLanternHolderProviderQualificationV1 {
    /// Construct the sole first-release qualification.
    #[must_use]
    pub const fn new(revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            version: 1,
            revision,
            policy_digest,
        }
    }
    fn validate(self) -> Result<(), BootleLanternHolderStoreErrorV1> {
        if self.version != 1 || self.revision == 0 || self.policy_digest == [0; 32] {
            return Err(BootleLanternHolderStoreErrorV1::ProviderUnqualified);
        }
        Ok(())
    }
}
/// Payload-free failure class returned across a KMS or sealed-store boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootleLanternHolderExternalErrorV1 {
    /// The provider is temporarily unavailable.
    Unavailable,
    /// The provider definitively rejected the exact request.
    Rejected,
    /// A compare-and-swap may have committed and requires exact readback.
    Ambiguous,
}
/// Runtime-only provider boundary for wrapping per-object data-encryption keys.
pub trait BootleLanternHolderKeyWrapperV1: Send + Sync + core::fmt::Debug {
    /// Opaque, non-secret deployment handle.
    fn handle(&self) -> &str;
    /// Qualify the current provider and public policy revision.
    fn qualification(
        &self,
    ) -> Result<BootleLanternHolderProviderQualificationV1, BootleLanternHolderExternalErrorV1>;
    /// Active non-secret wrapping-key identifier.
    fn active_key_id(&self) -> &str;
    /// Wrap one ephemeral 256-bit DEK under the exact context.
    fn wrap_dek(
        &self,
        context: [u8; 32],
        dek: &[u8; 32],
    ) -> Result<Vec<u8>, BootleLanternHolderExternalErrorV1>;
    /// Unwrap one persisted DEK under the exact context and key identifier.
    fn unwrap_dek(
        &self,
        key_id: &str,
        context: [u8; 32],
        wrapped_dek: &[u8],
    ) -> Result<[u8; 32], BootleLanternHolderExternalErrorV1>;
}
/// Canonical record held by the external sealed monotonic store.
#[derive(Clone, PartialEq, Eq)]
pub struct BootleLanternHolderSealedHeadV1 {
    generation: u64,
    revision: [u8; 32],
    payload: Vec<u8>,
}
impl core::fmt::Debug for BootleLanternHolderSealedHeadV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BootleLanternHolderSealedHeadV1")
            .field("generation", &self.generation)
            .field("revision", &self.revision)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}
impl BootleLanternHolderSealedHeadV1 {
    #[cfg(test)]
    /// Reconstruct a head loaded from the provider's durable representation.
    ///
    /// Full manifest, namespace, and revision validation is performed by the
    /// vault when the provider returns this value. This constructor enforces
    /// the provider-independent allocation and non-zero bounds first.
    pub fn from_canonical_parts_v1(
        generation: u64,
        revision: [u8; 32],
        payload: Vec<u8>,
    ) -> Result<Self, BootleLanternHolderStoreErrorV1> {
        if generation == 0
            || revision == [0; 32]
            || payload.is_empty()
            || payload.len() as u64 > BOOTLE_LANTERN_HOLDER_MAX_MANIFEST_BYTES_V1
        {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
        Ok(Self {
            generation,
            revision,
            payload,
        })
    }
    /// Monotonic manifest generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Deterministic manifest revision used as the CAS token.
    #[must_use]
    pub const fn revision(&self) -> [u8; 32] {
        self.revision
    }
    /// Exact canonical `ILM1` payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}
/// Mandatory rollback-resistant authority for one holder manifest.
pub trait BootleLanternHolderSealedHeadStoreV1: Send + Sync + core::fmt::Debug {
    /// Opaque, non-secret deployment handle.
    fn handle(&self) -> &str;
    /// Qualify the current provider and public policy revision.
    fn qualification(
        &self,
    ) -> Result<BootleLanternHolderProviderQualificationV1, BootleLanternHolderExternalErrorV1>;
    /// Load the latest sealed head for one exact vault namespace.
    fn load_v1(
        &self,
        vault_id: [u8; 32],
    ) -> Result<Option<BootleLanternHolderSealedHeadV1>, BootleLanternHolderExternalErrorV1>;
    /// Atomically replace the exact expected revision with `next`.
    fn compare_and_swap_v1(
        &self,
        vault_id: [u8; 32],
        expected_revision: Option<[u8; 32]>,
        next: BootleLanternHolderSealedHeadV1,
    ) -> Result<(), BootleLanternHolderExternalErrorV1>;
}
/// Validated capacity policy for one holder vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootleLanternHolderStoreConfigV1 {
    max_records: usize,
}
impl BootleLanternHolderStoreConfigV1 {
    /// Construct a bounded holder-vault configuration.
    pub fn new(max_records: usize) -> Result<Self, BootleLanternHolderStoreErrorV1> {
        if max_records == 0 || max_records > HOLDER_HARD_MAX_RECORDS_V1 {
            return Err(BootleLanternHolderStoreErrorV1::ConfigurationInvalid);
        }
        Ok(Self { max_records })
    }
    /// Maximum retained authorizations and credentials.
    #[must_use]
    pub const fn max_records(self) -> usize {
        self.max_records
    }
}
impl Default for BootleLanternHolderStoreConfigV1 {
    fn default() -> Self {
        Self {
            max_records: HOLDER_DEFAULT_MAX_RECORDS_V1,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct HolderManifestEntryV1 {
    authorization_digest: [u8; 32],
    request_digest: [u8; 32],
    scope_digest: [u8; 32],
    policy_record_digest: [u8; 32],
    response_digest: [u8; 32],
    entry_generation: u64,
    phase: BootleLanternHolderPhaseV1,
    envelope_digest: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct HolderManifestV1 {
    vault_id: [u8; 32],
    generation: u64,
    predecessor_revision: [u8; 32],
    entries: BTreeMap<[u8; 32], HolderManifestEntryV1>,
    revision: [u8; 32],
}
impl HolderManifestV1 {
    #[cfg(any(unix, test))]
    fn empty(vault_id: [u8; 32]) -> Result<Self, BootleLanternHolderStoreErrorV1> {
        let mut manifest = Self {
            vault_id,
            generation: 1,
            predecessor_revision: [0; 32],
            entries: BTreeMap::new(),
            revision: [0; 32],
        };
        manifest.revision = manifest_revision_v1(&manifest)?;
        Ok(manifest)
    }
    #[cfg(test)]
    fn successor_with_entry(
        &self,
        entry: HolderManifestEntryV1,
        max_records: usize,
    ) -> Result<Self, BootleLanternHolderStoreErrorV1> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(BootleLanternHolderStoreErrorV1::CapacityExceeded)?;
        if entry.entry_generation != generation {
            return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
        }
        let mut entries = self.entries.clone();
        if !entries.contains_key(&entry.authorization_digest) && entries.len() >= max_records {
            return Err(BootleLanternHolderStoreErrorV1::CapacityExceeded);
        }
        entries.insert(entry.authorization_digest, entry);
        let mut next = Self {
            vault_id: self.vault_id,
            generation,
            predecessor_revision: self.revision,
            entries,
            revision: [0; 32],
        };
        next.revision = manifest_revision_v1(&next)?;
        Ok(next)
    }
    fn sealed_head(
        &self,
    ) -> Result<BootleLanternHolderSealedHeadV1, BootleLanternHolderStoreErrorV1> {
        Ok(BootleLanternHolderSealedHeadV1 {
            generation: self.generation,
            revision: self.revision,
            payload: encode_manifest_v1(self)?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct HolderEnvelopeHeaderV1 {
    phase: BootleLanternHolderPhaseV1,
    vault_id: [u8; 32],
    authorization_digest: [u8; 32],
    request_digest: [u8; 32],
    scope_digest: [u8; 32],
    policy_record_digest: [u8; 32],
    response_digest: [u8; 32],
    predecessor_envelope_digest: [u8; 32],
    entry_generation: u64,
    plaintext_len: u32,
    ciphertext_len: u32,
    key_id_len: u16,
    wrapped_dek_len: u16,
    nonce: [u8; HOLDER_NONCE_BYTES_V1],
}
#[derive(Clone, PartialEq, Eq)]
struct HolderEnvelopeV1 {
    header: HolderEnvelopeHeaderV1,
    wrapping_key_id: String,
    wrapped_dek: Vec<u8>,
    ciphertext: Vec<u8>,
}
impl core::fmt::Debug for HolderEnvelopeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HolderEnvelopeV1")
            .field("phase", &self.header.phase)
            .field("entry_generation", &self.header.entry_generation)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("private_payload", &"<redacted>")
            .finish()
    }
}
struct PendingSecretV1 {
    authorization_digest: [u8; 32],
    request_digest: [u8; 32],
    scope_digest: [u8; 32],
    policy_record_digest: [u8; 32],
    response_digest: [u8; 32],
    request_bytes: Vec<u8>,
    randomness: [ApplicationPolynomialV1; HOLDER_RANDOMNESS_POLYNOMIALS_V1],
    attributes: [[u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1],
    response_bytes: Option<Vec<u8>>,
}
impl core::fmt::Debug for PendingSecretV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PendingSecretV1(<redacted>)")
    }
}
impl Drop for PendingSecretV1 {
    fn drop(&mut self) {
        self.request_bytes.zeroize();
        self.randomness.zeroize();
        self.attributes.zeroize();
        if let Some(response) = &mut self.response_bytes {
            response.zeroize();
        }
        self.request_digest.zeroize();
        self.scope_digest.zeroize();
        self.policy_record_digest.zeroize();
        self.response_digest.zeroize();
    }
}
struct FinalizedSecretV1 {
    authorization_digest: [u8; 32],
    request_digest: [u8; 32],
    scope_digest: [u8; 32],
    policy_record_digest: [u8; 32],
    response_digest: [u8; 32],
    randomness: [ApplicationPolynomialV1; 16],
    tag: [ApplicationPolynomialV1; 8],
    signature_one: [ApplicationPolynomialV1; 8],
    signature_two: [ApplicationPolynomialV1; 8],
    attributes: [[u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1],
}
impl core::fmt::Debug for FinalizedSecretV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FinalizedSecretV1(<redacted>)")
    }
}
impl Drop for FinalizedSecretV1 {
    fn drop(&mut self) {
        self.randomness.zeroize();
        self.tag.zeroize();
        self.signature_one.zeroize();
        self.signature_two.zeroize();
        self.attributes.zeroize();
        self.request_digest.zeroize();
        self.scope_digest.zeroize();
        self.policy_record_digest.zeroize();
        self.response_digest.zeroize();
    }
}
#[derive(Debug)]
struct HolderFileStateV1 {
    manifest: HolderManifestV1,
    poisoned: bool,
}
#[derive(Debug)]
struct HolderDirectoryLeaseV1 {
    canonical_root: PathBuf,
}
impl Drop for HolderDirectoryLeaseV1 {
    fn drop(&mut self) {
        if let Ok(mut roots) = open_holder_roots_v1().lock() {
            roots.remove(&self.canonical_root);
        }
    }
}
/// Encrypted, rollback-resistant native holder vault.
pub struct BootleLanternFileHolderStoreV1 {
    root: PathBuf,
    objects_root: PathBuf,
    temp_root: PathBuf,
    vault_id: [u8; 32],
    config: BootleLanternHolderStoreConfigV1,
    key_wrapper: Arc<dyn BootleLanternHolderKeyWrapperV1>,
    sealed_heads: Arc<dyn BootleLanternHolderSealedHeadStoreV1>,
    key_wrapper_qualification: BootleLanternHolderProviderQualificationV1,
    sealed_head_qualification: BootleLanternHolderProviderQualificationV1,
    state: Mutex<HolderFileStateV1>,
    _lease: HolderDirectoryLeaseV1,
    _writer_lock: File,
    #[cfg(test)]
    fail_next_write_stage: AtomicU8,
}
impl core::fmt::Debug for BootleLanternFileHolderStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BootleLanternFileHolderStoreV1")
            .field("root", &self.root)
            .field("vault_id", &self.vault_id)
            .field("key_wrapper", &"<runtime-only>")
            .field("sealed_heads", &"<runtime-only>")
            .finish_non_exhaustive()
    }
}
impl BootleLanternFileHolderStoreV1 {
    /// Open or create one exclusively owned holder vault.
    ///
    /// # Errors
    ///
    /// Rejects zero identities, unqualified or drifting providers, concurrent
    /// openers, rollback, corrupt or untrusted filesystem entries, missing
    /// authoritative objects, and every persistence failure.
    pub fn open(
        root: impl AsRef<Path>,
        vault_id: [u8; 32],
        config: BootleLanternHolderStoreConfigV1,
        key_wrapper: Arc<dyn BootleLanternHolderKeyWrapperV1>,
        sealed_heads: Arc<dyn BootleLanternHolderSealedHeadStoreV1>,
    ) -> Result<Self, BootleLanternHolderStoreErrorV1> {
        #[cfg(not(unix))]
        {
            let _ = (root, vault_id, config, key_wrapper, sealed_heads);
            return Err(BootleLanternHolderStoreErrorV1::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            if vault_id == [0; 32] || root.as_ref().as_os_str().is_empty() {
                return Err(BootleLanternHolderStoreErrorV1::InvalidInput);
            }
            validate_runtime_handle_v1(key_wrapper.handle())?;
            validate_runtime_handle_v1(sealed_heads.handle())?;
            validate_key_id_v1(key_wrapper.active_key_id())?;
            let key_wrapper_qualification = qualify_key_wrapper_v1(key_wrapper.as_ref())?;
            let sealed_head_qualification = qualify_sealed_heads_v1(sealed_heads.as_ref())?;
            ensure_holder_root_v1(root.as_ref())?;
            let canonical_root = fs::canonicalize(root.as_ref())
                .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
            let lease = acquire_holder_lease_v1(canonical_root.clone())?;
            let writer_lock = acquire_holder_writer_lock_v1(&canonical_root)?;
            let objects_root = canonical_root.join(HOLDER_OBJECTS_DIRECTORY_V1);
            let temp_root = canonical_root.join(HOLDER_TEMP_DIRECTORY_V1);
            ensure_private_subdirectory_v1(&canonical_root, &objects_root)?;
            ensure_private_subdirectory_v1(&canonical_root, &temp_root)?;
            validate_holder_root_namespace_v1(&canonical_root)?;
            clean_holder_temp_v1(&temp_root)?;
            let manifest = load_or_create_manifest_v1(
                vault_id,
                config,
                sealed_heads.as_ref(),
                sealed_head_qualification,
            )?;
            validate_object_namespace_v1(&objects_root, &manifest)?;
            revalidate_provider_v1(
                key_wrapper.as_ref(),
                key_wrapper_qualification,
                sealed_heads.as_ref(),
                sealed_head_qualification,
            )?;
            let store = Self {
                root: canonical_root,
                objects_root,
                temp_root,
                vault_id,
                config,
                key_wrapper,
                sealed_heads,
                key_wrapper_qualification,
                sealed_head_qualification,
                state: Mutex::new(HolderFileStateV1 {
                    manifest,
                    poisoned: false,
                }),
                _lease: lease,
                _writer_lock: writer_lock,
                #[cfg(test)]
                fail_next_write_stage: AtomicU8::new(0),
            };
            store.validate_active_secrets_v1()?;
            drop(store.lock_healthy_state_v1()?);
            Ok(store)
        }
    }
    /// Canonical vault root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Return the authoritative phase of one holder handle.
    pub fn phase_v1(
        &self,
        handle: BootleLanternHolderHandleV1,
    ) -> Result<BootleLanternHolderPhaseV1, BootleLanternHolderStoreErrorV1> {
        self.revalidate_providers_v1()?;
        let state = self.lock_healthy_state_v1()?;
        state
            .manifest
            .entries
            .get(handle.as_bytes())
            .map(|entry| entry.phase)
            .ok_or(BootleLanternHolderStoreErrorV1::NotFound)
    }
    #[cfg(test)]
    /// Prepare and durably retain one holder P1 state before releasing `ILQ1`.
    ///
    /// Repeating the same authorization/context/policy/attributes returns the exact already-durable
    /// request without consuming RNG. Every substituted replay fails closed.
    pub fn prepare_blind_issuance_with_rng_v1<R: CryptoRng + RngCore>(
        &self,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
        authorization: &BootleLanternIssuanceAuthorizationV1,
        attributes: [[u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1],
        rng: &mut R,
    ) -> Result<BootleLanternPreparedRequestV1, BootleLanternHolderStoreErrorV1> {
        self.revalidate_providers_v1()?;
        let handle = BootleLanternHolderHandleV1::new(authorization.authorization_digest())?;
        let scope = BootleLanternCredentialScopeV1::new(context, canonical_genesis_hash, policy)
            .map_err(|_| BootleLanternHolderStoreErrorV1::BindingMismatch)?;
        let scope_digest = scope
            .digest()
            .map_err(|_| BootleLanternHolderStoreErrorV1::BindingMismatch)?;
        let policy_record_digest = *policy.record_digest.as_bytes();
        let mut state = self.lock_healthy_state_v1()?;
        if let Some(existing) = state.manifest.entries.get(handle.as_bytes()).cloned() {
            if existing.scope_digest != scope_digest
                || existing.policy_record_digest != policy_record_digest
            {
                return Err(BootleLanternHolderStoreErrorV1::BindingMismatch);
            }
            if existing.phase != BootleLanternHolderPhaseV1::Pending {
                return Err(BootleLanternHolderStoreErrorV1::InvalidState);
            }
            let pending = self.load_pending_locked_v1(&existing, &scope)?;
            if pending.attributes != attributes || pending.response_bytes.is_some() {
                return Err(BootleLanternHolderStoreErrorV1::BindingMismatch);
            }
            return Ok(BootleLanternPreparedRequestV1 {
                handle,
                request_bytes: pending.request_bytes.clone(),
            });
        }
        if state.manifest.entries.len() >= self.config.max_records {
            return Err(BootleLanternHolderStoreErrorV1::CapacityExceeded);
        }
        let (request, issuance_state) = holder_prepare_blind_issuance_with_rng_v1(
            context,
            canonical_genesis_hash,
            policy,
            authorization,
            attributes,
            rng,
        )
        .map_err(BootleLanternHolderStoreErrorV1::Issuance)?;
        let request_bytes = request
            .encode()
            .map_err(BootleLanternHolderStoreErrorV1::Issuance)?;
        let request_digest = request.request_digest();
        let pending = PendingSecretV1 {
            authorization_digest: *handle.as_bytes(),
            request_digest,
            scope_digest,
            policy_record_digest,
            response_digest: [0; 32],
            request_bytes: request_bytes.clone(),
            randomness: issuance_state.randomness,
            attributes: issuance_state.attributes,
            response_bytes: None,
        };
        let plaintext = encode_pending_secret_v1(&pending)?;
        self.publish_secret_locked_v1(
            &mut state,
            HolderPublishBindingV1 {
                phase: BootleLanternHolderPhaseV1::Pending,
                authorization_digest: *handle.as_bytes(),
                request_digest,
                scope_digest,
                policy_record_digest,
                response_digest: [0; 32],
            },
            [0; 32],
            plaintext.as_slice(),
        )?;
        drop(state);
        self.revalidate_providers_v1()?;
        Ok(BootleLanternPreparedRequestV1 {
            handle,
            request_bytes,
        })
    }
    #[cfg(test)]
    /// Read the exact already-durable `ILQ1` for transport retry.
    pub fn pending_request_v1(
        &self,
        handle: BootleLanternHolderHandleV1,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
    ) -> Result<Vec<u8>, BootleLanternHolderStoreErrorV1> {
        self.revalidate_providers_v1()?;
        let scope = BootleLanternCredentialScopeV1::new(context, canonical_genesis_hash, policy)
            .map_err(|_| BootleLanternHolderStoreErrorV1::BindingMismatch)?;
        let state = self.lock_healthy_state_v1()?;
        let entry = state
            .manifest
            .entries
            .get(handle.as_bytes())
            .ok_or(BootleLanternHolderStoreErrorV1::NotFound)?;
        if !matches!(
            entry.phase,
            BootleLanternHolderPhaseV1::Pending | BootleLanternHolderPhaseV1::ResponseCached
        ) {
            return Err(BootleLanternHolderStoreErrorV1::InvalidState);
        }
        Ok(self
            .load_pending_locked_v1(entry, &scope)?
            .request_bytes
            .clone())
    }
    #[cfg(test)]
    /// Cache one exact, correctly bound `ILR1` before attempting finalization.
    ///
    /// Once this returns, process loss cannot require another issuer response:
    /// [`Self::resume_cached_response_v1`] can complete the transition after reopen. Canonical but
    /// substituted response bindings fail without changing an existing pending record.
    pub fn cache_issuer_response_v1(
        &self,
        handle: BootleLanternHolderHandleV1,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
        response_bytes: &[u8],
    ) -> Result<(), BootleLanternHolderStoreErrorV1> {
        self.revalidate_providers_v1()?;
        if response_bytes.len() != BLIND_ISSUANCE_RESPONSE_BYTES_V1 {
            return Err(BootleLanternHolderStoreErrorV1::ResponseInvalid);
        }
        let response = BootleLanternBlindIssuanceResponseV1::decode_exact(response_bytes)
            .map_err(|_| BootleLanternHolderStoreErrorV1::ResponseInvalid)?;
        let response_digest = response_digest_v1(response_bytes);
        let scope = BootleLanternCredentialScopeV1::new(context, canonical_genesis_hash, policy)
            .map_err(|_| BootleLanternHolderStoreErrorV1::BindingMismatch)?;
        let scope_digest = scope
            .digest()
            .map_err(|_| BootleLanternHolderStoreErrorV1::BindingMismatch)?;
        let mut state = self.lock_healthy_state_v1()?;
        let existing = state
            .manifest
            .entries
            .get(handle.as_bytes())
            .cloned()
            .ok_or(BootleLanternHolderStoreErrorV1::NotFound)?;
        if existing.scope_digest != scope_digest
            || existing.policy_record_digest != *policy.record_digest.as_bytes()
            || response.request_digest_v1() != existing.request_digest
            || response.scope_digest_v1() != existing.scope_digest
            || response.policy_record_digest_v1() != existing.policy_record_digest
        {
            return Err(BootleLanternHolderStoreErrorV1::BindingMismatch);
        }
        match existing.phase {
            BootleLanternHolderPhaseV1::Finalized => {
                if existing.response_digest == response_digest {
                    return Ok(());
                }
                return Err(BootleLanternHolderStoreErrorV1::BindingMismatch);
            }
            BootleLanternHolderPhaseV1::Rejected => {
                return Err(BootleLanternHolderStoreErrorV1::HolderStateTerminal);
            }
            BootleLanternHolderPhaseV1::ResponseCached => {
                if existing.response_digest != response_digest {
                    return Err(BootleLanternHolderStoreErrorV1::BindingMismatch);
                }
            }
            BootleLanternHolderPhaseV1::Pending => {
                let mut pending = self.load_pending_locked_v1(&existing, &scope)?;
                let request = BootleLanternBlindIssuanceRequestV1::decode_exact(
                    &pending.request_bytes,
                    u32::try_from(BLIND_ISSUANCE_REQUEST_BYTES_V1)
                        .expect("fixed ILQ1 length fits u32"),
                )
                .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
                if request.request_digest() != existing.request_digest {
                    return Err(BootleLanternHolderStoreErrorV1::Corrupt);
                }
                pending.response_digest = response_digest;
                pending.response_bytes = Some(response_bytes.to_vec());
                let plaintext = encode_pending_secret_v1(&pending)?;
                self.publish_secret_locked_v1(
                    &mut state,
                    HolderPublishBindingV1 {
                        phase: BootleLanternHolderPhaseV1::ResponseCached,
                        authorization_digest: *handle.as_bytes(),
                        request_digest: existing.request_digest,
                        scope_digest,
                        policy_record_digest: existing.policy_record_digest,
                        response_digest,
                    },
                    existing.envelope_digest,
                    plaintext.as_slice(),
                )?;
            }
        }
        drop(response);
        self.ensure_manifest_authoritative_v1(&state.manifest)?;
        drop(state);
        self.revalidate_providers_v1()
    }
    #[cfg(test)]
    /// Cache one exact `ILR1`, then finalize and durably retain its credential.
    ///
    /// The cache transition commits independently first, so a crash cannot
    /// lose the response. Cryptographic rejection then durably discards only
    /// that untrusted response and restores the original pending state.
    pub fn accept_issuer_response_v1(
        &self,
        handle: BootleLanternHolderHandleV1,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
        response_bytes: &[u8],
    ) -> Result<(), BootleLanternHolderStoreErrorV1> {
        self.cache_issuer_response_v1(
            handle,
            context,
            canonical_genesis_hash,
            policy,
            response_bytes,
        )?;
        self.resume_cached_response_v1(handle, context, canonical_genesis_hash, policy)
    }
    #[cfg(test)]
    /// Finalize an already cached response after process restart.
    ///
    /// A correctly bound but cryptographically invalid untrusted response is
    /// removed by a durable transition back to `Pending`; the original ILQ1
    /// state remains usable with a later legitimate response.
    pub fn resume_cached_response_v1(
        &self,
        handle: BootleLanternHolderHandleV1,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
    ) -> Result<(), BootleLanternHolderStoreErrorV1> {
        self.revalidate_providers_v1()?;
        let scope = BootleLanternCredentialScopeV1::new(context, canonical_genesis_hash, policy)
            .map_err(|_| BootleLanternHolderStoreErrorV1::BindingMismatch)?;
        let mut state = self.lock_healthy_state_v1()?;
        self.finalize_cached_locked_v1(
            &mut state,
            handle,
            context,
            canonical_genesis_hash,
            policy,
            &scope,
        )
    }
    #[cfg(test)]
    /// Produce one complete presentation while keeping credential material local.
    pub fn prove_presentation_encoded_with_rng_v1<R: CryptoRng + RngCore>(
        &self,
        handle: BootleLanternHolderHandleV1,
        statement: &IrohaBootleLanternAnoncredStatementV1,
        policy: &BootleLanternIssuerPolicyV1,
        canonical_genesis_hash: [u8; 32],
        rng: &mut R,
    ) -> Result<Vec<u8>, BootleLanternHolderStoreErrorV1> {
        self.revalidate_providers_v1()?;
        let scope =
            BootleLanternCredentialScopeV1::new(&statement.context, canonical_genesis_hash, policy)
                .map_err(|_| BootleLanternHolderStoreErrorV1::BindingMismatch)?;
        let state = self.lock_healthy_state_v1()?;
        let entry = state
            .manifest
            .entries
            .get(handle.as_bytes())
            .ok_or(BootleLanternHolderStoreErrorV1::NotFound)?;
        if entry.phase != BootleLanternHolderPhaseV1::Finalized {
            return Err(BootleLanternHolderStoreErrorV1::InvalidState);
        }
        let secret = self.load_finalized_locked_v1(entry, &scope)?;
        let credential = BootleLanternCredentialV1 {
            randomness: secret.randomness,
            tag: secret.tag,
            signature_one: secret.signature_one,
            signature_two: secret.signature_two,
            attributes: secret.attributes,
            scope,
        };
        let witness = credential
            .presentation_witness_v1(statement, policy, canonical_genesis_hash)
            .map_err(BootleLanternHolderStoreErrorV1::Issuance)?;
        let proof = super::prove_bound_presentation_v1(
            statement,
            policy,
            canonical_genesis_hash,
            &witness,
            rng,
        )
        .map_err(|_| BootleLanternHolderStoreErrorV1::PresentationFailed)?;
        let bytes = proof.encode();
        if bytes.len() != PROOF_BYTES_V1 {
            return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
        }
        drop(witness);
        drop(credential);
        drop(secret);
        self.ensure_manifest_authoritative_v1(&state.manifest)?;
        drop(state);
        self.revalidate_providers_v1()?;
        Ok(bytes)
    }
    #[cfg(test)]
    fn finalize_cached_locked_v1(
        &self,
        state: &mut HolderFileStateV1,
        handle: BootleLanternHolderHandleV1,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
        scope: &BootleLanternCredentialScopeV1,
    ) -> Result<(), BootleLanternHolderStoreErrorV1> {
        let existing = state
            .manifest
            .entries
            .get(handle.as_bytes())
            .cloned()
            .ok_or(BootleLanternHolderStoreErrorV1::NotFound)?;
        match existing.phase {
            BootleLanternHolderPhaseV1::Finalized => return Ok(()),
            BootleLanternHolderPhaseV1::Rejected => {
                return Err(BootleLanternHolderStoreErrorV1::HolderStateTerminal);
            }
            BootleLanternHolderPhaseV1::Pending => {
                return Err(BootleLanternHolderStoreErrorV1::InvalidState);
            }
            BootleLanternHolderPhaseV1::ResponseCached => {}
        }
        if existing.scope_digest
            != scope
                .digest()
                .map_err(|_| BootleLanternHolderStoreErrorV1::BindingMismatch)?
            || existing.policy_record_digest != *policy.record_digest.as_bytes()
        {
            return Err(BootleLanternHolderStoreErrorV1::BindingMismatch);
        }
        let mut pending = self.load_pending_locked_v1(&existing, scope)?;
        let response_bytes = pending
            .response_bytes
            .take()
            .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
        if response_digest_v1(&response_bytes) != existing.response_digest {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
        let response = BootleLanternBlindIssuanceResponseV1::decode_exact(&response_bytes)
            .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
        let holder_state = BootleLanternBlindIssuanceStateV1 {
            randomness: pending.randomness,
            attributes: pending.attributes,
            request_digest: pending.request_digest,
            scope: scope.clone(),
        };
        let credential = match holder_finalize_blind_issuance_v1(
            holder_state,
            context,
            canonical_genesis_hash,
            policy,
            response,
        ) {
            Ok(credential) => credential,
            Err(
                BootleLanternIssuanceErrorV1::IssuanceResponseMismatch
                | BootleLanternIssuanceErrorV1::CredentialValidationFailed,
            ) => {
                pending.response_digest = [0; 32];
                let restored = encode_pending_secret_v1(&pending)?;
                self.publish_secret_locked_v1(
                    state,
                    HolderPublishBindingV1 {
                        phase: BootleLanternHolderPhaseV1::Pending,
                        authorization_digest: existing.authorization_digest,
                        request_digest: existing.request_digest,
                        scope_digest: existing.scope_digest,
                        policy_record_digest: existing.policy_record_digest,
                        response_digest: [0; 32],
                    },
                    existing.envelope_digest,
                    restored.as_slice(),
                )?;
                return Err(BootleLanternHolderStoreErrorV1::CredentialRejected);
            }
            Err(_) => {
                let rejected = encode_rejected_secret_v1(
                    existing.authorization_digest,
                    existing.request_digest,
                    existing.scope_digest,
                    existing.policy_record_digest,
                    existing.response_digest,
                    1,
                )?;
                self.publish_secret_locked_v1(
                    state,
                    HolderPublishBindingV1 {
                        phase: BootleLanternHolderPhaseV1::Rejected,
                        authorization_digest: existing.authorization_digest,
                        request_digest: existing.request_digest,
                        scope_digest: existing.scope_digest,
                        policy_record_digest: existing.policy_record_digest,
                        response_digest: existing.response_digest,
                    },
                    existing.envelope_digest,
                    rejected.as_slice(),
                )?;
                return Err(BootleLanternHolderStoreErrorV1::HolderStateTerminal);
            }
        };
        let finalized = FinalizedSecretV1 {
            authorization_digest: existing.authorization_digest,
            request_digest: existing.request_digest,
            scope_digest: existing.scope_digest,
            policy_record_digest: existing.policy_record_digest,
            response_digest: existing.response_digest,
            randomness: credential.randomness,
            tag: credential.tag,
            signature_one: credential.signature_one,
            signature_two: credential.signature_two,
            attributes: credential.attributes,
        };
        let plaintext = encode_finalized_secret_v1(&finalized)?;
        self.publish_secret_locked_v1(
            state,
            HolderPublishBindingV1 {
                phase: BootleLanternHolderPhaseV1::Finalized,
                authorization_digest: existing.authorization_digest,
                request_digest: existing.request_digest,
                scope_digest: existing.scope_digest,
                policy_record_digest: existing.policy_record_digest,
                response_digest: existing.response_digest,
            },
            existing.envelope_digest,
            plaintext.as_slice(),
        )?;
        self.revalidate_providers_v1()
    }
    #[cfg(test)]
    fn load_pending_locked_v1(
        &self,
        entry: &HolderManifestEntryV1,
        scope: &BootleLanternCredentialScopeV1,
    ) -> Result<PendingSecretV1, BootleLanternHolderStoreErrorV1> {
        if entry.scope_digest
            != scope
                .digest()
                .map_err(|_| BootleLanternHolderStoreErrorV1::BindingMismatch)?
        {
            return Err(BootleLanternHolderStoreErrorV1::BindingMismatch);
        }
        let plaintext = self.load_plaintext_v1(entry)?;
        let pending = decode_pending_secret_v1(entry.phase, plaintext.as_slice())?;
        validate_pending_against_entry_v1(&pending, entry)?;
        Ok(pending)
    }
    #[cfg(any(unix, test))]
    fn validate_active_secrets_v1(&self) -> Result<(), BootleLanternHolderStoreErrorV1> {
        let state = self
            .state
            .lock()
            .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        for entry in state.manifest.entries.values() {
            let plaintext = self.load_plaintext_v1(entry)?;
            match entry.phase {
                BootleLanternHolderPhaseV1::Pending
                | BootleLanternHolderPhaseV1::ResponseCached => {
                    let pending = decode_pending_secret_v1(entry.phase, plaintext.as_slice())?;
                    validate_pending_against_entry_v1(&pending, entry)?;
                }
                BootleLanternHolderPhaseV1::Finalized => {
                    let finalized = decode_finalized_secret_v1(plaintext.as_slice())?;
                    validate_finalized_against_entry_v1(&finalized, entry)?;
                }
                BootleLanternHolderPhaseV1::Rejected => {
                    if decode_rejected_secret_v1(plaintext.as_slice())?
                        != entry_binding_digests_v1(entry)
                    {
                        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
                    }
                }
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn load_finalized_locked_v1(
        &self,
        entry: &HolderManifestEntryV1,
        scope: &BootleLanternCredentialScopeV1,
    ) -> Result<FinalizedSecretV1, BootleLanternHolderStoreErrorV1> {
        if entry.scope_digest
            != scope
                .digest()
                .map_err(|_| BootleLanternHolderStoreErrorV1::BindingMismatch)?
        {
            return Err(BootleLanternHolderStoreErrorV1::BindingMismatch);
        }
        let plaintext = self.load_plaintext_v1(entry)?;
        let finalized = decode_finalized_secret_v1(plaintext.as_slice())?;
        validate_finalized_against_entry_v1(&finalized, entry)?;
        Ok(finalized)
    }
    fn load_plaintext_v1(
        &self,
        entry: &HolderManifestEntryV1,
    ) -> Result<Zeroizing<Vec<u8>>, BootleLanternHolderStoreErrorV1> {
        let bytes = read_object_v1(&self.objects_root, entry.envelope_digest)?;
        if envelope_digest_v1(&bytes) != entry.envelope_digest {
            return Err(BootleLanternHolderStoreErrorV1::RollbackDetected);
        }
        let envelope = decode_envelope_v1(&bytes)?;
        validate_envelope_against_entry_v1(&envelope, self.vault_id, entry)?;
        let context = envelope_dek_context_v1(&envelope.header);
        let before = qualify_key_wrapper_v1(self.key_wrapper.as_ref())?;
        if before != self.key_wrapper_qualification {
            return Err(BootleLanternHolderStoreErrorV1::ProviderDrift);
        }
        let dek = self
            .key_wrapper
            .unwrap_dek(&envelope.wrapping_key_id, context, &envelope.wrapped_dek)
            .map_err(map_key_wrapper_operation_error_v1)?;
        let dek = Zeroizing::new(dek);
        if dek.iter().all(|byte| *byte == 0) {
            return Err(BootleLanternHolderStoreErrorV1::KeyWrapping);
        }
        let after = qualify_key_wrapper_v1(self.key_wrapper.as_ref())?;
        if after != before {
            return Err(BootleLanternHolderStoreErrorV1::ProviderDrift);
        }
        let aad = envelope_aad_v1(&envelope)?;
        let cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice())
            .map_err(|_| BootleLanternHolderStoreErrorV1::Encryption)?;
        let nonce: chacha20poly1305::XNonce = envelope.header.nonce.into();
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| BootleLanternHolderStoreErrorV1::Authentication)?;
        if plaintext.len()
            != usize::try_from(envelope.header.plaintext_len)
                .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?
        {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
        Ok(Zeroizing::new(plaintext))
    }
    #[cfg(test)]
    fn publish_secret_locked_v1(
        &self,
        state: &mut HolderFileStateV1,
        binding: HolderPublishBindingV1,
        predecessor_envelope_digest: [u8; 32],
        plaintext: &[u8],
    ) -> Result<(), BootleLanternHolderStoreErrorV1> {
        ensure_state_healthy_v1(state)?;
        validate_publish_plaintext_v1(binding, plaintext)?;
        if let Err(error) = self.revalidate_providers_v1() {
            poison_on_integrity_error_v1(state, &error);
            return Err(error);
        }
        if let Err(error) = self.ensure_manifest_authoritative_v1(&state.manifest) {
            poison_on_integrity_error_v1(state, &error);
            return Err(error);
        }
        let entry_generation = state
            .manifest
            .generation
            .checked_add(1)
            .ok_or(BootleLanternHolderStoreErrorV1::CapacityExceeded)?;
        let envelope = match self.encrypt_envelope_v1(
            binding,
            predecessor_envelope_digest,
            entry_generation,
            plaintext,
        ) {
            Ok(envelope) => envelope,
            Err(error) => {
                poison_on_integrity_error_v1(state, &error);
                return Err(error);
            }
        };
        let envelope_bytes = encode_envelope_v1(&envelope)?;
        let envelope_digest = envelope_digest_v1(&envelope_bytes);
        if let Err(error) = self.persist_immutable_object_v1(envelope_digest, &envelope_bytes) {
            if error == BootleLanternHolderStoreErrorV1::DurabilityUncertain {
                state.poisoned = true;
            }
            return Err(error);
        }
        let entry = HolderManifestEntryV1 {
            authorization_digest: binding.authorization_digest,
            request_digest: binding.request_digest,
            scope_digest: binding.scope_digest,
            policy_record_digest: binding.policy_record_digest,
            response_digest: binding.response_digest,
            entry_generation,
            phase: binding.phase,
            envelope_digest,
        };
        let readback = match self.load_plaintext_v1(&entry) {
            Ok(readback) => readback,
            Err(error) => {
                self.cleanup_superseded_object_v1(envelope_digest, &state.manifest);
                poison_on_integrity_error_v1(state, &error);
                return Err(error);
            }
        };
        if readback.as_slice() != plaintext {
            self.cleanup_superseded_object_v1(envelope_digest, &state.manifest);
            state.poisoned = true;
            return Err(BootleLanternHolderStoreErrorV1::DurabilityUncertain);
        }
        let next = match state
            .manifest
            .successor_with_entry(entry, self.config.max_records)
        {
            Ok(next) => next,
            Err(error) => {
                self.cleanup_superseded_object_v1(envelope_digest, &state.manifest);
                return Err(error);
            }
        };
        match publish_manifest_v1(
            self.vault_id,
            &state.manifest,
            &next,
            self.sealed_heads.as_ref(),
            self.sealed_head_qualification,
        ) {
            Ok(()) => {
                state.manifest = next;
                self.cleanup_superseded_object_v1(predecessor_envelope_digest, &state.manifest);
                Ok(())
            }
            Err(
                error @ (BootleLanternHolderStoreErrorV1::DurabilityUncertain
                | BootleLanternHolderStoreErrorV1::ProviderDrift
                | BootleLanternHolderStoreErrorV1::RollbackDetected),
            ) => {
                state.poisoned = true;
                Err(error)
            }
            Err(error) => {
                self.cleanup_superseded_object_v1(envelope_digest, &state.manifest);
                Err(error)
            }
        }
    }
    #[cfg(test)]
    fn encrypt_envelope_v1(
        &self,
        binding: HolderPublishBindingV1,
        predecessor_envelope_digest: [u8; 32],
        entry_generation: u64,
        plaintext: &[u8],
    ) -> Result<HolderEnvelopeV1, BootleLanternHolderStoreErrorV1> {
        validate_plaintext_length_v1(binding.phase, plaintext.len())?;
        let key_id = self.key_wrapper.active_key_id().to_owned();
        validate_key_id_v1(&key_id)?;
        let before = qualify_key_wrapper_v1(self.key_wrapper.as_ref())?;
        if before != self.key_wrapper_qualification {
            return Err(BootleLanternHolderStoreErrorV1::ProviderDrift);
        }
        let mut entropy = Zeroizing::new([0_u8; HOLDER_DEK_BYTES_V1 + HOLDER_NONCE_BYTES_V1]);
        OsRng
            .try_fill_bytes(entropy.as_mut())
            .map_err(|_| BootleLanternHolderStoreErrorV1::RandomnessUnavailable)?;
        if entropy[..HOLDER_DEK_BYTES_V1]
            .iter()
            .all(|byte| *byte == entropy[0])
            || entropy[HOLDER_DEK_BYTES_V1..]
                .iter()
                .all(|byte| *byte == entropy[HOLDER_DEK_BYTES_V1])
            || entropy[..HOLDER_NONCE_BYTES_V1]
                == entropy[HOLDER_DEK_BYTES_V1..HOLDER_DEK_BYTES_V1 + HOLDER_NONCE_BYTES_V1]
        {
            return Err(BootleLanternHolderStoreErrorV1::RandomnessUnavailable);
        }
        let mut dek = Zeroizing::new([0_u8; HOLDER_DEK_BYTES_V1]);
        dek.copy_from_slice(&entropy[..HOLDER_DEK_BYTES_V1]);
        let mut nonce = [0_u8; HOLDER_NONCE_BYTES_V1];
        nonce.copy_from_slice(&entropy[HOLDER_DEK_BYTES_V1..]);
        let plaintext_len = u32::try_from(plaintext.len())
            .map_err(|_| BootleLanternHolderStoreErrorV1::InternalInvariant)?;
        let ciphertext_len = plaintext_len
            .checked_add(
                u32::try_from(HOLDER_AEAD_TAG_BYTES_V1).expect("fixed AEAD tag length fits u32"),
            )
            .ok_or(BootleLanternHolderStoreErrorV1::InternalInvariant)?;
        let key_id_len = u16::try_from(key_id.len())
            .map_err(|_| BootleLanternHolderStoreErrorV1::KeyWrapping)?;
        let provisional = HolderEnvelopeHeaderV1 {
            phase: binding.phase,
            vault_id: self.vault_id,
            authorization_digest: binding.authorization_digest,
            request_digest: binding.request_digest,
            scope_digest: binding.scope_digest,
            policy_record_digest: binding.policy_record_digest,
            response_digest: binding.response_digest,
            predecessor_envelope_digest,
            entry_generation,
            plaintext_len,
            ciphertext_len,
            key_id_len,
            wrapped_dek_len: 0,
            nonce,
        };
        let context = envelope_dek_context_v1(&provisional);
        let wrapped_dek = self
            .key_wrapper
            .wrap_dek(context, &dek)
            .map_err(map_key_wrapper_operation_error_v1)?;
        if wrapped_dek.is_empty() || wrapped_dek.len() > HOLDER_WRAPPED_DEK_MAX_BYTES_V1 {
            return Err(BootleLanternHolderStoreErrorV1::KeyWrapping);
        }
        if self.key_wrapper.active_key_id() != key_id {
            return Err(BootleLanternHolderStoreErrorV1::ProviderDrift);
        }
        let after = qualify_key_wrapper_v1(self.key_wrapper.as_ref())?;
        if after != before {
            return Err(BootleLanternHolderStoreErrorV1::ProviderDrift);
        }
        let header = HolderEnvelopeHeaderV1 {
            wrapped_dek_len: u16::try_from(wrapped_dek.len())
                .map_err(|_| BootleLanternHolderStoreErrorV1::KeyWrapping)?,
            ..provisional
        };
        let mut envelope = HolderEnvelopeV1 {
            header,
            wrapping_key_id: key_id,
            wrapped_dek,
            ciphertext: Vec::new(),
        };
        let aad = envelope_aad_v1(&envelope)?;
        let cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice())
            .map_err(|_| BootleLanternHolderStoreErrorV1::Encryption)?;
        let nonce: chacha20poly1305::XNonce = envelope.header.nonce.into();
        envelope.ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| BootleLanternHolderStoreErrorV1::Encryption)?;
        if envelope.ciphertext.len()
            != usize::try_from(envelope.header.ciphertext_len)
                .map_err(|_| BootleLanternHolderStoreErrorV1::InternalInvariant)?
        {
            return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
        }
        Ok(envelope)
    }
    #[cfg(test)]
    fn persist_immutable_object_v1(
        &self,
        digest: [u8; 32],
        bytes: &[u8],
    ) -> Result<(), BootleLanternHolderStoreErrorV1> {
        let file_name = holder_object_file_name_v1(digest);
        let target = self.objects_root.join(&file_name);
        let temp = self
            .temp_root
            .join(format!("{file_name}{HOLDER_TEMP_EXTENSION_V1}"));
        reject_existing_holder_path_v1(&target)?;
        reject_existing_holder_path_v1(&temp)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        }
        if file.write_all(bytes).is_err() || file.sync_all().is_err() {
            drop(file);
            let _ = fs::remove_file(&temp);
            return Err(BootleLanternHolderStoreErrorV1::Backend);
        }
        drop(file);
        #[cfg(test)]
        let failure = self.fail_next_write_stage.swap(0, Ordering::SeqCst);
        #[cfg(test)]
        if failure == 1 {
            let _ = fs::remove_file(&temp);
            return Err(BootleLanternHolderStoreErrorV1::Backend);
        }
        if fs::rename(&temp, &target).is_err() {
            let _ = fs::remove_file(&temp);
            return Err(BootleLanternHolderStoreErrorV1::Backend);
        }
        #[cfg(test)]
        if failure == 2 {
            return Err(BootleLanternHolderStoreErrorV1::DurabilityUncertain);
        }
        sync_directory_v1(&self.objects_root)
            .map_err(|_| BootleLanternHolderStoreErrorV1::DurabilityUncertain)?;
        sync_directory_v1(&self.temp_root)
            .map_err(|_| BootleLanternHolderStoreErrorV1::DurabilityUncertain)
    }
    #[cfg(test)]
    fn cleanup_superseded_object_v1(&self, digest: [u8; 32], manifest: &HolderManifestV1) {
        if digest == [0; 32]
            || manifest
                .entries
                .values()
                .any(|entry| entry.envelope_digest == digest)
        {
            return;
        }
        let path = self.objects_root.join(holder_object_file_name_v1(digest));
        if fs::remove_file(path).is_ok() {
            let _ = sync_directory_v1(&self.objects_root);
        }
    }
    fn lock_healthy_state_v1(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HolderFileStateV1>, BootleLanternHolderStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        ensure_state_healthy_v1(&state)?;
        if let Err(error) = self.ensure_manifest_authoritative_v1(&state.manifest) {
            if matches!(
                error,
                BootleLanternHolderStoreErrorV1::DurabilityUncertain
                    | BootleLanternHolderStoreErrorV1::ProviderDrift
                    | BootleLanternHolderStoreErrorV1::RollbackDetected
            ) {
                state.poisoned = true;
            }
            return Err(error);
        }
        Ok(state)
    }
    fn ensure_manifest_authoritative_v1(
        &self,
        manifest: &HolderManifestV1,
    ) -> Result<(), BootleLanternHolderStoreErrorV1> {
        ensure_sealed_qualification_v1(self.sealed_heads.as_ref(), self.sealed_head_qualification)?;
        let authoritative = self
            .sealed_heads
            .load_v1(self.vault_id)
            .map_err(map_external_provider_error_v1)?
            .ok_or(BootleLanternHolderStoreErrorV1::RollbackDetected)?;
        ensure_sealed_qualification_v1(self.sealed_heads.as_ref(), self.sealed_head_qualification)?;
        if authoritative != manifest.sealed_head()? {
            return Err(BootleLanternHolderStoreErrorV1::RollbackDetected);
        }
        Ok(())
    }
    fn revalidate_providers_v1(&self) -> Result<(), BootleLanternHolderStoreErrorV1> {
        revalidate_provider_v1(
            self.key_wrapper.as_ref(),
            self.key_wrapper_qualification,
            self.sealed_heads.as_ref(),
            self.sealed_head_qualification,
        )
    }
    #[cfg(test)]
    fn inject_next_write_before_rename_failure_v1(&self) {
        self.fail_next_write_stage.store(1, Ordering::SeqCst);
    }
    #[cfg(test)]
    fn inject_next_write_after_rename_failure_v1(&self) {
        self.fail_next_write_stage.store(2, Ordering::SeqCst);
    }
}
#[cfg(test)]
#[derive(Clone, Copy)]
struct HolderPublishBindingV1 {
    phase: BootleLanternHolderPhaseV1,
    authorization_digest: [u8; 32],
    request_digest: [u8; 32],
    scope_digest: [u8; 32],
    policy_record_digest: [u8; 32],
    response_digest: [u8; 32],
}
/// Failure in native encrypted holder custody.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BootleLanternHolderStoreErrorV1 {
    /// A zero, empty, or otherwise invalid public input was supplied.
    #[error("Bootle/Lantern holder store input is invalid")]
    InvalidInput,
    /// Configured bounds are zero or exceed the fixed first-release caps.
    #[error("Bootle/Lantern holder store configuration is invalid")]
    ConfigurationInvalid,
    /// The bounded holder manifest has no free record slot.
    #[error("Bootle/Lantern holder store capacity is exhausted")]
    CapacityExceeded,
    /// Another process or object already owns this holder directory.
    #[error("Bootle/Lantern holder store directory is already open")]
    StoreAlreadyOpen,
    /// The strict file store requires Unix advisory locking.
    #[error("Bootle/Lantern holder store requires Unix advisory locking")]
    UnsupportedPlatform,
    /// A requested authorization or credential is absent.
    #[error("Bootle/Lantern holder record was not found")]
    NotFound,
    /// The requested transition is not valid from the authoritative phase.
    #[error("Bootle/Lantern holder state transition is invalid")]
    InvalidState,
    /// Public scope, policy, request, response, or authorization binding differs.
    #[error("Bootle/Lantern holder binding mismatch")]
    BindingMismatch,
    /// The supplied issuer response was not exact canonical `ILR1`.
    #[error("Bootle/Lantern holder response is invalid")]
    ResponseInvalid,
    /// An untrusted response could not produce a valid credential; pending
    /// holder state was durably restored so another response may be tried.
    #[error("Bootle/Lantern holder response was rejected; pending state was retained")]
    CredentialRejected,
    /// Holder-owned semantic state made finalization deterministically
    /// impossible and was durably terminalized without retaining secrets.
    #[error("Bootle/Lantern holder state is terminally invalid")]
    HolderStateTerminal,
    /// Provider qualification was malformed or not production-ready.
    #[error("Bootle/Lantern holder runtime provider is unqualified")]
    ProviderUnqualified,
    /// A provider became unavailable or rejected the exact operation.
    #[error("Bootle/Lantern holder runtime provider is unavailable")]
    ProviderUnavailable,
    /// Provider identity or public qualification changed during an operation.
    #[error("Bootle/Lantern holder runtime provider drifted")]
    ProviderDrift,
    /// Wrapping-key output or unwrapping failed.
    #[error("Bootle/Lantern holder DEK wrapping failed")]
    KeyWrapping,
    /// Operating-system encryption entropy was unavailable or unhealthy.
    #[error("Bootle/Lantern holder encryption randomness is unavailable")]
    RandomnessUnavailable,
    /// Local authenticated encryption failed.
    #[error("Bootle/Lantern holder encryption failed")]
    Encryption,
    /// Encrypted holder state failed authentication.
    #[error("Bootle/Lantern holder state authentication failed")]
    Authentication,
    /// An older valid filesystem or sealed-head state was substituted.
    #[error("Bootle/Lantern holder rollback or fork was detected")]
    RollbackDetected,
    /// A file, manifest, envelope, or secret payload is malformed or noncanonical.
    #[error("Bootle/Lantern holder store is corrupt")]
    Corrupt,
    /// A publication may be visible but its durability is uncertain; reopen is required.
    #[error("Bootle/Lantern holder durability is uncertain; reopen required")]
    DurabilityUncertain,
    /// Native issuance rejected the operation.
    #[error("Bootle/Lantern holder issuance failed: {0}")]
    Issuance(BootleLanternIssuanceErrorV1),
    /// Native presentation construction or self-check failed.
    #[error("Bootle/Lantern holder presentation failed")]
    PresentationFailed,
    /// Filesystem, locking, or persistence failed before durable publication.
    #[error("Bootle/Lantern holder store backend failed")]
    Backend,
    /// A closed fixed-profile implementation invariant failed.
    #[error("Bootle/Lantern holder store internal invariant failed")]
    InternalInvariant,
}
fn encode_manifest_v1(
    manifest: &HolderManifestV1,
) -> Result<Vec<u8>, BootleLanternHolderStoreErrorV1> {
    validate_manifest_v1(manifest, HOLDER_HARD_MAX_RECORDS_V1)?;
    let mut bytes = Vec::with_capacity(
        HOLDER_MANIFEST_HEADER_BYTES_V1
            + manifest.entries.len() * HOLDER_MANIFEST_ENTRY_BYTES_V1
            + HOLDER_MANIFEST_REVISION_BYTES_V1,
    );
    bytes.extend_from_slice(&HOLDER_MANIFEST_MAGIC_V1);
    bytes.push(HOLDER_VERSION_V1);
    bytes.push(0);
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&manifest.vault_id);
    bytes.extend_from_slice(&manifest.generation.to_be_bytes());
    bytes.extend_from_slice(&manifest.predecessor_revision);
    bytes.extend_from_slice(
        &u32::try_from(manifest.entries.len())
            .map_err(|_| BootleLanternHolderStoreErrorV1::CapacityExceeded)?
            .to_be_bytes(),
    );
    for entry in manifest.entries.values() {
        for digest in [
            entry.authorization_digest,
            entry.request_digest,
            entry.scope_digest,
            entry.policy_record_digest,
            entry.response_digest,
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&entry.entry_generation.to_be_bytes());
        bytes.push(entry.phase.tag());
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&entry.envelope_digest);
    }
    bytes.extend_from_slice(&manifest.revision);
    if bytes.len() as u64 > BOOTLE_LANTERN_HOLDER_MAX_MANIFEST_BYTES_V1 {
        return Err(BootleLanternHolderStoreErrorV1::CapacityExceeded);
    }
    Ok(bytes)
}
#[cfg(any(unix, test))]
fn decode_manifest_v1(
    bytes: &[u8],
    expected_vault_id: [u8; 32],
    max_records: usize,
) -> Result<HolderManifestV1, BootleLanternHolderStoreErrorV1> {
    if bytes.len() < HOLDER_MANIFEST_HEADER_BYTES_V1 + HOLDER_MANIFEST_REVISION_BYTES_V1
        || bytes.len() as u64 > BOOTLE_LANTERN_HOLDER_MAX_MANIFEST_BYTES_V1
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let mut offset = 0;
    if take_array_v1::<4>(bytes, &mut offset)? != HOLDER_MANIFEST_MAGIC_V1
        || take_u8_v1(bytes, &mut offset)? != HOLDER_VERSION_V1
        || take_u8_v1(bytes, &mut offset)? != 0
        || take_array_v1::<2>(bytes, &mut offset)? != [0; 2]
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let vault_id = take_array_v1::<32>(bytes, &mut offset)?;
    let generation = u64::from_be_bytes(take_array_v1::<8>(bytes, &mut offset)?);
    let predecessor_revision = take_array_v1::<32>(bytes, &mut offset)?;
    let count = usize::try_from(u32::from_be_bytes(take_array_v1::<4>(bytes, &mut offset)?))
        .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
    let expected_len = HOLDER_MANIFEST_HEADER_BYTES_V1
        .checked_add(
            count
                .checked_mul(HOLDER_MANIFEST_ENTRY_BYTES_V1)
                .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?,
        )
        .and_then(|length| length.checked_add(HOLDER_MANIFEST_REVISION_BYTES_V1))
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
    if vault_id != expected_vault_id || count > max_records || bytes.len() != expected_len {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let authorization_digest = take_array_v1::<32>(bytes, &mut offset)?;
        let request_digest = take_array_v1::<32>(bytes, &mut offset)?;
        let scope_digest = take_array_v1::<32>(bytes, &mut offset)?;
        let policy_record_digest = take_array_v1::<32>(bytes, &mut offset)?;
        let response_digest = take_array_v1::<32>(bytes, &mut offset)?;
        let entry_generation = u64::from_be_bytes(take_array_v1::<8>(bytes, &mut offset)?);
        let phase = BootleLanternHolderPhaseV1::from_tag(take_u8_v1(bytes, &mut offset)?)?;
        if take_array_v1::<7>(bytes, &mut offset)? != [0; 7] {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
        let envelope_digest = take_array_v1::<32>(bytes, &mut offset)?;
        let entry = HolderManifestEntryV1 {
            authorization_digest,
            request_digest,
            scope_digest,
            policy_record_digest,
            response_digest,
            entry_generation,
            phase,
            envelope_digest,
        };
        if entries.insert(authorization_digest, entry).is_some() {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
    }
    let revision = take_array_v1::<32>(bytes, &mut offset)?;
    if offset != bytes.len() {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let manifest = HolderManifestV1 {
        vault_id,
        generation,
        predecessor_revision,
        entries,
        revision,
    };
    validate_manifest_v1(&manifest, max_records)?;
    if manifest_revision_v1(&manifest)? != revision || encode_manifest_v1(&manifest)? != bytes {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok(manifest)
}
fn validate_manifest_v1(
    manifest: &HolderManifestV1,
    max_records: usize,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    if manifest.vault_id == [0; 32]
        || manifest.generation == 0
        || manifest.entries.len() > max_records
        || manifest.entries.len() > HOLDER_HARD_MAX_RECORDS_V1
        || (manifest.generation == 1) != (manifest.predecessor_revision == [0; 32])
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let mut envelope_digests = BTreeSet::new();
    for (key, entry) in &manifest.entries {
        if key != &entry.authorization_digest
            || entry.authorization_digest == [0; 32]
            || entry.request_digest == [0; 32]
            || entry.scope_digest == [0; 32]
            || entry.policy_record_digest == [0; 32]
            || entry.envelope_digest == [0; 32]
            || entry.entry_generation < 2
            || entry.entry_generation > manifest.generation
            || matches!(entry.phase, BootleLanternHolderPhaseV1::Pending)
                && entry.response_digest != [0; 32]
            || !matches!(entry.phase, BootleLanternHolderPhaseV1::Pending)
                && entry.response_digest == [0; 32]
            || !envelope_digests.insert(entry.envelope_digest)
        {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
    }
    Ok(())
}
fn manifest_revision_v1(
    manifest: &HolderManifestV1,
) -> Result<[u8; 32], BootleLanternHolderStoreErrorV1> {
    let mut clone = manifest.clone();
    clone.revision = [0; 32];
    let mut bytes = encode_manifest_without_validation_v1(&clone)?;
    let mut hash = Sha256::new();
    hash.update(HOLDER_MANIFEST_REVISION_DOMAIN_V1);
    hash.update(
        u64::try_from(bytes.len())
            .map_err(|_| BootleLanternHolderStoreErrorV1::CapacityExceeded)?
            .to_be_bytes(),
    );
    hash.update(&bytes);
    bytes.zeroize();
    Ok(hash.finalize().into())
}
fn encode_manifest_without_validation_v1(
    manifest: &HolderManifestV1,
) -> Result<Vec<u8>, BootleLanternHolderStoreErrorV1> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&HOLDER_MANIFEST_MAGIC_V1);
    bytes.push(HOLDER_VERSION_V1);
    bytes.push(0);
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&manifest.vault_id);
    bytes.extend_from_slice(&manifest.generation.to_be_bytes());
    bytes.extend_from_slice(&manifest.predecessor_revision);
    bytes.extend_from_slice(
        &u32::try_from(manifest.entries.len())
            .map_err(|_| BootleLanternHolderStoreErrorV1::CapacityExceeded)?
            .to_be_bytes(),
    );
    for entry in manifest.entries.values() {
        for digest in [
            entry.authorization_digest,
            entry.request_digest,
            entry.scope_digest,
            entry.policy_record_digest,
            entry.response_digest,
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&entry.entry_generation.to_be_bytes());
        bytes.push(entry.phase.tag());
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&entry.envelope_digest);
    }
    bytes.extend_from_slice(&manifest.revision);
    Ok(bytes)
}
fn encode_envelope_v1(
    envelope: &HolderEnvelopeV1,
) -> Result<Vec<u8>, BootleLanternHolderStoreErrorV1> {
    validate_envelope_shape_v1(envelope)?;
    let mut bytes = encode_envelope_header_v1(&envelope.header);
    bytes.extend_from_slice(envelope.wrapping_key_id.as_bytes());
    bytes.extend_from_slice(&envelope.wrapped_dek);
    bytes.extend_from_slice(&envelope.ciphertext);
    if bytes.len() as u64 > BOOTLE_LANTERN_HOLDER_MAX_ENVELOPE_BYTES_V1 {
        return Err(BootleLanternHolderStoreErrorV1::CapacityExceeded);
    }
    Ok(bytes)
}
fn decode_envelope_v1(bytes: &[u8]) -> Result<HolderEnvelopeV1, BootleLanternHolderStoreErrorV1> {
    if bytes.len() < HOLDER_ENVELOPE_HEADER_BYTES_V1
        || bytes.len() as u64 > BOOTLE_LANTERN_HOLDER_MAX_ENVELOPE_BYTES_V1
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let (header, mut offset) = decode_envelope_header_v1(bytes)?;
    let expected_len = HOLDER_ENVELOPE_HEADER_BYTES_V1
        .checked_add(usize::from(header.key_id_len))
        .and_then(|length| length.checked_add(usize::from(header.wrapped_dek_len)))
        .and_then(|length| {
            usize::try_from(header.ciphertext_len)
                .ok()
                .and_then(|ciphertext_len| length.checked_add(ciphertext_len))
        })
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
    if bytes.len() != expected_len {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let key_end = offset
        .checked_add(usize::from(header.key_id_len))
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
    let key_bytes = bytes
        .get(offset..key_end)
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
    let wrapping_key_id = core::str::from_utf8(key_bytes)
        .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?
        .to_owned();
    offset = key_end;
    let wrapped_end = offset
        .checked_add(usize::from(header.wrapped_dek_len))
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
    let wrapped_dek = bytes
        .get(offset..wrapped_end)
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?
        .to_vec();
    offset = wrapped_end;
    let ciphertext_end = offset
        .checked_add(
            usize::try_from(header.ciphertext_len)
                .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?,
        )
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
    let ciphertext = bytes
        .get(offset..ciphertext_end)
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?
        .to_vec();
    if ciphertext_end != bytes.len() {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let envelope = HolderEnvelopeV1 {
        header,
        wrapping_key_id,
        wrapped_dek,
        ciphertext,
    };
    validate_envelope_shape_v1(&envelope)?;
    if encode_envelope_v1(&envelope)? != bytes {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok(envelope)
}
fn encode_envelope_header_v1(header: &HolderEnvelopeHeaderV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HOLDER_ENVELOPE_HEADER_BYTES_V1);
    bytes.extend_from_slice(&HOLDER_ENVELOPE_MAGIC_V1);
    bytes.push(HOLDER_VERSION_V1);
    bytes.push(header.phase.tag());
    bytes.extend_from_slice(&[0; 2]);
    for digest in [
        header.vault_id,
        header.authorization_digest,
        header.request_digest,
        header.scope_digest,
        header.policy_record_digest,
        header.response_digest,
        header.predecessor_envelope_digest,
    ] {
        bytes.extend_from_slice(&digest);
    }
    bytes.extend_from_slice(&header.entry_generation.to_be_bytes());
    bytes.extend_from_slice(&header.plaintext_len.to_be_bytes());
    bytes.extend_from_slice(&header.ciphertext_len.to_be_bytes());
    bytes.extend_from_slice(&header.key_id_len.to_be_bytes());
    bytes.extend_from_slice(&header.wrapped_dek_len.to_be_bytes());
    bytes.extend_from_slice(&header.nonce);
    debug_assert_eq!(bytes.len(), HOLDER_ENVELOPE_HEADER_BYTES_V1);
    bytes
}
fn decode_envelope_header_v1(
    bytes: &[u8],
) -> Result<(HolderEnvelopeHeaderV1, usize), BootleLanternHolderStoreErrorV1> {
    let mut offset = 0;
    if take_array_v1::<4>(bytes, &mut offset)? != HOLDER_ENVELOPE_MAGIC_V1
        || take_u8_v1(bytes, &mut offset)? != HOLDER_VERSION_V1
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let phase = BootleLanternHolderPhaseV1::from_tag(take_u8_v1(bytes, &mut offset)?)?;
    if take_array_v1::<2>(bytes, &mut offset)? != [0; 2] {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let header = HolderEnvelopeHeaderV1 {
        phase,
        vault_id: take_array_v1::<32>(bytes, &mut offset)?,
        authorization_digest: take_array_v1::<32>(bytes, &mut offset)?,
        request_digest: take_array_v1::<32>(bytes, &mut offset)?,
        scope_digest: take_array_v1::<32>(bytes, &mut offset)?,
        policy_record_digest: take_array_v1::<32>(bytes, &mut offset)?,
        response_digest: take_array_v1::<32>(bytes, &mut offset)?,
        predecessor_envelope_digest: take_array_v1::<32>(bytes, &mut offset)?,
        entry_generation: u64::from_be_bytes(take_array_v1::<8>(bytes, &mut offset)?),
        plaintext_len: u32::from_be_bytes(take_array_v1::<4>(bytes, &mut offset)?),
        ciphertext_len: u32::from_be_bytes(take_array_v1::<4>(bytes, &mut offset)?),
        key_id_len: u16::from_be_bytes(take_array_v1::<2>(bytes, &mut offset)?),
        wrapped_dek_len: u16::from_be_bytes(take_array_v1::<2>(bytes, &mut offset)?),
        nonce: take_array_v1::<HOLDER_NONCE_BYTES_V1>(bytes, &mut offset)?,
    };
    if offset != HOLDER_ENVELOPE_HEADER_BYTES_V1 {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok((header, offset))
}
fn validate_envelope_shape_v1(
    envelope: &HolderEnvelopeV1,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    let header = &envelope.header;
    validate_plaintext_length_v1(
        header.phase,
        usize::try_from(header.plaintext_len)
            .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?,
    )?;
    if header.vault_id == [0; 32]
        || header.authorization_digest == [0; 32]
        || header.request_digest == [0; 32]
        || header.scope_digest == [0; 32]
        || header.policy_record_digest == [0; 32]
        || header.entry_generation < 2
        || header.nonce.iter().all(|byte| *byte == 0)
        || matches!(header.phase, BootleLanternHolderPhaseV1::Pending)
            && header.response_digest != [0; 32]
        || !matches!(header.phase, BootleLanternHolderPhaseV1::Pending)
            && header.response_digest == [0; 32]
        || usize::from(header.key_id_len) != envelope.wrapping_key_id.len()
        || usize::from(header.wrapped_dek_len) != envelope.wrapped_dek.len()
        || envelope.wrapped_dek.is_empty()
        || envelope.wrapped_dek.len() > HOLDER_WRAPPED_DEK_MAX_BYTES_V1
        || usize::try_from(header.ciphertext_len).ok() != Some(envelope.ciphertext.len())
        || envelope.ciphertext.len()
            != usize::try_from(header.plaintext_len)
                .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?
                + HOLDER_AEAD_TAG_BYTES_V1
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    validate_key_id_v1(&envelope.wrapping_key_id)
        .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)
}
fn envelope_aad_v1(
    envelope: &HolderEnvelopeV1,
) -> Result<Vec<u8>, BootleLanternHolderStoreErrorV1> {
    validate_envelope_shape_except_ciphertext_v1(envelope)?;
    let mut aad = Vec::with_capacity(
        HOLDER_ENVELOPE_AAD_DOMAIN_V1.len()
            + HOLDER_ENVELOPE_HEADER_BYTES_V1
            + envelope.wrapping_key_id.len()
            + envelope.wrapped_dek.len(),
    );
    aad.extend_from_slice(HOLDER_ENVELOPE_AAD_DOMAIN_V1);
    aad.extend_from_slice(&encode_envelope_header_v1(&envelope.header));
    aad.extend_from_slice(envelope.wrapping_key_id.as_bytes());
    aad.extend_from_slice(&envelope.wrapped_dek);
    Ok(aad)
}
fn validate_envelope_shape_except_ciphertext_v1(
    envelope: &HolderEnvelopeV1,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    validate_key_id_v1(&envelope.wrapping_key_id)?;
    if envelope.header.vault_id == [0; 32]
        || envelope.header.authorization_digest == [0; 32]
        || envelope.header.request_digest == [0; 32]
        || envelope.header.scope_digest == [0; 32]
        || envelope.header.policy_record_digest == [0; 32]
        || envelope.header.nonce.iter().all(|byte| *byte == 0)
        || envelope.wrapped_dek.is_empty()
        || envelope.wrapped_dek.len() > HOLDER_WRAPPED_DEK_MAX_BYTES_V1
        || usize::from(envelope.header.key_id_len) != envelope.wrapping_key_id.len()
        || usize::from(envelope.header.wrapped_dek_len) != envelope.wrapped_dek.len()
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok(())
}
fn envelope_dek_context_v1(header: &HolderEnvelopeHeaderV1) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(HOLDER_DEK_CONTEXT_DOMAIN_V1);
    hash.update(header.phase.tag().to_be_bytes());
    for digest in [
        header.vault_id,
        header.authorization_digest,
        header.request_digest,
        header.scope_digest,
        header.policy_record_digest,
        header.response_digest,
        header.predecessor_envelope_digest,
    ] {
        hash.update(digest);
    }
    hash.update(header.entry_generation.to_be_bytes());
    hash.update(header.plaintext_len.to_be_bytes());
    hash.finalize().into()
}
fn envelope_digest_v1(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(HOLDER_ENVELOPE_DIGEST_DOMAIN_V1);
    hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}
fn response_digest_v1(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(HOLDER_RESPONSE_DIGEST_DOMAIN_V1);
    hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}
#[cfg(test)]
fn encode_pending_secret_v1(
    pending: &PendingSecretV1,
) -> Result<Zeroizing<Vec<u8>>, BootleLanternHolderStoreErrorV1> {
    let phase = if pending.response_bytes.is_some() {
        BootleLanternHolderPhaseV1::ResponseCached
    } else {
        BootleLanternHolderPhaseV1::Pending
    };
    if pending.authorization_digest == [0; 32]
        || pending.request_digest == [0; 32]
        || pending.scope_digest == [0; 32]
        || pending.policy_record_digest == [0; 32]
        || pending.request_bytes.len() != BLIND_ISSUANCE_REQUEST_BYTES_V1
        || matches!(phase, BootleLanternHolderPhaseV1::Pending)
            && pending.response_digest != [0; 32]
        || matches!(phase, BootleLanternHolderPhaseV1::ResponseCached)
            && (pending.response_digest == [0; 32]
                || pending.response_bytes.as_ref().map(Vec::len)
                    != Some(BLIND_ISSUANCE_RESPONSE_BYTES_V1))
    {
        return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
    }
    let expected = plaintext_length_v1(phase);
    let mut bytes = Zeroizing::new(Vec::with_capacity(expected));
    bytes.extend_from_slice(if phase == BootleLanternHolderPhaseV1::Pending {
        &HOLDER_PENDING_MAGIC_V1
    } else {
        &HOLDER_CACHED_MAGIC_V1
    });
    bytes.push(HOLDER_VERSION_V1);
    bytes.push(phase.tag());
    bytes.extend_from_slice(&[0; 2]);
    for digest in [
        pending.authorization_digest,
        pending.request_digest,
        pending.scope_digest,
        pending.policy_record_digest,
        pending.response_digest,
    ] {
        bytes.extend_from_slice(&digest);
    }
    bytes.extend_from_slice(&pending.request_bytes);
    encode_polynomials_v1(&pending.randomness, &mut bytes)?;
    for attribute in &pending.attributes {
        bytes.extend_from_slice(attribute);
    }
    if let Some(response) = &pending.response_bytes {
        bytes.extend_from_slice(response);
    }
    if bytes.len() != expected {
        return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
    }
    Ok(bytes)
}
fn decode_pending_secret_v1(
    phase: BootleLanternHolderPhaseV1,
    bytes: &[u8],
) -> Result<PendingSecretV1, BootleLanternHolderStoreErrorV1> {
    if !matches!(
        phase,
        BootleLanternHolderPhaseV1::Pending | BootleLanternHolderPhaseV1::ResponseCached
    ) || bytes.len() != plaintext_length_v1(phase)
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let mut offset = 0;
    let expected_magic = if phase == BootleLanternHolderPhaseV1::Pending {
        HOLDER_PENDING_MAGIC_V1
    } else {
        HOLDER_CACHED_MAGIC_V1
    };
    if take_array_v1::<4>(bytes, &mut offset)? != expected_magic
        || take_u8_v1(bytes, &mut offset)? != HOLDER_VERSION_V1
        || take_u8_v1(bytes, &mut offset)? != phase.tag()
        || take_array_v1::<2>(bytes, &mut offset)? != [0; 2]
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let authorization_digest = take_array_v1::<32>(bytes, &mut offset)?;
    let request_digest = take_array_v1::<32>(bytes, &mut offset)?;
    let scope_digest = take_array_v1::<32>(bytes, &mut offset)?;
    let policy_record_digest = take_array_v1::<32>(bytes, &mut offset)?;
    let response_digest = take_array_v1::<32>(bytes, &mut offset)?;
    let request_bytes =
        take_slice_v1(bytes, &mut offset, BLIND_ISSUANCE_REQUEST_BYTES_V1)?.to_vec();
    let randomness = decode_polynomials_v1::<HOLDER_RANDOMNESS_POLYNOMIALS_V1>(bytes, &mut offset)?;
    let mut attributes = [[0_u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1];
    for attribute in &mut attributes {
        *attribute = take_array_v1::<8>(bytes, &mut offset)?;
    }
    let response_bytes = if phase == BootleLanternHolderPhaseV1::ResponseCached {
        Some(take_slice_v1(bytes, &mut offset, BLIND_ISSUANCE_RESPONSE_BYTES_V1)?.to_vec())
    } else {
        None
    };
    if offset != bytes.len()
        || authorization_digest == [0; 32]
        || request_digest == [0; 32]
        || scope_digest == [0; 32]
        || policy_record_digest == [0; 32]
        || matches!(phase, BootleLanternHolderPhaseV1::Pending) && response_digest != [0; 32]
        || matches!(phase, BootleLanternHolderPhaseV1::ResponseCached)
            && (response_digest == [0; 32]
                || response_bytes
                    .as_ref()
                    .is_none_or(|response| response_digest_v1(response) != response_digest))
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let request = BootleLanternBlindIssuanceRequestV1::decode_exact(
        &request_bytes,
        u32::try_from(BLIND_ISSUANCE_REQUEST_BYTES_V1).expect("fixed ILQ1 length fits u32"),
    )
    .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
    if request.request_digest() != request_digest
        || request.issuance_authorization_digest_v1() != authorization_digest
        || request.scope_digest_v1() != scope_digest
        || request.policy_record_digest_v1() != policy_record_digest
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    if let Some(response) = &response_bytes {
        let response = BootleLanternBlindIssuanceResponseV1::decode_exact(response)
            .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
        if response.request_digest_v1() != request_digest
            || response.scope_digest_v1() != scope_digest
            || response.policy_record_digest_v1() != policy_record_digest
        {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
    }
    Ok(PendingSecretV1 {
        authorization_digest,
        request_digest,
        scope_digest,
        policy_record_digest,
        response_digest,
        request_bytes,
        randomness,
        attributes,
        response_bytes,
    })
}
#[cfg(test)]
fn encode_finalized_secret_v1(
    secret: &FinalizedSecretV1,
) -> Result<Zeroizing<Vec<u8>>, BootleLanternHolderStoreErrorV1> {
    if [
        secret.authorization_digest,
        secret.request_digest,
        secret.scope_digest,
        secret.policy_record_digest,
        secret.response_digest,
    ]
    .iter()
    .any(|digest| *digest == [0; 32])
    {
        return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        BOOTLE_LANTERN_HOLDER_FINALIZED_PLAINTEXT_BYTES_V1,
    ));
    bytes.extend_from_slice(&HOLDER_FINALIZED_MAGIC_V1);
    bytes.push(HOLDER_VERSION_V1);
    bytes.push(HOLDER_FINALIZED_TAG_V1);
    bytes.extend_from_slice(&[0; 2]);
    for digest in [
        secret.authorization_digest,
        secret.request_digest,
        secret.scope_digest,
        secret.policy_record_digest,
        secret.response_digest,
    ] {
        bytes.extend_from_slice(&digest);
    }
    encode_polynomials_v1(&secret.randomness, &mut bytes)?;
    encode_polynomials_v1(&secret.tag, &mut bytes)?;
    encode_polynomials_v1(&secret.signature_one, &mut bytes)?;
    encode_polynomials_v1(&secret.signature_two, &mut bytes)?;
    for attribute in &secret.attributes {
        bytes.extend_from_slice(attribute);
    }
    if bytes.len() != BOOTLE_LANTERN_HOLDER_FINALIZED_PLAINTEXT_BYTES_V1 {
        return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
    }
    Ok(bytes)
}
fn decode_finalized_secret_v1(
    bytes: &[u8],
) -> Result<FinalizedSecretV1, BootleLanternHolderStoreErrorV1> {
    if bytes.len() != BOOTLE_LANTERN_HOLDER_FINALIZED_PLAINTEXT_BYTES_V1 {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let mut offset = 0;
    if take_array_v1::<4>(bytes, &mut offset)? != HOLDER_FINALIZED_MAGIC_V1
        || take_u8_v1(bytes, &mut offset)? != HOLDER_VERSION_V1
        || take_u8_v1(bytes, &mut offset)? != HOLDER_FINALIZED_TAG_V1
        || take_array_v1::<2>(bytes, &mut offset)? != [0; 2]
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let authorization_digest = take_array_v1::<32>(bytes, &mut offset)?;
    let request_digest = take_array_v1::<32>(bytes, &mut offset)?;
    let scope_digest = take_array_v1::<32>(bytes, &mut offset)?;
    let policy_record_digest = take_array_v1::<32>(bytes, &mut offset)?;
    let response_digest = take_array_v1::<32>(bytes, &mut offset)?;
    let randomness = decode_polynomials_v1::<16>(bytes, &mut offset)?;
    let tag = decode_polynomials_v1::<8>(bytes, &mut offset)?;
    let signature_one = decode_polynomials_v1::<8>(bytes, &mut offset)?;
    let signature_two = decode_polynomials_v1::<8>(bytes, &mut offset)?;
    let mut attributes = [[0_u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1];
    for attribute in &mut attributes {
        *attribute = take_array_v1::<8>(bytes, &mut offset)?;
    }
    if offset != bytes.len()
        || [
            authorization_digest,
            request_digest,
            scope_digest,
            policy_record_digest,
            response_digest,
        ]
        .iter()
        .any(|digest| *digest == [0; 32])
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok(FinalizedSecretV1 {
        authorization_digest,
        request_digest,
        scope_digest,
        policy_record_digest,
        response_digest,
        randomness,
        tag,
        signature_one,
        signature_two,
        attributes,
    })
}
#[cfg(test)]
fn encode_rejected_secret_v1(
    authorization_digest: [u8; 32],
    request_digest: [u8; 32],
    scope_digest: [u8; 32],
    policy_record_digest: [u8; 32],
    response_digest: [u8; 32],
    reason: u8,
) -> Result<Zeroizing<Vec<u8>>, BootleLanternHolderStoreErrorV1> {
    if reason == 0
        || [
            authorization_digest,
            request_digest,
            scope_digest,
            policy_record_digest,
            response_digest,
        ]
        .iter()
        .any(|digest| *digest == [0; 32])
    {
        return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        BOOTLE_LANTERN_HOLDER_REJECTED_PLAINTEXT_BYTES_V1,
    ));
    bytes.extend_from_slice(&HOLDER_REJECTED_MAGIC_V1);
    bytes.push(HOLDER_VERSION_V1);
    bytes.push(HOLDER_REJECTED_TAG_V1);
    bytes.extend_from_slice(&[0; 2]);
    for digest in [
        authorization_digest,
        request_digest,
        scope_digest,
        policy_record_digest,
        response_digest,
    ] {
        bytes.extend_from_slice(&digest);
    }
    bytes.push(reason);
    bytes.extend_from_slice(&[0; 7]);
    if bytes.len() != BOOTLE_LANTERN_HOLDER_REJECTED_PLAINTEXT_BYTES_V1 {
        return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
    }
    Ok(bytes)
}
#[cfg(test)]
fn validate_publish_plaintext_v1(
    binding: HolderPublishBindingV1,
    bytes: &[u8],
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    let observed = match binding.phase {
        BootleLanternHolderPhaseV1::Pending | BootleLanternHolderPhaseV1::ResponseCached => {
            let secret = decode_pending_secret_v1(binding.phase, bytes)?;
            [
                secret.authorization_digest,
                secret.request_digest,
                secret.scope_digest,
                secret.policy_record_digest,
                secret.response_digest,
            ]
        }
        BootleLanternHolderPhaseV1::Finalized => {
            let secret = decode_finalized_secret_v1(bytes)?;
            [
                secret.authorization_digest,
                secret.request_digest,
                secret.scope_digest,
                secret.policy_record_digest,
                secret.response_digest,
            ]
        }
        BootleLanternHolderPhaseV1::Rejected => decode_rejected_secret_v1(bytes)?,
    };
    if observed
        != [
            binding.authorization_digest,
            binding.request_digest,
            binding.scope_digest,
            binding.policy_record_digest,
            binding.response_digest,
        ]
    {
        return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
    }
    Ok(())
}
fn decode_rejected_secret_v1(
    bytes: &[u8],
) -> Result<[[u8; 32]; HOLDER_BINDING_DIGESTS_V1], BootleLanternHolderStoreErrorV1> {
    if bytes.len() != BOOTLE_LANTERN_HOLDER_REJECTED_PLAINTEXT_BYTES_V1 {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let mut offset = 0;
    if take_array_v1::<4>(bytes, &mut offset)? != HOLDER_REJECTED_MAGIC_V1
        || take_u8_v1(bytes, &mut offset)? != HOLDER_VERSION_V1
        || take_u8_v1(bytes, &mut offset)? != HOLDER_REJECTED_TAG_V1
        || take_array_v1::<2>(bytes, &mut offset)? != [0; 2]
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let mut bindings = [[0_u8; 32]; HOLDER_BINDING_DIGESTS_V1];
    for binding in &mut bindings {
        *binding = take_array_v1::<32>(bytes, &mut offset)?;
    }
    let reason = take_u8_v1(bytes, &mut offset)?;
    if offset.checked_add(7) != Some(bytes.len())
        || take_array_v1::<7>(bytes, &mut offset)? != [0; 7]
        || offset != bytes.len()
        || reason == 0
        || bindings.iter().any(|digest| *digest == [0; 32])
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok(bindings)
}
#[cfg(test)]
fn encode_polynomials_v1<const N: usize>(
    polynomials: &[ApplicationPolynomialV1; N],
    output: &mut Vec<u8>,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    for polynomial in polynomials {
        for coefficient in polynomial.coefficients() {
            if *coefficient >= APPLICATION_MODULUS_V1 {
                return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
            }
            output.extend_from_slice(&coefficient.to_be_bytes());
        }
    }
    Ok(())
}
fn decode_polynomials_v1<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[ApplicationPolynomialV1; N], BootleLanternHolderStoreErrorV1> {
    let mut output = [ApplicationPolynomialV1::ZERO; N];
    for polynomial in &mut output {
        let mut coefficients = [0_u16; APPLICATION_RING_DEGREE_V1];
        for coefficient in &mut coefficients {
            *coefficient = u16::from_be_bytes(take_array_v1::<2>(bytes, offset)?);
            if *coefficient >= APPLICATION_MODULUS_V1 {
                return Err(BootleLanternHolderStoreErrorV1::Corrupt);
            }
        }
        *polynomial = ApplicationPolynomialV1::new(coefficients)
            .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
    }
    Ok(output)
}
fn validate_pending_against_entry_v1(
    pending: &PendingSecretV1,
    entry: &HolderManifestEntryV1,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    if pending.authorization_digest != entry.authorization_digest
        || pending.request_digest != entry.request_digest
        || pending.scope_digest != entry.scope_digest
        || pending.policy_record_digest != entry.policy_record_digest
        || pending.response_digest != entry.response_digest
        || pending.response_bytes.is_some()
            != (entry.phase == BootleLanternHolderPhaseV1::ResponseCached)
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok(())
}
fn validate_finalized_against_entry_v1(
    secret: &FinalizedSecretV1,
    entry: &HolderManifestEntryV1,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    if [
        secret.authorization_digest,
        secret.request_digest,
        secret.scope_digest,
        secret.policy_record_digest,
        secret.response_digest,
    ] != entry_binding_digests_v1(entry)
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok(())
}
fn entry_binding_digests_v1(
    entry: &HolderManifestEntryV1,
) -> [[u8; 32]; HOLDER_BINDING_DIGESTS_V1] {
    [
        entry.authorization_digest,
        entry.request_digest,
        entry.scope_digest,
        entry.policy_record_digest,
        entry.response_digest,
    ]
}
fn validate_envelope_against_entry_v1(
    envelope: &HolderEnvelopeV1,
    vault_id: [u8; 32],
    entry: &HolderManifestEntryV1,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    let header = &envelope.header;
    if header.vault_id != vault_id
        || header.authorization_digest != entry.authorization_digest
        || header.request_digest != entry.request_digest
        || header.scope_digest != entry.scope_digest
        || header.policy_record_digest != entry.policy_record_digest
        || header.response_digest != entry.response_digest
        || header.entry_generation != entry.entry_generation
        || header.phase != entry.phase
    {
        return Err(BootleLanternHolderStoreErrorV1::RollbackDetected);
    }
    Ok(())
}
fn validate_plaintext_length_v1(
    phase: BootleLanternHolderPhaseV1,
    length: usize,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    if length != plaintext_length_v1(phase) {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok(())
}
const fn plaintext_length_v1(phase: BootleLanternHolderPhaseV1) -> usize {
    match phase {
        BootleLanternHolderPhaseV1::Pending => BOOTLE_LANTERN_HOLDER_PENDING_PLAINTEXT_BYTES_V1,
        BootleLanternHolderPhaseV1::ResponseCached => {
            BOOTLE_LANTERN_HOLDER_CACHED_PLAINTEXT_BYTES_V1
        }
        BootleLanternHolderPhaseV1::Finalized => BOOTLE_LANTERN_HOLDER_FINALIZED_PLAINTEXT_BYTES_V1,
        BootleLanternHolderPhaseV1::Rejected => BOOTLE_LANTERN_HOLDER_REJECTED_PLAINTEXT_BYTES_V1,
    }
}
#[cfg(any(unix, test))]
fn load_or_create_manifest_v1(
    vault_id: [u8; 32],
    config: BootleLanternHolderStoreConfigV1,
    store: &dyn BootleLanternHolderSealedHeadStoreV1,
    qualification: BootleLanternHolderProviderQualificationV1,
) -> Result<HolderManifestV1, BootleLanternHolderStoreErrorV1> {
    let loaded = store
        .load_v1(vault_id)
        .map_err(map_external_provider_error_v1)?;
    ensure_sealed_qualification_v1(store, qualification)?;
    if let Some(head) = loaded {
        return validate_sealed_head_v1(head, vault_id, config.max_records);
    }
    let empty = HolderManifestV1::empty(vault_id)?;
    let next = empty.sealed_head()?;
    match store.compare_and_swap_v1(vault_id, None, next.clone()) {
        Ok(()) | Err(BootleLanternHolderExternalErrorV1::Ambiguous) => {
            let authoritative = store
                .load_v1(vault_id)
                .map_err(|_| BootleLanternHolderStoreErrorV1::DurabilityUncertain)?
                .ok_or(BootleLanternHolderStoreErrorV1::DurabilityUncertain)?;
            ensure_sealed_qualification_v1(store, qualification)?;
            let recovered = validate_sealed_head_v1(authoritative, vault_id, config.max_records)?;
            if recovered != empty {
                return Err(BootleLanternHolderStoreErrorV1::RollbackDetected);
            }
            Ok(recovered)
        }
        Err(BootleLanternHolderExternalErrorV1::Rejected) => {
            let authoritative = store
                .load_v1(vault_id)
                .map_err(|_| BootleLanternHolderStoreErrorV1::DurabilityUncertain)?
                .ok_or(BootleLanternHolderStoreErrorV1::RollbackDetected)?;
            ensure_sealed_qualification_v1(store, qualification)?;
            let recovered = validate_sealed_head_v1(authoritative, vault_id, config.max_records)?;
            if recovered != empty {
                return Err(BootleLanternHolderStoreErrorV1::RollbackDetected);
            }
            Ok(recovered)
        }
        Err(error) => Err(map_external_provider_error_v1(error)),
    }
}
#[cfg(test)]
fn publish_manifest_v1(
    vault_id: [u8; 32],
    current: &HolderManifestV1,
    next: &HolderManifestV1,
    store: &dyn BootleLanternHolderSealedHeadStoreV1,
    qualification: BootleLanternHolderProviderQualificationV1,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    if next.generation != current.generation.checked_add(1).unwrap_or(0)
        || next.predecessor_revision != current.revision
    {
        return Err(BootleLanternHolderStoreErrorV1::InternalInvariant);
    }
    ensure_sealed_qualification_v1(store, qualification)?;
    let expected = Some(current.revision);
    let next_head = next.sealed_head()?;
    match store.compare_and_swap_v1(vault_id, expected, next_head.clone()) {
        Ok(()) | Err(BootleLanternHolderExternalErrorV1::Ambiguous) => {
            let authoritative = store
                .load_v1(vault_id)
                .map_err(|_| BootleLanternHolderStoreErrorV1::DurabilityUncertain)?
                .ok_or(BootleLanternHolderStoreErrorV1::DurabilityUncertain)?;
            ensure_sealed_qualification_v1(store, qualification)?;
            if authoritative != next_head {
                return Err(BootleLanternHolderStoreErrorV1::RollbackDetected);
            }
            Ok(())
        }
        Err(BootleLanternHolderExternalErrorV1::Rejected) => {
            let authoritative = store
                .load_v1(vault_id)
                .map_err(|_| BootleLanternHolderStoreErrorV1::DurabilityUncertain)?
                .ok_or(BootleLanternHolderStoreErrorV1::RollbackDetected)?;
            ensure_sealed_qualification_v1(store, qualification)?;
            if authoritative == next_head {
                Ok(())
            } else {
                Err(BootleLanternHolderStoreErrorV1::RollbackDetected)
            }
        }
        Err(BootleLanternHolderExternalErrorV1::Unavailable) => {
            Err(BootleLanternHolderStoreErrorV1::ProviderUnavailable)
        }
    }
}
#[cfg(any(unix, test))]
fn validate_sealed_head_v1(
    head: BootleLanternHolderSealedHeadV1,
    vault_id: [u8; 32],
    max_records: usize,
) -> Result<HolderManifestV1, BootleLanternHolderStoreErrorV1> {
    if head.generation == 0
        || head.revision == [0; 32]
        || head.payload.is_empty()
        || head.payload.len() as u64 > BOOTLE_LANTERN_HOLDER_MAX_MANIFEST_BYTES_V1
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let manifest = decode_manifest_v1(&head.payload, vault_id, max_records)?;
    if manifest.generation != head.generation || manifest.revision != head.revision {
        return Err(BootleLanternHolderStoreErrorV1::RollbackDetected);
    }
    Ok(manifest)
}
fn qualify_key_wrapper_v1(
    provider: &dyn BootleLanternHolderKeyWrapperV1,
) -> Result<BootleLanternHolderProviderQualificationV1, BootleLanternHolderStoreErrorV1> {
    let qualification = provider
        .qualification()
        .map_err(map_external_provider_error_v1)?;
    qualification.validate()?;
    Ok(qualification)
}
fn qualify_sealed_heads_v1(
    provider: &dyn BootleLanternHolderSealedHeadStoreV1,
) -> Result<BootleLanternHolderProviderQualificationV1, BootleLanternHolderStoreErrorV1> {
    let qualification = provider
        .qualification()
        .map_err(map_external_provider_error_v1)?;
    qualification.validate()?;
    Ok(qualification)
}
fn ensure_sealed_qualification_v1(
    provider: &dyn BootleLanternHolderSealedHeadStoreV1,
    expected: BootleLanternHolderProviderQualificationV1,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    if qualify_sealed_heads_v1(provider)? != expected {
        return Err(BootleLanternHolderStoreErrorV1::ProviderDrift);
    }
    Ok(())
}
fn revalidate_provider_v1(
    key_wrapper: &dyn BootleLanternHolderKeyWrapperV1,
    key_expected: BootleLanternHolderProviderQualificationV1,
    sealed_heads: &dyn BootleLanternHolderSealedHeadStoreV1,
    sealed_expected: BootleLanternHolderProviderQualificationV1,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    if qualify_key_wrapper_v1(key_wrapper)? != key_expected
        || qualify_sealed_heads_v1(sealed_heads)? != sealed_expected
    {
        return Err(BootleLanternHolderStoreErrorV1::ProviderDrift);
    }
    Ok(())
}
fn map_external_provider_error_v1(
    error: BootleLanternHolderExternalErrorV1,
) -> BootleLanternHolderStoreErrorV1 {
    match error {
        BootleLanternHolderExternalErrorV1::Unavailable
        | BootleLanternHolderExternalErrorV1::Rejected
        | BootleLanternHolderExternalErrorV1::Ambiguous => {
            BootleLanternHolderStoreErrorV1::ProviderUnavailable
        }
    }
}
fn map_key_wrapper_operation_error_v1(
    error: BootleLanternHolderExternalErrorV1,
) -> BootleLanternHolderStoreErrorV1 {
    match error {
        BootleLanternHolderExternalErrorV1::Rejected => {
            BootleLanternHolderStoreErrorV1::KeyWrapping
        }
        BootleLanternHolderExternalErrorV1::Unavailable
        | BootleLanternHolderExternalErrorV1::Ambiguous => {
            BootleLanternHolderStoreErrorV1::ProviderUnavailable
        }
    }
}
fn ensure_state_healthy_v1(
    state: &HolderFileStateV1,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    if state.poisoned {
        return Err(BootleLanternHolderStoreErrorV1::DurabilityUncertain);
    }
    Ok(())
}
#[cfg(test)]
fn poison_on_integrity_error_v1(
    state: &mut HolderFileStateV1,
    error: &BootleLanternHolderStoreErrorV1,
) {
    if matches!(
        error,
        BootleLanternHolderStoreErrorV1::DurabilityUncertain
            | BootleLanternHolderStoreErrorV1::ProviderDrift
            | BootleLanternHolderStoreErrorV1::RollbackDetected
    ) {
        state.poisoned = true;
    }
}
fn validate_runtime_handle_v1(value: &str) -> Result<(), BootleLanternHolderStoreErrorV1> {
    if value.is_empty()
        || value.len() > HOLDER_KEY_ID_MAX_BYTES_V1
        || !value.as_bytes().iter().all(|byte| byte.is_ascii_graphic())
    {
        return Err(BootleLanternHolderStoreErrorV1::ProviderUnqualified);
    }
    Ok(())
}
fn validate_key_id_v1(value: &str) -> Result<(), BootleLanternHolderStoreErrorV1> {
    validate_runtime_handle_v1(value).map_err(|_| BootleLanternHolderStoreErrorV1::KeyWrapping)
}
#[cfg(any(unix, test))]
fn ensure_holder_root_v1(root: &Path) -> Result<(), BootleLanternHolderStoreErrorV1> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(BootleLanternHolderStoreErrorV1::Corrupt);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = root
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .ok_or(BootleLanternHolderStoreErrorV1::InvalidInput)?;
            let metadata = fs::symlink_metadata(parent)
                .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(BootleLanternHolderStoreErrorV1::Corrupt);
            }
            #[cfg(unix)]
            let mut builder = fs::DirBuilder::new();
            #[cfg(not(unix))]
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder
                .create(root)
                .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                    .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
            }
            sync_directory_v1(parent)
                .map_err(|_| BootleLanternHolderStoreErrorV1::DurabilityUncertain)?;
        }
        Err(_) => return Err(BootleLanternHolderStoreErrorV1::Backend),
    }
    validate_private_directory_v1(root)
}
#[cfg(any(unix, test))]
fn ensure_private_subdirectory_v1(
    parent: &Path,
    path: &Path,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory_v1(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            let mut builder = fs::DirBuilder::new();
            #[cfg(not(unix))]
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder
                .create(path)
                .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
            }
            sync_directory_v1(parent)
                .map_err(|_| BootleLanternHolderStoreErrorV1::DurabilityUncertain)?;
            validate_private_directory_v1(path)
        }
        Err(_) => Err(BootleLanternHolderStoreErrorV1::Backend),
    }
}
#[cfg(any(unix, test))]
fn validate_private_directory_v1(path: &Path) -> Result<(), BootleLanternHolderStoreErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o777 != 0o700
        {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
    }
    Ok(())
}
#[cfg(any(unix, test))]
fn validate_holder_root_namespace_v1(root: &Path) -> Result<(), BootleLanternHolderStoreErrorV1> {
    let mut expected = BTreeSet::from([
        HOLDER_OBJECTS_DIRECTORY_V1,
        HOLDER_TEMP_DIRECTORY_V1,
        HOLDER_WRITER_LOCK_FILE_V1,
    ]);
    for entry in fs::read_dir(root).map_err(|_| BootleLanternHolderStoreErrorV1::Backend)? {
        let entry = entry.map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
        if !expected.remove(name.as_str()) {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
    }
    if !expected.is_empty() {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok(())
}
#[cfg(any(unix, test))]
fn clean_holder_temp_v1(path: &Path) -> Result<(), BootleLanternHolderStoreErrorV1> {
    let mut removed = false;
    for entry in fs::read_dir(path).map_err(|_| BootleLanternHolderStoreErrorV1::Backend)? {
        let entry = entry.map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        let file_type = entry
            .file_type()
            .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
        let object_name = name
            .strip_suffix(HOLDER_TEMP_EXTENSION_V1)
            .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
        parse_holder_object_file_name_v1(object_name)?;
        let metadata = entry
            .metadata()
            .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        if file_type.is_symlink()
            || !file_type.is_file()
            || metadata.len() > BOOTLE_LANTERN_HOLDER_MAX_ENVELOPE_BYTES_V1
        {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o777 != 0o600
            {
                return Err(BootleLanternHolderStoreErrorV1::Corrupt);
            }
        }
        fs::remove_file(entry.path()).map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        removed = true;
    }
    if removed {
        sync_directory_v1(path)
            .map_err(|_| BootleLanternHolderStoreErrorV1::DurabilityUncertain)?;
    }
    Ok(())
}
#[cfg(any(unix, test))]
fn validate_object_namespace_v1(
    objects_root: &Path,
    manifest: &HolderManifestV1,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    let active = manifest
        .entries
        .values()
        .map(|entry| (entry.envelope_digest, entry))
        .collect::<BTreeMap<_, _>>();
    // Validate the complete namespace before mutating it, but retain no orphan
    // paths: interrupted publications can accumulate across failed cleanups,
    // so a directory-sized path vector is not a safe recovery structure.
    let mut observed = BTreeSet::new();
    let mut has_orphans = false;
    for entry in fs::read_dir(objects_root).map_err(|_| BootleLanternHolderStoreErrorV1::Backend)? {
        let entry = entry.map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        let (_, digest, envelope) = load_holder_object_entry_v1(entry)?;
        if let Some(active_entry) = active.get(&digest) {
            validate_envelope_against_entry_v1(&envelope, manifest.vault_id, active_entry)?;
            observed.insert(digest);
        } else {
            has_orphans = true;
        }
    }
    if observed.len() != active.len() || !observed.iter().all(|digest| active.contains_key(digest))
    {
        return Err(BootleLanternHolderStoreErrorV1::RollbackDetected);
    }
    if has_orphans {
        remove_orphan_holder_objects_v1(objects_root, manifest, &active)?;
    }
    Ok(())
}
#[cfg(any(unix, test))]
fn load_holder_object_entry_v1(
    entry: fs::DirEntry,
) -> Result<(PathBuf, [u8; 32], HolderEnvelopeV1), BootleLanternHolderStoreErrorV1> {
    let path = entry.path();
    let name = entry
        .file_name()
        .into_string()
        .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
    let digest = parse_holder_object_file_name_v1(&name)?;
    let metadata = entry
        .metadata()
        .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
    let file_type = entry
        .file_type()
        .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
    }
    if file_type.is_symlink()
        || !file_type.is_file()
        || metadata.len() == 0
        || metadata.len() > BOOTLE_LANTERN_HOLDER_MAX_ENVELOPE_BYTES_V1
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o777 != 0o600
        {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
    }
    let bytes = read_regular_bounded_v1(&path, BOOTLE_LANTERN_HOLDER_MAX_ENVELOPE_BYTES_V1)?;
    if envelope_digest_v1(&bytes) != digest {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok((path, digest, decode_envelope_v1(&bytes)?))
}
#[cfg(any(unix, test))]
fn remove_orphan_holder_objects_v1(
    objects_root: &Path,
    manifest: &HolderManifestV1,
    active: &BTreeMap<[u8; 32], &HolderManifestEntryV1>,
) -> Result<(), BootleLanternHolderStoreErrorV1> {
    let mut observed = BTreeSet::new();
    let mut removed = false;
    for entry in fs::read_dir(objects_root).map_err(|_| BootleLanternHolderStoreErrorV1::Backend)? {
        let entry = entry.map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        let (path, digest, envelope) = load_holder_object_entry_v1(entry)?;
        if let Some(active_entry) = active.get(&digest) {
            validate_envelope_against_entry_v1(&envelope, manifest.vault_id, active_entry)?;
            observed.insert(digest);
        } else {
            fs::remove_file(path).map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
            removed = true;
        }
    }
    if observed.len() != active.len() || !observed.iter().all(|digest| active.contains_key(digest))
    {
        return Err(BootleLanternHolderStoreErrorV1::RollbackDetected);
    }
    if removed {
        sync_directory_v1(objects_root)
            .map_err(|_| BootleLanternHolderStoreErrorV1::DurabilityUncertain)?;
    }
    Ok(())
}
fn read_object_v1(
    objects_root: &Path,
    digest: [u8; 32],
) -> Result<Vec<u8>, BootleLanternHolderStoreErrorV1> {
    read_regular_bounded_v1(
        &objects_root.join(holder_object_file_name_v1(digest)),
        BOOTLE_LANTERN_HOLDER_MAX_ENVELOPE_BYTES_V1,
    )
}
fn read_regular_bounded_v1(
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, BootleLanternHolderStoreErrorV1> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|_| BootleLanternHolderStoreErrorV1::RollbackDetected)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.len() == 0
        || path_metadata.len() > max_bytes
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        if path_metadata.nlink() != 1 {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
        if path_metadata.uid() != rustix::process::geteuid().as_raw()
            || path_metadata.mode() & 0o777 != 0o600
        {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(u32::cast_signed(rustix::fs::OFlags::NOFOLLOW.bits()))
            .open(path)
            .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
        let opened = file
            .metadata()
            .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        if opened.nlink() != 1
            || opened.dev() != path_metadata.dev()
            || opened.ino() != path_metadata.ino()
            || opened.len() != path_metadata.len()
            || opened.uid() != rustix::process::geteuid().as_raw()
            || opened.mode() & 0o777 != 0o600
        {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(path_metadata.len())
                .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?,
        );
        file.take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
        if bytes.len() as u64 != path_metadata.len() {
            return Err(BootleLanternHolderStoreErrorV1::Corrupt);
        }
        return Ok(bytes);
    }
    #[cfg(not(unix))]
    {
        let _ = max_bytes;
        Err(BootleLanternHolderStoreErrorV1::UnsupportedPlatform)
    }
}
#[cfg(test)]
fn reject_existing_holder_path_v1(path: &Path) -> Result<(), BootleLanternHolderStoreErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(BootleLanternHolderStoreErrorV1::Corrupt),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(BootleLanternHolderStoreErrorV1::Backend),
    }
}
fn holder_object_file_name_v1(digest: [u8; 32]) -> String {
    let mut name = hex_lower_v1(digest);
    name.push_str(HOLDER_OBJECT_EXTENSION_V1);
    name
}
#[cfg(any(unix, test))]
fn parse_holder_object_file_name_v1(
    name: &str,
) -> Result<[u8; 32], BootleLanternHolderStoreErrorV1> {
    let value = name
        .strip_suffix(HOLDER_OBJECT_EXTENSION_V1)
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble_v1(pair[0])? << 4) | hex_nibble_v1(pair[1])?;
    }
    if holder_object_file_name_v1(digest) != name || digest == [0; 32] {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    Ok(digest)
}
fn hex_lower_v1(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
#[cfg(any(unix, test))]
fn hex_nibble_v1(byte: u8) -> Result<u8, BootleLanternHolderStoreErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(BootleLanternHolderStoreErrorV1::Corrupt),
    }
}
#[cfg(unix)]
fn acquire_holder_writer_lock_v1(root: &Path) -> Result<File, BootleLanternHolderStoreErrorV1> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let path = root.join(HOLDER_WRITER_LOCK_FILE_V1);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.nlink() != 1
                || metadata.len() != 0
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o777 != 0o600
            {
                return Err(BootleLanternHolderStoreErrorV1::Corrupt);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(BootleLanternHolderStoreErrorV1::Backend),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(u32::cast_signed(rustix::fs::OFlags::NOFOLLOW.bits()))
        .mode(0o600)
        .open(&path)
        .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
    file.set_permissions({
        use std::os::unix::fs::PermissionsExt as _;
        fs::Permissions::from_mode(0o600)
    })
    .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
    let opened = file
        .metadata()
        .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.nlink() != 1
        || path_metadata.len() != 0
        || path_metadata.uid() != rustix::process::geteuid().as_raw()
        || path_metadata.mode() & 0o777 != 0o600
        || opened.dev() != path_metadata.dev()
        || opened.ino() != path_metadata.ino()
        || opened.uid() != rustix::process::geteuid().as_raw()
        || opened.mode() & 0o777 != 0o600
    {
        return Err(BootleLanternHolderStoreErrorV1::Corrupt);
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| BootleLanternHolderStoreErrorV1::StoreAlreadyOpen)?;
    sync_directory_v1(root).map_err(|_| BootleLanternHolderStoreErrorV1::DurabilityUncertain)?;
    Ok(file)
}
#[cfg(all(test, not(unix)))]
fn acquire_holder_writer_lock_v1(_root: &Path) -> Result<File, BootleLanternHolderStoreErrorV1> {
    Err(BootleLanternHolderStoreErrorV1::UnsupportedPlatform)
}
#[cfg(any(unix, test))]
fn acquire_holder_lease_v1(
    canonical_root: PathBuf,
) -> Result<HolderDirectoryLeaseV1, BootleLanternHolderStoreErrorV1> {
    let mut roots = open_holder_roots_v1()
        .lock()
        .map_err(|_| BootleLanternHolderStoreErrorV1::Backend)?;
    if !roots.insert(canonical_root.clone()) {
        return Err(BootleLanternHolderStoreErrorV1::StoreAlreadyOpen);
    }
    Ok(HolderDirectoryLeaseV1 { canonical_root })
}
fn open_holder_roots_v1() -> &'static Mutex<BTreeSet<PathBuf>> {
    static ROOTS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
    ROOTS.get_or_init(|| Mutex::new(BTreeSet::new()))
}
fn sync_directory_v1(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}
fn take_array_v1<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], BootleLanternHolderStoreErrorV1> {
    let end = offset
        .checked_add(N)
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?
        .try_into()
        .map_err(|_| BootleLanternHolderStoreErrorV1::Corrupt)?;
    *offset = end;
    Ok(value)
}
fn take_u8_v1(bytes: &[u8], offset: &mut usize) -> Result<u8, BootleLanternHolderStoreErrorV1> {
    Ok(take_array_v1::<1>(bytes, offset)?[0])
}
fn take_slice_v1<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], BootleLanternHolderStoreErrorV1> {
    let end = offset
        .checked_add(length)
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(BootleLanternHolderStoreErrorV1::Corrupt)?;
    *offset = end;
    Ok(value)
}
#[cfg(test)]
mod tests {
    use super::super::issuer::{
        BootleLanternInMemoryIssuanceStoreV1, BootleLanternIssuerKeyPairV1,
        BootleLanternIssuerPolicyMetadataV1, issuer_authorize_blind_issuance_with_rng_v1,
        issuer_blind_issue_once_encoded_with_rng_v1,
    };
    use super::*;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::privacy::{
        BootleLanternAllowedAttributeValuesV1, BootleLanternAttributeValueV1,
        BootleLanternDisclosedAttributeV1, PrivacyEngineManifestDigestV1, PrivacyIssuerIdV1,
        PrivacyParameterDigestV1, PrivacyParameterIdV1, PrivacyPolicyIdV1,
        PrivacyStatementSchemaDigestV1, PrivacyTransactionIntentDigestV1, PrivacyVerifierDigestV1,
    };
    use iroha_data_model::{NetworkId, block::BlockHeader};
    use rand_core_06::Error as RngError;
    struct TestRng {
        state: u64,
    }
    impl TestRng {
        const fn healthy(seed: u64) -> Self {
            Self { state: seed }
        }
    }
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0_u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.try_fill_bytes(destination)
                .expect("infallible deterministic test RNG");
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            for byte in destination {
                self.state ^= self.state << 13;
                self.state ^= self.state >> 7;
                self.state ^= self.state << 17;
                *byte = self.state as u8;
            }
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}
    struct PanicRng;
    impl RngCore for PanicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("idempotent holder recovery consumed RNG")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("idempotent holder recovery consumed RNG")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("idempotent holder recovery consumed RNG")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), RngError> {
            panic!("idempotent holder recovery consumed RNG")
        }
    }
    impl CryptoRng for PanicRng {}
    #[derive(Debug)]
    struct TestWrapper {
        qualification: Mutex<BootleLanternHolderProviderQualificationV1>,
        key: [u8; 32],
        zero_unwrap: bool,
    }
    impl TestWrapper {
        fn exact() -> Self {
            Self {
                qualification: Mutex::new(BootleLanternHolderProviderQualificationV1::new(
                    1, [0x31; 32],
                )),
                key: [0x52; 32],
                zero_unwrap: false,
            }
        }
        fn zero_unwrap() -> Self {
            Self {
                zero_unwrap: true,
                ..Self::exact()
            }
        }
    }
    impl BootleLanternHolderKeyWrapperV1 for TestWrapper {
        fn handle(&self) -> &str {
            "kms://bootle/holder-primary"
        }
        fn qualification(
            &self,
        ) -> Result<BootleLanternHolderProviderQualificationV1, BootleLanternHolderExternalErrorV1>
        {
            Ok(*self.qualification.lock().unwrap())
        }
        fn active_key_id(&self) -> &str {
            "kms://bootle/holder-key-1"
        }
        fn wrap_dek(
            &self,
            context: [u8; 32],
            dek: &[u8; 32],
        ) -> Result<Vec<u8>, BootleLanternHolderExternalErrorV1> {
            let wrapped: [u8; 32] =
                core::array::from_fn(|index| dek[index] ^ context[index] ^ self.key[index]);
            Ok(wrapped.to_vec())
        }
        fn unwrap_dek(
            &self,
            key_id: &str,
            context: [u8; 32],
            wrapped_dek: &[u8],
        ) -> Result<[u8; 32], BootleLanternHolderExternalErrorV1> {
            if self.zero_unwrap {
                return Ok([0; 32]);
            }
            if key_id != self.active_key_id() || wrapped_dek.len() != 32 {
                return Err(BootleLanternHolderExternalErrorV1::Rejected);
            }
            Ok(core::array::from_fn(|index| {
                wrapped_dek[index] ^ context[index] ^ self.key[index]
            }))
        }
    }
    #[derive(Debug)]
    struct TestHeads {
        qualification: Mutex<BootleLanternHolderProviderQualificationV1>,
        head: Mutex<Option<BootleLanternHolderSealedHeadV1>>,
        next_outcome: Mutex<Option<BootleLanternHolderExternalErrorV1>>,
        ambiguous_without_commit: Mutex<bool>,
        next_load_outcome: Mutex<Option<BootleLanternHolderExternalErrorV1>>,
        post_cas_load_outcome: Mutex<Option<BootleLanternHolderExternalErrorV1>>,
    }
    impl TestHeads {
        fn new() -> Self {
            Self {
                qualification: Mutex::new(BootleLanternHolderProviderQualificationV1::new(
                    1, [0x73; 32],
                )),
                head: Mutex::new(None),
                next_outcome: Mutex::new(None),
                ambiguous_without_commit: Mutex::new(false),
                next_load_outcome: Mutex::new(None),
                post_cas_load_outcome: Mutex::new(None),
            }
        }
        fn inject(&self, outcome: BootleLanternHolderExternalErrorV1) {
            *self.next_outcome.lock().unwrap() = Some(outcome);
        }
        fn inject_ambiguous_without_commit(&self) {
            *self.next_outcome.lock().unwrap() =
                Some(BootleLanternHolderExternalErrorV1::Ambiguous);
            *self.ambiguous_without_commit.lock().unwrap() = true;
        }
        fn inject_post_cas_load_failure(&self, outcome: BootleLanternHolderExternalErrorV1) {
            *self.post_cas_load_outcome.lock().unwrap() = Some(outcome);
        }
    }
    impl BootleLanternHolderSealedHeadStoreV1 for TestHeads {
        fn handle(&self) -> &str {
            "sealed://bootle/holder-head-primary"
        }
        fn qualification(
            &self,
        ) -> Result<BootleLanternHolderProviderQualificationV1, BootleLanternHolderExternalErrorV1>
        {
            Ok(*self.qualification.lock().unwrap())
        }
        fn load_v1(
            &self,
            _vault_id: [u8; 32],
        ) -> Result<Option<BootleLanternHolderSealedHeadV1>, BootleLanternHolderExternalErrorV1>
        {
            if let Some(outcome) = self.next_load_outcome.lock().unwrap().take() {
                return Err(outcome);
            }
            Ok(self.head.lock().unwrap().clone())
        }
        fn compare_and_swap_v1(
            &self,
            _vault_id: [u8; 32],
            expected_revision: Option<[u8; 32]>,
            next: BootleLanternHolderSealedHeadV1,
        ) -> Result<(), BootleLanternHolderExternalErrorV1> {
            let outcome = self.next_outcome.lock().unwrap().take();
            if let Some(
                outcome @ (BootleLanternHolderExternalErrorV1::Unavailable
                | BootleLanternHolderExternalErrorV1::Rejected),
            ) = outcome
            {
                return Err(outcome);
            }
            if outcome == Some(BootleLanternHolderExternalErrorV1::Ambiguous)
                && core::mem::take(&mut *self.ambiguous_without_commit.lock().unwrap())
            {
                return Err(BootleLanternHolderExternalErrorV1::Ambiguous);
            }
            let mut head = self.head.lock().unwrap();
            if head.as_ref().map(BootleLanternHolderSealedHeadV1::revision) != expected_revision {
                return Err(BootleLanternHolderExternalErrorV1::Rejected);
            }
            *head = Some(next);
            if let Some(outcome) = self.post_cas_load_outcome.lock().unwrap().take() {
                *self.next_load_outcome.lock().unwrap() = Some(outcome);
            }
            outcome.map_or(Ok(()), Err)
        }
    }
    fn digest(value: u8) -> [u8; 32] {
        [value; 32]
    }
    fn network_id(value: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed(digest(value)),
        ))
    }
    fn statement_context_v1() -> PrivacyStatementContextV1 {
        PrivacyStatementContextV1 {
            network_id: network_id(0x32),
            action_index: 3,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(digest(0x11)),
            parameter_id: PrivacyParameterIdV1::new(digest(0x12)),
            parameter_digest: PrivacyParameterDigestV1::new([0x31; 32]),
            verifier_digest: PrivacyVerifierDigestV1::new(digest(0x14)),
            statement_schema_digest: PrivacyStatementSchemaDigestV1::new(digest(0x15)),
            engine_manifest_digest: PrivacyEngineManifestDigestV1::new(digest(0x16)),
        }
    }
    fn policy_metadata_v1() -> BootleLanternIssuerPolicyMetadataV1 {
        BootleLanternIssuerPolicyMetadataV1 {
            issuer_id: PrivacyIssuerIdV1::new(digest(0x21)),
            policy_id: PrivacyPolicyIdV1::new(digest(0x22)),
            epoch: 1,
            required_disclosure_bitmap: 0b0000_0010,
            allowed_values: (0..BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1)
                .map(|index| BootleLanternAllowedAttributeValuesV1 {
                    values: if index == 1 {
                        vec![BootleLanternAttributeValueV1::new([1; 8])]
                    } else {
                        Vec::new()
                    },
                })
                .collect(),
        }
    }
    fn attributes_v1() -> [[u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1] {
        let mut attributes = [[0_u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1];
        attributes[1] = [1; 8];
        attributes
    }
    fn presentation_statement_v1(
        context: PrivacyStatementContextV1,
        policy: &BootleLanternIssuerPolicyV1,
    ) -> IrohaBootleLanternAnoncredStatementV1 {
        IrohaBootleLanternAnoncredStatementV1 {
            context,
            issuer_id: policy.issuer_id,
            policy_id: policy.policy_id,
            issuer_policy_epoch: policy.epoch,
            issuer_policy_record_digest: policy.record_digest,
            issuer_parameter_id: policy.issuer_parameter_id,
            issuer_parameter_digest: policy.issuer_parameter_digest,
            disclosures: vec![BootleLanternDisclosedAttributeV1 {
                index: 1,
                value: BootleLanternAttributeValueV1::new([1; 8]),
            }],
        }
    }
    fn open_test_store_v1(
        root: &Path,
        wrapper: Arc<TestWrapper>,
        heads: Arc<TestHeads>,
    ) -> Result<BootleLanternFileHolderStoreV1, BootleLanternHolderStoreErrorV1> {
        BootleLanternFileHolderStoreV1::open(
            root,
            digest(0x91),
            BootleLanternHolderStoreConfigV1::default(),
            wrapper,
            heads,
        )
    }
    fn publish_rejected_test_record_v1(
        store: &BootleLanternFileHolderStoreV1,
        discriminator: u8,
    ) -> Result<BootleLanternHolderHandleV1, BootleLanternHolderStoreErrorV1> {
        let authorization_digest = digest(discriminator);
        let request_digest = digest(discriminator.wrapping_add(1));
        let scope_digest = digest(discriminator.wrapping_add(2));
        let policy_record_digest = digest(discriminator.wrapping_add(3));
        let response_digest = digest(discriminator.wrapping_add(4));
        let plaintext = encode_rejected_secret_v1(
            authorization_digest,
            request_digest,
            scope_digest,
            policy_record_digest,
            response_digest,
            1,
        )?;
        let mut state = store.lock_healthy_state_v1()?;
        store.publish_secret_locked_v1(
            &mut state,
            HolderPublishBindingV1 {
                phase: BootleLanternHolderPhaseV1::Rejected,
                authorization_digest,
                request_digest,
                scope_digest,
                policy_record_digest,
                response_digest,
            },
            [0; 32],
            plaintext.as_slice(),
        )?;
        BootleLanternHolderHandleV1::new(authorization_digest)
    }
    fn synthetic_entry(phase: BootleLanternHolderPhaseV1) -> HolderManifestEntryV1 {
        HolderManifestEntryV1 {
            authorization_digest: digest(1),
            request_digest: digest(2),
            scope_digest: digest(3),
            policy_record_digest: digest(4),
            response_digest: if phase == BootleLanternHolderPhaseV1::Pending {
                [0; 32]
            } else {
                digest(5)
            },
            entry_generation: 2,
            phase,
            envelope_digest: digest(6),
        }
    }
    #[test]
    fn fixed_wire_sizes_are_exact() {
        assert_eq!(BOOTLE_LANTERN_HOLDER_PENDING_PLAINTEXT_BYTES_V1, 73_856);
        assert_eq!(BOOTLE_LANTERN_HOLDER_CACHED_PLAINTEXT_BYTES_V1, 77_032);
        assert_eq!(BOOTLE_LANTERN_HOLDER_FINALIZED_PLAINTEXT_BYTES_V1, 5_352);
        assert_eq!(BOOTLE_LANTERN_HOLDER_REJECTED_PLAINTEXT_BYTES_V1, 176);
        assert_eq!(BOOTLE_LANTERN_HOLDER_MAX_ENVELOPE_BYTES_V1, 81_675);
        assert_eq!(BOOTLE_LANTERN_HOLDER_MAX_MANIFEST_BYTES_V1, 852_084);
        assert_eq!(HOLDER_ENVELOPE_HEADER_BYTES_V1, 276);
        assert_eq!(HOLDER_MANIFEST_ENTRY_BYTES_V1, 208);
    }
    #[test]
    fn canonical_holder_lifecycle_survives_cached_and_finalized_restarts() {
        let mut keygen_rng = TestRng::healthy(0x6a09_e667_f3bc_c908);
        let issuer = BootleLanternIssuerKeyPairV1::generate_with_rng_v1(
            PrivacyParameterIdV1::new(digest(0x41)),
            &mut keygen_rng,
        )
        .expect("native issuer key generation");
        let policy = issuer
            .active_policy_v1(policy_metadata_v1())
            .expect("active issuer policy");
        let context = statement_context_v1();
        let genesis_hash = *context.network_id.as_bytes();
        let issuance_store = BootleLanternInMemoryIssuanceStoreV1::new();
        let mut authorization_rng = TestRng::healthy(0x1f83_d9ab_fb41_bd6b);
        let authorization = issuer_authorize_blind_issuance_with_rng_v1(
            &issuer,
            &context,
            genesis_hash,
            &policy,
            digest(0x43),
            10,
            20,
            &issuance_store,
            &mut authorization_rng,
        )
        .expect("holder authorization");
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let holder = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        let mut holder_rng = TestRng::healthy(0xbb67_ae85_84ca_a73b);
        let prepared = holder
            .prepare_blind_issuance_with_rng_v1(
                &context,
                genesis_hash,
                &policy,
                &authorization,
                attributes_v1(),
                &mut holder_rng,
            )
            .expect("durable pending holder state");
        assert_eq!(
            holder.phase_v1(prepared.handle()).unwrap(),
            BootleLanternHolderPhaseV1::Pending
        );
        let mut panic_rng = PanicRng;
        let recovered = holder
            .prepare_blind_issuance_with_rng_v1(
                &context,
                genesis_hash,
                &policy,
                &authorization,
                attributes_v1(),
                &mut panic_rng,
            )
            .expect("idempotent pending recovery");
        assert_eq!(recovered.request_bytes(), prepared.request_bytes());
        let mut issuer_rng = TestRng::healthy(0xa54f_f53a_5f1d_36f1);
        let response = issuer_blind_issue_once_encoded_with_rng_v1(
            &issuer,
            &context,
            genesis_hash,
            &policy,
            &authorization,
            prepared.request_bytes(),
            11,
            &issuance_store,
            &mut issuer_rng,
        )
        .expect("canonical issuer response");
        let response_bytes = response.encode().expect("canonical ILR1");
        assert_eq!(
            holder.cache_issuer_response_v1(
                prepared.handle(),
                &context,
                genesis_hash,
                &policy,
                &response_bytes[..response_bytes.len() - 1],
            ),
            Err(BootleLanternHolderStoreErrorV1::ResponseInvalid)
        );
        let mut substituted = response_bytes.clone();
        let request_binding_start = BLIND_ISSUANCE_RESPONSE_BYTES_V1 - 96;
        substituted[request_binding_start] ^= 1;
        if substituted[request_binding_start..request_binding_start + 32]
            .iter()
            .all(|byte| *byte == 0)
        {
            substituted[request_binding_start] = 2;
        }
        assert_eq!(
            holder.cache_issuer_response_v1(
                prepared.handle(),
                &context,
                genesis_hash,
                &policy,
                &substituted,
            ),
            Err(BootleLanternHolderStoreErrorV1::BindingMismatch)
        );
        assert_eq!(
            holder.phase_v1(prepared.handle()).unwrap(),
            BootleLanternHolderPhaseV1::Pending
        );
        let mut forged = response_bytes.clone();
        let first_signature_coefficient = 8 + 8 * APPLICATION_RING_DEGREE_V1 * 2;
        let coefficient = u16::from_be_bytes([
            forged[first_signature_coefficient],
            forged[first_signature_coefficient + 1],
        ]);
        let forged_coefficient = (coefficient + 1) % APPLICATION_MODULUS_V1;
        forged[first_signature_coefficient..first_signature_coefficient + 2]
            .copy_from_slice(&forged_coefficient.to_be_bytes());
        holder
            .cache_issuer_response_v1(prepared.handle(), &context, genesis_hash, &policy, &forged)
            .expect("correctly bound forged response is cached before validation");
        assert_eq!(
            holder.phase_v1(prepared.handle()).unwrap(),
            BootleLanternHolderPhaseV1::ResponseCached
        );
        drop(holder);
        let holder = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        assert_eq!(
            holder.resume_cached_response_v1(prepared.handle(), &context, genesis_hash, &policy,),
            Err(BootleLanternHolderStoreErrorV1::CredentialRejected)
        );
        assert_eq!(
            holder.phase_v1(prepared.handle()).unwrap(),
            BootleLanternHolderPhaseV1::Pending
        );
        assert_eq!(fs::read_dir(&holder.objects_root).unwrap().count(), 1);
        holder
            .cache_issuer_response_v1(prepared.handle(), &context, genesis_hash, &policy, &forged)
            .expect("repeated forged response cache");
        assert_eq!(
            holder.resume_cached_response_v1(prepared.handle(), &context, genesis_hash, &policy,),
            Err(BootleLanternHolderStoreErrorV1::CredentialRejected)
        );
        assert_eq!(
            holder.phase_v1(prepared.handle()).unwrap(),
            BootleLanternHolderPhaseV1::Pending
        );
        assert_eq!(fs::read_dir(&holder.objects_root).unwrap().count(), 1);
        holder
            .cache_issuer_response_v1(
                prepared.handle(),
                &context,
                genesis_hash,
                &policy,
                &response_bytes,
            )
            .expect("legitimate response remains consumable");
        assert_eq!(
            holder.phase_v1(prepared.handle()).unwrap(),
            BootleLanternHolderPhaseV1::ResponseCached
        );
        drop(holder);
        let holder = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        let recovered_request = holder
            .pending_request_v1(prepared.handle(), &context, genesis_hash, &policy)
            .unwrap();
        assert_eq!(recovered_request.as_slice(), prepared.request_bytes());
        holder
            .resume_cached_response_v1(prepared.handle(), &context, genesis_hash, &policy)
            .expect("restart finalization");
        assert_eq!(
            holder.phase_v1(prepared.handle()).unwrap(),
            BootleLanternHolderPhaseV1::Finalized
        );
        drop(holder);
        let holder = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        assert_eq!(
            holder.phase_v1(prepared.handle()).unwrap(),
            BootleLanternHolderPhaseV1::Finalized
        );
        holder
            .accept_issuer_response_v1(
                prepared.handle(),
                &context,
                genesis_hash,
                &policy,
                &response_bytes,
            )
            .expect("idempotent finalized response retry");
        let statement = presentation_statement_v1(context.clone(), &policy);
        let mut presentation_rng = TestRng::healthy(0x510e_527f_ade6_82d1);
        let proof = holder
            .prove_presentation_encoded_with_rng_v1(
                prepared.handle(),
                &statement,
                &policy,
                genesis_hash,
                &mut presentation_rng,
            )
            .expect("proof-only credential use");
        super::super::verify_bound_presentation_encoded_v1(
            &statement,
            &policy,
            genesis_hash,
            &proof,
            u32::try_from(PROOF_BYTES_V1).unwrap(),
        )
        .expect("holder-produced presentation verifies");
        assert_eq!(fs::read_dir(&holder.objects_root).unwrap().count(), 1);
    }
    #[test]
    fn manifest_roundtrip_rejects_every_truncation_and_trailing_byte() {
        let empty = HolderManifestV1::empty(digest(9)).unwrap();
        let manifest = empty
            .successor_with_entry(
                synthetic_entry(BootleLanternHolderPhaseV1::Pending),
                HOLDER_HARD_MAX_RECORDS_V1,
            )
            .unwrap();
        let bytes = encode_manifest_v1(&manifest).unwrap();
        assert_eq!(bytes.len(), 116 + HOLDER_MANIFEST_ENTRY_BYTES_V1);
        assert_eq!(
            decode_manifest_v1(&bytes, digest(9), HOLDER_HARD_MAX_RECORDS_V1).unwrap(),
            manifest
        );
        for length in 0..bytes.len() {
            assert!(
                decode_manifest_v1(&bytes[..length], digest(9), HOLDER_HARD_MAX_RECORDS_V1)
                    .is_err(),
                "accepted manifest prefix {length}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_manifest_v1(&trailing, digest(9), HOLDER_HARD_MAX_RECORDS_V1).is_err());
    }
    #[test]
    fn manifest_rejects_header_counts_order_bindings_and_revision_substitution() {
        let empty = HolderManifestV1::empty(digest(9)).unwrap();
        let manifest = empty
            .successor_with_entry(
                synthetic_entry(BootleLanternHolderPhaseV1::Pending),
                HOLDER_HARD_MAX_RECORDS_V1,
            )
            .unwrap();
        let bytes = encode_manifest_v1(&manifest).unwrap();
        for offset in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(
                decode_manifest_v1(&changed, digest(9), HOLDER_HARD_MAX_RECORDS_V1).is_err(),
                "accepted manifest mutation at {offset}"
            );
        }
        assert!(decode_manifest_v1(&bytes, digest(8), HOLDER_HARD_MAX_RECORDS_V1).is_err());
        assert!(decode_manifest_v1(&bytes, digest(9), 0).is_err());
    }
    #[test]
    fn sealed_head_ambiguous_commit_reconciles_exactly() {
        let heads = TestHeads::new();
        heads.inject(BootleLanternHolderExternalErrorV1::Ambiguous);
        let qualification = heads.qualification().unwrap();
        let manifest = load_or_create_manifest_v1(
            digest(9),
            BootleLanternHolderStoreConfigV1::default(),
            &heads,
            qualification,
        )
        .unwrap();
        assert_eq!(manifest.generation, 1);
        let next = manifest
            .successor_with_entry(
                synthetic_entry(BootleLanternHolderPhaseV1::Pending),
                HOLDER_HARD_MAX_RECORDS_V1,
            )
            .unwrap();
        heads.inject(BootleLanternHolderExternalErrorV1::Ambiguous);
        publish_manifest_v1(digest(9), &manifest, &next, &heads, qualification).unwrap();
        assert_eq!(
            heads.head.lock().unwrap().as_ref().unwrap().revision(),
            next.revision
        );
    }
    #[test]
    fn sealed_head_rejects_rollback_fork_and_provider_drift() {
        let heads = TestHeads::new();
        let qualification = heads.qualification().unwrap();
        let manifest = load_or_create_manifest_v1(
            digest(9),
            BootleLanternHolderStoreConfigV1::default(),
            &heads,
            qualification,
        )
        .unwrap();
        let next = manifest
            .successor_with_entry(
                synthetic_entry(BootleLanternHolderPhaseV1::Pending),
                HOLDER_HARD_MAX_RECORDS_V1,
            )
            .unwrap();
        *heads.head.lock().unwrap() = Some(next.sealed_head().unwrap());
        assert_eq!(
            publish_manifest_v1(digest(9), &manifest, &next, &heads, qualification),
            Ok(())
        );
        let mut fork = next.sealed_head().unwrap();
        fork.revision[0] ^= 1;
        *heads.head.lock().unwrap() = Some(fork);
        assert_eq!(
            publish_manifest_v1(digest(9), &manifest, &next, &heads, qualification),
            Err(BootleLanternHolderStoreErrorV1::RollbackDetected)
        );
        *heads.qualification.lock().unwrap() =
            BootleLanternHolderProviderQualificationV1::new(2, digest(7));
        assert_eq!(
            ensure_sealed_qualification_v1(&heads, qualification),
            Err(BootleLanternHolderStoreErrorV1::ProviderDrift)
        );
    }
    #[test]
    fn encrypted_object_commit_readback_and_restart_are_authoritative() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        let handle = publish_rejected_test_record_v1(&store, 0x51).unwrap();
        assert_eq!(
            store.phase_v1(handle).unwrap(),
            BootleLanternHolderPhaseV1::Rejected
        );
        let generation = heads.head.lock().unwrap().as_ref().unwrap().generation();
        assert_eq!(generation, 2);
        drop(store);
        let reopened = open_test_store_v1(&root, wrapper, heads).unwrap();
        assert_eq!(
            reopened.phase_v1(handle).unwrap(),
            BootleLanternHolderPhaseV1::Rejected
        );
    }
    #[test]
    fn pre_rename_failure_is_retryable_but_post_rename_uncertainty_poisons() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        let handle = BootleLanternHolderHandleV1::new(digest(0x61)).unwrap();
        store.inject_next_write_before_rename_failure_v1();
        assert_eq!(
            publish_rejected_test_record_v1(&store, 0x61),
            Err(BootleLanternHolderStoreErrorV1::Backend)
        );
        assert_eq!(
            store.phase_v1(handle),
            Err(BootleLanternHolderStoreErrorV1::NotFound)
        );
        store.inject_next_write_after_rename_failure_v1();
        assert_eq!(
            publish_rejected_test_record_v1(&store, 0x61),
            Err(BootleLanternHolderStoreErrorV1::DurabilityUncertain)
        );
        assert_eq!(
            store.phase_v1(handle),
            Err(BootleLanternHolderStoreErrorV1::DurabilityUncertain)
        );
        assert_eq!(heads.head.lock().unwrap().as_ref().unwrap().generation(), 1);
        drop(store);
        let reopened = open_test_store_v1(&root, wrapper, heads).unwrap();
        assert_eq!(
            reopened.phase_v1(handle),
            Err(BootleLanternHolderStoreErrorV1::NotFound)
        );
    }
    #[test]
    fn committed_cas_with_failed_readback_is_uncertain_until_exact_reopen() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        let handle = BootleLanternHolderHandleV1::new(digest(0x69)).unwrap();
        heads.inject_post_cas_load_failure(BootleLanternHolderExternalErrorV1::Unavailable);
        assert_eq!(
            publish_rejected_test_record_v1(&store, 0x69),
            Err(BootleLanternHolderStoreErrorV1::DurabilityUncertain)
        );
        assert_eq!(heads.head.lock().unwrap().as_ref().unwrap().generation(), 2);
        assert_eq!(
            store.phase_v1(handle),
            Err(BootleLanternHolderStoreErrorV1::DurabilityUncertain)
        );
        drop(store);
        let reopened = open_test_store_v1(&root, wrapper, heads).unwrap();
        assert_eq!(
            reopened.phase_v1(handle).unwrap(),
            BootleLanternHolderPhaseV1::Rejected
        );
    }
    #[test]
    fn ambiguous_cas_without_commit_fails_closed_and_restart_discards_orphan() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        let handle = BootleLanternHolderHandleV1::new(digest(0x71)).unwrap();
        heads.inject_ambiguous_without_commit();
        assert_eq!(
            publish_rejected_test_record_v1(&store, 0x71),
            Err(BootleLanternHolderStoreErrorV1::RollbackDetected)
        );
        assert_eq!(
            store.phase_v1(handle),
            Err(BootleLanternHolderStoreErrorV1::DurabilityUncertain)
        );
        drop(store);
        let reopened = open_test_store_v1(&root, wrapper, heads).unwrap();
        assert_eq!(
            reopened.phase_v1(handle),
            Err(BootleLanternHolderStoreErrorV1::NotFound)
        );
    }
    #[cfg(unix)]
    #[test]
    fn restart_streams_multiple_orphans_without_collecting_paths() {
        use std::os::unix::fs::PermissionsExt as _;
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        heads.inject_ambiguous_without_commit();
        assert_eq!(
            publish_rejected_test_record_v1(&store, 0x72),
            Err(BootleLanternHolderStoreErrorV1::RollbackDetected)
        );
        let orphan_path = fs::read_dir(&store.objects_root)
            .unwrap()
            .next()
            .expect("ambiguous publication leaves one orphan")
            .unwrap()
            .path();
        let mut second_bytes = fs::read(orphan_path).unwrap();
        *second_bytes.last_mut().expect("envelope is non-empty") ^= 1;
        let second_digest = envelope_digest_v1(&second_bytes);
        let second_path = store
            .objects_root
            .join(holder_object_file_name_v1(second_digest));
        fs::write(&second_path, second_bytes).unwrap();
        fs::set_permissions(&second_path, fs::Permissions::from_mode(0o600)).unwrap();
        drop(store);
        let reopened = open_test_store_v1(&root, wrapper, heads).unwrap();
        assert_eq!(
            fs::read_dir(&reopened.objects_root).unwrap().count(),
            0,
            "streaming recovery removes every validated orphan"
        );
    }
    #[test]
    fn unavailable_cas_does_not_publish_and_is_retryable() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        let handle = BootleLanternHolderHandleV1::new(digest(0x79)).unwrap();
        heads.inject(BootleLanternHolderExternalErrorV1::Unavailable);
        assert_eq!(
            publish_rejected_test_record_v1(&store, 0x79),
            Err(BootleLanternHolderStoreErrorV1::ProviderUnavailable)
        );
        assert_eq!(
            store.phase_v1(handle),
            Err(BootleLanternHolderStoreErrorV1::NotFound)
        );
        assert_eq!(heads.head.lock().unwrap().as_ref().unwrap().generation(), 1);
        assert_eq!(publish_rejected_test_record_v1(&store, 0x79), Ok(handle));
        assert_eq!(
            store.phase_v1(handle).unwrap(),
            BootleLanternHolderPhaseV1::Rejected
        );
        drop(store);
        let reopened = open_test_store_v1(&root, wrapper, heads).unwrap();
        assert_eq!(fs::read_dir(&reopened.objects_root).unwrap().count(), 1);
    }
    #[test]
    fn authoritative_head_rollback_poisons_live_store_even_if_head_is_restored() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, wrapper, Arc::clone(&heads)).unwrap();
        let initial = heads.head.lock().unwrap().clone().unwrap();
        let handle = publish_rejected_test_record_v1(&store, 0x81).unwrap();
        let current = heads.head.lock().unwrap().clone().unwrap();
        *heads.head.lock().unwrap() = Some(initial);
        assert_eq!(
            store.phase_v1(handle),
            Err(BootleLanternHolderStoreErrorV1::RollbackDetected)
        );
        *heads.head.lock().unwrap() = Some(current);
        assert_eq!(
            store.phase_v1(handle),
            Err(BootleLanternHolderStoreErrorV1::DurabilityUncertain)
        );
    }
    #[test]
    fn unusable_wrapped_dek_never_advances_the_sealed_head() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::zero_unwrap());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, wrapper, Arc::clone(&heads)).unwrap();
        assert_eq!(
            publish_rejected_test_record_v1(&store, 0x91),
            Err(BootleLanternHolderStoreErrorV1::KeyWrapping)
        );
        assert_eq!(heads.head.lock().unwrap().as_ref().unwrap().generation(), 1);
        assert_eq!(fs::read_dir(&store.objects_root).unwrap().count(), 0);
    }
    #[test]
    fn restart_audits_every_active_dek_before_open_succeeds() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, wrapper, Arc::clone(&heads)).unwrap();
        publish_rejected_test_record_v1(&store, 0x99).unwrap();
        drop(store);
        assert_eq!(
            open_test_store_v1(&root, Arc::new(TestWrapper::zero_unwrap()), heads).unwrap_err(),
            BootleLanternHolderStoreErrorV1::KeyWrapping
        );
    }
    #[test]
    fn active_object_substitution_and_permission_widening_fail_reopen() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        publish_rejected_test_record_v1(&store, 0xa1).unwrap();
        let envelope_digest = store
            .state
            .lock()
            .unwrap()
            .manifest
            .entries
            .values()
            .next()
            .unwrap()
            .envelope_digest;
        let object = store
            .objects_root
            .join(holder_object_file_name_v1(envelope_digest));
        drop(store);
        let mut bytes = fs::read(&object).unwrap();
        bytes[HOLDER_ENVELOPE_HEADER_BYTES_V1] ^= 1;
        fs::write(&object, &bytes).unwrap();
        assert_eq!(
            open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap_err(),
            BootleLanternHolderStoreErrorV1::Corrupt
        );
        bytes[HOLDER_ENVELOPE_HEADER_BYTES_V1] ^= 1;
        fs::write(&object, &bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&object, fs::Permissions::from_mode(0o640)).unwrap();
            assert_eq!(
                open_test_store_v1(&root, wrapper, heads).unwrap_err(),
                BootleLanternHolderStoreErrorV1::Corrupt
            );
        }
    }
    #[test]
    fn sealed_head_constructor_and_provider_drift_reject_noncanonical_state() {
        for (generation, revision, payload) in [
            (0, digest(1), vec![1]),
            (1, [0; 32], vec![1]),
            (1, digest(1), Vec::new()),
            (
                1,
                digest(1),
                vec![0; BOOTLE_LANTERN_HOLDER_MAX_MANIFEST_BYTES_V1 as usize + 1],
            ),
        ] {
            assert!(
                BootleLanternHolderSealedHeadV1::from_canonical_parts_v1(
                    generation, revision, payload
                )
                .is_err()
            );
        }
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, Arc::clone(&wrapper), heads).unwrap();
        *wrapper.qualification.lock().unwrap() =
            BootleLanternHolderProviderQualificationV1::new(2, digest(0xee));
        assert_eq!(
            store.phase_v1(BootleLanternHolderHandleV1::new(digest(1)).unwrap()),
            Err(BootleLanternHolderStoreErrorV1::ProviderDrift)
        );
    }
    #[test]
    fn envelope_header_and_aad_bind_every_public_field() {
        let header = HolderEnvelopeHeaderV1 {
            phase: BootleLanternHolderPhaseV1::Pending,
            vault_id: digest(1),
            authorization_digest: digest(2),
            request_digest: digest(3),
            scope_digest: digest(4),
            policy_record_digest: digest(5),
            response_digest: [0; 32],
            predecessor_envelope_digest: [0; 32],
            entry_generation: 2,
            plaintext_len: BOOTLE_LANTERN_HOLDER_PENDING_PLAINTEXT_BYTES_V1 as u32,
            ciphertext_len: (BOOTLE_LANTERN_HOLDER_PENDING_PLAINTEXT_BYTES_V1
                + HOLDER_AEAD_TAG_BYTES_V1) as u32,
            key_id_len: 5,
            wrapped_dek_len: 32,
            nonce: [7; 24],
        };
        let envelope = HolderEnvelopeV1 {
            header,
            wrapping_key_id: "key-1".to_owned(),
            wrapped_dek: vec![8; 32],
            ciphertext: vec![9; BOOTLE_LANTERN_HOLDER_PENDING_PLAINTEXT_BYTES_V1 + 16],
        };
        let encoded = encode_envelope_v1(&envelope).unwrap();
        assert_eq!(decode_envelope_v1(&encoded).unwrap(), envelope);
        let baseline = envelope_aad_v1(&envelope).unwrap();
        for length in 0..encoded.len() {
            assert!(
                decode_envelope_v1(&encoded[..length]).is_err(),
                "accepted envelope prefix {length}"
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_envelope_v1(&trailing).is_err());
        for offset in 0..HOLDER_ENVELOPE_HEADER_BYTES_V1 {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 1;
            if let Ok(decoded) = decode_envelope_v1(&mutated) {
                assert_ne!(envelope_aad_v1(&decoded).unwrap(), baseline);
            }
        }
        let mut changed = envelope.clone();
        changed.wrapped_dek[0] ^= 1;
        assert_ne!(envelope_aad_v1(&changed).unwrap(), baseline);
        changed = envelope.clone();
        changed.wrapping_key_id = "key-2".to_owned();
        assert_ne!(envelope_aad_v1(&changed).unwrap(), baseline);
    }
    #[test]
    fn rejected_secret_codec_rejects_every_truncation_trailing_and_mutation() {
        let bytes =
            encode_rejected_secret_v1(digest(1), digest(2), digest(3), digest(4), digest(5), 1)
                .unwrap();
        assert_eq!(
            decode_rejected_secret_v1(bytes.as_slice()).unwrap(),
            [digest(1), digest(2), digest(3), digest(4), digest(5)]
        );
        for length in 0..bytes.len() {
            assert!(decode_rejected_secret_v1(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(decode_rejected_secret_v1(&trailing).is_err());
        for offset in 0..bytes.len() {
            let mut changed = bytes.to_vec();
            changed[offset] ^= 1;
            if (8..168).contains(&offset) {
                // Binding bytes have no inner checksum; the authenticated
                // envelope and manifest provide their integrity.
                assert_ne!(
                    decode_rejected_secret_v1(&changed).unwrap(),
                    [digest(1), digest(2), digest(3), digest(4), digest(5),]
                );
            } else {
                assert!(decode_rejected_secret_v1(&changed).is_err());
            }
        }
    }
    #[test]
    fn private_directory_and_content_address_reject_symlink_hardlink_and_substitution() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        ensure_holder_root_v1(&root).unwrap();
        let objects = root.join(HOLDER_OBJECTS_DIRECTORY_V1);
        ensure_private_subdirectory_v1(&root, &objects).unwrap();
        let bytes = vec![1_u8; 64];
        let digest = envelope_digest_v1(&bytes);
        let path = objects.join(holder_object_file_name_v1(digest));
        fs::write(&path, &bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read_regular_bounded_v1(&path, 128).unwrap(), bytes);
        fs::write(&path, [2_u8; 64]).unwrap();
        assert_ne!(envelope_digest_v1(&fs::read(&path).unwrap()), digest);
        #[cfg(unix)]
        {
            let alias = parent.path().join("alias");
            fs::hard_link(&path, &alias).unwrap();
            assert_eq!(
                read_regular_bounded_v1(&path, 128),
                Err(BootleLanternHolderStoreErrorV1::Corrupt)
            );
            fs::remove_file(alias).unwrap();
            fs::remove_file(&path).unwrap();
            let outside = parent.path().join("outside");
            fs::write(&outside, b"sentinel").unwrap();
            std::os::unix::fs::symlink(&outside, &path).unwrap();
            assert_eq!(
                read_regular_bounded_v1(&path, 128),
                Err(BootleLanternHolderStoreErrorV1::Corrupt)
            );
            assert_eq!(fs::read(outside).unwrap(), b"sentinel");
        }
    }
    #[test]
    fn vault_lease_writer_lock_and_root_identity_reject_aliasing() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("holder");
        let wrapper = Arc::new(TestWrapper::exact());
        let heads = Arc::new(TestHeads::new());
        let store = open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap();
        assert_eq!(
            open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap_err(),
            BootleLanternHolderStoreErrorV1::StoreAlreadyOpen
        );
        drop(store);
        #[cfg(unix)]
        {
            let lock = root.join(HOLDER_WRITER_LOCK_FILE_V1);
            let alias = parent.path().join("lock-alias");
            fs::hard_link(&lock, &alias).unwrap();
            assert_eq!(
                open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap_err(),
                BootleLanternHolderStoreErrorV1::Corrupt
            );
            fs::remove_file(alias).unwrap();
            let unknown = root.join("unexpected");
            fs::write(&unknown, b"unexpected root entry").unwrap();
            assert_eq!(
                open_test_store_v1(&root, Arc::clone(&wrapper), Arc::clone(&heads)).unwrap_err(),
                BootleLanternHolderStoreErrorV1::Corrupt
            );
            fs::remove_file(unknown).unwrap();
            let root_alias = parent.path().join("holder-alias");
            std::os::unix::fs::symlink(&root, &root_alias).unwrap();
            assert_eq!(
                open_test_store_v1(&root_alias, wrapper, heads).unwrap_err(),
                BootleLanternHolderStoreErrorV1::Corrupt
            );
        }
    }
    #[test]
    fn qualification_and_bounds_reject_zero_oversize_and_noncanonical_values() {
        for max_records in [0, HOLDER_HARD_MAX_RECORDS_V1 + 1] {
            assert_eq!(
                BootleLanternHolderStoreConfigV1::new(max_records),
                Err(BootleLanternHolderStoreErrorV1::ConfigurationInvalid)
            );
        }
        for qualification in [
            BootleLanternHolderProviderQualificationV1::new(0, digest(1)),
            BootleLanternHolderProviderQualificationV1::new(1, [0; 32]),
            BootleLanternHolderProviderQualificationV1 {
                version: 2,
                revision: 1,
                policy_digest: digest(1),
            },
        ] {
            assert_eq!(
                qualification.validate(),
                Err(BootleLanternHolderStoreErrorV1::ProviderUnqualified)
            );
        }
        assert!(validate_runtime_handle_v1("").is_err());
        assert!(validate_runtime_handle_v1("contains space").is_err());
        assert!(validate_runtime_handle_v1(&"x".repeat(256)).is_err());
    }
}
