//! Authenticated Torii boundary for the SoraFS proof-of-personhood service.
//!
//! This module never accepts plaintext enrollment, credential, issuance-draft, holder-secret, or
//! Merkle-witness material over HTTP. Those values are supplied only by runtime-owned adapters and
//! remain behind the authority and durability checks in [`sorafs_node::pop_credentials`].
use crate::{JsonBody, SharedAppState, utils::extractors::NoritoJson};
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroha_config::parameters::{ProductionRuntimeHandleError, validate_production_runtime_handle};
#[cfg(test)]
use iroha_crypto::HybridSecretKey;
use norito::derive::{JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize};
use rand::rngs::OsRng;
use sorafs_manifest::{
    hybrid_envelope::HybridPayloadEnvelopeV1,
    pop_credentials::{
        POP_IDENTITY_TEXT_MAX_BYTES_V1, POP_MEMBERSHIP_CONTEXT_MAX_BYTES_V1,
        POP_MEMBERSHIP_PROOF_MAX_BYTES_V1, PopMembershipProofV1, PopMembershipWitnessV1,
        PopRevocationListV1,
    },
};
#[cfg(test)]
use sorafs_node::pop_credentials::PopRequestAuthorityV1;
#[cfg(test)]
use sorafs_node::pop_credentials::pop_enrollment_recipient_public_key_digest_v1;
use sorafs_node::pop_credentials::{
    POP_API_AUTHENTICATION_MAX_BYTES_V1, POP_CREDENTIAL_SERVICE_POLICY_VERSION_V1,
    POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1, POP_SERVICE_COLLECTION_MAX_V1, PopApprovalSignerV1,
    PopApprovalV1, PopCommittedRegistryContextV1, PopCredentialApiActionV1,
    PopCredentialApiAuthenticator, PopCredentialApiV1, PopCredentialService,
    PopCredentialServiceError, PopCredentialServicePolicyV1, PopEnrollmentRecipientV1,
    PopEnrollmentStateV1, PopEnrollmentStatusV1, PopFinalizedCursorV1,
    PopFinalizedRegistryProjectionV1, PopFinalizedRegistryReader, PopIssuanceDraftV1,
    PopIssuerSigner, PopIssuerSigningPurposeV1, PopOutboxSubmitOutcomeV1, PopRecipientOpenErrorV1,
    PopRegistrySubmitter, PopWalletKeyWrapper, PopWalletRecipientV1, PopWalletVault,
};
use std::{fmt, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Mutex;
/// Dedicated credential header. The value is `PopV1 <base64url-no-pad>`.
pub const POP_AUTHORIZATION_HEADER_V1: &str = "sora-pop-authorization";
/// Maximum canonical approval or other small signed control payload.
pub const POP_CONTROL_PAYLOAD_MAX_BYTES_V1: usize = 256 * 1024;
/// Maximum JSON/Norito request envelope for small PoP control operations.
pub const POP_CONTROL_REQUEST_MAX_BYTES_V1: usize = 384 * 1024;
/// Maximum request envelope for encrypted enrollment submission.
pub const POP_ENROLLMENT_REQUEST_MAX_BYTES_V1: usize =
    canonical_base64_max_len(POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1) + 8 * 1024;
/// Maximum request envelope for membership proofs.
pub const POP_PROOF_REQUEST_MAX_BYTES_V1: usize =
    canonical_base64_max_len(POP_MEMBERSHIP_PROOF_MAX_BYTES_V1) + 64 * 1024;
const POP_CANONICAL_DECODE_MAX_DEPTH_V1: usize = 64;
const fn canonical_base64_max_len(decoded_len: usize) -> usize {
    decoded_len.div_ceil(3).saturating_mul(4)
}
/// Drop guard for decoded opaque authorization material.
///
/// This type is deliberately neither cloneable nor serializable. Every exit
/// path overwrites the owned credential bytes before releasing the allocation.
struct PopApiCredentialV1 {
    bytes: Vec<u8>,
    #[cfg(test)]
    drop_probe: Option<Arc<std::sync::Mutex<Vec<u8>>>>,
}
impl PopApiCredentialV1 {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            drop_probe: None,
        }
    }
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl fmt::Debug for PopApiCredentialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PopApiCredentialV1([REDACTED])")
    }
}
impl Drop for PopApiCredentialV1 {
    fn drop(&mut self) {
        self.bytes.fill(0);
        std::hint::black_box(self.bytes.as_slice());
        #[cfg(test)]
        if let Some(probe) = &self.drop_probe
            && let Ok(mut observed) = probe.lock()
        {
            observed.clone_from(&self.bytes);
        }
    }
}
/// Non-secret, config-backed runtime settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PopCredentialRuntimeConfigV1 {
    /// Exact finalized service policy.
    pub service_policy: PopCredentialServicePolicyV1,
    /// Durable issuer state directory.
    pub issuer_state_dir: PathBuf,
    /// Encrypted wallet-vault directory.
    pub wallet_state_dir: PathBuf,
    /// Bounded submission/reconciliation worker cadence.
    pub worker_interval: Duration,
    /// Maximum absolute skew between finalized and runtime clock time.
    pub max_finalized_time_skew: Duration,
    /// Digest of the exact hybrid enrollment-recipient public key.
    pub enrollment_recipient_public_key_digest: [u8; 32],
    /// Exact non-secret wallet-recipient protected-key handle.
    pub wallet_recipient_key_id: String,
    /// Digest of the exact hybrid wallet-recipient public key.
    pub wallet_recipient_public_key_digest: [u8; 32],
    /// Exact non-secret wallet wrapping-key handle.
    pub wallet_wrapping_key_id: String,
    /// Exact non-secret deployment runtime-provider registry handle.
    pub runtime_provider_registry_handle: String,
    /// Exact non-zero deployment registry policy revision.
    pub runtime_provider_registry_revision: u64,
    /// Exact deployment registry policy digest.
    pub runtime_provider_registry_policy_digest: [u8; 32],
}
impl PopCredentialRuntimeConfigV1 {
    /// Validate configuration before any runtime secret is consumed.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid service policy, state directories, timing
    /// bounds, zero public bindings, or noncanonical runtime handles.
    pub fn validate(&self) -> Result<(), PopCredentialServiceError> {
        self.service_policy.validate()?;
        if self.issuer_state_dir.as_os_str().is_empty()
            || self.wallet_state_dir.as_os_str().is_empty()
            || self.issuer_state_dir == self.wallet_state_dir
            || self.worker_interval.is_zero()
            || self.worker_interval > Duration::from_secs(60 * 60)
            || self.max_finalized_time_skew > Duration::from_secs(5 * 60)
            || self.max_finalized_time_skew.subsec_nanos() != 0
            || self.enrollment_recipient_public_key_digest == [0; 32]
            || self.wallet_recipient_public_key_digest == [0; 32]
            || self.runtime_provider_registry_revision == 0
            || self.runtime_provider_registry_policy_digest == [0; 32]
        {
            return Err(PopCredentialServiceError::InvalidInput {
                field: "pop_runtime_config",
            });
        }
        validate_pop_runtime_provider_handle(
            &self.runtime_provider_registry_handle,
            "runtime_provider_registry_handle",
        )?;
        validate_pop_runtime_provider_handle(
            &self.wallet_recipient_key_id,
            "wallet_recipient_key_id",
        )?;
        validate_pop_runtime_provider_handle(
            &self.wallet_wrapping_key_id,
            "wallet_wrapping_key_id",
        )?;
        Ok(())
    }
}
impl From<&iroha_config::parameters::actual::SorafsPopCredentialService>
    for PopCredentialRuntimeConfigV1
{
    fn from(value: &iroha_config::parameters::actual::SorafsPopCredentialService) -> Self {
        Self {
            service_policy: PopCredentialServicePolicyV1 {
                version: POP_CREDENTIAL_SERVICE_POLICY_VERSION_V1,
                issuer_policy_digest: value.issuer_policy_digest,
                issuer_id: value.issuer_id.clone(),
                issuer_signer_handle: value.issuer_signer_handle.clone(),
                issuer_public_key: value.issuer_public_key,
                enrollment_recipient_key_id: value.enrollment_recipient_key_id.clone(),
                approval_quorum: value.approval_quorum,
                approval_signers: value
                    .approval_signers
                    .iter()
                    .map(|signer| PopApprovalSignerV1 {
                        signer_id: signer.signer_id.clone(),
                        public_key: signer.public_key,
                        revoked_at_epoch: signer.revoked_at_epoch,
                    })
                    .collect(),
                max_pending_enrollments: value.max_pending_enrollments,
                max_outbox_entries: value.max_outbox_entries,
                max_dead_letters: value.max_dead_letters,
                max_seen_nullifiers: value.max_seen_nullifiers,
                max_submission_attempts: value.max_submission_attempts,
            },
            issuer_state_dir: value.issuer_state_dir.clone(),
            wallet_state_dir: value.wallet_state_dir.clone(),
            worker_interval: value.worker_interval,
            max_finalized_time_skew: value.max_finalized_time_skew,
            enrollment_recipient_public_key_digest: value.enrollment_recipient_public_key_digest,
            wallet_recipient_key_id: value.wallet_recipient_key_id.clone(),
            wallet_recipient_public_key_digest: value.wallet_recipient_public_key_digest,
            wallet_wrapping_key_id: value.wallet_wrapping_key_id.clone(),
            runtime_provider_registry_handle: value.runtime_provider_registry_handle.clone(),
            runtime_provider_registry_revision: value.runtime_provider_registry_revision,
            runtime_provider_registry_policy_digest: value.runtime_provider_registry_policy_digest,
        }
    }
}
fn validate_pop_runtime_provider_handle(
    value: &str,
    field: &'static str,
) -> Result<(), PopCredentialServiceError> {
    validate_production_runtime_handle(value).map_err(|error| match error {
        ProductionRuntimeHandleError::InvalidSyntax | ProductionRuntimeHandleError::TestMarked => {
            PopCredentialServiceError::InvalidInput { field }
        }
    })
}
/// Exact public bindings supplied to a deployment-owned PoP provider registry.
///
/// The request contains stable handles and finalized public policy identity
/// only. Durable paths, credentials, recipient secrets, witnesses,
/// attestations, wallet material, and PII are deliberately excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PopCredentialRuntimeProviderBindingsV1 {
    issuer_policy_digest: [u8; 32],
    issuer_id: String,
    issuer_signer_handle: String,
    issuer_public_key: [u8; 32],
    enrollment_recipient_key_id: String,
    enrollment_recipient_public_key_digest: [u8; 32],
    wallet_recipient_key_id: String,
    wallet_recipient_public_key_digest: [u8; 32],
    wallet_wrapping_key_id: String,
}
impl PopCredentialRuntimeProviderBindingsV1 {
    /// Construct exact, validated public bindings for a deployment registry.
    ///
    /// Every V1 field is required by this typed constructor. Runtime handles
    /// must use canonical production syntax and may not be test-marked.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or noncanonical issuer identity, invalid
    /// production handles, an invalid Ed25519 key, or zero policy or recipient digests.
    pub fn try_new(
        issuer_policy_digest: [u8; 32],
        issuer_id: String,
        issuer_signer_handle: String,
        issuer_public_key: [u8; 32],
        (enrollment_recipient_key_id, enrollment_recipient_public_key_digest): (String, [u8; 32]),
        (wallet_recipient_key_id, wallet_recipient_public_key_digest): (String, [u8; 32]),
        wallet_wrapping_key_id: String,
    ) -> Result<Self, PopCredentialServiceError> {
        if issuer_policy_digest == [0; 32] {
            return Err(PopCredentialServiceError::InvalidInput {
                field: "issuer_policy_digest",
            });
        }
        if issuer_id.is_empty()
            || issuer_id != issuer_id.trim()
            || issuer_id.len() > POP_IDENTITY_TEXT_MAX_BYTES_V1
            || issuer_id.chars().any(char::is_control)
        {
            return Err(PopCredentialServiceError::InvalidInput { field: "issuer_id" });
        }
        validate_pop_runtime_provider_handle(&issuer_signer_handle, "issuer_signer_handle")?;
        validate_pop_runtime_provider_handle(
            &enrollment_recipient_key_id,
            "enrollment_recipient_key_id",
        )?;
        validate_pop_runtime_provider_handle(&wallet_recipient_key_id, "wallet_recipient_key_id")?;
        validate_pop_runtime_provider_handle(&wallet_wrapping_key_id, "wallet_wrapping_key_id")?;
        if issuer_public_key == [0; 32]
            || iroha_crypto::ed25519_parse_public_key(&issuer_public_key).is_err()
        {
            return Err(PopCredentialServiceError::InvalidInput {
                field: "issuer_public_key",
            });
        }
        if enrollment_recipient_public_key_digest == [0; 32] {
            return Err(PopCredentialServiceError::InvalidInput {
                field: "enrollment_recipient_public_key_digest",
            });
        }
        if wallet_recipient_public_key_digest == [0; 32] {
            return Err(PopCredentialServiceError::InvalidInput {
                field: "wallet_recipient_public_key_digest",
            });
        }
        Ok(Self {
            issuer_policy_digest,
            issuer_id,
            issuer_signer_handle,
            issuer_public_key,
            enrollment_recipient_key_id,
            enrollment_recipient_public_key_digest,
            wallet_recipient_key_id,
            wallet_recipient_public_key_digest,
            wallet_wrapping_key_id,
        })
    }
    fn from_config(
        config: &PopCredentialRuntimeConfigV1,
    ) -> Result<Self, PopCredentialServiceError> {
        Self::try_new(
            config.service_policy.issuer_policy_digest,
            config.service_policy.issuer_id.clone(),
            config.service_policy.issuer_signer_handle.clone(),
            config.service_policy.issuer_public_key,
            (
                config.service_policy.enrollment_recipient_key_id.clone(),
                config.enrollment_recipient_public_key_digest,
            ),
            (
                config.wallet_recipient_key_id.clone(),
                config.wallet_recipient_public_key_digest,
            ),
            config.wallet_wrapping_key_id.clone(),
        )
    }
    /// Exact active finalized issuer-policy digest.
    #[must_use]
    pub const fn issuer_policy_digest(&self) -> [u8; 32] {
        self.issuer_policy_digest
    }
    /// Exact governed public issuer identity.
    #[must_use]
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }
    /// Exact non-secret external signer handle.
    #[must_use]
    pub fn issuer_signer_handle(&self) -> &str {
        &self.issuer_signer_handle
    }
    /// Exact governed issuer public key.
    #[must_use]
    pub const fn issuer_public_key(&self) -> [u8; 32] {
        self.issuer_public_key
    }
    /// Exact non-secret encrypted-enrollment recipient handle.
    #[must_use]
    pub fn enrollment_recipient_key_id(&self) -> &str {
        &self.enrollment_recipient_key_id
    }
    /// Digest of the exact hybrid enrollment-recipient public key.
    #[must_use]
    pub const fn enrollment_recipient_public_key_digest(&self) -> [u8; 32] {
        self.enrollment_recipient_public_key_digest
    }
    /// Exact non-secret wallet-recipient protected-key handle.
    #[must_use]
    pub fn wallet_recipient_key_id(&self) -> &str {
        &self.wallet_recipient_key_id
    }
    /// Digest of the exact hybrid wallet-recipient public key.
    #[must_use]
    pub const fn wallet_recipient_public_key_digest(&self) -> [u8; 32] {
        self.wallet_recipient_public_key_digest
    }
    /// Exact non-secret wallet wrapping-key handle.
    #[must_use]
    pub fn wallet_wrapping_key_id(&self) -> &str {
        &self.wallet_wrapping_key_id
    }
}
/// Public identity of one deployment-owned PoP provider-registry policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PopCredentialRuntimeProviderQualificationV1 {
    /// Non-zero external provider policy revision.
    pub revision: u64,
    /// Non-zero digest of the exact external provider policy.
    pub policy_digest: [u8; 32],
}
impl PopCredentialRuntimeProviderQualificationV1 {
    /// Construct one public provider qualification.
    #[must_use]
    pub const fn new(revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            revision,
            policy_digest,
        }
    }
    fn is_valid(self) -> bool {
        self.revision != 0 && self.policy_digest != [0; 32]
    }
}
/// Stable redacted failure returned by a deployment provider registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PopCredentialRuntimeProviderRegistryErrorV1 {
    /// The provider control plane is unavailable.
    Unavailable,
    /// The provider policy is stale or revoked.
    StaleOrRevoked,
    /// The registry rejected the exact configured public bindings.
    RejectedBindings,
}
/// Deployment-owned factory for all PoP private runtime dependencies.
///
/// Implementations must change `qualification` whenever any signer, key-management, authentication,
/// enrollment-recipient, wallet, witness, finalized-query, or transaction adapter identity/policy
/// changes. `resolve` receives only public bindings and must never persist or log private material.
pub trait PopCredentialRuntimeProviderRegistryV1: Send + Sync + fmt::Debug {
    /// Exact stable non-secret registry handle.
    fn handle(&self) -> &str;
    /// Current independently administered public policy qualification.
    ///
    /// # Errors
    ///
    /// Returns an error when the control plane is unavailable or the provider
    /// policy is stale or revoked.
    fn qualification(
        &self,
    ) -> Result<
        PopCredentialRuntimeProviderQualificationV1,
        PopCredentialRuntimeProviderRegistryErrorV1,
    >;
    /// Resolve one coherent runtime provider set for the exact public bindings.
    ///
    /// # Errors
    ///
    /// Returns an error when the control plane is unavailable, its policy is stale
    /// or revoked, or the exact public bindings are rejected.
    fn resolve(
        &self,
        bindings: &PopCredentialRuntimeProviderBindingsV1,
    ) -> Result<PopCredentialRuntimeProvidersV1, PopCredentialRuntimeProviderRegistryErrorV1>;
}
#[derive(Clone)]
struct QualifiedPopCredentialRuntimeProviderRegistryV1 {
    handle: String,
    qualification: PopCredentialRuntimeProviderQualificationV1,
    registry: Arc<dyn PopCredentialRuntimeProviderRegistryV1>,
}
impl fmt::Debug for QualifiedPopCredentialRuntimeProviderRegistryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedPopCredentialRuntimeProviderRegistryV1")
            .field("handle", &self.handle)
            .field("qualification", &self.qualification)
            .finish_non_exhaustive()
    }
}
impl QualifiedPopCredentialRuntimeProviderRegistryV1 {
    fn try_new(
        config: &PopCredentialRuntimeConfigV1,
        registry: Option<Arc<dyn PopCredentialRuntimeProviderRegistryV1>>,
    ) -> Result<Self, PopCredentialServiceError> {
        let registry = registry.ok_or(PopCredentialServiceError::RuntimeProviderRegistryMissing)?;
        validate_pop_runtime_provider_handle(registry.handle(), "runtime_provider_registry_handle")
            .map_err(|_| PopCredentialServiceError::RuntimeProviderRegistryMismatch)?;
        if registry.handle() != config.runtime_provider_registry_handle {
            return Err(PopCredentialServiceError::RuntimeProviderRegistryMismatch);
        }
        let qualification = registry
            .qualification()
            .map_err(|_| PopCredentialServiceError::RuntimeProviderRegistryUnavailable)?;
        let expected = PopCredentialRuntimeProviderQualificationV1::new(
            config.runtime_provider_registry_revision,
            config.runtime_provider_registry_policy_digest,
        );
        if !qualification.is_valid() || qualification != expected {
            return Err(PopCredentialServiceError::RuntimeProviderRegistryMismatch);
        }
        let rechecked_qualification = registry
            .qualification()
            .map_err(|_| PopCredentialServiceError::RuntimeProviderRegistryUnavailable)?;
        if registry.handle() != config.runtime_provider_registry_handle
            || rechecked_qualification != qualification
        {
            return Err(PopCredentialServiceError::RuntimeProviderRegistryDrift);
        }
        Ok(Self {
            handle: config.runtime_provider_registry_handle.clone(),
            qualification,
            registry,
        })
    }
    fn assert_qualification(&self) -> Result<(), PopCredentialServiceError> {
        let qualification = self.registry.qualification().map_err(|error| match error {
            PopCredentialRuntimeProviderRegistryErrorV1::Unavailable => {
                PopCredentialServiceError::RuntimeProviderRegistryUnavailable
            }
            PopCredentialRuntimeProviderRegistryErrorV1::StaleOrRevoked
            | PopCredentialRuntimeProviderRegistryErrorV1::RejectedBindings => {
                PopCredentialServiceError::RuntimeProviderRegistryDrift
            }
        })?;
        if self.registry.handle() != self.handle || qualification != self.qualification {
            return Err(PopCredentialServiceError::RuntimeProviderRegistryDrift);
        }
        Ok(())
    }
    fn resolve(
        &self,
        bindings: &PopCredentialRuntimeProviderBindingsV1,
    ) -> Result<PopCredentialRuntimeProvidersV1, PopCredentialServiceError> {
        self.assert_qualification()?;
        let result = self
            .registry
            .resolve(bindings)
            .map_err(|_| PopCredentialServiceError::RuntimeProviderRegistryUnavailable);
        self.assert_qualification()?;
        result
    }
    fn finish<T>(
        &self,
        result: Result<T, PopCredentialServiceError>,
    ) -> Result<T, PopCredentialServiceError> {
        self.assert_qualification()?;
        result
    }
}
/// Stable runtime-provider failure. Provider details are deliberately absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PopPrivateMaterialProviderErrorV1 {
    /// The runtime provider could not produce current governed material.
    Unavailable,
}
/// Stable failure returned by the runtime-only finalized-time provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PopFinalizedTimeProviderErrorV1 {
    /// No authoritative finalized time sample is currently available.
    Unavailable,
}
/// One authoritative finalized-chain time sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PopFinalizedTimeSampleV1 {
    /// Finalized block height that anchors this sample.
    pub finalized_block_height: u64,
    /// Non-zero finalized block hash.
    pub finalized_block_hash: [u8; 32],
    /// Unix epoch seconds derived from the finalized block timestamp.
    pub finalized_epoch: u64,
    /// Independent Unix epoch observation used only for the skew bound.
    pub observed_epoch: u64,
}
/// Runtime-only provider for finalized-chain time and an independent clock
/// observation. Implementations must source the finalized fields from
/// committed state; no file or environment fallback is permitted.
pub trait PopFinalizedTimeProviderV1: Send + Sync + fmt::Debug {
    /// Return the current authoritative bounded sample.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` if no authoritative finalized-chain time sample
    /// and independent clock observation can be supplied.
    fn sample(&self) -> Result<PopFinalizedTimeSampleV1, PopFinalizedTimeProviderErrorV1>;
}
/// Runtime-only provider for private issuance material.
pub trait PopIssuanceDraftProviderV1: Send + Sync + fmt::Debug {
    /// Resolve a draft for one approved public request identifier.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` if the provider cannot produce current governed
    /// issuance material for the approved request and epoch.
    fn resolve(
        &self,
        request_id: [u8; 32],
        now_epoch: u64,
    ) -> Result<PopIssuanceDraftV1, PopPrivateMaterialProviderErrorV1>;
}
/// Runtime-only provider for a wallet's private updated membership witness.
pub trait PopWalletWitnessProviderV1: Send + Sync + fmt::Debug {
    /// Resolve a private witness for the exact current public projection.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` if the provider cannot produce a private membership
    /// witness matching the credential and current finalized projection.
    fn resolve(
        &self,
        credential_commitment: [u8; 32],
        projection: &PopFinalizedRegistryProjectionV1,
    ) -> Result<PopMembershipWitnessV1, PopPrivateMaterialProviderErrorV1>;
}
/// Runtime-only dependencies. No constructor reads keys from config, files, or
/// environment variables.
pub struct PopCredentialRuntimeProvidersV1 {
    /// Protected enrollment-recipient open capability.
    pub enrollment_recipient: Arc<dyn PopEnrollmentRecipientV1>,
    /// Authenticated external issuer signer.
    pub issuer_signer: Arc<dyn PopIssuerSigner>,
    /// Action- and request-bound API authenticator.
    pub authenticator: Arc<dyn PopCredentialApiAuthenticator>,
    /// Idempotent ledger transaction submitter.
    pub registry_submitter: Arc<dyn PopRegistrySubmitter>,
    /// Finalized ledger projection reader.
    pub registry_reader: Arc<dyn PopFinalizedRegistryReader>,
    /// Private issuance material provider.
    pub issuance_draft_provider: Arc<dyn PopIssuanceDraftProviderV1>,
    /// Protected wallet-recipient open capability.
    pub wallet_recipient: Arc<dyn PopWalletRecipientV1>,
    /// Qualified wallet DEK wrapper.
    pub wallet_key_wrapper: Arc<dyn PopWalletKeyWrapper>,
    /// Private wallet witness provider.
    pub wallet_witness_provider: Arc<dyn PopWalletWitnessProviderV1>,
    /// Finalized-chain time and independent clock provider.
    pub finalized_time_provider: Arc<dyn PopFinalizedTimeProviderV1>,
}
impl fmt::Debug for PopCredentialRuntimeProvidersV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PopCredentialRuntimeProvidersV1([REDACTED])")
    }
}
const POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1: &str = "PoP runtime provider unavailable";
#[derive(Clone)]
struct QualifiedPopIssuerSignerV1 {
    inner: Arc<dyn PopIssuerSigner>,
    key_id: String,
    public_key: [u8; 32],
    registry: QualifiedPopCredentialRuntimeProviderRegistryV1,
}
impl fmt::Debug for QualifiedPopIssuerSignerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedPopIssuerSignerV1")
            .field("key_id", &self.key_id)
            .field("private_provider", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl QualifiedPopIssuerSignerV1 {
    fn identity_matches(&self) -> bool {
        self.inner.key_id() == self.key_id && self.inner.public_key() == self.public_key
    }
}
impl PopIssuerSigner for QualifiedPopIssuerSignerV1 {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
    fn sign_digest(
        &self,
        purpose: PopIssuerSigningPurposeV1,
        digest: [u8; 32],
    ) -> Result<[u8; 64], String> {
        self.registry
            .assert_qualification()
            .map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())?;
        if !self.identity_matches() {
            return Err(POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned());
        }
        let result = self.inner.sign_digest(purpose, digest);
        if !self.identity_matches() {
            return Err(POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned());
        }
        self.registry
            .assert_qualification()
            .map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())?;
        result.map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())
    }
}
#[derive(Clone)]
struct QualifiedPopWalletKeyWrapperV1 {
    inner: Arc<dyn PopWalletKeyWrapper>,
    active_key_id: String,
    registry: QualifiedPopCredentialRuntimeProviderRegistryV1,
}
impl fmt::Debug for QualifiedPopWalletKeyWrapperV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedPopWalletKeyWrapperV1")
            .field("active_key_id", &self.active_key_id)
            .field("private_provider", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl QualifiedPopWalletKeyWrapperV1 {
    fn identity_matches(&self) -> bool {
        self.inner.active_key_id() == self.active_key_id
    }
    fn guard<T>(&self, operation: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        self.registry
            .assert_qualification()
            .map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())?;
        if !self.identity_matches() {
            return Err(POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned());
        }
        let result = operation();
        if !self.identity_matches() {
            return Err(POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned());
        }
        self.registry
            .assert_qualification()
            .map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())?;
        result.map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())
    }
}
impl PopWalletKeyWrapper for QualifiedPopWalletKeyWrapperV1 {
    fn active_key_id(&self) -> &str {
        &self.active_key_id
    }
    fn wrap_dek(&self, context: [u8; 32], dek: &[u8; 32]) -> Result<Vec<u8>, String> {
        self.guard(|| self.inner.wrap_dek(context, dek))
    }
    fn unwrap_dek(
        &self,
        key_id: &str,
        context: [u8; 32],
        wrapped_dek: &[u8],
    ) -> Result<[u8; 32], String> {
        self.guard(|| self.inner.unwrap_dek(key_id, context, wrapped_dek))
    }
}
#[derive(Clone)]
struct QualifiedPopCredentialApiAuthenticatorV1 {
    inner: Arc<dyn PopCredentialApiAuthenticator>,
    registry: QualifiedPopCredentialRuntimeProviderRegistryV1,
}
impl fmt::Debug for QualifiedPopCredentialApiAuthenticatorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QualifiedPopCredentialApiAuthenticatorV1([REDACTED])")
    }
}
impl PopCredentialApiAuthenticator for QualifiedPopCredentialApiAuthenticatorV1 {
    fn authenticate(
        &self,
        opaque_credential: &[u8],
        action: PopCredentialApiActionV1,
        request_binding: [u8; 32],
        now_epoch: u64,
    ) -> Result<sorafs_node::pop_credentials::PopAuthenticatedPrincipalV1, String> {
        self.registry
            .assert_qualification()
            .map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())?;
        let result = self
            .inner
            .authenticate(opaque_credential, action, request_binding, now_epoch);
        self.registry
            .assert_qualification()
            .map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())?;
        result.map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())
    }
}
#[derive(Clone)]
struct QualifiedPopRegistrySubmitterV1 {
    inner: Arc<dyn PopRegistrySubmitter>,
    registry: QualifiedPopCredentialRuntimeProviderRegistryV1,
}
impl fmt::Debug for QualifiedPopRegistrySubmitterV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QualifiedPopRegistrySubmitterV1([REDACTED])")
    }
}
impl PopRegistrySubmitter for QualifiedPopRegistrySubmitterV1 {
    fn submit(
        &self,
        idempotency_key: [u8; 32],
        operation: &sorafs_node::pop_credentials::PopRegistryOperationV1,
    ) -> Result<(), String> {
        self.registry
            .assert_qualification()
            .map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())?;
        let result = self.inner.submit(idempotency_key, operation);
        self.registry
            .assert_qualification()
            .map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())?;
        result.map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())
    }
}
#[derive(Clone)]
struct QualifiedPopFinalizedRegistryReaderV1 {
    inner: Arc<dyn PopFinalizedRegistryReader>,
    registry: QualifiedPopCredentialRuntimeProviderRegistryV1,
}
impl fmt::Debug for QualifiedPopFinalizedRegistryReaderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QualifiedPopFinalizedRegistryReaderV1([REDACTED])")
    }
}
impl PopFinalizedRegistryReader for QualifiedPopFinalizedRegistryReaderV1 {
    fn next_after(
        &self,
        cursor: Option<sorafs_node::pop_credentials::PopFinalizedCursorV1>,
    ) -> Result<Option<PopFinalizedRegistryProjectionV1>, String> {
        self.registry
            .assert_qualification()
            .map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())?;
        let result = self.inner.next_after(cursor);
        self.registry
            .assert_qualification()
            .map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())?;
        result.map_err(|_| POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())
    }
}
#[derive(Clone)]
struct QualifiedPopIssuanceDraftProviderV1 {
    inner: Arc<dyn PopIssuanceDraftProviderV1>,
    registry: QualifiedPopCredentialRuntimeProviderRegistryV1,
}
impl fmt::Debug for QualifiedPopIssuanceDraftProviderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QualifiedPopIssuanceDraftProviderV1([REDACTED])")
    }
}
impl PopIssuanceDraftProviderV1 for QualifiedPopIssuanceDraftProviderV1 {
    fn resolve(
        &self,
        request_id: [u8; 32],
        now_epoch: u64,
    ) -> Result<PopIssuanceDraftV1, PopPrivateMaterialProviderErrorV1> {
        self.registry
            .assert_qualification()
            .map_err(|_| PopPrivateMaterialProviderErrorV1::Unavailable)?;
        let result = self.inner.resolve(request_id, now_epoch);
        self.registry
            .assert_qualification()
            .map_err(|_| PopPrivateMaterialProviderErrorV1::Unavailable)?;
        result.map_err(|_| PopPrivateMaterialProviderErrorV1::Unavailable)
    }
}
#[derive(Clone)]
struct QualifiedPopWalletWitnessProviderV1 {
    inner: Arc<dyn PopWalletWitnessProviderV1>,
    registry: QualifiedPopCredentialRuntimeProviderRegistryV1,
}
impl fmt::Debug for QualifiedPopWalletWitnessProviderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QualifiedPopWalletWitnessProviderV1([REDACTED])")
    }
}
impl PopWalletWitnessProviderV1 for QualifiedPopWalletWitnessProviderV1 {
    fn resolve(
        &self,
        credential_commitment: [u8; 32],
        projection: &PopFinalizedRegistryProjectionV1,
    ) -> Result<PopMembershipWitnessV1, PopPrivateMaterialProviderErrorV1> {
        self.registry
            .assert_qualification()
            .map_err(|_| PopPrivateMaterialProviderErrorV1::Unavailable)?;
        let result = self.inner.resolve(credential_commitment, projection);
        self.registry
            .assert_qualification()
            .map_err(|_| PopPrivateMaterialProviderErrorV1::Unavailable)?;
        result.map_err(|_| PopPrivateMaterialProviderErrorV1::Unavailable)
    }
}
#[derive(Clone)]
struct QualifiedPopFinalizedTimeProviderV1 {
    inner: Arc<dyn PopFinalizedTimeProviderV1>,
    registry: QualifiedPopCredentialRuntimeProviderRegistryV1,
}
impl fmt::Debug for QualifiedPopFinalizedTimeProviderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QualifiedPopFinalizedTimeProviderV1([REDACTED])")
    }
}
impl PopFinalizedTimeProviderV1 for QualifiedPopFinalizedTimeProviderV1 {
    fn sample(&self) -> Result<PopFinalizedTimeSampleV1, PopFinalizedTimeProviderErrorV1> {
        self.registry
            .assert_qualification()
            .map_err(|_| PopFinalizedTimeProviderErrorV1::Unavailable)?;
        let result = self.inner.sample();
        self.registry
            .assert_qualification()
            .map_err(|_| PopFinalizedTimeProviderErrorV1::Unavailable)?;
        result.map_err(|_| PopFinalizedTimeProviderErrorV1::Unavailable)
    }
}
#[derive(Clone)]
struct QualifiedPopEnrollmentRecipientV1 {
    inner: Arc<dyn PopEnrollmentRecipientV1>,
    key_id: String,
    public_key_digest: [u8; 32],
    registry: QualifiedPopCredentialRuntimeProviderRegistryV1,
}
impl fmt::Debug for QualifiedPopEnrollmentRecipientV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedPopEnrollmentRecipientV1")
            .field("key_id", &self.key_id)
            .field("private_provider", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl PopEnrollmentRecipientV1 for QualifiedPopEnrollmentRecipientV1 {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn public_key_digest(&self) -> [u8; 32] {
        self.public_key_digest
    }
    fn open_enrollment(
        &self,
        encrypted_payload: &HybridPayloadEnvelopeV1,
        aad: &[u8],
    ) -> Result<Vec<u8>, PopRecipientOpenErrorV1> {
        self.registry
            .assert_qualification()
            .map_err(|_| PopRecipientOpenErrorV1::Unavailable)?;
        if self.inner.key_id() != self.key_id
            || self.inner.public_key_digest() != self.public_key_digest
        {
            return Err(PopRecipientOpenErrorV1::Unavailable);
        }
        let result = self.inner.open_enrollment(encrypted_payload, aad);
        if self.inner.key_id() != self.key_id
            || self.inner.public_key_digest() != self.public_key_digest
        {
            return Err(PopRecipientOpenErrorV1::Unavailable);
        }
        self.registry
            .assert_qualification()
            .map_err(|_| PopRecipientOpenErrorV1::Unavailable)?;
        result
    }
}
#[derive(Clone)]
struct QualifiedPopWalletRecipientV1 {
    inner: Arc<dyn PopWalletRecipientV1>,
    key_id: String,
    public_key_digest: [u8; 32],
    registry: QualifiedPopCredentialRuntimeProviderRegistryV1,
}
impl fmt::Debug for QualifiedPopWalletRecipientV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedPopWalletRecipientV1")
            .field("key_id", &self.key_id)
            .field("private_provider", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl PopWalletRecipientV1 for QualifiedPopWalletRecipientV1 {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn public_key_digest(&self) -> [u8; 32] {
        self.public_key_digest
    }
    fn open_wallet_delivery(
        &self,
        encrypted_payload: &HybridPayloadEnvelopeV1,
        aad: &[u8],
    ) -> Result<Vec<u8>, PopRecipientOpenErrorV1> {
        self.registry
            .assert_qualification()
            .map_err(|_| PopRecipientOpenErrorV1::Unavailable)?;
        if self.inner.key_id() != self.key_id
            || self.inner.public_key_digest() != self.public_key_digest
        {
            return Err(PopRecipientOpenErrorV1::Unavailable);
        }
        let result = self.inner.open_wallet_delivery(encrypted_payload, aad);
        if self.inner.key_id() != self.key_id
            || self.inner.public_key_digest() != self.public_key_digest
        {
            return Err(PopRecipientOpenErrorV1::Unavailable);
        }
        self.registry
            .assert_qualification()
            .map_err(|_| PopRecipientOpenErrorV1::Unavailable)?;
        result
    }
}
/// Torii-owned PoP issuer, registry reconciler, wallet, and verifier runtime.
pub struct PopCredentialToriiRuntimeV1 {
    config: PopCredentialRuntimeConfigV1,
    provider_registry: QualifiedPopCredentialRuntimeProviderRegistryV1,
    api: PopCredentialApiV1,
    service: Mutex<PopCredentialService>,
    registry_submitter: Arc<dyn PopRegistrySubmitter>,
    registry_reader: Arc<dyn PopFinalizedRegistryReader>,
    issuance_draft_provider: Arc<dyn PopIssuanceDraftProviderV1>,
    wallet: PopWalletVault,
    wallet_witness_provider: Arc<dyn PopWalletWitnessProviderV1>,
    finalized_time_provider: Arc<dyn PopFinalizedTimeProviderV1>,
    accepted_finalized_time: std::sync::Mutex<Option<PopFinalizedTimeSampleV1>>,
}
impl fmt::Debug for PopCredentialToriiRuntimeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PopCredentialToriiRuntimeV1")
            .field("issuer_id", &self.config.service_policy.issuer_id)
            .field("issuer_state_dir", &self.config.issuer_state_dir)
            .field("wallet_state_dir", &self.config.wallet_state_dir)
            .field("runtime_providers", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl PopCredentialToriiRuntimeV1 {
    /// Construct the runtime through an explicit deployment provider registry.
    ///
    /// Registry identity, revision, policy digest, resolved public signer
    /// identity, both recipient protected-key identities, and wallet wrapper
    /// identity are checked before issuer or wallet state is opened.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, missing or unavailable providers,
    /// qualification or public-identity mismatches, or failure to open and validate
    /// the durable issuer or wallet state.
    pub fn open(
        config: PopCredentialRuntimeConfigV1,
        registry: Option<Arc<dyn PopCredentialRuntimeProviderRegistryV1>>,
    ) -> Result<Self, PopCredentialServiceError> {
        config.validate()?;
        let provider_registry =
            QualifiedPopCredentialRuntimeProviderRegistryV1::try_new(&config, registry)?;
        let bindings = PopCredentialRuntimeProviderBindingsV1::from_config(&config)?;
        let providers = provider_registry.resolve(&bindings)?;
        provider_registry.assert_qualification()?;
        validate_pop_runtime_provider_handle(
            providers.issuer_signer.key_id(),
            "issuer_signer_handle",
        )
        .map_err(|_| PopCredentialServiceError::RuntimeProviderRegistryMismatch)?;
        validate_pop_runtime_provider_handle(
            providers.enrollment_recipient.key_id(),
            "enrollment_recipient_key_id",
        )
        .map_err(|_| PopCredentialServiceError::RuntimeProviderRegistryMismatch)?;
        validate_pop_runtime_provider_handle(
            providers.wallet_recipient.key_id(),
            "wallet_recipient_key_id",
        )
        .map_err(|_| PopCredentialServiceError::RuntimeProviderRegistryMismatch)?;
        validate_pop_runtime_provider_handle(
            providers.wallet_key_wrapper.active_key_id(),
            "wallet_wrapping_key_id",
        )
        .map_err(|_| PopCredentialServiceError::RuntimeProviderRegistryMismatch)?;
        if providers.issuer_signer.key_id() != config.service_policy.issuer_signer_handle
            || providers.issuer_signer.public_key() != config.service_policy.issuer_public_key
        {
            return Err(PopCredentialServiceError::SignerPolicyMismatch);
        }
        if providers.enrollment_recipient.key_id()
            != config.service_policy.enrollment_recipient_key_id
            || providers.enrollment_recipient.public_key_digest()
                != config.enrollment_recipient_public_key_digest
            || providers.wallet_recipient.key_id() != config.wallet_recipient_key_id
            || providers.wallet_recipient.public_key_digest()
                != config.wallet_recipient_public_key_digest
        {
            return Err(PopCredentialServiceError::RuntimeProviderRegistryMismatch);
        }
        if providers.wallet_key_wrapper.active_key_id() != config.wallet_wrapping_key_id {
            return Err(PopCredentialServiceError::RuntimeProviderRegistryMismatch);
        }
        let issuer_signer: Arc<dyn PopIssuerSigner> = Arc::new(QualifiedPopIssuerSignerV1 {
            inner: providers.issuer_signer,
            key_id: config.service_policy.issuer_signer_handle.clone(),
            public_key: config.service_policy.issuer_public_key,
            registry: provider_registry.clone(),
        });
        let wallet_key_wrapper: Arc<dyn PopWalletKeyWrapper> =
            Arc::new(QualifiedPopWalletKeyWrapperV1 {
                inner: providers.wallet_key_wrapper,
                active_key_id: config.wallet_wrapping_key_id.clone(),
                registry: provider_registry.clone(),
            });
        let enrollment_recipient: Arc<dyn PopEnrollmentRecipientV1> =
            Arc::new(QualifiedPopEnrollmentRecipientV1 {
                inner: providers.enrollment_recipient,
                key_id: config.service_policy.enrollment_recipient_key_id.clone(),
                public_key_digest: config.enrollment_recipient_public_key_digest,
                registry: provider_registry.clone(),
            });
        let wallet_recipient: Arc<dyn PopWalletRecipientV1> =
            Arc::new(QualifiedPopWalletRecipientV1 {
                inner: providers.wallet_recipient,
                key_id: config.wallet_recipient_key_id.clone(),
                public_key_digest: config.wallet_recipient_public_key_digest,
                registry: provider_registry.clone(),
            });
        let authenticator: Arc<dyn PopCredentialApiAuthenticator> =
            Arc::new(QualifiedPopCredentialApiAuthenticatorV1 {
                inner: providers.authenticator,
                registry: provider_registry.clone(),
            });
        let registry_submitter: Arc<dyn PopRegistrySubmitter> =
            Arc::new(QualifiedPopRegistrySubmitterV1 {
                inner: providers.registry_submitter,
                registry: provider_registry.clone(),
            });
        let registry_reader: Arc<dyn PopFinalizedRegistryReader> =
            Arc::new(QualifiedPopFinalizedRegistryReaderV1 {
                inner: providers.registry_reader,
                registry: provider_registry.clone(),
            });
        let issuance_draft_provider: Arc<dyn PopIssuanceDraftProviderV1> =
            Arc::new(QualifiedPopIssuanceDraftProviderV1 {
                inner: providers.issuance_draft_provider,
                registry: provider_registry.clone(),
            });
        let wallet_witness_provider: Arc<dyn PopWalletWitnessProviderV1> =
            Arc::new(QualifiedPopWalletWitnessProviderV1 {
                inner: providers.wallet_witness_provider,
                registry: provider_registry.clone(),
            });
        let finalized_time_provider: Arc<dyn PopFinalizedTimeProviderV1> =
            Arc::new(QualifiedPopFinalizedTimeProviderV1 {
                inner: providers.finalized_time_provider,
                registry: provider_registry.clone(),
            });
        provider_registry.assert_qualification()?;
        let service = PopCredentialService::open(
            &config.issuer_state_dir,
            config.service_policy.clone(),
            enrollment_recipient,
            issuer_signer,
        )?;
        if service.policy() != &config.service_policy {
            return Err(PopCredentialServiceError::WrongPolicy);
        }
        provider_registry.assert_qualification()?;
        let wallet = PopWalletVault::open(
            &config.wallet_state_dir,
            wallet_recipient,
            wallet_key_wrapper,
        )?;
        provider_registry.assert_qualification()?;
        Ok(Self {
            config,
            provider_registry,
            api: PopCredentialApiV1::new(Arc::clone(&authenticator)),
            service: Mutex::new(service),
            registry_submitter,
            registry_reader,
            issuance_draft_provider,
            wallet,
            wallet_witness_provider,
            finalized_time_provider,
            accepted_finalized_time: std::sync::Mutex::new(None),
        })
    }
    /// Exact non-secret config used to construct this runtime.
    #[must_use]
    pub fn config(&self) -> &PopCredentialRuntimeConfigV1 {
        &self.config
    }
    fn current_finalized_time_sample(
        &self,
    ) -> Result<PopFinalizedTimeSampleV1, PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = (|| {
            let mut accepted = self
                .accepted_finalized_time
                .lock()
                .map_err(|_| PopCredentialServiceError::RuntimeProviderUnavailable)?;
            let sample = self
                .finalized_time_provider
                .sample()
                .map_err(|_| PopCredentialServiceError::RuntimeProviderUnavailable)?;
            validate_finalized_time_sample(
                accepted.as_ref(),
                &sample,
                self.config.max_finalized_time_skew.as_secs(),
            )
            .map_err(|_| PopCredentialServiceError::RuntimeProviderUnavailable)?;
            self.provider_registry.assert_qualification()?;
            *accepted = Some(sample);
            Ok(sample)
        })();
        self.provider_registry.finish(result)
    }
    fn current_epoch(&self) -> Result<u64, PopCredentialServiceError> {
        self.current_finalized_time_sample()
            .map(|sample| sample.finalized_epoch)
    }
    fn committed_registry_context_after_authentication(
        &self,
        authenticated_sample: PopFinalizedTimeSampleV1,
    ) -> Result<PopCommittedRegistryContextV1<'_>, PopCredentialServiceError> {
        let sample = self.current_finalized_time_sample()?;
        if sample != authenticated_sample {
            return Err(PopCredentialServiceError::InvalidState);
        }
        PopCommittedRegistryContextV1::new(
            self.registry_reader.as_ref(),
            PopFinalizedCursorV1 {
                block_height: sample.finalized_block_height,
                block_hash: sample.finalized_block_hash,
            },
            sample.finalized_epoch,
        )
    }
    /// Run bounded retry-safe submission and finalized-chain reconciliation under Torii
    /// supervision.
    pub(crate) fn spawn(
        self: Arc<Self>,
        shutdown: iroha_futures::supervisor::ShutdownSignal,
    ) -> tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.config.worker_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.receive() => {
                        return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                    }
                    _ = ticker.tick() => {
                        if shutdown.is_sent() {
                            return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                        }
                        match self.provider_registry.assert_qualification() {
                            Ok(()) => {}
                            Err(PopCredentialServiceError::RuntimeProviderRegistryUnavailable) => {
                                iroha_logger::warn!(
                                    "SoraFS PoP runtime provider registry is temporarily unavailable before worker access"
                                );
                                continue;
                            }
                            Err(error) => {
                                iroha_logger::error!(
                                    ?error,
                                    "SoraFS PoP runtime provider identity or policy changed before worker access"
                                );
                                return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                            }
                        }
                        let mut service = self.service.lock().await;
                        let now_epoch = match self.current_epoch() {
                            Ok(now) => now,
                            Err(PopCredentialServiceError::RuntimeProviderRegistryUnavailable
                                | PopCredentialServiceError::RuntimeProviderUnavailable) => {
                                iroha_logger::warn!(
                                    "SoraFS PoP finalized-time provider is temporarily unavailable"
                                );
                                continue;
                            }
                            Err(error) => {
                                iroha_logger::error!(
                                    ?error,
                                    "SoraFS PoP finalized-time provider failed permanently"
                                );
                                return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                            }
                        };
                        if let Err(error) = service
                            .submit_next(self.registry_submitter.as_ref(), now_epoch)
                        {
                            iroha_logger::error!(
                                ?error,
                                "SoraFS PoP registry submission state failed permanently"
                            );
                            return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                        }
                        match service.reconcile_next(self.registry_reader.as_ref(), now_epoch) {
                            Ok(_) => {}
                            Err(PopCredentialServiceError::RegistryUnavailable) => {
                                iroha_logger::warn!(
                                    "SoraFS PoP finalized-registry reader is temporarily unavailable"
                                );
                            }
                            Err(error) => {
                                iroha_logger::error!(
                                    ?error,
                                    "SoraFS PoP finalized-registry reconciliation failed permanently"
                                );
                                return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                            }
                        }
                        drop(service);
                        match self.provider_registry.assert_qualification() {
                            Ok(()) => {}
                            Err(PopCredentialServiceError::RuntimeProviderRegistryUnavailable) => {
                                iroha_logger::warn!(
                                    "SoraFS PoP runtime provider registry became temporarily unavailable after worker access"
                                );
                            }
                            Err(error) => {
                                iroha_logger::error!(
                                    ?error,
                                    "SoraFS PoP runtime provider identity or policy changed during worker access"
                                );
                                return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                            }
                        }
                    }
                }
            }
        })
    }
    async fn submit_enrollment(
        &self,
        credential: &[u8],
        canonical_enrollment: &[u8],
    ) -> Result<PopEnrollmentStatusV1, PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let authorization = self.api.authorize_submit_enrollment(
                credential,
                canonical_enrollment,
                authenticated_sample.finalized_epoch,
            )?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let mut service = self.service.lock().await;
            self.api.submit_enrollment_authorized(
                &mut service,
                authorization,
                canonical_enrollment,
                committed,
            )
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn enrollment_status(
        &self,
        credential: &[u8],
        request_id: [u8; 32],
    ) -> Result<PopEnrollmentStatusV1, PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let authorization = self.api.authorize_enrollment_status(
                credential,
                request_id,
                authenticated_sample.finalized_epoch,
            )?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let mut service = self.service.lock().await;
            self.api.enrollment_status_authorized(
                &mut service,
                authorization,
                request_id,
                committed,
            )
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn record_approval(
        &self,
        credential: &[u8],
        approval: PopApprovalV1,
    ) -> Result<PopEnrollmentStatusV1, PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let authorization = self.api.authorize_record_approval(
                credential,
                &approval,
                authenticated_sample.finalized_epoch,
            )?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let mut service = self.service.lock().await;
            self.api
                .record_approval_authorized(&mut service, authorization, approval, committed)
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn issue(
        &self,
        credential: &[u8],
        request_id: [u8; 32],
    ) -> Result<[u8; 32], PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let authorization = self.api.authorize_issue_resolved(
                credential,
                request_id,
                authenticated_sample.finalized_epoch,
            )?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let now_epoch = committed.now_epoch();
            let mut service = self.service.lock().await;
            self.api
                .consume_issue_resolved_authorization(authorization, request_id, now_epoch)?;
            committed.reconcile(&mut service)?;
            let draft = self
                .issuance_draft_provider
                .resolve(request_id, now_epoch)
                .map_err(|_| PopCredentialServiceError::RuntimeProviderUnavailable)?;
            if draft.request_id != request_id {
                return Err(PopCredentialServiceError::InvalidIssuance);
            }
            service.issue(draft, now_epoch, &mut OsRng)
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn enqueue_revocation(
        &self,
        credential: &[u8],
        revocations: PopRevocationListV1,
    ) -> Result<[u8; 32], PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let authorization = self.api.authorize_enqueue_revocation(
                credential,
                &revocations,
                authenticated_sample.finalized_epoch,
            )?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let mut service = self.service.lock().await;
            self.api.enqueue_revocation_authorized(
                &mut service,
                authorization,
                revocations,
                committed,
            )
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn submit_next(
        &self,
        credential: &[u8],
    ) -> Result<PopOutboxSubmitOutcomeV1, PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let challenge = {
                let service = self.service.lock().await;
                self.api.submit_next_authorization_challenge(
                    &service,
                    authenticated_sample.finalized_epoch,
                )?
            };
            let authorization = self.api.authorize_challenge(credential, challenge)?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let mut service = self.service.lock().await;
            self.api.submit_next_authorized(
                &mut service,
                authorization,
                self.registry_submitter.as_ref(),
                committed,
            )
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn reconcile_next(&self, credential: &[u8]) -> Result<bool, PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let challenge = {
                let service = self.service.lock().await;
                self.api.reconcile_next_authorization_challenge(
                    &service,
                    authenticated_sample.finalized_epoch,
                )?
            };
            let authorization = self.api.authorize_challenge(credential, challenge)?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let now_epoch = committed.now_epoch();
            let mut service = self.service.lock().await;
            self.api.reconcile_next_authorized(
                &mut service,
                authorization,
                self.registry_reader.as_ref(),
                now_epoch,
            )
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn finalized_projection(
        &self,
        credential: &[u8],
    ) -> Result<Option<PopFinalizedRegistryProjectionV1>, PopCredentialServiceError> {
        self.finalized_projection_bounded(credential, POP_SERVICE_COLLECTION_MAX_V1)
            .await
    }
    async fn finalized_projection_bounded(
        &self,
        credential: &[u8],
        max_reconciliations: usize,
    ) -> Result<Option<PopFinalizedRegistryProjectionV1>, PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let challenge = {
                let service = self.service.lock().await;
                self.api.finalized_projection_authorization_challenge(
                    &service,
                    authenticated_sample.finalized_epoch,
                )?
            };
            let authorization = self.api.authorize_challenge(credential, challenge)?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let mut service = self.service.lock().await;
            self.api.finalized_projection_bounded_authorized(
                &mut service,
                authorization,
                committed,
                max_reconciliations,
            )
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn wallet_delivery(
        &self,
        credential: &[u8],
        request_id: [u8; 32],
    ) -> Result<Vec<u8>, PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let authorization = self.api.authorize_wallet_delivery(
                credential,
                request_id,
                authenticated_sample.finalized_epoch,
            )?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let mut service = self.service.lock().await;
            self.api
                .wallet_delivery_authorized(&mut service, authorization, request_id, committed)
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn import_wallet_delivery(
        &self,
        credential: &[u8],
        request_id: [u8; 32],
    ) -> Result<[u8; 32], PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let authorization = self.api.authorize_import_wallet_delivery(
                credential,
                request_id,
                authenticated_sample.finalized_epoch,
            )?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let mut service = self.service.lock().await;
            self.api.import_wallet_delivery_authorized(
                &mut service,
                &self.wallet,
                authorization,
                request_id,
                committed,
            )
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn acknowledge_wallet_delivery(
        &self,
        credential: &[u8],
        request_id: [u8; 32],
    ) -> Result<(), PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let authorization = self.api.authorize_acknowledge_wallet_delivery(
                credential,
                request_id,
                authenticated_sample.finalized_epoch,
            )?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let mut service = self.service.lock().await;
            self.api.acknowledge_wallet_delivery_authorized(
                &mut service,
                authorization,
                request_id,
                committed,
            )
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn synchronize_wallet_witness(
        &self,
        credential: &[u8],
        credential_commitment: [u8; 32],
    ) -> Result<(), PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let authorization = self.api.authorize_synchronize_wallet_witness(
                credential,
                credential_commitment,
                authenticated_sample.finalized_epoch,
            )?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let now_epoch = committed.now_epoch();
            let mut service = self.service.lock().await;
            self.api.consume_synchronize_wallet_witness_authorization(
                authorization,
                credential_commitment,
                now_epoch,
            )?;
            committed.reconcile(&mut service)?;
            let projection = service
                .finalized_projection()
                .ok_or(PopCredentialServiceError::NotSynchronized)?;
            let witness = self
                .wallet_witness_provider
                .resolve(credential_commitment, projection)
                .map_err(|_| PopCredentialServiceError::RuntimeProviderUnavailable)?;
            self.wallet
                .synchronize_witness(credential_commitment, projection, &witness)
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn prove_membership(
        &self,
        credential: &[u8],
        credential_commitment: [u8; 32],
        challenge_digest: [u8; 32],
        verifier_context: &str,
        presentation_binding_digest: [u8; 32],
    ) -> Result<PopMembershipProofV1, PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let authorization = self.api.authorize_prove_membership(
                credential,
                credential_commitment,
                challenge_digest,
                verifier_context,
                presentation_binding_digest,
                authenticated_sample.finalized_epoch,
            )?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let mut service = self.service.lock().await;
            self.api.prove_membership_authorized(
                &mut service,
                &self.wallet,
                authorization,
                credential_commitment,
                challenge_digest,
                verifier_context,
                presentation_binding_digest,
                committed,
            )
        }
        .await;
        self.provider_registry.finish(result)
    }
    async fn verify_membership(
        &self,
        credential: &[u8],
        proof: &PopMembershipProofV1,
        challenge_digest: [u8; 32],
        verifier_context: &str,
        presentation_binding_digest: [u8; 32],
    ) -> Result<(), PopCredentialServiceError> {
        self.provider_registry.assert_qualification()?;
        let result = async {
            let authenticated_sample = self.current_finalized_time_sample()?;
            let authorization = self.api.authorize_verify_membership(
                credential,
                proof,
                challenge_digest,
                verifier_context,
                presentation_binding_digest,
                authenticated_sample.finalized_epoch,
            )?;
            let committed =
                self.committed_registry_context_after_authentication(authenticated_sample)?;
            let mut service = self.service.lock().await;
            self.api.verify_membership_authorized(
                &mut service,
                authorization,
                proof,
                challenge_digest,
                verifier_context,
                presentation_binding_digest,
                committed,
            )
        }
        .await;
        self.provider_registry.finish(result)
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::pop_api::PopCanonicalPayloadRequestV1")]
#[derive(Clone, Debug, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
/// Request envelope carrying one exact canonical native-Norito payload.
pub struct PopCanonicalPayloadRequestV1 {
    /// Canonical native-Norito bytes encoded as unpadded URL-safe base64.
    pub canonical_payload_base64url: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::pop_api::PopRequestIdRequestV1")]
#[derive(Clone, Debug, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
/// Request envelope selecting one durable PoP enrollment by identifier.
pub struct PopRequestIdRequestV1 {
    /// Non-zero 32-byte request id as lowercase hex.
    pub request_id_hex: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::pop_api::PopCredentialCommitmentRequestV1")]
#[derive(Clone, Debug, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
/// Request envelope selecting one wallet credential commitment.
pub struct PopCredentialCommitmentRequestV1 {
    /// Non-zero credential commitment as lowercase hex.
    pub credential_commitment_hex: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::pop_api::PopMembershipRequestV1")]
#[derive(Clone, Debug, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
/// Request envelope for local membership-proof generation.
pub struct PopMembershipRequestV1 {
    /// Non-zero credential commitment as lowercase hex.
    pub credential_commitment_hex: String,
    /// Non-zero verifier challenge digest as lowercase hex.
    pub challenge_digest_hex: String,
    /// Canonical bounded verifier context.
    pub verifier_context: String,
    /// Non-zero recipient or action binding as lowercase hex, independent of the nullifier domain.
    pub presentation_binding_digest_hex: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::pop_api::PopVerifyMembershipRequestV1")]
#[derive(Clone, Debug, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
/// Request envelope for verification and exactly-once nullifier consumption.
pub struct PopVerifyMembershipRequestV1 {
    /// Canonical native-Norito proof encoded as unpadded URL-safe base64.
    pub canonical_proof_base64url: String,
    /// Non-zero verifier challenge digest as lowercase hex.
    pub challenge_digest_hex: String,
    /// Canonical bounded verifier context.
    pub verifier_context: String,
    /// Non-zero recipient or action binding as lowercase hex, independent of the nullifier domain.
    pub presentation_binding_digest_hex: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::pop_api::PopEmptyRequestV1")]
#[derive(Clone, Copy, Debug, Default, NoritoSerialize, NoritoDeserialize)]
#[norito(deny_unknown_fields)]
/// Strict empty-object request used by bounded worker and projection endpoints.
pub struct PopEmptyRequestV1;
impl norito::json::FastJsonWrite for PopEmptyRequestV1 {
    fn write_json(&self, out: &mut String) {
        out.push_str("{}");
    }
}
impl norito::json::JsonDeserialize for PopEmptyRequestV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        parser.expect(b'{')?;
        if !parser.try_consume_char(b'}')? {
            return Err(norito::json::Error::Message(
                "empty PoP request rejects unknown fields".to_owned(),
            ));
        }
        Ok(Self)
    }
}
#[derive(Clone, Debug, JsonSerialize)]
/// Payload-free durable enrollment lifecycle response.
pub struct PopEnrollmentStatusResponseV1 {
    /// Request identifier.
    pub request_id_hex: String,
    /// Stable lifecycle state.
    pub state: String,
    /// Number of current distinct non-revoked approvals.
    pub active_approval_count: u8,
    /// Registry operation digest, when issued.
    pub registry_operation_digest_hex: Option<String>,
}
#[derive(Clone, Debug, JsonSerialize)]
/// Accepted durable registry-operation response.
pub struct PopOperationResponseV1 {
    /// Domain-separated durable operation digest.
    pub operation_digest_hex: String,
}
#[derive(Clone, Copy, Debug, JsonSerialize)]
/// Result of one bounded reconciliation step.
pub struct PopBooleanOutcomeResponseV1 {
    /// Whether the requested bounded step advanced state.
    pub advanced: bool,
}
#[derive(Clone, Debug, JsonSerialize)]
/// Result of one bounded durable-outbox submission step.
pub struct PopOutboxOutcomeResponseV1 {
    /// Stable outcome label.
    pub outcome: String,
    /// Operation digest, absent only when the outbox was idle.
    pub operation_digest_hex: Option<String>,
}
#[derive(Clone, Debug, JsonSerialize)]
/// Public finalized registry projection response.
pub struct PopProjectionResponseV1 {
    /// Whether a finalized projection is currently available.
    pub available: bool,
    /// Finalized height.
    pub block_height: Option<u64>,
    /// Finalized block hash.
    pub block_hash_hex: Option<String>,
    /// Previous finalized block hash.
    pub previous_block_hash_hex: Option<String>,
    /// Active finalized issuer-policy digest.
    pub issuer_policy_digest_hex: Option<String>,
    /// Canonical signed commitment-root bytes.
    pub canonical_commitment_root_base64url: Option<String>,
    /// Canonical signed revocation-list bytes.
    pub canonical_revocation_list_base64url: Option<String>,
    /// Committed operation digests in canonical order.
    pub committed_operation_digests_hex: Vec<String>,
    /// Rejected operation digests in canonical order.
    pub rejected_operation_digests_hex: Vec<String>,
    /// Revoked issuer public keys in canonical order.
    pub revoked_issuer_public_keys_hex: Vec<String>,
}
#[derive(Clone, Debug, JsonSerialize)]
/// Encrypted finalized wallet-delivery response.
pub struct PopEncryptedDeliveryResponseV1 {
    /// Canonical encrypted delivery bytes; never plaintext credential material.
    pub canonical_delivery_base64url: String,
}
#[derive(Clone, Debug, JsonSerialize)]
/// Result of importing encrypted delivery into local wallet custody.
pub struct PopCredentialCommitmentResponseV1 {
    /// Imported encrypted-vault credential commitment.
    pub credential_commitment_hex: String,
}
#[derive(Clone, Debug, JsonSerialize)]
/// Public zero-knowledge membership-proof response.
pub struct PopMembershipProofResponseV1 {
    /// Canonical public zero-knowledge proof bytes.
    pub canonical_proof_base64url: String,
}
#[derive(Clone, Debug, JsonSerialize)]
struct PopOkResponseV1 {
    ok: bool,
}
#[derive(Clone, Debug, JsonSerialize)]
struct PopErrorResponseV1 {
    code: String,
    message: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PopFinalizedTimeSampleErrorV1 {
    Invalid,
    Skew,
    Rollback,
    Fork,
}
fn validate_finalized_time_sample(
    previous: Option<&PopFinalizedTimeSampleV1>,
    sample: &PopFinalizedTimeSampleV1,
    max_skew_secs: u64,
) -> Result<(), PopFinalizedTimeSampleErrorV1> {
    if sample.finalized_block_height == 0
        || sample.finalized_block_hash == [0; 32]
        || sample.finalized_epoch == 0
        || sample.observed_epoch == 0
    {
        return Err(PopFinalizedTimeSampleErrorV1::Invalid);
    }
    if sample.finalized_epoch.abs_diff(sample.observed_epoch) > max_skew_secs {
        return Err(PopFinalizedTimeSampleErrorV1::Skew);
    }
    let Some(previous) = previous else {
        return Ok(());
    };
    if sample.finalized_block_height < previous.finalized_block_height
        || sample.finalized_epoch < previous.finalized_epoch
        || sample.observed_epoch < previous.observed_epoch
    {
        return Err(PopFinalizedTimeSampleErrorV1::Rollback);
    }
    if (sample.finalized_block_height == previous.finalized_block_height
        && (sample.finalized_block_hash != previous.finalized_block_hash
            || sample.finalized_epoch != previous.finalized_epoch))
        || (sample.finalized_block_height > previous.finalized_block_height
            && sample.finalized_block_hash == previous.finalized_block_hash)
    {
        return Err(PopFinalizedTimeSampleErrorV1::Fork);
    }
    Ok(())
}
fn decode_hex_32(value: &str, field: &'static str) -> Result<[u8; 32], PopCredentialServiceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(PopCredentialServiceError::InvalidInput { field });
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(value, &mut digest)
        .map_err(|_| PopCredentialServiceError::InvalidInput { field })?;
    if digest == [0; 32] {
        return Err(PopCredentialServiceError::InvalidInput { field });
    }
    Ok(digest)
}
fn decode_base64url(value: &str, max_bytes: usize) -> Result<Vec<u8>, PopCredentialServiceError> {
    if value.is_empty()
        || value.len() > canonical_base64_max_len(max_bytes)
        || value
            .bytes()
            .any(|byte| byte == b'=' || byte.is_ascii_whitespace())
    {
        return Err(PopCredentialServiceError::Codec);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PopCredentialServiceError::Codec)?;
    if bytes.is_empty() || bytes.len() > max_bytes || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(PopCredentialServiceError::Codec);
    }
    Ok(bytes)
}
fn canonical_decode_limits(max_bytes: usize) -> norito::DecodeLimits {
    let bounded_bytes = max_bytes.max(1);
    norito::DecodeLimits::new(
        bounded_bytes,
        bounded_bytes,
        bounded_bytes,
        bounded_bytes.saturating_mul(4),
        POP_CANONICAL_DECODE_MAX_DEPTH_V1,
    )
}
fn decode_canonical_bytes_with_limits<T>(
    bytes: &[u8],
    limits: norito::DecodeLimits,
) -> Result<T, PopCredentialServiceError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    let decoded: T = norito::decode_from_bytes_with_limits(bytes, limits)
        .map_err(|_| PopCredentialServiceError::Codec)?;
    let canonical = norito::to_bytes(&decoded).map_err(|_| PopCredentialServiceError::Codec)?;
    if canonical != bytes {
        return Err(PopCredentialServiceError::Codec);
    }
    Ok(decoded)
}
fn decode_canonical<T>(value: &str, max_bytes: usize) -> Result<T, PopCredentialServiceError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    let bytes = decode_base64url(value, max_bytes)?;
    decode_canonical_bytes_with_limits(&bytes, canonical_decode_limits(max_bytes))
}
fn canonical_base64url<T: norito::core::NoritoSerialize>(
    value: &T,
) -> Result<String, PopCredentialServiceError> {
    norito::to_bytes(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| PopCredentialServiceError::Codec)
}
fn parse_authentication(
    headers: &HeaderMap,
) -> Result<PopApiCredentialV1, PopCredentialServiceError> {
    let mut values = headers.get_all(POP_AUTHORIZATION_HEADER_V1).iter();
    let value = values
        .next()
        .filter(|_| values.next().is_none())
        .and_then(|value| value.to_str().ok())
        .ok_or(PopCredentialServiceError::Unauthorized)?;
    let encoded = value
        .strip_prefix("PopV1 ")
        .ok_or(PopCredentialServiceError::Unauthorized)?;
    if encoded.is_empty()
        || encoded.len() > canonical_base64_max_len(POP_API_AUTHENTICATION_MAX_BYTES_V1)
        || encoded
            .bytes()
            .any(|byte| byte == b'=' || byte.is_ascii_whitespace())
    {
        return Err(PopCredentialServiceError::Unauthorized);
    }
    let credential = PopApiCredentialV1::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| PopCredentialServiceError::Unauthorized)?,
    );
    if credential.as_bytes().is_empty()
        || credential.as_bytes().len() > POP_API_AUTHENTICATION_MAX_BYTES_V1
        || URL_SAFE_NO_PAD.encode(credential.as_bytes()) != encoded
    {
        return Err(PopCredentialServiceError::Unauthorized);
    }
    Ok(credential)
}
fn status_response(status: PopEnrollmentStatusV1) -> PopEnrollmentStatusResponseV1 {
    let state = match status.state {
        PopEnrollmentStateV1::AwaitingApproval => "awaiting_approval",
        PopEnrollmentStateV1::Approved => "approved",
        PopEnrollmentStateV1::Rejected => "rejected",
        PopEnrollmentStateV1::PendingRegistry => "pending_registry",
        PopEnrollmentStateV1::DeliveryReady => "delivery_ready",
        PopEnrollmentStateV1::Delivered => "delivered",
    };
    PopEnrollmentStatusResponseV1 {
        request_id_hex: hex::encode(status.request_id),
        state: state.to_owned(),
        active_approval_count: status.active_approval_count,
        registry_operation_digest_hex: status.registry_operation_digest.map(hex::encode),
    }
}
fn outbox_response(outcome: PopOutboxSubmitOutcomeV1) -> PopOutboxOutcomeResponseV1 {
    match outcome {
        PopOutboxSubmitOutcomeV1::Idle => PopOutboxOutcomeResponseV1 {
            outcome: "idle".to_owned(),
            operation_digest_hex: None,
        },
        PopOutboxSubmitOutcomeV1::Submitted { operation_digest } => PopOutboxOutcomeResponseV1 {
            outcome: "submitted".to_owned(),
            operation_digest_hex: Some(hex::encode(operation_digest)),
        },
        PopOutboxSubmitOutcomeV1::RetryScheduled { operation_digest } => {
            PopOutboxOutcomeResponseV1 {
                outcome: "retry_scheduled".to_owned(),
                operation_digest_hex: Some(hex::encode(operation_digest)),
            }
        }
        PopOutboxSubmitOutcomeV1::DeadLettered { operation_digest } => PopOutboxOutcomeResponseV1 {
            outcome: "dead_lettered".to_owned(),
            operation_digest_hex: Some(hex::encode(operation_digest)),
        },
    }
}
fn projection_response(
    projection: Option<PopFinalizedRegistryProjectionV1>,
) -> PopProjectionResponseV1 {
    let Some(projection) = projection else {
        return PopProjectionResponseV1 {
            available: false,
            block_height: None,
            block_hash_hex: None,
            previous_block_hash_hex: None,
            issuer_policy_digest_hex: None,
            canonical_commitment_root_base64url: None,
            canonical_revocation_list_base64url: None,
            committed_operation_digests_hex: Vec::new(),
            rejected_operation_digests_hex: Vec::new(),
            revoked_issuer_public_keys_hex: Vec::new(),
        };
    };
    PopProjectionResponseV1 {
        available: true,
        block_height: Some(projection.cursor.block_height),
        block_hash_hex: Some(hex::encode(projection.cursor.block_hash)),
        previous_block_hash_hex: projection.previous_block_hash.map(hex::encode),
        issuer_policy_digest_hex: Some(hex::encode(projection.issuer_policy_digest)),
        canonical_commitment_root_base64url: Some(
            URL_SAFE_NO_PAD.encode(projection.canonical_commitment_root),
        ),
        canonical_revocation_list_base64url: Some(
            URL_SAFE_NO_PAD.encode(projection.canonical_revocation_list),
        ),
        committed_operation_digests_hex: projection
            .committed_operation_digests
            .into_iter()
            .map(hex::encode)
            .collect(),
        rejected_operation_digests_hex: projection
            .rejected_operation_digests
            .into_iter()
            .map(hex::encode)
            .collect(),
        revoked_issuer_public_keys_hex: projection
            .revoked_issuer_public_keys
            .into_iter()
            .map(hex::encode)
            .collect(),
    }
}
fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
fn error_response(error: PopCredentialServiceError) -> Response {
    let (status, code, message) = match error {
        PopCredentialServiceError::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            "pop_unauthorized",
            "PoP request authentication failed.",
        ),
        PopCredentialServiceError::SignerRevoked => (
            StatusCode::FORBIDDEN,
            "pop_signer_revoked",
            "The governed PoP signer is revoked.",
        ),
        PopCredentialServiceError::EnrollmentNotFound
        | PopCredentialServiceError::CredentialNotFound => (
            StatusCode::NOT_FOUND,
            "pop_not_found",
            "The requested PoP record was not found.",
        ),
        PopCredentialServiceError::EnrollmentReplay
        | PopCredentialServiceError::DuplicateApproval
        | PopCredentialServiceError::ReplayedProof
        | PopCredentialServiceError::RootRollback
        | PopCredentialServiceError::InvalidState
        | PopCredentialServiceError::ApprovalQuorum
        | PopCredentialServiceError::NotFinalized
        | PopCredentialServiceError::NotSynchronized => (
            StatusCode::CONFLICT,
            "pop_state_conflict",
            "The PoP transition conflicts with durable finalized state.",
        ),
        PopCredentialServiceError::ResourceExhausted => (
            StatusCode::TOO_MANY_REQUESTS,
            "pop_resource_exhausted",
            "The bounded PoP service resource policy was exhausted.",
        ),
        PopCredentialServiceError::CheckpointIo
        | PopCredentialServiceError::CheckpointDurabilityUncertain
        | PopCredentialServiceError::PoisonedCheckpoint
        | PopCredentialServiceError::RegistryUnavailable
        | PopCredentialServiceError::SignerUnavailable
        | PopCredentialServiceError::SignerPolicyMismatch
        | PopCredentialServiceError::KeyWrapping
        | PopCredentialServiceError::RuntimeProviderUnavailable
        | PopCredentialServiceError::RuntimeProviderRegistryMissing
        | PopCredentialServiceError::RuntimeProviderRegistryMismatch
        | PopCredentialServiceError::RuntimeProviderRegistryUnavailable
        | PopCredentialServiceError::RuntimeProviderRegistryDrift => (
            StatusCode::SERVICE_UNAVAILABLE,
            "pop_runtime_unavailable",
            "The governed PoP runtime is unavailable.",
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "pop_invalid_request",
            "The PoP request is malformed or violates canonical V1 policy.",
        ),
    };
    no_store((
        status,
        JsonBody(PopErrorResponseV1 {
            code: code.to_owned(),
            message: message.to_owned(),
        }),
    ))
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn runtime(app: &SharedAppState) -> Result<Arc<PopCredentialToriiRuntimeV1>, Response> {
    app.sorafs_pop_credentials
        .clone()
        .ok_or_else(|| error_response(PopCredentialServiceError::RuntimeProviderUnavailable))
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn request_context(
    app: &SharedAppState,
    headers: &HeaderMap,
) -> Result<(Arc<PopCredentialToriiRuntimeV1>, PopApiCredentialV1), Response> {
    let runtime = runtime(app)?;
    let credential = parse_authentication(headers).map_err(error_response)?;
    Ok((runtime, credential))
}
/// Submit a canonical encrypted enrollment.
pub(crate) async fn handle_post_pop_enrollment(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(request): NoritoJson<PopCanonicalPayloadRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let enrollment = match decode_base64url(
        &request.canonical_payload_base64url,
        POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1,
    ) {
        Ok(enrollment) => enrollment,
        Err(error) => return error_response(error),
    };
    match runtime
        .submit_enrollment(credential.as_bytes(), &enrollment)
        .await
    {
        Ok(status) => no_store((StatusCode::ACCEPTED, JsonBody(status_response(status)))),
        Err(error) => error_response(error),
    }
}
/// Return payload-free enrollment status.
pub(crate) async fn handle_post_pop_enrollment_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(request): NoritoJson<PopRequestIdRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let request_id = match decode_hex_32(&request.request_id_hex, "request_id_hex") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match runtime
        .enrollment_status(credential.as_bytes(), request_id)
        .await
    {
        Ok(status) => no_store(JsonBody(status_response(status))),
        Err(error) => error_response(error),
    }
}
/// Record one signed governed approval.
pub(crate) async fn handle_post_pop_approval(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(request): NoritoJson<PopCanonicalPayloadRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let approval = match decode_canonical::<PopApprovalV1>(
        &request.canonical_payload_base64url,
        POP_CONTROL_PAYLOAD_MAX_BYTES_V1,
    ) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match runtime
        .record_approval(credential.as_bytes(), approval)
        .await
    {
        Ok(status) => no_store(JsonBody(status_response(status))),
        Err(error) => error_response(error),
    }
}
/// Trigger server-resolved, external-signer-backed issuance.
pub(crate) async fn handle_post_pop_issue(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(request): NoritoJson<PopRequestIdRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let request_id = match decode_hex_32(&request.request_id_hex, "request_id_hex") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match runtime.issue(credential.as_bytes(), request_id).await {
        Ok(digest) => no_store((
            StatusCode::ACCEPTED,
            JsonBody(PopOperationResponseV1 {
                operation_digest_hex: hex::encode(digest),
            }),
        )),
        Err(error) => error_response(error),
    }
}
/// Enqueue a strict signed revocation successor.
pub(crate) async fn handle_post_pop_revocation(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(request): NoritoJson<PopCanonicalPayloadRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let revocations = match decode_canonical::<PopRevocationListV1>(
        &request.canonical_payload_base64url,
        POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1,
    ) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match runtime
        .enqueue_revocation(credential.as_bytes(), revocations)
        .await
    {
        Ok(digest) => no_store((
            StatusCode::ACCEPTED,
            JsonBody(PopOperationResponseV1 {
                operation_digest_hex: hex::encode(digest),
            }),
        )),
        Err(error) => error_response(error),
    }
}
/// Run one authenticated registry submission step.
pub(crate) async fn handle_post_pop_registry_submit(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(_request): NoritoJson<PopEmptyRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match runtime.submit_next(credential.as_bytes()).await {
        Ok(outcome) => no_store(JsonBody(outbox_response(outcome))),
        Err(error) => error_response(error),
    }
}
/// Reconcile at most one finalized ledger projection.
pub(crate) async fn handle_post_pop_registry_reconcile(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(_request): NoritoJson<PopEmptyRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match runtime.reconcile_next(credential.as_bytes()).await {
        Ok(advanced) => no_store(JsonBody(PopBooleanOutcomeResponseV1 { advanced })),
        Err(error) => error_response(error),
    }
}
/// Read the authenticated finalized public root projection.
pub(crate) async fn handle_post_pop_registry_projection(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(_request): NoritoJson<PopEmptyRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match runtime.finalized_projection(credential.as_bytes()).await {
        Ok(projection) => no_store(JsonBody(projection_response(projection))),
        Err(error) => error_response(error),
    }
}
/// Fetch canonical encrypted wallet delivery.
pub(crate) async fn handle_post_pop_wallet_delivery(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(request): NoritoJson<PopRequestIdRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let request_id = match decode_hex_32(&request.request_id_hex, "request_id_hex") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match runtime
        .wallet_delivery(credential.as_bytes(), request_id)
        .await
    {
        Ok(delivery) => no_store(JsonBody(PopEncryptedDeliveryResponseV1 {
            canonical_delivery_base64url: URL_SAFE_NO_PAD.encode(delivery),
        })),
        Err(error) => error_response(error),
    }
}
/// Import a finalized encrypted delivery into runtime wallet custody.
pub(crate) async fn handle_post_pop_wallet_import(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(request): NoritoJson<PopRequestIdRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let request_id = match decode_hex_32(&request.request_id_hex, "request_id_hex") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match runtime
        .import_wallet_delivery(credential.as_bytes(), request_id)
        .await
    {
        Ok(commitment) => no_store(JsonBody(PopCredentialCommitmentResponseV1 {
            credential_commitment_hex: hex::encode(commitment),
        })),
        Err(error) => error_response(error),
    }
}
/// Acknowledge encrypted delivery without deleting recoverable ciphertext.
pub(crate) async fn handle_post_pop_wallet_acknowledge(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(request): NoritoJson<PopRequestIdRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let request_id = match decode_hex_32(&request.request_id_hex, "request_id_hex") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match runtime
        .acknowledge_wallet_delivery(credential.as_bytes(), request_id)
        .await
    {
        Ok(()) => no_store(JsonBody(PopOkResponseV1 { ok: true })),
        Err(error) => error_response(error),
    }
}
/// Synchronize a runtime-only witness to the current finalized roots.
pub(crate) async fn handle_post_pop_wallet_synchronize(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(request): NoritoJson<PopCredentialCommitmentRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let commitment = match decode_hex_32(
        &request.credential_commitment_hex,
        "credential_commitment_hex",
    ) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match runtime
        .synchronize_wallet_witness(credential.as_bytes(), commitment)
        .await
    {
        Ok(()) => no_store(JsonBody(PopOkResponseV1 { ok: true })),
        Err(error) => error_response(error),
    }
}
/// Generate a public zero-knowledge membership proof from local wallet custody.
pub(crate) async fn handle_post_pop_wallet_prove(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(request): NoritoJson<PopMembershipRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let commitment = match decode_hex_32(
        &request.credential_commitment_hex,
        "credential_commitment_hex",
    ) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let challenge = match decode_hex_32(&request.challenge_digest_hex, "challenge_digest_hex") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let presentation_binding_digest = match decode_hex_32(
        &request.presentation_binding_digest_hex,
        "presentation_binding_digest_hex",
    ) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    if !valid_context(&request.verifier_context) {
        return error_response(PopCredentialServiceError::InvalidInput {
            field: "verifier_context",
        });
    }
    match runtime
        .prove_membership(
            credential.as_bytes(),
            commitment,
            challenge,
            &request.verifier_context,
            presentation_binding_digest,
        )
        .await
    {
        Ok(proof) => match canonical_base64url(&proof) {
            Ok(encoded) => no_store(JsonBody(PopMembershipProofResponseV1 {
                canonical_proof_base64url: encoded,
            })),
            Err(error) => error_response(error),
        },
        Err(error) => error_response(error),
    }
}
/// Verify a membership proof and durably consume its nullifier.
pub(crate) async fn handle_post_pop_verify(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    NoritoJson(request): NoritoJson<PopVerifyMembershipRequestV1>,
) -> Response {
    let (runtime, credential) = match request_context(&app, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let challenge = match decode_hex_32(&request.challenge_digest_hex, "challenge_digest_hex") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let presentation_binding_digest = match decode_hex_32(
        &request.presentation_binding_digest_hex,
        "presentation_binding_digest_hex",
    ) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    if !valid_context(&request.verifier_context) {
        return error_response(PopCredentialServiceError::InvalidInput {
            field: "verifier_context",
        });
    }
    let proof = match decode_canonical::<PopMembershipProofV1>(
        &request.canonical_proof_base64url,
        POP_MEMBERSHIP_PROOF_MAX_BYTES_V1,
    ) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match runtime
        .verify_membership(
            credential.as_bytes(),
            &proof,
            challenge,
            &request.verifier_context,
            presentation_binding_digest,
        )
        .await
    {
        Ok(()) => no_store(JsonBody(PopOkResponseV1 { ok: true })),
        Err(error) => error_response(error),
    }
}
fn valid_context(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.len() <= POP_MEMBERSHIP_CONTEXT_MAX_BYTES_V1
        && !value.chars().any(char::is_control)
}
#[cfg(test)]
#[path = "pop_api/presentation_binding_tests.rs"]
mod presentation_binding_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, HybridKeyPair, KeyPair, Signature};
    use sorafs_manifest::{
        hybrid_envelope::decrypt_payload,
        pop_credentials::{
            POP_COMMITMENT_ROOT_VERSION_V1, POP_CREDENTIAL_TREE_DEPTH_V1,
            POP_REVOCATION_LIST_VERSION_V1, POP_REVOCATION_TREE_DEPTH_V1, PopCommitmentRootV1,
            PopSignatureAlgorithmV1, PopSignatureV1, pop_commitment_root_signature_digest_v1,
            pop_revocation_list_signature_digest_v1, pop_revocation_root_v1,
        },
    };
    use sorafs_node::pop_credentials::{
        POP_FINALIZED_REGISTRY_PROJECTION_VERSION_V1, PopFinalizedCursorV1,
    };
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    #[derive(Debug)]
    struct FixedAuthenticator {
        principal_digest: [u8; 32],
        expires_at_epoch: u64,
        request_authority: PopRequestAuthorityV1,
        reject: bool,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl PopCredentialApiAuthenticator for FixedAuthenticator {
        fn authenticate(
            &self,
            _opaque_credential: &[u8],
            _action: PopCredentialApiActionV1,
            _request_binding: [u8; 32],
            _now_epoch: u64,
        ) -> Result<sorafs_node::pop_credentials::PopAuthenticatedPrincipalV1, String> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.reject {
                return Err("redacted test rejection".to_owned());
            }
            Ok(sorafs_node::pop_credentials::PopAuthenticatedPrincipalV1 {
                principal_digest: self.principal_digest,
                expires_at_epoch: self.expires_at_epoch,
                request_authority: self.request_authority,
            })
        }
    }
    struct TestRuntimeSigner {
        key_id: String,
        keypair: KeyPair,
        drift_revision: Option<Arc<AtomicU64>>,
    }
    impl fmt::Debug for TestRuntimeSigner {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("TestRuntimeSigner")
                .field("key_id", &self.key_id)
                .field("private_key", &"[REDACTED]")
                .finish_non_exhaustive()
        }
    }
    impl PopIssuerSigner for TestRuntimeSigner {
        fn key_id(&self) -> &str {
            &self.key_id
        }
        fn public_key(&self) -> [u8; 32] {
            self.keypair
                .public_key()
                .to_bytes()
                .1
                .try_into()
                .expect("Ed25519 public key width")
        }
        fn sign_digest(
            &self,
            _purpose: PopIssuerSigningPurposeV1,
            digest: [u8; 32],
        ) -> Result<[u8; 64], String> {
            let signature: [u8; 64] = Signature::try_new(self.keypair.private_key(), &digest)
                .map_err(|_| "external signer failed".to_owned())?
                .payload()
                .try_into()
                .map_err(|_| "external signer signature width changed".to_owned())?;
            if let Some(revision) = &self.drift_revision {
                revision.fetch_add(1, Ordering::SeqCst);
            }
            Ok(signature)
        }
    }
    struct TestWalletKeyWrapper {
        key_id: String,
        wrapping_key: [u8; 32],
        drift_revision: Option<Arc<AtomicU64>>,
    }
    impl fmt::Debug for TestWalletKeyWrapper {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("TestWalletKeyWrapper")
                .field("key_id", &self.key_id)
                .field("wrapping_key", &"[REDACTED]")
                .finish_non_exhaustive()
        }
    }
    impl PopWalletKeyWrapper for TestWalletKeyWrapper {
        fn active_key_id(&self) -> &str {
            &self.key_id
        }
        fn wrap_dek(&self, context: [u8; 32], dek: &[u8; 32]) -> Result<Vec<u8>, String> {
            let wrapped = dek
                .iter()
                .zip(self.wrapping_key)
                .zip(context)
                .map(|((&byte, key), aad)| byte ^ key ^ aad)
                .collect();
            if let Some(revision) = &self.drift_revision {
                revision.fetch_add(1, Ordering::SeqCst);
            }
            Ok(wrapped)
        }
        fn unwrap_dek(
            &self,
            key_id: &str,
            context: [u8; 32],
            wrapped_dek: &[u8],
        ) -> Result<[u8; 32], String> {
            if key_id != self.key_id || wrapped_dek.len() != 32 {
                return Err("wallet key unavailable".to_owned());
            }
            let mut dek = [0; 32];
            for (index, output) in dek.iter_mut().enumerate() {
                *output = wrapped_dek[index] ^ self.wrapping_key[index] ^ context[index];
            }
            if let Some(revision) = &self.drift_revision {
                revision.fetch_add(1, Ordering::SeqCst);
            }
            Ok(dek)
        }
    }
    struct TestRecipient {
        key_id: String,
        secret: HybridSecretKey,
        public_key_digest: [u8; 32],
    }
    impl fmt::Debug for TestRecipient {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("TestRecipient")
                .field("key_id", &self.key_id)
                .field("private_key", &"[REDACTED]")
                .finish_non_exhaustive()
        }
    }
    impl PopEnrollmentRecipientV1 for TestRecipient {
        fn key_id(&self) -> &str {
            &self.key_id
        }
        fn public_key_digest(&self) -> [u8; 32] {
            self.public_key_digest
        }
        fn open_enrollment(
            &self,
            encrypted_payload: &HybridPayloadEnvelopeV1,
            aad: &[u8],
        ) -> Result<Vec<u8>, PopRecipientOpenErrorV1> {
            decrypt_payload(encrypted_payload, aad, &self.secret)
                .map_err(|_| PopRecipientOpenErrorV1::Rejected)
        }
    }
    impl PopWalletRecipientV1 for TestRecipient {
        fn key_id(&self) -> &str {
            &self.key_id
        }
        fn public_key_digest(&self) -> [u8; 32] {
            self.public_key_digest
        }
        fn open_wallet_delivery(
            &self,
            encrypted_payload: &HybridPayloadEnvelopeV1,
            aad: &[u8],
        ) -> Result<Vec<u8>, PopRecipientOpenErrorV1> {
            decrypt_payload(encrypted_payload, aad, &self.secret)
                .map_err(|_| PopRecipientOpenErrorV1::Rejected)
        }
    }
    #[derive(Debug)]
    struct NoopRegistrySubmitter;
    impl PopRegistrySubmitter for NoopRegistrySubmitter {
        fn submit(
            &self,
            _idempotency_key: [u8; 32],
            _operation: &sorafs_node::pop_credentials::PopRegistryOperationV1,
        ) -> Result<(), String> {
            Ok(())
        }
    }
    #[derive(Debug)]
    struct EmptyRegistryReader;
    impl PopFinalizedRegistryReader for EmptyRegistryReader {
        fn next_after(
            &self,
            _cursor: Option<PopFinalizedCursorV1>,
        ) -> Result<Option<PopFinalizedRegistryProjectionV1>, String> {
            Ok(None)
        }
    }
    #[derive(Debug)]
    struct ProjectionSequenceReader {
        projections: Vec<PopFinalizedRegistryProjectionV1>,
        calls: Arc<AtomicUsize>,
    }
    impl PopFinalizedRegistryReader for ProjectionSequenceReader {
        fn next_after(
            &self,
            cursor: Option<PopFinalizedCursorV1>,
        ) -> Result<Option<PopFinalizedRegistryProjectionV1>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let next_index = match cursor {
                None => 0,
                Some(cursor) => self
                    .projections
                    .iter()
                    .position(|projection| projection.cursor == cursor)
                    .ok_or_else(|| "unknown finalized cursor".to_owned())?
                    .saturating_add(1),
            };
            Ok(self.projections.get(next_index).cloned())
        }
    }
    #[derive(Debug)]
    struct FailingRegistryReader {
        calls: Arc<AtomicUsize>,
    }
    impl PopFinalizedRegistryReader for FailingRegistryReader {
        fn next_after(
            &self,
            _cursor: Option<PopFinalizedCursorV1>,
        ) -> Result<Option<PopFinalizedRegistryProjectionV1>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err("finalized registry unavailable".to_owned())
        }
    }
    #[derive(Debug)]
    struct UnavailableIssuanceDraftProvider;
    impl PopIssuanceDraftProviderV1 for UnavailableIssuanceDraftProvider {
        fn resolve(
            &self,
            _request_id: [u8; 32],
            _now_epoch: u64,
        ) -> Result<PopIssuanceDraftV1, PopPrivateMaterialProviderErrorV1> {
            Err(PopPrivateMaterialProviderErrorV1::Unavailable)
        }
    }
    #[derive(Debug)]
    struct UnavailableWalletWitnessProvider;
    impl PopWalletWitnessProviderV1 for UnavailableWalletWitnessProvider {
        fn resolve(
            &self,
            _credential_commitment: [u8; 32],
            _projection: &PopFinalizedRegistryProjectionV1,
        ) -> Result<PopMembershipWitnessV1, PopPrivateMaterialProviderErrorV1> {
            Err(PopPrivateMaterialProviderErrorV1::Unavailable)
        }
    }
    #[derive(Debug)]
    struct FixedFinalizedTimeProvider {
        calls: AtomicUsize,
        revision: Arc<AtomicU64>,
        drift_on_sample: AtomicBool,
        sample: std::sync::Mutex<PopFinalizedTimeSampleV1>,
    }
    impl PopFinalizedTimeProviderV1 for FixedFinalizedTimeProvider {
        fn sample(&self) -> Result<PopFinalizedTimeSampleV1, PopFinalizedTimeProviderErrorV1> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.drift_on_sample.load(Ordering::SeqCst) {
                self.revision.fetch_add(1, Ordering::SeqCst);
            }
            self.sample
                .lock()
                .map(|sample| *sample)
                .map_err(|_| PopFinalizedTimeProviderErrorV1::Unavailable)
        }
    }
    #[derive(Debug)]
    struct AdvancingFinalizedTimeAuthenticator {
        finalized_time: Arc<FixedFinalizedTimeProvider>,
        next_sample: PopFinalizedTimeSampleV1,
        calls: AtomicUsize,
    }
    impl PopCredentialApiAuthenticator for AdvancingFinalizedTimeAuthenticator {
        fn authenticate(
            &self,
            _opaque_credential: &[u8],
            _action: PopCredentialApiActionV1,
            _request_binding: [u8; 32],
            _now_epoch: u64,
        ) -> Result<sorafs_node::pop_credentials::PopAuthenticatedPrincipalV1, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self
                .finalized_time
                .sample
                .lock()
                .map_err(|_| "finalized time lock unavailable".to_owned())? = self.next_sample;
            Ok(sorafs_node::pop_credentials::PopAuthenticatedPrincipalV1 {
                principal_digest: [0x71; 32],
                expires_at_epoch: 1_000,
                request_authority: PopRequestAuthorityV1::CallerSignedTransaction,
            })
        }
    }
    struct TestRuntimeProviderRegistry {
        handle: String,
        revision: Arc<AtomicU64>,
        policy_digest: [u8; 32],
        qualification_refused: AtomicBool,
        drift_on_resolve: AtomicBool,
        providers: std::sync::Mutex<Option<PopCredentialRuntimeProvidersV1>>,
        observed_bindings: std::sync::Mutex<Option<PopCredentialRuntimeProviderBindingsV1>>,
    }
    impl fmt::Debug for TestRuntimeProviderRegistry {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("TestRuntimeProviderRegistry")
                .field("handle", &self.handle)
                .field("private_providers", &"[REDACTED]")
                .finish_non_exhaustive()
        }
    }
    impl PopCredentialRuntimeProviderRegistryV1 for TestRuntimeProviderRegistry {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            PopCredentialRuntimeProviderQualificationV1,
            PopCredentialRuntimeProviderRegistryErrorV1,
        > {
            if self.qualification_refused.load(Ordering::SeqCst) {
                return Err(PopCredentialRuntimeProviderRegistryErrorV1::StaleOrRevoked);
            }
            Ok(PopCredentialRuntimeProviderQualificationV1::new(
                self.revision.load(Ordering::SeqCst),
                self.policy_digest,
            ))
        }
        fn resolve(
            &self,
            bindings: &PopCredentialRuntimeProviderBindingsV1,
        ) -> Result<PopCredentialRuntimeProvidersV1, PopCredentialRuntimeProviderRegistryErrorV1>
        {
            *self
                .observed_bindings
                .lock()
                .map_err(|_| PopCredentialRuntimeProviderRegistryErrorV1::Unavailable)? =
                Some(bindings.clone());
            let providers = self
                .providers
                .lock()
                .map_err(|_| PopCredentialRuntimeProviderRegistryErrorV1::Unavailable)?
                .take()
                .ok_or(PopCredentialRuntimeProviderRegistryErrorV1::Unavailable)?;
            if self.drift_on_resolve.load(Ordering::SeqCst) {
                self.revision.fetch_add(1, Ordering::SeqCst);
            }
            Ok(providers)
        }
    }
    fn finalized_time_sample(
        height: u64,
        hash_byte: u8,
        finalized_epoch: u64,
        observed_epoch: u64,
    ) -> PopFinalizedTimeSampleV1 {
        PopFinalizedTimeSampleV1 {
            finalized_block_height: height,
            finalized_block_hash: [hash_byte; 32],
            finalized_epoch,
            observed_epoch,
        }
    }
    fn ed25519(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("derive test Ed25519 key")
    }
    fn public_key_bytes(keypair: &KeyPair) -> [u8; 32] {
        keypair
            .public_key()
            .to_bytes()
            .1
            .try_into()
            .expect("Ed25519 public key width")
    }
    fn pop_scalar(value: u64) -> [u8; 32] {
        let mut scalar = [0; 32];
        scalar[..8].copy_from_slice(&value.to_le_bytes());
        scalar
    }
    fn empty_pop_signature(keypair: &KeyPair) -> PopSignatureV1 {
        PopSignatureV1 {
            algorithm: PopSignatureAlgorithmV1::Ed25519,
            public_key: public_key_bytes(keypair).to_vec(),
            signature: Vec::new(),
        }
    }
    fn signed_pop_signature(keypair: &KeyPair, digest: [u8; 32]) -> PopSignatureV1 {
        PopSignatureV1 {
            algorithm: PopSignatureAlgorithmV1::Ed25519,
            public_key: public_key_bytes(keypair).to_vec(),
            signature: Signature::try_new(keypair.private_key(), &digest)
                .expect("sign finalized projection fixture")
                .payload()
                .to_vec(),
        }
    }
    fn finalized_projection_fixture(
        keypair: &KeyPair,
        height: u64,
        previous_block_hash: Option<[u8; 32]>,
        root_version: u64,
        previous_root_digest: Option<[u8; 32]>,
    ) -> PopFinalizedRegistryProjectionV1 {
        let mut root = PopCommitmentRootV1 {
            version: POP_COMMITMENT_ROOT_VERSION_V1,
            root_digest: pop_scalar(100 + root_version),
            tree_size: root_version,
            tree_depth: POP_CREDENTIAL_TREE_DEPTH_V1,
            tree_version: root_version,
            issuer_id: "pop-issuer-runtime-primary".to_owned(),
            published_at_epoch: 30 + root_version,
            previous_root_digest,
            governance_event_digest: [0x61; 32],
            publisher_signature: empty_pop_signature(keypair),
        };
        let root_signature_digest =
            pop_commitment_root_signature_digest_v1(&root).expect("commitment root digest");
        root.publisher_signature = signed_pop_signature(keypair, root_signature_digest);
        let mut revocations = PopRevocationListV1 {
            version: POP_REVOCATION_LIST_VERSION_V1,
            list_version: root_version,
            commitment_root: root.root_digest,
            revocation_root: pop_revocation_root_v1(&[]).expect("empty revocation root"),
            revocation_tree_depth: POP_REVOCATION_TREE_DEPTH_V1,
            issuer_id: "pop-issuer-runtime-primary".to_owned(),
            published_at_epoch: 30 + root_version,
            entries: Vec::new(),
            publisher_signature: empty_pop_signature(keypair),
        };
        let revocation_signature_digest =
            pop_revocation_list_signature_digest_v1(&revocations).expect("revocation-list digest");
        revocations.publisher_signature =
            signed_pop_signature(keypair, revocation_signature_digest);
        PopFinalizedRegistryProjectionV1 {
            version: POP_FINALIZED_REGISTRY_PROJECTION_VERSION_V1,
            cursor: PopFinalizedCursorV1 {
                block_height: height,
                block_hash: [u8::try_from(height).expect("fixture height fits in u8"); 32],
            },
            previous_block_hash,
            issuer_policy_digest: [0x51; 32],
            canonical_commitment_root: norito::to_bytes(&root)
                .expect("encode commitment-root fixture"),
            canonical_revocation_list: norito::to_bytes(&revocations)
                .expect("encode revocation-list fixture"),
            committed_operation_digests: Vec::new(),
            rejected_operation_digests: Vec::new(),
            revoked_issuer_public_keys: Vec::new(),
        }
    }
    fn finalized_projection_sequence(count: u64) -> Vec<PopFinalizedRegistryProjectionV1> {
        let keypair = ed25519(0x41);
        let mut projections = Vec::new();
        let mut previous_block_hash = None;
        let mut previous_root_digest = None;
        for height in 1..=count {
            let projection = finalized_projection_fixture(
                &keypair,
                height,
                previous_block_hash,
                height,
                previous_root_digest,
            );
            previous_block_hash = Some(projection.cursor.block_hash);
            previous_root_digest = Some(pop_scalar(100 + height));
            projections.push(projection);
        }
        projections
    }
    #[test]
    fn runtime_provider_bindings_constructor_is_exact_and_fail_closed() {
        let issuer_public_key = public_key_bytes(&ed25519(0x40));
        let bindings = PopCredentialRuntimeProviderBindingsV1::try_new(
            [0x41; 32],
            "pop-issuer-runtime-primary".to_owned(),
            "software://sorafs/pop-credentials/primary".to_owned(),
            issuer_public_key,
            ("kms:pop/enrollment:primary".to_owned(), [0x42; 32]),
            ("kms:pop/wallet-recipient:primary".to_owned(), [0x43; 32]),
            "kms:pop/wallet:primary".to_owned(),
        )
        .expect("canonical exact bindings");
        assert_eq!(bindings.issuer_policy_digest(), [0x41; 32]);
        assert_eq!(bindings.issuer_id(), "pop-issuer-runtime-primary");
        assert_eq!(
            bindings.issuer_signer_handle(),
            "software://sorafs/pop-credentials/primary"
        );
        assert_eq!(bindings.issuer_public_key(), issuer_public_key);
        assert_eq!(
            bindings.enrollment_recipient_key_id(),
            "kms:pop/enrollment:primary"
        );
        assert_eq!(
            bindings.enrollment_recipient_public_key_digest(),
            [0x42; 32]
        );
        assert_eq!(
            bindings.wallet_recipient_key_id(),
            "kms:pop/wallet-recipient:primary"
        );
        assert_eq!(bindings.wallet_recipient_public_key_digest(), [0x43; 32]);
        assert_eq!(bindings.wallet_wrapping_key_id(), "kms:pop/wallet:primary");
        let assert_rejected = |issuer_policy_digest,
                               issuer_id: &str,
                               issuer_signer_handle: &str,
                               issuer_public_key,
                               enrollment_recipient_key_id: &str,
                               enrollment_recipient_public_key_digest,
                               wallet_recipient_key_id: &str,
                               wallet_recipient_public_key_digest,
                               wallet_wrapping_key_id: &str,
                               field| {
            assert_eq!(
                PopCredentialRuntimeProviderBindingsV1::try_new(
                    issuer_policy_digest,
                    issuer_id.to_owned(),
                    issuer_signer_handle.to_owned(),
                    issuer_public_key,
                    (
                        enrollment_recipient_key_id.to_owned(),
                        enrollment_recipient_public_key_digest
                    ),
                    (
                        wallet_recipient_key_id.to_owned(),
                        wallet_recipient_public_key_digest
                    ),
                    wallet_wrapping_key_id.to_owned(),
                ),
                Err(PopCredentialServiceError::InvalidInput { field })
            );
        };
        assert_rejected(
            [0; 32],
            "pop-issuer-runtime-primary",
            "software://sorafs/pop-credentials/primary",
            issuer_public_key,
            "kms:pop/enrollment:primary",
            [0x42; 32],
            "kms:pop/wallet-recipient:primary",
            [0x43; 32],
            "kms:pop/wallet:primary",
            "issuer_policy_digest",
        );
        for issuer_id in [
            "",
            " pop-issuer-runtime-primary",
            "pop-issuer-runtime-primary\n",
        ] {
            assert_rejected(
                [0x41; 32],
                issuer_id,
                "software://sorafs/pop-credentials/primary",
                issuer_public_key,
                "kms:pop/enrollment:primary",
                [0x42; 32],
                "kms:pop/wallet-recipient:primary",
                [0x43; 32],
                "kms:pop/wallet:primary",
                "issuer_id",
            );
        }
        let oversized_issuer = "i".repeat(POP_IDENTITY_TEXT_MAX_BYTES_V1 + 1);
        assert_rejected(
            [0x41; 32],
            &oversized_issuer,
            "software://sorafs/pop-credentials/primary",
            issuer_public_key,
            "kms:pop/enrollment:primary",
            [0x42; 32],
            "kms:pop/wallet-recipient:primary",
            [0x43; 32],
            "kms:pop/wallet:primary",
            "issuer_id",
        );
        for (issuer_signer_handle, enrollment_key_id, wallet_key_id, field) in [
            (
                "software://sorafs/pop-credentials/test",
                "kms:pop/enrollment:primary",
                "kms:pop/wallet:primary",
                "issuer_signer_handle",
            ),
            (
                "software://sorafs/pop-credentials/primary",
                "kms://pop/mock/enrollment",
                "kms:pop/wallet:primary",
                "enrollment_recipient_key_id",
            ),
            (
                "software://sorafs/pop-credentials/primary",
                "kms:pop/enrollment:primary",
                "kms://pop/fake/wallet",
                "wallet_wrapping_key_id",
            ),
        ] {
            assert_rejected(
                [0x41; 32],
                "pop-issuer-runtime-primary",
                issuer_signer_handle,
                issuer_public_key,
                enrollment_key_id,
                [0x42; 32],
                "kms:pop/wallet-recipient:primary",
                [0x43; 32],
                wallet_key_id,
                field,
            );
        }
        assert_rejected(
            [0x41; 32],
            "pop-issuer-runtime-primary",
            "software://sorafs/pop-credentials/primary",
            issuer_public_key,
            "kms:pop/enrollment:primary",
            [0x42; 32],
            "kms://pop/mock/wallet-recipient",
            [0x43; 32],
            "kms:pop/wallet:primary",
            "wallet_recipient_key_id",
        );
        assert_rejected(
            [0x41; 32],
            "pop-issuer-runtime-primary",
            "software://sorafs/pop-credentials/primary",
            [0; 32],
            "kms:pop/enrollment:primary",
            [0x42; 32],
            "kms:pop/wallet-recipient:primary",
            [0x43; 32],
            "kms:pop/wallet:primary",
            "issuer_public_key",
        );
        assert_rejected(
            [0x41; 32],
            "pop-issuer-runtime-primary",
            "software://sorafs/pop-credentials/primary",
            issuer_public_key,
            "kms:pop/enrollment:primary",
            [0; 32],
            "kms:pop/wallet-recipient:primary",
            [0x43; 32],
            "kms:pop/wallet:primary",
            "enrollment_recipient_public_key_digest",
        );
        assert_rejected(
            [0x41; 32],
            "pop-issuer-runtime-primary",
            "software://sorafs/pop-credentials/primary",
            issuer_public_key,
            "kms:pop/enrollment:primary",
            [0x42; 32],
            "kms:pop/wallet-recipient:primary",
            [0; 32],
            "kms:pop/wallet:primary",
            "wallet_recipient_public_key_digest",
        );
    }
    fn runtime_fixture(
        root: &std::path::Path,
        expected_registry_handle: &str,
        provider_registry_handle: &str,
    ) -> (
        PopCredentialRuntimeConfigV1,
        Arc<TestRuntimeProviderRegistry>,
        Arc<FixedFinalizedTimeProvider>,
    ) {
        runtime_fixture_with_registry_reader(
            root,
            expected_registry_handle,
            provider_registry_handle,
            Arc::new(EmptyRegistryReader),
        )
    }
    fn runtime_fixture_with_registry_reader(
        root: &std::path::Path,
        expected_registry_handle: &str,
        provider_registry_handle: &str,
        registry_reader: Arc<dyn PopFinalizedRegistryReader>,
    ) -> (
        PopCredentialRuntimeConfigV1,
        Arc<TestRuntimeProviderRegistry>,
        Arc<FixedFinalizedTimeProvider>,
    ) {
        let root = root
            .canonicalize()
            .expect("canonical runtime fixture root without symlink ancestors");
        let signer = Arc::new(TestRuntimeSigner {
            key_id: "software://sorafs/pop-credentials/primary".to_owned(),
            keypair: ed25519(0x41),
            drift_revision: None,
        });
        let approver_a = ed25519(0x42);
        let approver_b = ed25519(0x43);
        let mut rng = OsRng;
        let enrollment_recipient =
            HybridKeyPair::generate(&mut rng).expect("enrollment recipient key");
        let wallet_recipient = HybridKeyPair::generate(&mut rng).expect("wallet recipient key");
        let config = PopCredentialRuntimeConfigV1 {
            service_policy: PopCredentialServicePolicyV1 {
                version: POP_CREDENTIAL_SERVICE_POLICY_VERSION_V1,
                issuer_policy_digest: [0x51; 32],
                issuer_id: "pop-issuer-runtime-primary".to_owned(),
                issuer_signer_handle: signer.key_id.clone(),
                issuer_public_key: signer.public_key(),
                enrollment_recipient_key_id: "kms:pop/enrollment:primary".to_owned(),
                approval_quorum: 2,
                approval_signers: vec![
                    PopApprovalSignerV1 {
                        signer_id: "approver-a".to_owned(),
                        public_key: public_key_bytes(&approver_a),
                        revoked_at_epoch: None,
                    },
                    PopApprovalSignerV1 {
                        signer_id: "approver-b".to_owned(),
                        public_key: public_key_bytes(&approver_b),
                        revoked_at_epoch: None,
                    },
                ],
                max_pending_enrollments: 16,
                max_outbox_entries: 16,
                max_dead_letters: 16,
                max_seen_nullifiers: 16,
                max_submission_attempts: 3,
            },
            issuer_state_dir: root.join("issuer"),
            wallet_state_dir: root.join("wallet"),
            worker_interval: Duration::from_secs(1),
            max_finalized_time_skew: Duration::from_secs(30),
            enrollment_recipient_public_key_digest: pop_enrollment_recipient_public_key_digest_v1(
                enrollment_recipient.public(),
            ),
            wallet_recipient_key_id: "kms:pop/wallet-recipient:primary".to_owned(),
            wallet_recipient_public_key_digest: pop_enrollment_recipient_public_key_digest_v1(
                wallet_recipient.public(),
            ),
            wallet_wrapping_key_id: "kms:pop/wallet:primary".to_owned(),
            runtime_provider_registry_handle: expected_registry_handle.to_owned(),
            runtime_provider_registry_revision: 7,
            runtime_provider_registry_policy_digest: [0x61; 32],
        };
        let revision = Arc::new(AtomicU64::new(7));
        let finalized_time_provider = Arc::new(FixedFinalizedTimeProvider {
            calls: AtomicUsize::new(0),
            revision: Arc::clone(&revision),
            drift_on_sample: AtomicBool::new(false),
            sample: std::sync::Mutex::new(finalized_time_sample(1, 1, 100, 100)),
        });
        let providers = PopCredentialRuntimeProvidersV1 {
            enrollment_recipient: Arc::new(TestRecipient {
                key_id: config.service_policy.enrollment_recipient_key_id.clone(),
                secret: enrollment_recipient.secret().clone(),
                public_key_digest: config.enrollment_recipient_public_key_digest,
            }),
            issuer_signer: signer,
            authenticator: Arc::new(FixedAuthenticator {
                principal_digest: [0x71; 32],
                expires_at_epoch: 1_000,
                request_authority: PopRequestAuthorityV1::CallerSignedTransaction,
                reject: false,
                calls: AtomicUsize::new(0),
            }),
            registry_submitter: Arc::new(NoopRegistrySubmitter),
            registry_reader,
            issuance_draft_provider: Arc::new(UnavailableIssuanceDraftProvider),
            wallet_recipient: Arc::new(TestRecipient {
                key_id: config.wallet_recipient_key_id.clone(),
                secret: wallet_recipient.secret().clone(),
                public_key_digest: config.wallet_recipient_public_key_digest,
            }),
            wallet_key_wrapper: Arc::new(TestWalletKeyWrapper {
                key_id: "kms:pop/wallet:primary".to_owned(),
                wrapping_key: [0x72; 32],
                drift_revision: None,
            }),
            wallet_witness_provider: Arc::new(UnavailableWalletWitnessProvider),
            finalized_time_provider: finalized_time_provider.clone(),
        };
        let registry = Arc::new(TestRuntimeProviderRegistry {
            handle: provider_registry_handle.to_owned(),
            revision,
            policy_digest: [0x61; 32],
            qualification_refused: AtomicBool::new(false),
            drift_on_resolve: AtomicBool::new(false),
            providers: std::sync::Mutex::new(Some(providers)),
            observed_bindings: std::sync::Mutex::new(None),
        });
        (config, registry, finalized_time_provider)
    }
    fn as_runtime_registry(
        registry: &Arc<TestRuntimeProviderRegistry>,
    ) -> Arc<dyn PopCredentialRuntimeProviderRegistryV1> {
        registry.clone()
    }
    fn assert_startup_failure_before_state(
        config: PopCredentialRuntimeConfigV1,
        registry: Option<Arc<dyn PopCredentialRuntimeProviderRegistryV1>>,
        expected: PopCredentialServiceError,
    ) {
        let issuer_state_dir = config.issuer_state_dir.clone();
        let wallet_state_dir = config.wallet_state_dir.clone();
        let error = PopCredentialToriiRuntimeV1::open(config, registry)
            .expect_err("runtime startup must fail");
        assert_eq!(error, expected);
        assert!(!issuer_state_dir.exists());
        assert!(!wallet_state_dir.exists());
    }
    #[test]
    fn runtime_registry_pins_public_bindings_and_blocks_preexisting_drift() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, finalized_time) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        let runtime =
            PopCredentialToriiRuntimeV1::open(config.clone(), Some(as_runtime_registry(&registry)))
                .expect("exact provider registry must qualify");
        let observed = registry
            .observed_bindings
            .lock()
            .expect("observed binding lock")
            .clone()
            .expect("registry observed public bindings");
        assert_eq!(
            observed.issuer_policy_digest(),
            config.service_policy.issuer_policy_digest
        );
        assert_eq!(observed.issuer_id(), config.service_policy.issuer_id);
        assert_eq!(
            observed.issuer_signer_handle(),
            config.service_policy.issuer_signer_handle
        );
        assert_eq!(
            observed.issuer_public_key(),
            config.service_policy.issuer_public_key
        );
        assert_eq!(
            observed.enrollment_recipient_key_id(),
            config.service_policy.enrollment_recipient_key_id
        );
        assert_eq!(
            observed.enrollment_recipient_public_key_digest(),
            config.enrollment_recipient_public_key_digest
        );
        assert_eq!(
            observed.wallet_recipient_key_id(),
            config.wallet_recipient_key_id
        );
        assert_eq!(
            observed.wallet_recipient_public_key_digest(),
            config.wallet_recipient_public_key_digest
        );
        assert_eq!(
            observed.wallet_wrapping_key_id(),
            config.wallet_wrapping_key_id
        );
        assert!(config.issuer_state_dir.exists());
        assert!(config.wallet_state_dir.exists());
        registry.revision.store(8, Ordering::SeqCst);
        assert_eq!(
            runtime.current_epoch(),
            Err(PopCredentialServiceError::RuntimeProviderRegistryDrift)
        );
        assert_eq!(finalized_time.calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn supervised_worker_honors_preexisting_shutdown_before_provider_access() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, finalized_time) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        let runtime = Arc::new(
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("exact provider registry must qualify"),
        );
        let shutdown = iroha_futures::supervisor::ShutdownSignal::new();
        shutdown.send();
        let exit = runtime
            .spawn(shutdown)
            .await
            .expect("PoP worker must join after preexisting shutdown");
        assert_eq!(exit, crate::ToriiCriticalWorkerExit::StoppedByShutdown);
        assert_eq!(finalized_time.calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn supervised_worker_exits_when_provider_registry_identity_drifts() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, finalized_time) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        let runtime = Arc::new(
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("exact provider registry must qualify"),
        );
        registry.revision.store(8, Ordering::SeqCst);
        let exit = tokio::time::timeout(
            Duration::from_secs(1),
            runtime.spawn(iroha_futures::supervisor::ShutdownSignal::new()),
        )
        .await
        .expect("permanent registry drift must stop the worker")
        .expect("PoP worker must join");
        assert_eq!(exit, crate::ToriiCriticalWorkerExit::UnexpectedExit);
        assert_eq!(finalized_time.calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn runtime_registry_failures_have_one_payload_free_unavailable_surface() {
        for error in [
            PopCredentialServiceError::RuntimeProviderRegistryMissing,
            PopCredentialServiceError::RuntimeProviderRegistryMismatch,
            PopCredentialServiceError::RuntimeProviderRegistryUnavailable,
            PopCredentialServiceError::RuntimeProviderRegistryDrift,
        ] {
            assert_eq!(
                error_response(error).status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
    }
    #[tokio::test]
    async fn finalized_projection_read_stops_at_sampled_head_and_survives_restart() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let projections = finalized_projection_sequence(3);
        let expected = projections[1].clone();
        let reader_calls = Arc::new(AtomicUsize::new(0));
        let reader: Arc<dyn PopFinalizedRegistryReader> = Arc::new(ProjectionSequenceReader {
            projections,
            calls: Arc::clone(&reader_calls),
        });
        let (config, registry, finalized_time) = runtime_fixture_with_registry_reader(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
            reader,
        );
        *finalized_time.sample.lock().expect("finalized sample lock") =
            finalized_time_sample(2, 2, 100, 100);
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with finalized reader");
        let projection = runtime
            .finalized_projection(b"credential")
            .await
            .expect("fresh projection read")
            .expect("finalized projection");
        assert_eq!(projection, expected);
        assert_eq!(reader_calls.load(Ordering::SeqCst), 2);
        drop(runtime);
        let (config, registry, finalized_time) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        *finalized_time.sample.lock().expect("finalized sample lock") =
            finalized_time_sample(2, 2, 100, 100);
        let restarted =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("restart from durable projection checkpoint");
        assert_eq!(
            restarted
                .finalized_projection(b"credential")
                .await
                .expect("projection read after restart"),
            Some(expected)
        );
    }
    #[tokio::test]
    async fn finalized_projection_rejects_reader_caught_up_below_authoritative_head() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let projections = finalized_projection_sequence(1);
        let stale = projections[0].clone();
        let reader_calls = Arc::new(AtomicUsize::new(0));
        let reader: Arc<dyn PopFinalizedRegistryReader> = Arc::new(ProjectionSequenceReader {
            projections,
            calls: Arc::clone(&reader_calls),
        });
        let (config, registry, finalized_time) = runtime_fixture_with_registry_reader(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
            reader,
        );
        *finalized_time.sample.lock().expect("finalized sample lock") =
            finalized_time_sample(2, 2, 100, 100);
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with stale finalized reader");
        assert_eq!(
            runtime.finalized_projection(b"credential").await,
            Err(PopCredentialServiceError::RegistryUnavailable)
        );
        assert_eq!(reader_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            runtime.service.lock().await.finalized_projection().cloned(),
            Some(stale)
        );
    }
    #[tokio::test]
    async fn finalized_projection_reader_error_with_cache_returns_unavailable() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let projections = finalized_projection_sequence(1);
        let cached = projections[0].clone();
        let initial_reader: Arc<dyn PopFinalizedRegistryReader> =
            Arc::new(ProjectionSequenceReader {
                projections,
                calls: Arc::new(AtomicUsize::new(0)),
            });
        let (config, registry, _) = runtime_fixture_with_registry_reader(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
            initial_reader,
        );
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with finalized reader");
        assert_eq!(
            runtime
                .finalized_projection(b"credential")
                .await
                .expect("initial projection read"),
            Some(cached.clone())
        );
        drop(runtime);
        let reader_calls = Arc::new(AtomicUsize::new(0));
        let failing_reader: Arc<dyn PopFinalizedRegistryReader> = Arc::new(FailingRegistryReader {
            calls: Arc::clone(&reader_calls),
        });
        let (config, registry, finalized_time) = runtime_fixture_with_registry_reader(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
            failing_reader,
        );
        *finalized_time.sample.lock().expect("finalized sample lock") =
            finalized_time_sample(2, 2, 100, 100);
        let restarted =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("restart with unavailable finalized reader");
        let error = restarted
            .finalized_projection(b"credential")
            .await
            .expect_err("cached projection must not mask reader failure");
        assert_eq!(error, PopCredentialServiceError::RegistryUnavailable);
        assert_eq!(
            error_response(error).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(reader_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            restarted
                .service
                .lock()
                .await
                .finalized_projection()
                .cloned(),
            Some(cached)
        );
    }
    #[tokio::test]
    async fn every_non_projection_read_rejects_an_unavailable_finalized_reader() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let reader_calls = Arc::new(AtomicUsize::new(0));
        let reader: Arc<dyn PopFinalizedRegistryReader> = Arc::new(FailingRegistryReader {
            calls: Arc::clone(&reader_calls),
        });
        let (config, registry, _) = runtime_fixture_with_registry_reader(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
            reader,
        );
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with failing finalized reader");
        assert_eq!(
            runtime.enrollment_status(b"credential", [0x81; 32]).await,
            Err(PopCredentialServiceError::RegistryUnavailable)
        );
        assert_eq!(
            runtime.wallet_delivery(b"credential", [0x82; 32]).await,
            Err(PopCredentialServiceError::RegistryUnavailable)
        );
        assert_eq!(
            runtime
                .prove_membership(
                    b"credential",
                    [0x83; 32],
                    [0x84; 32],
                    "verifier.example",
                    [0x85; 32]
                )
                .await,
            Err(PopCredentialServiceError::RegistryUnavailable)
        );
        assert_eq!(reader_calls.load(Ordering::SeqCst), 3);
    }
    #[tokio::test]
    async fn public_mutation_requires_caller_signature_before_fresh_reconciliation() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let unsigned_reader_calls = Arc::new(AtomicUsize::new(0));
        let reader: Arc<dyn PopFinalizedRegistryReader> = Arc::new(FailingRegistryReader {
            calls: Arc::clone(&unsigned_reader_calls),
        });
        let (config, registry, _) = runtime_fixture_with_registry_reader(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
            reader,
        );
        registry
            .providers
            .lock()
            .expect("runtime providers lock")
            .as_mut()
            .expect("runtime providers")
            .authenticator = Arc::new(FixedAuthenticator {
            principal_digest: [0x71; 32],
            expires_at_epoch: 1_000,
            request_authority: PopRequestAuthorityV1::AuthenticatedRequest,
            reject: false,
            calls: AtomicUsize::new(0),
        });
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with unsigned authenticator");
        assert_eq!(
            runtime.submit_enrollment(b"credential", b"invalid").await,
            Err(PopCredentialServiceError::Unauthorized)
        );
        assert_eq!(unsigned_reader_calls.load(Ordering::SeqCst), 0);
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let signed_reader_calls = Arc::new(AtomicUsize::new(0));
        let reader: Arc<dyn PopFinalizedRegistryReader> = Arc::new(FailingRegistryReader {
            calls: Arc::clone(&signed_reader_calls),
        });
        let (config, registry, _) = runtime_fixture_with_registry_reader(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
            reader,
        );
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with caller-signed authenticator");
        assert_eq!(
            runtime.submit_enrollment(b"credential", b"invalid").await,
            Err(PopCredentialServiceError::RegistryUnavailable)
        );
        assert_eq!(signed_reader_calls.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn invalid_request_authentication_is_not_delayed_by_the_service_mutex() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        registry
            .providers
            .lock()
            .expect("runtime providers lock")
            .as_mut()
            .expect("runtime providers")
            .authenticator = Arc::new(FixedAuthenticator {
            principal_digest: [0x71; 32],
            expires_at_epoch: 1_000,
            request_authority: PopRequestAuthorityV1::CallerSignedTransaction,
            reject: true,
            calls: AtomicUsize::new(0),
        });
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with rejecting authenticator");
        let service_guard = runtime.service.lock().await;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            runtime.enrollment_status(b"invalid credential", [0x91; 32]),
        )
        .await
        .expect("authentication must complete without waiting for service state");
        assert_eq!(result, Err(PopCredentialServiceError::Unauthorized));
        drop(service_guard);
    }
    #[tokio::test]
    async fn stale_reconciliation_authorization_cannot_advance_state() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let projections = finalized_projection_sequence(1);
        let expected_projection = projections[0].clone();
        let reader_calls = Arc::new(AtomicUsize::new(0));
        let reader: Arc<dyn PopFinalizedRegistryReader> = Arc::new(ProjectionSequenceReader {
            projections,
            calls: Arc::clone(&reader_calls),
        });
        let (config, registry, _) = runtime_fixture_with_registry_reader(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
            reader,
        );
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with finalized reader");
        let now_epoch = runtime.current_epoch().expect("finalized epoch");
        let challenge = {
            let service = runtime.service.lock().await;
            runtime
                .api
                .reconcile_next_authorization_challenge(&service, now_epoch)
                .expect("authorization challenge")
        };
        let authorization = runtime
            .api
            .authorize_challenge(b"credential", challenge)
            .expect("challenge authentication");
        {
            let mut service = runtime.service.lock().await;
            assert!(
                service
                    .reconcile_next(runtime.registry_reader.as_ref(), now_epoch)
                    .expect("independent reconciliation must advance")
            );
        }
        let calls_before_stale_attempt = reader_calls.load(Ordering::SeqCst);
        let result = {
            let mut service = runtime.service.lock().await;
            runtime.api.reconcile_next_authorized(
                &mut service,
                authorization,
                runtime.registry_reader.as_ref(),
                now_epoch,
            )
        };
        assert_eq!(result, Err(PopCredentialServiceError::InvalidState));
        assert_eq!(
            reader_calls.load(Ordering::SeqCst),
            calls_before_stale_attempt,
            "stale authorization must fail before consulting the effectful reader"
        );
        assert_eq!(
            runtime.service.lock().await.finalized_projection(),
            Some(&expected_projection)
        );
    }
    #[tokio::test]
    async fn stable_reconciliation_authorization_succeeds_with_one_authenticator_call() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        let authenticator = Arc::new(FixedAuthenticator {
            principal_digest: [0x71; 32],
            expires_at_epoch: 1_000,
            request_authority: PopRequestAuthorityV1::CallerSignedTransaction,
            reject: false,
            calls: AtomicUsize::new(0),
        });
        registry
            .providers
            .lock()
            .expect("runtime providers lock")
            .as_mut()
            .expect("runtime providers")
            .authenticator = authenticator.clone();
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with stable state");
        assert_eq!(runtime.reconcile_next(b"credential").await, Ok(false));
        assert_eq!(authenticator.calls.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn finalized_head_advance_during_authentication_rejects_before_reconciliation() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let reader_calls = Arc::new(AtomicUsize::new(0));
        let reader: Arc<dyn PopFinalizedRegistryReader> = Arc::new(FailingRegistryReader {
            calls: Arc::clone(&reader_calls),
        });
        let (config, registry, finalized_time) = runtime_fixture_with_registry_reader(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
            reader,
        );
        let authenticator = Arc::new(AdvancingFinalizedTimeAuthenticator {
            finalized_time,
            next_sample: finalized_time_sample(2, 2, 101, 101),
            calls: AtomicUsize::new(0),
        });
        registry
            .providers
            .lock()
            .expect("runtime providers lock")
            .as_mut()
            .expect("runtime providers")
            .authenticator = authenticator.clone();
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with advancing finalized time");

        assert_eq!(
            runtime.reconcile_next(b"credential").await,
            Err(PopCredentialServiceError::InvalidState)
        );
        assert_eq!(authenticator.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            reader_calls.load(Ordering::SeqCst),
            0,
            "a stale finalized-head authorization must fail before reader effects"
        );
        assert!(
            runtime
                .service
                .lock()
                .await
                .finalized_projection()
                .is_none()
        );
    }
    #[tokio::test]
    async fn finalized_projection_read_fails_closed_at_reconciliation_bound() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let projections = finalized_projection_sequence(3);
        let second = projections[1].clone();
        let reader_calls = Arc::new(AtomicUsize::new(0));
        let reader: Arc<dyn PopFinalizedRegistryReader> = Arc::new(ProjectionSequenceReader {
            projections,
            calls: Arc::clone(&reader_calls),
        });
        let (config, registry, finalized_time) = runtime_fixture_with_registry_reader(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
            reader,
        );
        *finalized_time.sample.lock().expect("finalized sample lock") =
            finalized_time_sample(3, 3, 100, 100);
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with finalized reader");
        let error = runtime
            .finalized_projection_bounded(b"credential", 2)
            .await
            .expect_err("unproven head must fail closed at the bound");
        assert_eq!(error, PopCredentialServiceError::RegistryUnavailable);
        assert_eq!(
            error_response(error).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(reader_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            runtime.service.lock().await.finalized_projection().cloned(),
            Some(second)
        );
    }
    #[tokio::test]
    async fn unauthorized_projection_read_does_not_reconcile() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let reader_calls = Arc::new(AtomicUsize::new(0));
        let reader: Arc<dyn PopFinalizedRegistryReader> = Arc::new(ProjectionSequenceReader {
            projections: finalized_projection_sequence(2),
            calls: Arc::clone(&reader_calls),
        });
        let (config, registry, _) = runtime_fixture_with_registry_reader(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
            reader,
        );
        registry
            .providers
            .lock()
            .expect("runtime providers lock")
            .as_mut()
            .expect("runtime providers")
            .authenticator = Arc::new(FixedAuthenticator {
            principal_digest: [0x71; 32],
            expires_at_epoch: 1_000,
            request_authority: PopRequestAuthorityV1::CallerSignedTransaction,
            reject: true,
            calls: AtomicUsize::new(0),
        });
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("runtime with rejecting authenticator");
        assert_eq!(
            runtime.finalized_projection(b"credential").await,
            Err(PopCredentialServiceError::Unauthorized)
        );
        assert_eq!(reader_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn runtime_registry_discards_a_provider_result_when_policy_drifts_during_call() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, finalized_time) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        let runtime =
            PopCredentialToriiRuntimeV1::open(config, Some(as_runtime_registry(&registry)))
                .expect("exact provider registry must qualify");
        finalized_time.drift_on_sample.store(true, Ordering::SeqCst);
        assert_eq!(
            runtime.current_epoch(),
            Err(PopCredentialServiceError::RuntimeProviderRegistryDrift)
        );
        assert_eq!(finalized_time.calls.load(Ordering::SeqCst), 1);
        assert!(
            runtime
                .accepted_finalized_time
                .lock()
                .expect("accepted-time lock")
                .is_none()
        );
    }
    #[test]
    fn qualified_signer_and_kms_discard_results_when_policy_drifts_during_call() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        let qualified_registry = QualifiedPopCredentialRuntimeProviderRegistryV1::try_new(
            &config,
            Some(as_runtime_registry(&registry)),
        )
        .expect("exact provider registry must qualify");
        let signer = QualifiedPopIssuerSignerV1 {
            inner: Arc::new(TestRuntimeSigner {
                key_id: config.service_policy.issuer_signer_handle.clone(),
                keypair: ed25519(0x41),
                drift_revision: Some(Arc::clone(&registry.revision)),
            }),
            key_id: config.service_policy.issuer_signer_handle.clone(),
            public_key: config.service_policy.issuer_public_key,
            registry: qualified_registry,
        };
        assert_eq!(
            signer.sign_digest(PopIssuerSigningPurposeV1::Credential, [0x91; 32]),
            Err(POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())
        );
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        let qualified_registry = QualifiedPopCredentialRuntimeProviderRegistryV1::try_new(
            &config,
            Some(as_runtime_registry(&registry)),
        )
        .expect("exact provider registry must qualify");
        let wrapper = QualifiedPopWalletKeyWrapperV1 {
            inner: Arc::new(TestWalletKeyWrapper {
                key_id: config.wallet_wrapping_key_id.clone(),
                wrapping_key: [0x92; 32],
                drift_revision: Some(Arc::clone(&registry.revision)),
            }),
            active_key_id: config.wallet_wrapping_key_id,
            registry: qualified_registry,
        };
        assert_eq!(
            wrapper.wrap_dek([0x93; 32], &[0x94; 32]),
            Err(POP_RUNTIME_PROVIDER_REDACTED_FAILURE_V1.to_owned())
        );
    }
    #[test]
    fn runtime_provider_handles_use_central_production_grammar() {
        const FIELD: &str = "runtime_provider_registry_handle";
        for handle in [
            "runtime:pop/providers/primary",
            "provider:prod/pop.providers-v1_slot-a",
        ] {
            validate_pop_runtime_provider_handle(handle, FIELD)
                .expect("canonical production provider handle");
        }
        for handle in [
            "https://operator:secret@pop-provider",
            "https://pop-provider/path?credential=secret",
            "https://pop-provider/path#fragment",
            "runtime:pop/%70roviders/primary",
            "runtime:pop\\providers\\primary",
        ] {
            assert!(matches!(
                validate_pop_runtime_provider_handle(handle, FIELD),
                Err(PopCredentialServiceError::InvalidInput { field: FIELD })
            ));
        }
    }
    #[test]
    fn runtime_startup_rejects_missing_substituted_and_test_registries_before_state() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, _, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        assert_startup_failure_before_state(
            config,
            None,
            PopCredentialServiceError::RuntimeProviderRegistryMissing,
        );
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:secondary",
        );
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::RuntimeProviderRegistryMismatch,
        );
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:test",
            "runtime:pop:providers:test",
        );
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::InvalidInput {
                field: "runtime_provider_registry_handle",
            },
        );
    }
    #[test]
    fn runtime_startup_rejects_stale_mismatched_and_drifting_qualification() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        registry.qualification_refused.store(true, Ordering::SeqCst);
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::RuntimeProviderRegistryUnavailable,
        );
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        assert!(
            registry
                .providers
                .lock()
                .expect("runtime providers lock")
                .take()
                .is_some()
        );
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::RuntimeProviderRegistryUnavailable,
        );
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        registry.revision.store(8, Ordering::SeqCst);
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::RuntimeProviderRegistryMismatch,
        );
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        let mut rng = OsRng;
        let substituted_wallet_recipient =
            HybridKeyPair::generate(&mut rng).expect("substituted wallet recipient key");
        registry
            .providers
            .lock()
            .expect("runtime providers lock")
            .as_mut()
            .expect("runtime providers")
            .wallet_recipient = Arc::new(TestRecipient {
            key_id: config.wallet_recipient_key_id.clone(),
            secret: substituted_wallet_recipient.secret().clone(),
            public_key_digest: pop_enrollment_recipient_public_key_digest_v1(
                substituted_wallet_recipient.public(),
            ),
        });
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::RuntimeProviderRegistryMismatch,
        );
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (mut config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        config.runtime_provider_registry_policy_digest = [0x62; 32];
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::RuntimeProviderRegistryMismatch,
        );
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        registry.drift_on_resolve.store(true, Ordering::SeqCst);
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::RuntimeProviderRegistryDrift,
        );
    }
    #[test]
    fn runtime_startup_rejects_substituted_signer_enrollment_and_wallet_identities_before_state() {
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (mut config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        config.service_policy.issuer_public_key = public_key_bytes(&ed25519(0x77));
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::SignerPolicyMismatch,
        );
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        let mut rng = OsRng;
        let substituted_enrollment_recipient =
            HybridKeyPair::generate(&mut rng).expect("substituted enrollment recipient key");
        registry
            .providers
            .lock()
            .expect("runtime providers lock")
            .as_mut()
            .expect("runtime providers")
            .enrollment_recipient = Arc::new(TestRecipient {
            key_id: config.service_policy.enrollment_recipient_key_id.clone(),
            secret: substituted_enrollment_recipient.secret().clone(),
            public_key_digest: pop_enrollment_recipient_public_key_digest_v1(
                substituted_enrollment_recipient.public(),
            ),
        });
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::RuntimeProviderRegistryMismatch,
        );
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (mut config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        config.wallet_wrapping_key_id = "kms:pop:wallet:secondary".to_owned();
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::RuntimeProviderRegistryMismatch,
        );
        let temporary = tempfile::tempdir().expect("temporary runtime root");
        let (config, registry, _) = runtime_fixture(
            temporary.path(),
            "runtime:pop:providers:primary",
            "runtime:pop:providers:primary",
        );
        let test_marked_wrapper: Arc<dyn PopWalletKeyWrapper> = Arc::new(TestWalletKeyWrapper {
            key_id: "kms:pop:wallet:test".to_owned(),
            wrapping_key: [0x72; 32],
            drift_revision: None,
        });
        registry
            .providers
            .lock()
            .expect("runtime providers lock")
            .as_mut()
            .expect("runtime providers")
            .wallet_key_wrapper = test_marked_wrapper;
        assert_startup_failure_before_state(
            config,
            Some(as_runtime_registry(&registry)),
            PopCredentialServiceError::RuntimeProviderRegistryMismatch,
        );
    }
    #[test]
    fn finalized_time_rejects_rollback_and_same_height_fork() {
        let previous = finalized_time_sample(10, 0x11, 1_000, 1_001);
        let next = finalized_time_sample(11, 0x12, 1_002, 1_003);
        assert_eq!(
            validate_finalized_time_sample(Some(&previous), &next, 30),
            Ok(())
        );
        for rollback in [
            finalized_time_sample(9, 0x10, 1_002, 1_003),
            finalized_time_sample(11, 0x12, 999, 1_003),
            finalized_time_sample(11, 0x12, 1_002, 1_000),
        ] {
            assert_eq!(
                validate_finalized_time_sample(Some(&previous), &rollback, 30),
                Err(PopFinalizedTimeSampleErrorV1::Rollback)
            );
        }
        assert_eq!(
            validate_finalized_time_sample(
                Some(&previous),
                &finalized_time_sample(10, 0x22, 1_000, 1_002),
                30,
            ),
            Err(PopFinalizedTimeSampleErrorV1::Fork)
        );
    }
    #[test]
    fn finalized_time_rejects_future_and_stale_samples() {
        assert_eq!(
            validate_finalized_time_sample(
                None,
                &finalized_time_sample(10, 0x11, 1_031, 1_000),
                30,
            ),
            Err(PopFinalizedTimeSampleErrorV1::Skew)
        );
        assert_eq!(
            validate_finalized_time_sample(
                None,
                &finalized_time_sample(10, 0x11, 1_000, 1_031),
                30,
            ),
            Err(PopFinalizedTimeSampleErrorV1::Skew)
        );
        assert_eq!(
            validate_finalized_time_sample(
                None,
                &finalized_time_sample(10, 0x11, 1_030, 1_000),
                30,
            ),
            Ok(())
        );
    }
    #[test]
    fn auth_header_is_strict_canonical_and_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(
            POP_AUTHORIZATION_HEADER_V1,
            HeaderValue::from_static("PopV1 Y3JlZGVudGlhbA"),
        );
        let credential = parse_authentication(&headers).expect("canonical credential");
        assert_eq!(credential.as_bytes(), b"credential");
        assert_eq!(format!("{credential:?}"), "PopApiCredentialV1([REDACTED])");
        for value in [
            "Bearer Y3JlZGVudGlhbA",
            "PopV1 ",
            "PopV1 Y3JlZGVudGlhbA==",
            "PopV1 Y3Jl ZGVudGlhbA",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                POP_AUTHORIZATION_HEADER_V1,
                HeaderValue::from_str(value).expect("test header"),
            );
            assert!(matches!(
                parse_authentication(&headers),
                Err(PopCredentialServiceError::Unauthorized)
            ));
        }
    }
    #[test]
    fn empty_request_accepts_only_an_empty_object() {
        assert!(norito::json::from_json::<PopEmptyRequestV1>("{}").is_ok());
        assert!(norito::json::from_json::<PopEmptyRequestV1>("{ }").is_ok());
        assert_eq!(
            norito::json::to_json(&PopEmptyRequestV1).expect("encode empty request JSON"),
            "{}"
        );
        for malformed in [r#"{"unexpected":true}"#, "[]", "null", ""] {
            assert!(norito::json::from_json::<PopEmptyRequestV1>(malformed).is_err());
        }
        let encoded = crate::frame_test_support::assert_current_frame(
            &PopEmptyRequestV1,
            "iroha_torii::sorafs::pop_api::PopEmptyRequestV1",
        );
        assert_eq!(encoded.len(), norito::core::Header::SIZE);
        let decoded = norito::decode_from_bytes::<PopEmptyRequestV1>(&encoded)
            .expect("native Norito must preserve the exact empty request shape");
        assert_eq!(
            norito::to_bytes(&decoded).expect("re-encode empty request"),
            encoded
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(
            norito::decode_from_bytes::<PopEmptyRequestV1>(&trailing).is_err(),
            "native Norito must reject trailing bytes"
        );
    }
    #[test]
    fn issue_trigger_requires_current_action_authorization() {
        let valid = Arc::new(FixedAuthenticator {
            principal_digest: [0x44; 32],
            expires_at_epoch: 101,
            request_authority: PopRequestAuthorityV1::CallerSignedTransaction,
            reject: false,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let api = PopCredentialApiV1::new(valid.clone());
        assert!(
            api.authorize_issue_resolved(b"opaque", [0x22; 32], 100)
                .is_ok()
        );
        assert_eq!(valid.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        let unsigned = Arc::new(FixedAuthenticator {
            principal_digest: [0x44; 32],
            expires_at_epoch: 101,
            request_authority: PopRequestAuthorityV1::AuthenticatedRequest,
            reject: false,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let api = PopCredentialApiV1::new(unsigned.clone());
        assert_eq!(
            api.authorize_issue_resolved(b"opaque", [0x22; 32], 100),
            Err(PopCredentialServiceError::Unauthorized)
        );
        assert_eq!(unsigned.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        for invalid in [
            FixedAuthenticator {
                principal_digest: [0; 32],
                expires_at_epoch: 101,
                request_authority: PopRequestAuthorityV1::CallerSignedTransaction,
                reject: false,
                calls: std::sync::atomic::AtomicUsize::new(0),
            },
            FixedAuthenticator {
                principal_digest: [0x44; 32],
                expires_at_epoch: 100,
                request_authority: PopRequestAuthorityV1::CallerSignedTransaction,
                reject: false,
                calls: std::sync::atomic::AtomicUsize::new(0),
            },
            FixedAuthenticator {
                principal_digest: [0x44; 32],
                expires_at_epoch: 101,
                request_authority: PopRequestAuthorityV1::CallerSignedTransaction,
                reject: true,
                calls: std::sync::atomic::AtomicUsize::new(0),
            },
        ] {
            let api = PopCredentialApiV1::new(Arc::new(invalid));
            assert_eq!(
                api.authorize_issue_resolved(b"opaque", [0x22; 32], 100),
                Err(PopCredentialServiceError::Unauthorized)
            );
        }
        let not_called = Arc::new(FixedAuthenticator {
            principal_digest: [0x44; 32],
            expires_at_epoch: 101,
            request_authority: PopRequestAuthorityV1::CallerSignedTransaction,
            reject: false,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let api = PopCredentialApiV1::new(not_called.clone());
        assert_eq!(
            api.authorize_issue_resolved(&[], [0x22; 32], 100),
            Err(PopCredentialServiceError::Unauthorized)
        );
        assert_eq!(
            not_called.calls.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }
    #[test]
    fn authentication_guard_zeroizes_on_early_error() {
        fn fail_after_authentication(
            headers: &HeaderMap,
            probe: Arc<std::sync::Mutex<Vec<u8>>>,
        ) -> Result<(), PopCredentialServiceError> {
            let mut credential = parse_authentication(headers)?;
            credential.drop_probe = Some(probe);
            Err(PopCredentialServiceError::Codec)
        }
        let sentinel = b"pop-auth-sentinel-v1".to_vec();
        let mut headers = HeaderMap::new();
        let encoded = format!("PopV1 {}", URL_SAFE_NO_PAD.encode(&sentinel));
        headers.insert(
            POP_AUTHORIZATION_HEADER_V1,
            HeaderValue::from_str(&encoded).expect("sentinel header"),
        );
        let probe = Arc::new(std::sync::Mutex::new(sentinel.clone()));
        assert!(matches!(
            fail_after_authentication(&headers, Arc::clone(&probe)),
            Err(PopCredentialServiceError::Codec)
        ));
        assert_eq!(
            *probe.lock().expect("drop probe"),
            vec![0_u8; sentinel.len()]
        );
    }
    #[test]
    fn public_request_frames_preserve_canonical_payload_and_distinct_selectors() {
        let payload = vec![0x42_u8, 0x43];
        let request = PopCanonicalPayloadRequestV1 {
            canonical_payload_base64url: URL_SAFE_NO_PAD
                .encode(norito::encode_canonical(&payload).expect("nested frame")),
        };
        crate::frame_test_support::assert_current_frame(
            &request,
            "iroha_torii::sorafs::pop_api::PopCanonicalPayloadRequestV1",
        );
        assert_eq!(
            decode_canonical::<Vec<u8>>(&request.canonical_payload_base64url, 4096)
                .expect("exact nested frame"),
            payload
        );
        let by_request = PopRequestIdRequestV1 {
            request_id_hex: "42".repeat(32),
        };
        let by_credential = PopCredentialCommitmentRequestV1 {
            credential_commitment_hex: "42".repeat(32),
        };
        let request_bytes = crate::frame_test_support::assert_current_frame(
            &by_request,
            "iroha_torii::sorafs::pop_api::PopRequestIdRequestV1",
        );
        let credential_bytes = crate::frame_test_support::assert_current_frame(
            &by_credential,
            "iroha_torii::sorafs::pop_api::PopCredentialCommitmentRequestV1",
        );
        assert_ne!(&request_bytes[6..22], &credential_bytes[6..22]);
        assert!(matches!(
            norito::decode_canonical::<PopCredentialCommitmentRequestV1>(&request_bytes),
            Err(norito::Error::SchemaMismatch)
        ));
    }
    #[test]
    fn canonical_payload_rejects_padding_malformed_and_oversized_data() {
        assert!(decode_base64url("YQ", 1).is_ok());
        assert_eq!(
            decode_base64url("YQ==", 1),
            Err(PopCredentialServiceError::Codec)
        );
        assert_eq!(
            decode_base64url("**", 8),
            Err(PopCredentialServiceError::Codec)
        );
        assert_eq!(
            decode_base64url(&URL_SAFE_NO_PAD.encode([0_u8; 9]), 8),
            Err(PopCredentialServiceError::Codec)
        );
    }
    #[test]
    fn canonical_decode_rejects_total_allocation_bomb() {
        let payload = vec![vec![0x5a_u8; 64]; 4];
        let encoded = norito::to_bytes(&payload).expect("encode allocation probe");
        let limits = norito::DecodeLimits::new(
            encoded.len(),
            encoded.len(),
            encoded.len(),
            1,
            POP_CANONICAL_DECODE_MAX_DEPTH_V1,
        );
        assert_eq!(
            decode_canonical_bytes_with_limits::<Vec<Vec<u8>>>(&encoded, limits),
            Err(PopCredentialServiceError::Codec)
        );
    }
    #[test]
    fn canonical_decode_rejects_nesting_depth_bomb() {
        let payload = vec![vec![vec![0x5a_u8]]];
        let encoded = norito::to_bytes(&payload).expect("encode depth probe");
        let limits = norito::DecodeLimits::new(
            encoded.len(),
            encoded.len(),
            encoded.len(),
            encoded.len().saturating_mul(4),
            0,
        );
        assert_eq!(
            decode_canonical_bytes_with_limits::<Vec<Vec<Vec<u8>>>>(&encoded, limits),
            Err(PopCredentialServiceError::Codec)
        );
    }
    #[test]
    fn digest_and_context_parsing_reject_noncanonical_values() {
        assert_eq!(
            decode_hex_32(&"ab".repeat(32), "digest").expect("digest"),
            [0xab; 32]
        );
        for value in ["", &"AB".repeat(32), &"00".repeat(32), &"ab".repeat(31)] {
            assert!(decode_hex_32(value, "digest").is_err());
        }
        assert!(valid_context("moderation.assignment.v1"));
        assert!(!valid_context(""));
        assert!(!valid_context(" padded"));
        assert!(!valid_context("line\nbreak"));
        assert!(!valid_context(
            &"x".repeat(POP_MEMBERSHIP_CONTEXT_MAX_BYTES_V1 + 1)
        ));
    }
    #[test]
    fn projection_response_contains_only_public_projection_material() {
        let response = projection_response(Some(PopFinalizedRegistryProjectionV1 {
            version: 1,
            cursor: sorafs_node::pop_credentials::PopFinalizedCursorV1 {
                block_height: 7,
                block_hash: [0x11; 32],
            },
            previous_block_hash: Some([0x10; 32]),
            issuer_policy_digest: [0x22; 32],
            canonical_commitment_root: vec![1, 2, 3],
            canonical_revocation_list: vec![4, 5, 6],
            committed_operation_digests: vec![[0x33; 32]],
            rejected_operation_digests: Vec::new(),
            revoked_issuer_public_keys: vec![[0x44; 32]],
        }));
        let json = norito::json::to_string(&response).expect("serialize response");
        assert!(json.contains("\"block_height\":7"));
        assert!(json.contains("\"canonical_commitment_root_base64url\":\"AQID\""));
        for forbidden in [
            "credential",
            "witness",
            "holder_secret",
            "attestation",
            "applicant",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
}
