//! Runtime-only, role-separated signing boundary for production PoTR receipts.
//!
//! Torii constructs the canonical receipt, but it never owns or derives the provider key. Gateway
//! Ed25519 and provider ML-DSA-65 operations are routed through distinct runtime services. Torii
//! constructs an identity-pinned reader over its authoritative finalized state and rechecks the
//! exact native provider-admission policy after both signatures. Private key material remains
//! inside the injected signers.
use iroha_config::parameters::{ProductionRuntimeHandleError, validate_production_runtime_handle};
use iroha_core::{
    smartcontracts::isi::sorafs_proof_outcome::read_sorafs_proof_outcome_signer_policy_in_finalized_view,
    state::{State, StateReadOnly},
};
use iroha_crypto::{Algorithm, PublicKey};
use iroha_data_model::sorafs::{
    capacity::ProviderId,
    proof_ledger::{
        PROOF_OUTCOME_SIGNER_POLICY_VERSION_V1, ProofOutcomeFinalizedCursorV1,
        ProofOutcomeSignerPolicyRecordV1,
    },
};
use sorafs_manifest::{
    AdmissionRecord,
    potr::{PotrReceiptV1, PotrReceiptValidationError, PotrSignatureAlgorithm, PotrSignatureV1},
    proof_stream::ProofStreamTier,
    provider_advert::AvailabilityTier,
};
use sorafs_node::{
    PotrAdmissionPolicyBindingError, PotrAdmissionPolicyBindingV1, PotrAdmissionPolicyProgressError,
};
use std::{fmt, sync::Arc};
use thiserror::Error;
/// Fixed, payload-free failure classes returned by a runtime signing service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PotrSignerServiceError {
    /// The configured signing provider is temporarily unavailable.
    #[error("runtime signer unavailable")]
    Unavailable,
    /// The signer refused the exact canonical payload.
    #[error("runtime signer refused request")]
    Refused,
}
/// Public, non-secret qualification for one PoTR runtime signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PotrRuntimeProviderQualificationV1 {
    revision: u64,
    policy_digest: [u8; 32],
}
impl PotrRuntimeProviderQualificationV1 {
    /// Construct one adapter and public-policy qualification.
    #[must_use]
    pub const fn new(revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            revision,
            policy_digest,
        }
    }
    /// Return the non-zero adapter and public-policy revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }
    /// Return the non-zero digest of the exact public policy.
    #[must_use]
    pub const fn policy_digest(self) -> [u8; 32] {
        self.policy_digest
    }
    fn is_valid(self) -> bool {
        self.revision != 0 && self.policy_digest != [0; 32]
    }
    fn from_admission_binding(binding: PotrAdmissionPolicyBindingV1) -> Self {
        Self::new(binding.policy_sequence, binding.policy_digest)
    }
}
/// Independently configured identity and policy binding for one PoTR signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PotrRuntimeProviderBindingV1 {
    handle: String,
    signer_id: [u8; 32],
    qualification: PotrRuntimeProviderQualificationV1,
}
impl PotrRuntimeProviderBindingV1 {
    /// Construct and validate one production runtime signer binding.
    ///
    /// # Errors
    ///
    /// Rejects malformed or test-marked handles, zero identities, and invalid
    /// revision or public-policy digests.
    pub fn try_new(
        handle: impl Into<String>,
        signer_id: [u8; 32],
        qualification: PotrRuntimeProviderQualificationV1,
    ) -> Result<Self, PotrRuntimeSignerConfigError> {
        let binding = Self {
            handle: handle.into(),
            signer_id,
            qualification,
        };
        binding.validate()?;
        Ok(binding)
    }
    /// Return the stable opaque production handle.
    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }
    /// Return the stable signer administration identity.
    #[must_use]
    pub const fn signer_id(&self) -> [u8; 32] {
        self.signer_id
    }
    /// Return the expected adapter and public-policy qualification.
    #[must_use]
    pub const fn qualification(&self) -> PotrRuntimeProviderQualificationV1 {
        self.qualification
    }
    fn validate(&self) -> Result<(), PotrRuntimeSignerConfigError> {
        validate_potr_runtime_handle(&self.handle)?;
        if self.signer_id == [0; 32] {
            return Err(PotrRuntimeSignerConfigError::ZeroSignerBindingId);
        }
        if !self.qualification.is_valid() {
            return Err(PotrRuntimeSignerConfigError::InvalidProviderQualification);
        }
        Ok(())
    }
}
/// Stable identities of the independently administered PoTR policy reader.
///
/// These public, non-secret pins keep the immutable finalized-state source and admission-material
/// resolver distinct from the reader facade and both runtime signer roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "Each id names a separately pinned and independently authenticated provider identity."
)]
pub struct PotrRuntimeReaderBindingsV1 {
    reader_id: [u8; 32],
    source_id: [u8; 32],
    resolver_id: [u8; 32],
}
impl PotrRuntimeReaderBindingsV1 {
    /// Construct and validate the three independent reader identities.
    ///
    /// # Errors
    ///
    /// Rejects zero identities and reuse between reader components.
    pub fn try_new(
        reader_id: [u8; 32],
        source_id: [u8; 32],
        resolver_id: [u8; 32],
    ) -> Result<Self, PotrRuntimeSignerConfigError> {
        let bindings = Self {
            reader_id,
            source_id,
            resolver_id,
        };
        bindings.validate()?;
        Ok(bindings)
    }
    /// Return the admission-reader facade identity.
    #[must_use]
    pub const fn reader_id(self) -> [u8; 32] {
        self.reader_id
    }
    /// Return the immutable finalized-state source identity.
    #[must_use]
    pub const fn source_id(self) -> [u8; 32] {
        self.source_id
    }
    /// Return the admission-material resolver identity.
    #[must_use]
    pub const fn resolver_id(self) -> [u8; 32] {
        self.resolver_id
    }
    fn validate(self) -> Result<(), PotrRuntimeSignerConfigError> {
        if self.reader_id == [0; 32] {
            return Err(PotrRuntimeSignerConfigError::ZeroAdmissionReaderId);
        }
        if self.source_id == [0; 32] {
            return Err(PotrRuntimeSignerConfigError::ZeroAdmissionSourceId);
        }
        if self.resolver_id == [0; 32] {
            return Err(PotrRuntimeSignerConfigError::ZeroAdmissionResolverId);
        }
        if self.reader_id == self.source_id
            || self.reader_id == self.resolver_id
            || self.source_id == self.resolver_id
        {
            return Err(PotrRuntimeSignerConfigError::RuntimeIdentityCollision);
        }
        Ok(())
    }
}
/// Fixed, payload-free failure classes returned by the live admission reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PotrAdmissionReaderError {
    /// The finalized policy source is temporarily unavailable.
    #[error("PoTR admission reader unavailable")]
    Unavailable,
    /// The reader cannot satisfy the supplied exact policy floor.
    #[error("PoTR admission reader is stale")]
    Stale,
    /// The provider or its PoTR key is revoked at the requested finality point.
    #[error("PoTR provider admission is revoked")]
    Revoked,
    /// The reader refused the exact bounded query.
    #[error("PoTR admission reader refused request")]
    Refused,
}
/// Exact live council admission and its finalized policy binding.
#[derive(Clone)]
pub struct PotrAdmissionSnapshotV1 {
    /// Exact policy identity, revision, and finalized cursor.
    pub binding: PotrAdmissionPolicyBindingV1,
    /// Council-verified admission selected by that policy revision.
    pub admission: Arc<AdmissionRecord>,
}
impl fmt::Debug for PotrAdmissionSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PotrAdmissionSnapshotV1")
            .field("policy_sequence", &self.binding.policy_sequence)
            .field("finalized_height", &self.binding.finalized_height)
            .finish_non_exhaustive()
    }
}
/// Runtime-only exact-anchor reader for active provider admission policy.
///
/// Implementations must query the authoritative finalized policy source and either return an active
/// revision at or after `minimum` or fail closed. They must authenticate the policy series and
/// validate its revision chain before returning a snapshot; a process-local registry or
/// self-advertised provider key is not a production implementation.
pub trait PotrAdmissionReaderV1: Send + Sync {
    /// Stable non-secret identity of this administered reader.
    fn reader_id(&self) -> [u8; 32];
    /// Resolve the exact active provider admission for one receipt interval.
    ///
    /// # Errors
    ///
    /// Returns an error if finalized admission is unavailable, cannot satisfy
    /// the minimum policy revision, is revoked, or rejects the requested interval.
    fn active_admission(
        &self,
        provider_id: [u8; 32],
        requested_at_ms: u64,
        recorded_at_ms: u64,
        minimum: &PotrAdmissionPolicyBindingV1,
    ) -> Result<PotrAdmissionSnapshotV1, PotrAdmissionReaderError>;
}
/// One provider policy read from a single immutable finalized state view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PotrFinalizedPolicySnapshotV1 {
    /// Exact finalized block containing the queried state.
    pub finalized_cursor: ProofOutcomeFinalizedCursorV1,
    /// Timestamp of that exact finalized block.
    pub finalized_at_unix_ms: u64,
    /// Native governed provider proof/admission policy.
    pub policy: ProofOutcomeSignerPolicyRecordV1,
}
/// Exact-view source used by the production admission reader.
///
/// A source identity names the administered chain-query connection, not a signer or key.
/// Implementations must return a policy and block timestamp from one immutable finalized view.
pub trait PotrFinalizedPolicySourceV1: Send + Sync {
    /// Stable non-secret identity of the administered finalized-state source.
    fn source_id(&self) -> [u8; 32];
    /// Read one provider's current native policy from an immutable finalized view.
    ///
    /// # Errors
    ///
    /// Returns an error if the finalized policy source is unavailable or stale,
    /// the provider admission is revoked, or the exact finalized query is refused.
    fn active_policy(
        &self,
        provider_id: [u8; 32],
    ) -> Result<PotrFinalizedPolicySnapshotV1, PotrAdmissionReaderError>;
}
/// Native state-backed finalized policy source used by Torii.
#[derive(Clone)]
pub struct PotrStateFinalizedPolicySourceV1 {
    source_id: [u8; 32],
    state: Arc<State>,
}
impl fmt::Debug for PotrStateFinalizedPolicySourceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PotrStateFinalizedPolicySourceV1")
            .finish_non_exhaustive()
    }
}
impl PotrStateFinalizedPolicySourceV1 {
    /// Pin a non-secret source identity to the node's authoritative state.
    ///
    /// # Errors
    ///
    /// Fails when the source identity uses the zero sentinel.
    pub fn try_new(
        source_id: [u8; 32],
        state: Arc<State>,
    ) -> Result<Self, PotrFinalizedAdmissionReaderConfigError> {
        if source_id == [0; 32] {
            return Err(PotrFinalizedAdmissionReaderConfigError::ZeroSourceId);
        }
        Ok(Self { source_id, state })
    }
}
impl PotrFinalizedPolicySourceV1 for PotrStateFinalizedPolicySourceV1 {
    fn source_id(&self) -> [u8; 32] {
        self.source_id
    }
    fn active_policy(
        &self,
        provider_id: [u8; 32],
    ) -> Result<PotrFinalizedPolicySnapshotV1, PotrAdmissionReaderError> {
        let view = self.state.query_view();
        let finalized_at_unix_ms = view
            .authenticated_query_ledger_time_ms()
            .ok_or(PotrAdmissionReaderError::Unavailable)?;
        if finalized_at_unix_ms == 0 {
            return Err(PotrAdmissionReaderError::Refused);
        }
        let (finalized_cursor, policy) = read_sorafs_proof_outcome_signer_policy_in_finalized_view(
            &view,
            ProviderId::new(provider_id),
        )
        .map_err(|_| PotrAdmissionReaderError::Refused)?;
        if u64::try_from(view.height()).ok() != Some(finalized_cursor.height)
            || view.latest_block_hash().map(|hash| *hash.as_ref())
                != Some(finalized_cursor.block_hash)
        {
            return Err(PotrAdmissionReaderError::Refused);
        }
        let policy = policy.ok_or(PotrAdmissionReaderError::Revoked)?;
        if policy.activated_at_unix_ms > finalized_at_unix_ms {
            return Err(PotrAdmissionReaderError::Refused);
        }
        Ok(PotrFinalizedPolicySnapshotV1 {
            finalized_cursor,
            finalized_at_unix_ms,
            policy,
        })
    }
}
/// Resolver for council-verified admission envelope material.
///
/// The finalized ledger policy remains authoritative. A resolver may only
/// supply the exact envelope named by its digest; it cannot select a provider,
/// policy revision, key, validity interval, or finality cursor.
pub trait PotrAdmissionMaterialResolverV1: Send + Sync {
    /// Stable non-secret identity of this administered material resolver.
    fn resolver_id(&self) -> [u8; 32];
    /// Resolve one exact council-verified envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if the admission material is unavailable, stale, revoked,
    /// or does not match the exact provider and envelope digest.
    fn resolve(
        &self,
        provider_id: [u8; 32],
        admission_envelope_digest: [u8; 32],
    ) -> Result<Arc<AdmissionRecord>, PotrAdmissionReaderError>;
}
/// Immutable resolver around Torii's council-verified admission registry.
#[derive(Clone)]
pub struct PotrAdmissionRegistryResolverV1 {
    resolver_id: [u8; 32],
    registry: Arc<crate::sorafs::AdmissionRegistry>,
}
impl fmt::Debug for PotrAdmissionRegistryResolverV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PotrAdmissionRegistryResolverV1")
            .finish_non_exhaustive()
    }
}
impl PotrAdmissionRegistryResolverV1 {
    /// Bind an explicit non-secret identity to a verified registry snapshot.
    ///
    /// # Errors
    ///
    /// Fails when the resolver identity uses the zero sentinel.
    pub fn try_new(
        resolver_id: [u8; 32],
        registry: Arc<crate::sorafs::AdmissionRegistry>,
    ) -> Result<Self, PotrFinalizedAdmissionReaderConfigError> {
        if resolver_id == [0; 32] {
            return Err(PotrFinalizedAdmissionReaderConfigError::ZeroResolverId);
        }
        Ok(Self {
            resolver_id,
            registry,
        })
    }
}
impl PotrAdmissionMaterialResolverV1 for PotrAdmissionRegistryResolverV1 {
    fn resolver_id(&self) -> [u8; 32] {
        self.resolver_id
    }
    fn resolve(
        &self,
        provider_id: [u8; 32],
        admission_envelope_digest: [u8; 32],
    ) -> Result<Arc<AdmissionRecord>, PotrAdmissionReaderError> {
        let admission = self
            .registry
            .entry(&provider_id)
            .ok_or(PotrAdmissionReaderError::Revoked)?;
        if admission.envelope_digest() != &admission_envelope_digest {
            return Err(PotrAdmissionReaderError::Refused);
        }
        Ok(admission)
    }
}
/// Production exact-finalized PoTR admission reader.
#[derive(Clone)]
pub struct PotrFinalizedAdmissionReaderV1 {
    reader_id: [u8; 32],
    policy_identity: [u8; 32],
    expected_gateway_public_key: [u8; 32],
    source: Arc<dyn PotrFinalizedPolicySourceV1>,
    resolver: Arc<dyn PotrAdmissionMaterialResolverV1>,
    source_id: [u8; 32],
    resolver_id: [u8; 32],
}
impl fmt::Debug for PotrFinalizedAdmissionReaderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PotrFinalizedAdmissionReaderV1")
            .finish_non_exhaustive()
    }
}
impl PotrFinalizedAdmissionReaderV1 {
    /// Construct an identity-pinned finalized admission reader.
    ///
    /// All identities are explicit non-secret deployment values. In
    /// particular, none is derived from the gateway or provider signer.
    ///
    /// # Errors
    ///
    /// Fails for zero or colliding administrative identities, a zero policy
    /// identity, or a malformed gateway policy key.
    pub fn try_new(
        reader_id: [u8; 32],
        policy_identity: [u8; 32],
        expected_gateway_public_key: [u8; 32],
        source: Arc<dyn PotrFinalizedPolicySourceV1>,
        resolver: Arc<dyn PotrAdmissionMaterialResolverV1>,
    ) -> Result<Self, PotrFinalizedAdmissionReaderConfigError> {
        if reader_id == [0; 32] {
            return Err(PotrFinalizedAdmissionReaderConfigError::ZeroReaderId);
        }
        if policy_identity == [0; 32] {
            return Err(PotrFinalizedAdmissionReaderConfigError::ZeroPolicyIdentity);
        }
        validate_gateway_public_key(&expected_gateway_public_key)
            .map_err(|_| PotrFinalizedAdmissionReaderConfigError::InvalidGatewayPolicyKey)?;
        let source_id = source.source_id();
        let resolver_id = resolver.resolver_id();
        if source_id == [0; 32] {
            return Err(PotrFinalizedAdmissionReaderConfigError::ZeroSourceId);
        }
        if resolver_id == [0; 32] {
            return Err(PotrFinalizedAdmissionReaderConfigError::ZeroResolverId);
        }
        if reader_id == source_id || reader_id == resolver_id || source_id == resolver_id {
            return Err(PotrFinalizedAdmissionReaderConfigError::IdentityCollision);
        }
        Ok(Self {
            reader_id,
            policy_identity,
            expected_gateway_public_key,
            source,
            resolver,
            source_id,
            resolver_id,
        })
    }
    fn check_dependency_identities(&self) -> Result<(), PotrAdmissionReaderError> {
        if self.source.source_id() != self.source_id
            || self.resolver.resolver_id() != self.resolver_id
        {
            return Err(PotrAdmissionReaderError::Refused);
        }
        Ok(())
    }
}
impl PotrAdmissionReaderV1 for PotrFinalizedAdmissionReaderV1 {
    fn reader_id(&self) -> [u8; 32] {
        self.reader_id
    }
    fn active_admission(
        &self,
        provider_id: [u8; 32],
        requested_at_ms: u64,
        recorded_at_ms: u64,
        minimum: &PotrAdmissionPolicyBindingV1,
    ) -> Result<PotrAdmissionSnapshotV1, PotrAdmissionReaderError> {
        minimum
            .validate()
            .map_err(|_| PotrAdmissionReaderError::Refused)?;
        if provider_id == [0; 32] || requested_at_ms == 0 || recorded_at_ms < requested_at_ms {
            return Err(PotrAdmissionReaderError::Refused);
        }
        if minimum.provider_id != provider_id || minimum.policy_identity != self.policy_identity {
            return Err(PotrAdmissionReaderError::Stale);
        }
        self.check_dependency_identities()?;
        let finalized = self.source.active_policy(provider_id)?;
        let policy = &finalized.policy.policy;
        if policy.version != PROOF_OUTCOME_SIGNER_POLICY_VERSION_V1
            || policy.provider_id.as_bytes() != &provider_id
            || policy.revision == 0
            || (policy.revision == 1) != policy.predecessor_digest.is_none()
            || policy.predecessor_digest == Some([0; 32])
            || finalized.policy.policy_digest == [0; 32]
        {
            return Err(PotrAdmissionReaderError::Refused);
        }
        let binding = PotrAdmissionPolicyBindingV1 {
            provider_id,
            policy_identity: self.policy_identity,
            policy_digest: finalized.policy.policy_digest,
            policy_sequence: policy.revision,
            finalized_height: finalized.finalized_cursor.height,
            finalized_block_hash: finalized.finalized_cursor.block_hash,
            admission_envelope_digest: policy.admission_envelope_digest,
        };
        binding
            .validate()
            .map_err(|_| PotrAdmissionReaderError::Refused)?;
        binding
            .ensure_at_or_after(*minimum)
            .map_err(|_| PotrAdmissionReaderError::Stale)?;
        let requested_at_unix = requested_at_ms / 1_000;
        let recorded_at_unix = recorded_at_ms / 1_000;
        if requested_at_unix < policy.valid_from_unix || recorded_at_unix > policy.valid_until_unix
        {
            return Err(PotrAdmissionReaderError::Revoked);
        }
        if finalized.policy.activated_at_unix_ms > requested_at_ms {
            return Err(PotrAdmissionReaderError::Revoked);
        }
        if policy.gateway_public_key != self.expected_gateway_public_key {
            return Err(PotrAdmissionReaderError::Refused);
        }
        validate_provider_public_key(&policy.potr_mldsa_public_key)
            .map_err(|_| PotrAdmissionReaderError::Refused)?;
        let admission = self
            .resolver
            .resolve(provider_id, policy.admission_envelope_digest)?;
        self.check_dependency_identities()?;
        if !(admission.is_council_verified() || admission.is_genesis_material())
            || admission.provider_id() != &provider_id
            || admission.envelope_digest() != &policy.admission_envelope_digest
            || admission.potr_mldsa_key() != Some(policy.potr_mldsa_public_key.as_slice())
            || requested_at_unix < admission.envelope().issued_at
            || recorded_at_unix > admission.envelope().retention_epoch
        {
            return Err(PotrAdmissionReaderError::Refused);
        }
        Ok(PotrAdmissionSnapshotV1 { binding, admission })
    }
}
/// Invalid configuration for the production finalized admission reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PotrFinalizedAdmissionReaderConfigError {
    /// Reader identity uses the zero sentinel.
    #[error("PoTR finalized admission reader identity must be non-zero")]
    ZeroReaderId,
    /// Finalized-state source identity uses the zero sentinel.
    #[error("PoTR finalized admission source identity must be non-zero")]
    ZeroSourceId,
    /// Admission material resolver identity uses the zero sentinel.
    #[error("PoTR admission material resolver identity must be non-zero")]
    ZeroResolverId,
    /// Governance policy-series identity uses the zero sentinel.
    #[error("PoTR admission policy identity must be non-zero")]
    ZeroPolicyIdentity,
    /// Gateway policy key is not a canonical strong Ed25519 key.
    #[error("PoTR gateway policy key must be a canonical strong Ed25519 public key")]
    InvalidGatewayPolicyKey,
    /// Two independent reader components claimed one identity.
    #[error("PoTR finalized reader component identities must be distinct")]
    IdentityCollision,
}
/// Runtime-only Ed25519 signer for the gateway role of a PoTR receipt.
///
/// Implementations use a qualified deployment-owned signing provider. `signer_id` is a non-secret
/// stable deployment identity for the signer instance, not a key handle or credential.
pub trait PotrGatewaySignerV1: Send + Sync {
    /// Stable opaque production provider handle.
    fn handle(&self) -> &str;
    /// Stable non-secret identity of this independently administered signer.
    fn signer_id(&self) -> [u8; 32];
    /// Qualify the active adapter and exact public-policy revision.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer service is unavailable or refuses the
    /// qualification probe.
    fn qualification(&self) -> Result<PotrRuntimeProviderQualificationV1, PotrSignerServiceError>;
    /// Return the active Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer service is unavailable or refuses to
    /// provide its active public key.
    fn public_key(&self) -> Result<[u8; 32], PotrSignerServiceError>;
    /// Sign the exact domain-separated canonical PoTR payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer service is unavailable or refuses the
    /// exact canonical receipt payload.
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, PotrSignerServiceError>;
}
/// Runtime-only ML-DSA-65 signer for the provider role of a PoTR receipt.
///
/// The declared provider identity and public key are checked against the current council-verified
/// admission on every operation. This makes provider revocation and key rotation fail closed
/// without trusting a self-advertised receipt key.
pub trait PotrProviderSignerV1: Send + Sync {
    /// Stable opaque production provider handle.
    fn handle(&self) -> &str;
    /// Stable non-secret identity of this independently administered signer.
    fn signer_id(&self) -> [u8; 32];
    /// Qualify the active adapter and governed admission-policy revision.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer service is unavailable or refuses the
    /// qualification probe.
    fn qualification(&self) -> Result<PotrRuntimeProviderQualificationV1, PotrSignerServiceError>;
    /// Governed provider identity served by this signer.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer service is unavailable or refuses to
    /// provide its governed provider identity.
    fn provider_id(&self) -> Result<[u8; 32], PotrSignerServiceError>;
    /// Return the active ML-DSA-65 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer service is unavailable or refuses to
    /// provide its active public key.
    fn public_key(&self) -> Result<Vec<u8>, PotrSignerServiceError>;
    /// Sign the exact domain-separated canonical PoTR payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer service is unavailable or refuses the
    /// exact canonical receipt payload.
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, PotrSignerServiceError>;
}
fn validate_potr_runtime_handle(handle: &str) -> Result<(), PotrRuntimeSignerConfigError> {
    match validate_production_runtime_handle(handle) {
        Ok(()) => Ok(()),
        Err(ProductionRuntimeHandleError::InvalidSyntax) => {
            Err(PotrRuntimeSignerConfigError::InvalidProviderHandle)
        }
        Err(ProductionRuntimeHandleError::TestMarked) => {
            Err(PotrRuntimeSignerConfigError::TestMarkedProviderHandle)
        }
    }
}
fn qualify_gateway_signer(
    expected: &PotrRuntimeProviderBindingV1,
    signer: &dyn PotrGatewaySignerV1,
    expected_public_key: [u8; 32],
) -> Result<(), PotrRuntimeSignerConfigError> {
    if signer.handle() != expected.handle() || signer.signer_id() != expected.signer_id() {
        return Err(PotrRuntimeSignerConfigError::SignerBindingMismatch);
    }
    let qualification = signer
        .qualification()
        .map_err(|_| PotrRuntimeSignerConfigError::SignerQualificationUnavailable)?;
    if !qualification.is_valid() {
        return Err(PotrRuntimeSignerConfigError::InvalidProviderQualification);
    }
    if signer.handle() != expected.handle()
        || signer.signer_id() != expected.signer_id()
        || qualification != expected.qualification()
    {
        return Err(PotrRuntimeSignerConfigError::SignerBindingMismatch);
    }
    let public_key_result = signer.public_key();
    let qualification_after_key = signer
        .qualification()
        .map_err(|_| PotrRuntimeSignerConfigError::SignerQualificationUnavailable)?;
    let public_key = public_key_result
        .map_err(|_| PotrRuntimeSignerConfigError::SignerQualificationUnavailable)?;
    if signer.handle() != expected.handle()
        || signer.signer_id() != expected.signer_id()
        || qualification_after_key != expected.qualification()
        || public_key != expected_public_key
    {
        return Err(PotrRuntimeSignerConfigError::SignerBindingMismatch);
    }
    Ok(())
}
fn qualify_provider_signer(
    expected: &PotrRuntimeProviderBindingV1,
    signer: &dyn PotrProviderSignerV1,
    expected_provider_id: [u8; 32],
) -> Result<(), PotrRuntimeSignerConfigError> {
    if signer.handle() != expected.handle() || signer.signer_id() != expected.signer_id() {
        return Err(PotrRuntimeSignerConfigError::SignerBindingMismatch);
    }
    let qualification = signer
        .qualification()
        .map_err(|_| PotrRuntimeSignerConfigError::SignerQualificationUnavailable)?;
    if !qualification.is_valid() {
        return Err(PotrRuntimeSignerConfigError::InvalidProviderQualification);
    }
    if signer.handle() != expected.handle()
        || signer.signer_id() != expected.signer_id()
        || qualification != expected.qualification()
    {
        return Err(PotrRuntimeSignerConfigError::SignerBindingMismatch);
    }
    let provider_id_result = signer.provider_id();
    let qualification_after_id = signer
        .qualification()
        .map_err(|_| PotrRuntimeSignerConfigError::SignerQualificationUnavailable)?;
    let provider_id = provider_id_result
        .map_err(|_| PotrRuntimeSignerConfigError::SignerQualificationUnavailable)?;
    if signer.handle() != expected.handle()
        || signer.signer_id() != expected.signer_id()
        || qualification_after_id != expected.qualification()
        || provider_id != expected_provider_id
    {
        return Err(PotrRuntimeSignerConfigError::SignerBindingMismatch);
    }
    let public_key_result = signer.public_key();
    let qualification_after_key = signer
        .qualification()
        .map_err(|_| PotrRuntimeSignerConfigError::SignerQualificationUnavailable)?;
    let public_key = public_key_result
        .map_err(|_| PotrRuntimeSignerConfigError::SignerQualificationUnavailable)?;
    if signer.handle() != expected.handle()
        || signer.signer_id() != expected.signer_id()
        || qualification_after_key != expected.qualification()
        || validate_provider_public_key(&public_key).is_err()
    {
        return Err(PotrRuntimeSignerConfigError::SignerBindingMismatch);
    }
    Ok(())
}
/// Externally administered PoTR signer roles plus non-secret reader pins.
///
/// Torii accepts this object before API construction, then binds the two signer
/// roles to its own finalized [`State`] and council-verified admission
/// registry. The launcher cannot inject a process-local admission reader.
#[derive(Clone)]
pub struct PotrRuntimeSignerRolesV1 {
    gateway: Arc<dyn PotrGatewaySignerV1>,
    provider: Arc<dyn PotrProviderSignerV1>,
    gateway_binding: PotrRuntimeProviderBindingV1,
    provider_binding: PotrRuntimeProviderBindingV1,
    expected_gateway_public_key: [u8; 32],
    baseline_admission_policy: PotrAdmissionPolicyBindingV1,
    reader_bindings: PotrRuntimeReaderBindingsV1,
}
impl fmt::Debug for PotrRuntimeSignerRolesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PotrRuntimeSignerRolesV1")
            .field(
                "admission_policy_sequence",
                &self.baseline_admission_policy.policy_sequence,
            )
            .finish_non_exhaustive()
    }
}
impl PotrRuntimeSignerRolesV1 {
    /// Validate independently administered signer roles and exact non-secret
    /// finalized-reader identities.
    ///
    /// # Errors
    ///
    /// Fails for malformed keys or policy anchors, shared signer objects, zero identities, or
    /// identity reuse across signing and policy-observation roles.
    pub fn try_new(
        gateway: Arc<dyn PotrGatewaySignerV1>,
        provider: Arc<dyn PotrProviderSignerV1>,
        gateway_binding: PotrRuntimeProviderBindingV1,
        provider_binding: PotrRuntimeProviderBindingV1,
        expected_gateway_public_key: [u8; 32],
        baseline_admission_policy: PotrAdmissionPolicyBindingV1,
        reader_bindings: PotrRuntimeReaderBindingsV1,
    ) -> Result<Self, PotrRuntimeSignerConfigError> {
        validate_gateway_public_key(&expected_gateway_public_key)
            .map_err(|_| PotrRuntimeSignerConfigError::InvalidGatewayPolicyKey)?;
        baseline_admission_policy
            .validate()
            .map_err(|_| PotrRuntimeSignerConfigError::InvalidAdmissionPolicyAnchor)?;
        gateway_binding.validate()?;
        provider_binding.validate()?;
        reader_bindings.validate()?;
        if provider_binding.qualification()
            != PotrRuntimeProviderQualificationV1::from_admission_binding(baseline_admission_policy)
        {
            return Err(PotrRuntimeSignerConfigError::ProviderQualificationPolicyMismatch);
        }
        let gateway_object = Arc::as_ptr(&gateway).cast::<()>();
        let provider_object = Arc::as_ptr(&provider).cast::<()>();
        if gateway_object == provider_object {
            return Err(PotrRuntimeSignerConfigError::SharedSignerObject);
        }
        let gateway_signer_id = gateway_binding.signer_id();
        let provider_signer_id = provider_binding.signer_id();
        if gateway_signer_id == [0; 32] {
            return Err(PotrRuntimeSignerConfigError::ZeroGatewaySignerId);
        }
        if provider_signer_id == [0; 32] {
            return Err(PotrRuntimeSignerConfigError::ZeroProviderSignerId);
        }
        if gateway_signer_id == provider_signer_id {
            return Err(PotrRuntimeSignerConfigError::SharedSignerIdentity);
        }
        if gateway_binding.handle() == provider_binding.handle() {
            return Err(PotrRuntimeSignerConfigError::SharedSignerHandle);
        }
        let reader_id = reader_bindings.reader_id();
        let source_id = reader_bindings.source_id();
        let resolver_id = reader_bindings.resolver_id();
        let administrative_identities = [
            gateway_signer_id,
            provider_signer_id,
            reader_id,
            source_id,
            resolver_id,
        ];
        for (index, identity) in administrative_identities.iter().enumerate() {
            if administrative_identities[..index].contains(identity) {
                return Err(PotrRuntimeSignerConfigError::RuntimeIdentityCollision);
            }
        }
        qualify_gateway_signer(
            &gateway_binding,
            gateway.as_ref(),
            expected_gateway_public_key,
        )?;
        qualify_provider_signer(
            &provider_binding,
            provider.as_ref(),
            baseline_admission_policy.provider_id,
        )?;
        Ok(Self {
            gateway,
            provider,
            gateway_binding,
            provider_binding,
            expected_gateway_public_key,
            baseline_admission_policy,
            reader_bindings,
        })
    }
    /// Return the independently configured gateway signer binding.
    #[must_use]
    pub fn gateway_binding(&self) -> &PotrRuntimeProviderBindingV1 {
        &self.gateway_binding
    }
    /// Return the independently configured provider signer binding.
    #[must_use]
    pub fn provider_binding(&self) -> &PotrRuntimeProviderBindingV1 {
        &self.provider_binding
    }
    /// Return the exact configured gateway verification key.
    #[must_use]
    pub const fn expected_gateway_public_key(&self) -> [u8; 32] {
        self.expected_gateway_public_key
    }
    /// Return the baseline finalized provider-admission policy.
    #[must_use]
    pub const fn baseline_admission_policy(&self) -> PotrAdmissionPolicyBindingV1 {
        self.baseline_admission_policy
    }
    /// Return the configured reader, finalized-source, and resolver identities.
    #[must_use]
    pub const fn reader_bindings(&self) -> PotrRuntimeReaderBindingsV1 {
        self.reader_bindings
    }
    /// Bind these roles to Torii's authoritative finalized state and verified
    /// admission material after both are constructed.
    ///
    /// # Errors
    ///
    /// Fails closed when any reader pin is malformed or the complete runtime
    /// boundary cannot be constructed.
    pub fn bind_finalized_reader(
        &self,
        state: Arc<State>,
        admission_registry: Arc<crate::sorafs::AdmissionRegistry>,
    ) -> Result<PotrRuntimeSignersV1, PotrRuntimeSignerConfigError> {
        let source: Arc<dyn PotrFinalizedPolicySourceV1> = Arc::new(
            PotrStateFinalizedPolicySourceV1::try_new(self.reader_bindings.source_id(), state)
                .map_err(PotrRuntimeSignerConfigError::FinalizedReader)?,
        );
        let resolver: Arc<dyn PotrAdmissionMaterialResolverV1> = Arc::new(
            PotrAdmissionRegistryResolverV1::try_new(
                self.reader_bindings.resolver_id(),
                admission_registry,
            )
            .map_err(PotrRuntimeSignerConfigError::FinalizedReader)?,
        );
        let reader: Arc<dyn PotrAdmissionReaderV1> = Arc::new(
            PotrFinalizedAdmissionReaderV1::try_new(
                self.reader_bindings.reader_id(),
                self.baseline_admission_policy.policy_identity,
                self.expected_gateway_public_key,
                source,
                resolver,
            )
            .map_err(PotrRuntimeSignerConfigError::FinalizedReader)?,
        );
        PotrRuntimeSignersV1::try_new(
            Arc::clone(&self.gateway),
            Arc::clone(&self.provider),
            self.gateway_binding.clone(),
            self.provider_binding.clone(),
            reader,
            self.expected_gateway_public_key,
            self.baseline_admission_policy,
        )
    }
}
/// Independently administered runtime signers plus a live admission reader.
#[derive(Clone)]
pub struct PotrRuntimeSignersV1 {
    gateway: Arc<dyn PotrGatewaySignerV1>,
    provider: Arc<dyn PotrProviderSignerV1>,
    gateway_binding: PotrRuntimeProviderBindingV1,
    provider_binding: PotrRuntimeProviderBindingV1,
    admission_reader: Arc<dyn PotrAdmissionReaderV1>,
    expected_gateway_public_key: [u8; 32],
    baseline_admission_policy: PotrAdmissionPolicyBindingV1,
    gateway_signer_id: [u8; 32],
    provider_signer_id: [u8; 32],
    admission_reader_id: [u8; 32],
}
impl fmt::Debug for PotrRuntimeSignersV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PotrRuntimeSignersV1")
            .field("gateway_signer_id", &self.gateway_signer_id)
            .field("provider_signer_id", &self.provider_signer_id)
            .field("admission_reader_id", &self.admission_reader_id)
            .field(
                "admission_policy_sequence",
                &self.baseline_admission_policy.policy_sequence,
            )
            .finish_non_exhaustive()
    }
}
impl PotrRuntimeSignersV1 {
    /// Bind two independently administered signer objects and an exact-anchor
    /// finalized admission reader.
    ///
    /// # Errors
    ///
    /// Fails if either non-secret policy anchor is malformed, a stable runtime identity is zero or
    /// collides, or a reader/signer role reuses the same trait-object allocation.
    pub fn try_new(
        gateway: Arc<dyn PotrGatewaySignerV1>,
        provider: Arc<dyn PotrProviderSignerV1>,
        gateway_binding: PotrRuntimeProviderBindingV1,
        provider_binding: PotrRuntimeProviderBindingV1,
        admission_reader: Arc<dyn PotrAdmissionReaderV1>,
        expected_gateway_public_key: [u8; 32],
        baseline_admission_policy: PotrAdmissionPolicyBindingV1,
    ) -> Result<Self, PotrRuntimeSignerConfigError> {
        validate_gateway_public_key(&expected_gateway_public_key)
            .map_err(|_| PotrRuntimeSignerConfigError::InvalidGatewayPolicyKey)?;
        baseline_admission_policy
            .validate()
            .map_err(|_| PotrRuntimeSignerConfigError::InvalidAdmissionPolicyAnchor)?;
        gateway_binding.validate()?;
        provider_binding.validate()?;
        if provider_binding.qualification()
            != PotrRuntimeProviderQualificationV1::from_admission_binding(baseline_admission_policy)
        {
            return Err(PotrRuntimeSignerConfigError::ProviderQualificationPolicyMismatch);
        }
        let gateway_object = Arc::as_ptr(&gateway).cast::<()>();
        let provider_object = Arc::as_ptr(&provider).cast::<()>();
        if gateway_object == provider_object {
            return Err(PotrRuntimeSignerConfigError::SharedSignerObject);
        }
        let admission_reader_object = Arc::as_ptr(&admission_reader).cast::<()>();
        if admission_reader_object == gateway_object || admission_reader_object == provider_object {
            return Err(PotrRuntimeSignerConfigError::AdmissionReaderSharesSignerObject);
        }
        let gateway_signer_id = gateway_binding.signer_id();
        let provider_signer_id = provider_binding.signer_id();
        let admission_reader_id = admission_reader.reader_id();
        if gateway_signer_id == [0; 32] {
            return Err(PotrRuntimeSignerConfigError::ZeroGatewaySignerId);
        }
        if provider_signer_id == [0; 32] {
            return Err(PotrRuntimeSignerConfigError::ZeroProviderSignerId);
        }
        if admission_reader_id == [0; 32] {
            return Err(PotrRuntimeSignerConfigError::ZeroAdmissionReaderId);
        }
        if gateway_signer_id == provider_signer_id {
            return Err(PotrRuntimeSignerConfigError::SharedSignerIdentity);
        }
        if gateway_binding.handle() == provider_binding.handle() {
            return Err(PotrRuntimeSignerConfigError::SharedSignerHandle);
        }
        if admission_reader_id == gateway_signer_id || admission_reader_id == provider_signer_id {
            return Err(PotrRuntimeSignerConfigError::AdmissionReaderSharesSignerIdentity);
        }
        qualify_gateway_signer(
            &gateway_binding,
            gateway.as_ref(),
            expected_gateway_public_key,
        )?;
        qualify_provider_signer(
            &provider_binding,
            provider.as_ref(),
            baseline_admission_policy.provider_id,
        )?;
        Ok(Self {
            gateway,
            provider,
            gateway_binding,
            provider_binding,
            admission_reader,
            expected_gateway_public_key,
            baseline_admission_policy,
            gateway_signer_id,
            provider_signer_id,
            admission_reader_id,
        })
    }
    /// Return the non-secret Ed25519 gateway key required by runtime policy.
    #[must_use]
    pub const fn expected_gateway_public_key(&self) -> [u8; 32] {
        self.expected_gateway_public_key
    }
    fn revalidate_gateway_binding(&self) -> Result<(), PotrReceiptRuntimeSigningError> {
        if self.gateway.handle() != self.gateway_binding.handle()
            || self.gateway.signer_id() != self.gateway_binding.signer_id()
        {
            return Err(PotrReceiptRuntimeSigningError::GatewaySignerIdentityDrift);
        }
        let qualification = self
            .gateway
            .qualification()
            .map_err(PotrReceiptRuntimeSigningError::GatewayService)?;
        if !qualification.is_valid()
            || self.gateway.handle() != self.gateway_binding.handle()
            || self.gateway.signer_id() != self.gateway_binding.signer_id()
            || qualification != self.gateway_binding.qualification()
        {
            return Err(PotrReceiptRuntimeSigningError::GatewaySignerIdentityDrift);
        }
        Ok(())
    }
    fn revalidate_provider_identity(&self) -> Result<(), PotrReceiptRuntimeSigningError> {
        if self.provider.handle() != self.provider_binding.handle()
            || self.provider.signer_id() != self.provider_binding.signer_id()
        {
            return Err(PotrReceiptRuntimeSigningError::ProviderSignerIdentityDrift);
        }
        Ok(())
    }
    fn revalidate_provider_binding(
        &self,
        expected: PotrRuntimeProviderQualificationV1,
    ) -> Result<(), PotrReceiptRuntimeSigningError> {
        self.revalidate_provider_identity()?;
        let qualification = self
            .provider
            .qualification()
            .map_err(PotrReceiptRuntimeSigningError::ProviderService)?;
        if !qualification.is_valid()
            || self.provider.handle() != self.provider_binding.handle()
            || self.provider.signer_id() != self.provider_binding.signer_id()
            || qualification != expected
        {
            return Err(PotrReceiptRuntimeSigningError::ProviderSignerIdentityDrift);
        }
        Ok(())
    }
    fn revalidate_admission_reader(&self) -> Result<(), PotrReceiptRuntimeSigningError> {
        if self.admission_reader.reader_id() != self.admission_reader_id {
            return Err(PotrReceiptRuntimeSigningError::AdmissionReaderIdentityDrift);
        }
        Ok(())
    }
    fn read_admission(
        &self,
        receipt: &PotrReceiptV1,
        minimum: &PotrAdmissionPolicyBindingV1,
    ) -> Result<PotrAdmissionSnapshotV1, PotrReceiptRuntimeSigningError> {
        self.revalidate_admission_reader()?;
        let result = self.admission_reader.active_admission(
            receipt.provider_id,
            receipt.requested_at_ms,
            receipt.recorded_at_ms,
            minimum,
        );
        self.revalidate_admission_reader()?;
        result.map_err(PotrReceiptRuntimeSigningError::AdmissionReader)
    }
    fn gateway_public_key(&self) -> Result<[u8; 32], PotrReceiptRuntimeSigningError> {
        self.revalidate_gateway_binding()?;
        let result = self.gateway.public_key();
        self.revalidate_gateway_binding()?;
        result.map_err(PotrReceiptRuntimeSigningError::GatewayService)
    }
    fn provider_id(
        &self,
        expected: PotrRuntimeProviderQualificationV1,
    ) -> Result<[u8; 32], PotrReceiptRuntimeSigningError> {
        self.revalidate_provider_binding(expected)?;
        let result = self.provider.provider_id();
        self.revalidate_provider_binding(expected)?;
        result.map_err(PotrReceiptRuntimeSigningError::ProviderService)
    }
    fn provider_public_key(
        &self,
        expected: PotrRuntimeProviderQualificationV1,
    ) -> Result<Vec<u8>, PotrReceiptRuntimeSigningError> {
        self.revalidate_provider_binding(expected)?;
        let result = self.provider.public_key();
        self.revalidate_provider_binding(expected)?;
        result.map_err(PotrReceiptRuntimeSigningError::ProviderService)
    }
    fn gateway_sign(&self, payload: &[u8]) -> Result<Vec<u8>, PotrReceiptRuntimeSigningError> {
        self.revalidate_gateway_binding()?;
        let result = self.gateway.sign(payload);
        self.revalidate_gateway_binding()?;
        result.map_err(PotrReceiptRuntimeSigningError::GatewayService)
    }
    fn provider_sign(
        &self,
        expected: PotrRuntimeProviderQualificationV1,
        payload: &[u8],
    ) -> Result<Vec<u8>, PotrReceiptRuntimeSigningError> {
        self.revalidate_provider_binding(expected)?;
        let result = self.provider.sign(payload);
        self.revalidate_provider_binding(expected)?;
        result.map_err(PotrReceiptRuntimeSigningError::ProviderService)
    }
    /// Attach both signatures after validating runtime keys against policy.
    pub(crate) fn sign_receipt(
        &self,
        mut receipt: PotrReceiptV1,
        durable_policy_floor: Option<&PotrAdmissionPolicyBindingV1>,
    ) -> Result<SignedPotrReceiptV1, PotrReceiptRuntimeSigningError> {
        receipt
            .validate_unsigned()
            .map_err(PotrReceiptRuntimeSigningError::InvalidUnsignedReceipt)?;
        // A runtime adapter may rotate credentials behind a stable object, but
        // it may not silently replace either administrative signer identity.
        // Re-check the identities before consulting keys so a drifting or
        // substituted provider fails before either service sees signable
        // material.
        self.revalidate_gateway_binding()?;
        self.revalidate_provider_identity()?;
        self.revalidate_admission_reader()?;
        let policy_floor = self.effective_policy_floor(durable_policy_floor)?;
        let admission_snapshot = self.read_admission(&receipt, &policy_floor)?;
        validate_admission_snapshot(&admission_snapshot, &receipt, policy_floor)?;
        let admission = admission_snapshot.admission.as_ref();
        let provider_qualification =
            PotrRuntimeProviderQualificationV1::from_admission_binding(admission_snapshot.binding);
        self.revalidate_provider_binding(provider_qualification)?;
        let runtime_gateway_public_key = self.gateway_public_key()?;
        validate_gateway_public_key(&runtime_gateway_public_key)?;
        if runtime_gateway_public_key != self.expected_gateway_public_key {
            return Err(PotrReceiptRuntimeSigningError::GatewayPolicyMismatch);
        }
        let runtime_provider_id = self.provider_id(provider_qualification)?;
        if runtime_provider_id == [0; 32] {
            return Err(PotrReceiptRuntimeSigningError::InvalidProviderIdentity);
        }
        if runtime_provider_id != receipt.provider_id {
            return Err(PotrReceiptRuntimeSigningError::RuntimeProviderMismatch);
        }
        let runtime_provider_public_key = self.provider_public_key(provider_qualification)?;
        validate_provider_public_key(&runtime_provider_public_key)?;
        let governed_provider_public_key = admission
            .potr_mldsa_key()
            .ok_or(PotrReceiptRuntimeSigningError::ProviderPolicyUnavailable)?;
        if runtime_provider_public_key.as_slice() != governed_provider_public_key {
            return Err(PotrReceiptRuntimeSigningError::ProviderPolicyMismatch);
        }
        receipt.gateway_signature = None;
        receipt.provider_signature = None;
        let payload = receipt
            .signing_payload_bytes()
            .map_err(|_| PotrReceiptRuntimeSigningError::CanonicalPayload)?;
        let gateway_signature = self.gateway_sign(&payload)?;
        let gateway_signature = PotrSignatureV1 {
            algorithm: PotrSignatureAlgorithm::Ed25519,
            public_key: runtime_gateway_public_key.to_vec(),
            signature: gateway_signature,
        };
        gateway_signature
            .verify("gateway", &payload)
            .map_err(|_| PotrReceiptRuntimeSigningError::InvalidSignedReceipt)?;
        receipt.gateway_signature = Some(gateway_signature);
        let provider_signature = self.provider_sign(provider_qualification, &payload)?;
        receipt.provider_signature = Some(PotrSignatureV1 {
            algorithm: PotrSignatureAlgorithm::MlDsa65,
            public_key: runtime_provider_public_key,
            signature: provider_signature,
        });
        receipt
            .validate_with_governed_keys(&self.expected_gateway_public_key, admission)
            .map_err(|_| PotrReceiptRuntimeSigningError::InvalidSignedReceipt)?;
        let rechecked = self.read_admission(&receipt, &admission_snapshot.binding)?;
        validate_admission_snapshot(&rechecked, &receipt, admission_snapshot.binding)?;
        if rechecked.binding != admission_snapshot.binding
            || rechecked.admission.envelope_digest() != admission.envelope_digest()
        {
            return Err(PotrReceiptRuntimeSigningError::AdmissionChangedDuringSigning);
        }
        self.revalidate_gateway_binding()?;
        self.revalidate_provider_binding(
            PotrRuntimeProviderQualificationV1::from_admission_binding(rechecked.binding),
        )?;
        self.revalidate_admission_reader()?;
        Ok(SignedPotrReceiptV1 {
            receipt,
            admission: Arc::clone(&admission_snapshot.admission),
            admission_policy: admission_snapshot.binding,
        })
    }
    fn effective_policy_floor(
        &self,
        durable_policy_floor: Option<&PotrAdmissionPolicyBindingV1>,
    ) -> Result<PotrAdmissionPolicyBindingV1, PotrReceiptRuntimeSigningError> {
        let Some(durable) = durable_policy_floor.copied() else {
            return Ok(self.baseline_admission_policy);
        };
        durable
            .validate()
            .map_err(PotrReceiptRuntimeSigningError::AdmissionPolicyBinding)?;
        if durable.policy_sequence >= self.baseline_admission_policy.policy_sequence {
            durable
                .ensure_at_or_after(self.baseline_admission_policy)
                .map_err(PotrReceiptRuntimeSigningError::AdmissionPolicyProgress)?;
            Ok(durable)
        } else {
            self.baseline_admission_policy
                .ensure_at_or_after(durable)
                .map_err(PotrReceiptRuntimeSigningError::AdmissionPolicyProgress)?;
            Ok(self.baseline_admission_policy)
        }
    }
}
pub(crate) struct SignedPotrReceiptV1 {
    receipt: PotrReceiptV1,
    admission: Arc<AdmissionRecord>,
    admission_policy: PotrAdmissionPolicyBindingV1,
}
impl fmt::Debug for SignedPotrReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPotrReceiptV1")
            .field("status", &self.receipt.status)
            .field("policy_sequence", &self.admission_policy.policy_sequence)
            .finish_non_exhaustive()
    }
}
impl SignedPotrReceiptV1 {
    pub(crate) fn into_parts(
        self,
    ) -> (
        PotrReceiptV1,
        Arc<AdmissionRecord>,
        PotrAdmissionPolicyBindingV1,
    ) {
        (self.receipt, self.admission, self.admission_policy)
    }
}
fn validate_admission_snapshot(
    snapshot: &PotrAdmissionSnapshotV1,
    receipt: &PotrReceiptV1,
    policy_floor: PotrAdmissionPolicyBindingV1,
) -> Result<(), PotrReceiptRuntimeSigningError> {
    snapshot
        .binding
        .validate_for(snapshot.admission.as_ref())
        .map_err(PotrReceiptRuntimeSigningError::AdmissionPolicyBinding)?;
    snapshot
        .binding
        .ensure_at_or_after(policy_floor)
        .map_err(PotrReceiptRuntimeSigningError::AdmissionPolicyProgress)?;
    if !(snapshot.admission.is_council_verified() || snapshot.admission.is_genesis_material()) {
        return Err(PotrReceiptRuntimeSigningError::UntrustedAdmission);
    }
    if snapshot.admission.provider_id() != &receipt.provider_id {
        return Err(PotrReceiptRuntimeSigningError::AdmissionProviderMismatch);
    }
    let requested_at_unix = receipt.requested_at_ms / 1_000;
    let recorded_at_unix = receipt.recorded_at_ms / 1_000;
    if requested_at_unix < snapshot.admission.envelope().issued_at
        || recorded_at_unix > snapshot.admission.envelope().retention_epoch
    {
        return Err(PotrReceiptRuntimeSigningError::InactiveAdmission);
    }
    let qos = snapshot.admission.envelope().advert_body.qos;
    if receipt.deadline_ms != qos.max_retrieval_latency_ms {
        return Err(PotrReceiptRuntimeSigningError::AdmissionDeadlineMismatch);
    }
    if receipt.tier != proof_stream_tier_for_availability(qos.availability) {
        return Err(PotrReceiptRuntimeSigningError::AdmissionTierMismatch);
    }
    Ok(())
}
const fn proof_stream_tier_for_availability(availability: AvailabilityTier) -> ProofStreamTier {
    match availability {
        AvailabilityTier::Hot => ProofStreamTier::Hot,
        AvailabilityTier::Warm => ProofStreamTier::Warm,
        AvailabilityTier::Cold => ProofStreamTier::Archive,
    }
}
fn validate_gateway_public_key(
    public_key: &[u8; 32],
) -> Result<(), PotrReceiptRuntimeSigningError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| PotrReceiptRuntimeSigningError::InvalidGatewayPublicKey)?;
    if key.to_bytes() != *public_key || key.is_weak() {
        return Err(PotrReceiptRuntimeSigningError::InvalidGatewayPublicKey);
    }
    Ok(())
}
fn validate_provider_public_key(public_key: &[u8]) -> Result<(), PotrReceiptRuntimeSigningError> {
    PublicKey::from_bytes(Algorithm::MlDsa, public_key)
        .map(|_| ())
        .map_err(|_| PotrReceiptRuntimeSigningError::InvalidProviderPublicKey)
}
/// Invalid construction of the role-separated PoTR runtime boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PotrRuntimeSignerConfigError {
    /// A configured signer handle is malformed.
    #[error("PoTR runtime signer handle is invalid")]
    InvalidProviderHandle,
    /// A configured signer handle is explicitly test- or development-marked.
    #[error("PoTR runtime signer handle is test-marked")]
    TestMarkedProviderHandle,
    /// A configured signer binding uses the zero identity sentinel.
    #[error("PoTR runtime signer binding identity must be non-zero")]
    ZeroSignerBindingId,
    /// A configured signer revision or policy digest is zero.
    #[error("PoTR runtime signer qualification is invalid")]
    InvalidProviderQualification,
    /// Runtime signer readiness could not be established.
    #[error("PoTR runtime signer is unavailable or stale")]
    SignerQualificationUnavailable,
    /// The injected signer differs from its independently configured binding.
    #[error("PoTR runtime signer binding does not match the injected provider")]
    SignerBindingMismatch,
    /// Provider signer qualification does not match the baseline admission policy.
    #[error("PoTR provider signer qualification does not match admission policy")]
    ProviderQualificationPolicyMismatch,
    /// Gateway policy must carry a canonical strong Ed25519 public key.
    #[error("PoTR gateway policy key must be a canonical strong Ed25519 public key")]
    InvalidGatewayPolicyKey,
    /// Gateway signer identities must not use the zero sentinel.
    #[error("PoTR gateway runtime signer identity must be non-zero")]
    ZeroGatewaySignerId,
    /// Provider signer identities must not use the zero sentinel.
    #[error("PoTR provider runtime signer identity must be non-zero")]
    ZeroProviderSignerId,
    /// Admission reader identities must not use the zero sentinel.
    #[error("PoTR admission reader identity must be non-zero")]
    ZeroAdmissionReaderId,
    /// Both roles claimed the same runtime signer identity.
    #[error("PoTR gateway and provider runtime signer identities must be distinct")]
    SharedSignerIdentity,
    /// Both roles claimed the same runtime provider handle.
    #[error("PoTR gateway and provider runtime signer handles must be distinct")]
    SharedSignerHandle,
    /// Policy observation must not claim either signer administration identity.
    #[error("PoTR admission reader identity must be distinct from signer identities")]
    AdmissionReaderSharesSignerIdentity,
    /// Both roles were backed by the same in-process object.
    #[error("PoTR gateway and provider roles must use distinct runtime signer objects")]
    SharedSignerObject,
    /// Policy observation must not reuse either signer object.
    #[error("PoTR admission reader must use a distinct runtime object")]
    AdmissionReaderSharesSignerObject,
    /// The configured exact policy floor was malformed.
    #[error("PoTR baseline admission-policy anchor is invalid")]
    InvalidAdmissionPolicyAnchor,
    /// Finalized-state source identity uses the zero sentinel.
    #[error("PoTR admission finalized-state source identity must be non-zero")]
    ZeroAdmissionSourceId,
    /// Admission material resolver identity uses the zero sentinel.
    #[error("PoTR admission material resolver identity must be non-zero")]
    ZeroAdmissionResolverId,
    /// One administrative identity was reused across signing or observation roles.
    #[error("PoTR signer and admission observation identities must all be distinct")]
    RuntimeIdentityCollision,
    /// The production finalized admission reader could not be constructed.
    #[error("PoTR finalized admission reader configuration is invalid")]
    FinalizedReader(PotrFinalizedAdmissionReaderConfigError),
    /// PoTR is enabled without the exact public runtime binding.
    #[error("enabled PoTR requires an exact runtime binding")]
    MissingRuntimeConfiguration,
    /// A PoTR runtime binding was retained while the service is disabled.
    #[error("disabled PoTR must not retain a runtime binding")]
    DisabledRuntimeConfiguration,
    /// Enabled PoTR configuration has no injected runtime signer roles.
    #[error("enabled PoTR runtime configuration requires injected signer roles")]
    MissingRuntimeSignerRoles,
    /// Runtime roles were injected without an enabled exact configuration.
    #[error("PoTR runtime signer roles were injected without enabled configuration")]
    RuntimeSignerRolesNotConfigured,
    /// Injected runtime roles differ from the exact public configuration.
    #[error("PoTR runtime signer roles do not match the exact configured bindings")]
    RuntimeConfigurationMismatch,
    /// Torii cannot build the finalized reader without verified admission material.
    #[error("PoTR runtime signer roles require a council-verified admission registry")]
    MissingAdmissionRegistry,
}
/// Fail-closed PoTR receipt signing and policy-binding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum PotrReceiptRuntimeSigningError {
    /// The gateway adapter changed its stable administrative identity.
    #[error("PoTR gateway runtime signer identity changed")]
    GatewaySignerIdentityDrift,
    /// The provider adapter changed its stable administrative identity.
    #[error("PoTR provider runtime signer identity changed")]
    ProviderSignerIdentityDrift,
    /// The admission reader changed its stable administrative identity.
    #[error("PoTR admission reader identity changed")]
    AdmissionReaderIdentityDrift,
    /// The live finalized admission query failed closed.
    #[error("PoTR live admission query failed")]
    AdmissionReader(PotrAdmissionReaderError),
    /// The live admission binding was malformed or mismatched.
    #[error("PoTR live admission binding is invalid")]
    AdmissionPolicyBinding(PotrAdmissionPolicyBindingError),
    /// The live admission binding regressed or conflicted with its exact floor.
    #[error("PoTR live admission policy conflicts with the retained floor")]
    AdmissionPolicyProgress(PotrAdmissionPolicyProgressError),
    /// Admission changed or was revoked while provider signatures were being made.
    #[error("PoTR admission changed during receipt signing")]
    AdmissionChangedDuringSigning,
    /// The admission record did not establish council trust.
    #[error("PoTR provider admission is not council verified")]
    UntrustedAdmission,
    /// The admission record belongs to another provider.
    #[error("PoTR provider admission does not match the receipt")]
    AdmissionProviderMismatch,
    /// The admission was not active when the request began.
    #[error("PoTR provider admission is not active")]
    InactiveAdmission,
    /// The signed deadline differs from the council-verified provider QoS.
    #[error("PoTR receipt deadline does not match governed provider QoS")]
    AdmissionDeadlineMismatch,
    /// The signed storage tier differs from the council-verified provider QoS.
    #[error("PoTR receipt tier does not match governed provider QoS")]
    AdmissionTierMismatch,
    /// The unsigned receipt violates canonical semantic invariants.
    #[error("PoTR unsigned receipt is invalid: {0}")]
    InvalidUnsignedReceipt(PotrReceiptValidationError),
    /// Runtime gateway service failure.
    #[error("PoTR gateway signer service failed")]
    GatewayService(PotrSignerServiceError),
    /// Runtime provider service failure.
    #[error("PoTR provider signer service failed")]
    ProviderService(PotrSignerServiceError),
    /// The runtime gateway key is malformed or weak.
    #[error("PoTR gateway signer returned an invalid Ed25519 public key")]
    InvalidGatewayPublicKey,
    /// The runtime gateway key does not match configured gateway policy.
    #[error("PoTR gateway signer does not match configured gateway policy")]
    GatewayPolicyMismatch,
    /// The runtime provider identity is the zero sentinel.
    #[error("PoTR provider signer returned an invalid provider identity")]
    InvalidProviderIdentity,
    /// The runtime provider service serves another provider.
    #[error("PoTR provider signer identity does not match the request")]
    RuntimeProviderMismatch,
    /// The runtime provider key is not a canonical ML-DSA-65 public key.
    #[error("PoTR provider signer returned an invalid ML-DSA-65 public key")]
    InvalidProviderPublicKey,
    /// No governed PoTR key is present in active provider policy.
    #[error("PoTR provider policy has no ML-DSA-65 key")]
    ProviderPolicyUnavailable,
    /// The runtime provider key does not match active governed policy.
    #[error("PoTR provider signer does not match governed provider policy")]
    ProviderPolicyMismatch,
    /// The unsigned receipt could not be encoded canonically.
    #[error("PoTR signing payload could not be encoded canonically")]
    CanonicalPayload,
    /// A signer returned invalid signature material.
    #[error("runtime signers produced an invalid PoTR receipt")]
    InvalidSignedReceipt,
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use iroha_crypto::{KeyPair, Signature};
    use iroha_data_model::{account::AccountId, sorafs::proof_ledger::ProofOutcomeSignerPolicyV1};
    use sorafs_manifest::{
        CapabilityTlv, CapabilityType, CouncilSignature, ProviderAdmissionCouncilPolicy,
        ProviderAdmissionEnvelopeV1, compute_advert_body_digest,
        compute_envelope_authorization_digest, compute_proposal_digest,
        potr::{POTR_RECEIPT_VERSION_V1, PotrStatus},
        proof_stream::ProofStreamTier,
    };
    use std::collections::BTreeMap;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    const GATEWAY_SIGNER_ID: [u8; 32] = [0xA1; 32];
    const PROVIDER_SIGNER_ID: [u8; 32] = [0xB2; 32];
    const GATEWAY_HANDLE: &str = "provider:potr:gateway-primary";
    const PROVIDER_HANDLE: &str = "provider:potr:provider-primary";
    const GATEWAY_QUALIFICATION: PotrRuntimeProviderQualificationV1 =
        PotrRuntimeProviderQualificationV1::new(1, [0xA7; 32]);
    const PROVIDER_BASELINE_QUALIFICATION: PotrRuntimeProviderQualificationV1 =
        PotrRuntimeProviderQualificationV1::new(1, [0xE5; 32]);
    const ADMISSION_READER_ID: [u8; 32] = [0xC3; 32];
    const ADMISSION_POLICY_IDENTITY: [u8; 32] = [0xD4; 32];
    const FINALIZED_SOURCE_ID: [u8; 32] = [0xD5; 32];
    const ADMISSION_RESOLVER_ID: [u8; 32] = [0xD6; 32];
    struct TestAdmissionReader {
        reader_id: [u8; 32],
        responses: Mutex<Vec<Result<PotrAdmissionSnapshotV1, PotrAdmissionReaderError>>>,
        calls: AtomicUsize,
    }
    impl TestAdmissionReader {
        fn stable(snapshot: PotrAdmissionSnapshotV1) -> Self {
            Self {
                reader_id: ADMISSION_READER_ID,
                responses: Mutex::new(vec![Ok(snapshot)]),
                calls: AtomicUsize::new(0),
            }
        }
        fn with_responses(
            responses: Vec<Result<PotrAdmissionSnapshotV1, PotrAdmissionReaderError>>,
        ) -> Self {
            assert!(!responses.is_empty());
            Self {
                reader_id: ADMISSION_READER_ID,
                responses: Mutex::new(responses),
                calls: AtomicUsize::new(0),
            }
        }
        fn replace_responses(
            &self,
            responses: Vec<Result<PotrAdmissionSnapshotV1, PotrAdmissionReaderError>>,
        ) {
            assert!(!responses.is_empty());
            *self.responses.lock().expect("admission reader lock") = responses;
            self.calls.store(0, Ordering::SeqCst);
        }
    }
    impl PotrAdmissionReaderV1 for TestAdmissionReader {
        fn reader_id(&self) -> [u8; 32] {
            self.reader_id
        }
        fn active_admission(
            &self,
            _provider_id: [u8; 32],
            _requested_at_ms: u64,
            _recorded_at_ms: u64,
            _minimum: &PotrAdmissionPolicyBindingV1,
        ) -> Result<PotrAdmissionSnapshotV1, PotrAdmissionReaderError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let responses = self.responses.lock().expect("admission reader lock");
            responses[call.min(responses.len() - 1)].clone()
        }
    }
    struct TestFinalizedPolicySource {
        source_id: Mutex<[u8; 32]>,
        responses: Mutex<Vec<Result<PotrFinalizedPolicySnapshotV1, PotrAdmissionReaderError>>>,
        calls: AtomicUsize,
    }
    impl TestFinalizedPolicySource {
        fn stable(snapshot: PotrFinalizedPolicySnapshotV1) -> Self {
            Self {
                source_id: Mutex::new(FINALIZED_SOURCE_ID),
                responses: Mutex::new(vec![Ok(snapshot)]),
                calls: AtomicUsize::new(0),
            }
        }
        fn with_error(error: PotrAdmissionReaderError) -> Self {
            Self {
                source_id: Mutex::new(FINALIZED_SOURCE_ID),
                responses: Mutex::new(vec![Err(error)]),
                calls: AtomicUsize::new(0),
            }
        }
        fn drift_identity(&self) {
            *self.source_id.lock().expect("source identity lock") = [0xE1; 32];
        }
    }
    impl PotrFinalizedPolicySourceV1 for TestFinalizedPolicySource {
        fn source_id(&self) -> [u8; 32] {
            *self.source_id.lock().expect("source identity lock")
        }
        fn active_policy(
            &self,
            _provider_id: [u8; 32],
        ) -> Result<PotrFinalizedPolicySnapshotV1, PotrAdmissionReaderError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let responses = self.responses.lock().expect("policy responses lock");
            responses[call.min(responses.len() - 1)].clone()
        }
    }
    struct TestAdmissionMaterialResolver {
        resolver_id: Mutex<[u8; 32]>,
        admissions: Mutex<BTreeMap<[u8; 32], Arc<AdmissionRecord>>>,
    }
    impl TestAdmissionMaterialResolver {
        fn new(admissions: impl IntoIterator<Item = AdmissionRecord>) -> Self {
            Self {
                resolver_id: Mutex::new(ADMISSION_RESOLVER_ID),
                admissions: Mutex::new(
                    admissions
                        .into_iter()
                        .map(|admission| (*admission.envelope_digest(), Arc::new(admission)))
                        .collect(),
                ),
            }
        }
        fn drift_identity(&self) {
            *self.resolver_id.lock().expect("resolver identity lock") = [0xE2; 32];
        }
    }
    impl PotrAdmissionMaterialResolverV1 for TestAdmissionMaterialResolver {
        fn resolver_id(&self) -> [u8; 32] {
            *self.resolver_id.lock().expect("resolver identity lock")
        }
        fn resolve(
            &self,
            provider_id: [u8; 32],
            admission_envelope_digest: [u8; 32],
        ) -> Result<Arc<AdmissionRecord>, PotrAdmissionReaderError> {
            let admission = self
                .admissions
                .lock()
                .map_err(|_| PotrAdmissionReaderError::Unavailable)?
                .get(&admission_envelope_digest)
                .cloned()
                .ok_or(PotrAdmissionReaderError::Revoked)?;
            if admission.provider_id() != &provider_id {
                return Err(PotrAdmissionReaderError::Refused);
            }
            Ok(admission)
        }
    }
    struct TestGatewaySigner {
        signer_id: [u8; 32],
        qualification: PotrRuntimeProviderQualificationV1,
        key: SigningKey,
        public_key_override: Option<[u8; 32]>,
        unavailable: AtomicBool,
        corrupt_signature: bool,
        calls: Arc<AtomicUsize>,
    }
    impl PotrGatewaySignerV1 for TestGatewaySigner {
        fn handle(&self) -> &str {
            GATEWAY_HANDLE
        }
        fn signer_id(&self) -> [u8; 32] {
            self.signer_id
        }
        fn qualification(
            &self,
        ) -> Result<PotrRuntimeProviderQualificationV1, PotrSignerServiceError> {
            Ok(self.qualification)
        }
        fn public_key(&self) -> Result<[u8; 32], PotrSignerServiceError> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(PotrSignerServiceError::Unavailable);
            }
            Ok(self
                .public_key_override
                .unwrap_or_else(|| self.key.verifying_key().to_bytes()))
        }
        fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, PotrSignerServiceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(PotrSignerServiceError::Unavailable);
            }
            let mut signature = self.key.sign(payload).to_bytes().to_vec();
            if self.corrupt_signature {
                signature[0] ^= 0x80;
            }
            Ok(signature)
        }
    }
    struct TestProviderSigner {
        signer_id: [u8; 32],
        qualification: PotrRuntimeProviderQualificationV1,
        provider_id: [u8; 32],
        key: KeyPair,
        public_key_override: Option<Vec<u8>>,
        unavailable: AtomicBool,
        corrupt_signature: bool,
        calls: Arc<AtomicUsize>,
    }
    impl TestProviderSigner {
        fn public_key_bytes(&self) -> Vec<u8> {
            let (algorithm, public_key) = self
                .key
                .public_key()
                .try_to_bytes()
                .expect("encode test provider public key");
            assert_eq!(algorithm, Algorithm::MlDsa);
            public_key.to_vec()
        }
    }
    impl PotrProviderSignerV1 for TestProviderSigner {
        fn handle(&self) -> &str {
            PROVIDER_HANDLE
        }
        fn signer_id(&self) -> [u8; 32] {
            self.signer_id
        }
        fn qualification(
            &self,
        ) -> Result<PotrRuntimeProviderQualificationV1, PotrSignerServiceError> {
            Ok(self.qualification)
        }
        fn provider_id(&self) -> Result<[u8; 32], PotrSignerServiceError> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(PotrSignerServiceError::Unavailable);
            }
            Ok(self.provider_id)
        }
        fn public_key(&self) -> Result<Vec<u8>, PotrSignerServiceError> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(PotrSignerServiceError::Unavailable);
            }
            Ok(self
                .public_key_override
                .clone()
                .unwrap_or_else(|| self.public_key_bytes()))
        }
        fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, PotrSignerServiceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(PotrSignerServiceError::Unavailable);
            }
            let mut signature = Signature::try_new(self.key.private_key(), payload)
                .map_err(|_| PotrSignerServiceError::Refused)?
                .payload()
                .to_vec();
            if self.corrupt_signature {
                signature[0] ^= 0x80;
            }
            Ok(signature)
        }
    }
    struct PostSignQualificationDriftingGatewaySigner {
        key: SigningKey,
        qualification: Mutex<PotrRuntimeProviderQualificationV1>,
        calls: Arc<AtomicUsize>,
    }
    impl PotrGatewaySignerV1 for PostSignQualificationDriftingGatewaySigner {
        fn handle(&self) -> &str {
            GATEWAY_HANDLE
        }
        fn signer_id(&self) -> [u8; 32] {
            GATEWAY_SIGNER_ID
        }
        fn qualification(
            &self,
        ) -> Result<PotrRuntimeProviderQualificationV1, PotrSignerServiceError> {
            self.qualification
                .lock()
                .map(|qualification| *qualification)
                .map_err(|_| PotrSignerServiceError::Unavailable)
        }
        fn public_key(&self) -> Result<[u8; 32], PotrSignerServiceError> {
            Ok(self.key.verifying_key().to_bytes())
        }
        fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, PotrSignerServiceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let signature = self.key.sign(payload).to_bytes().to_vec();
            *self
                .qualification
                .lock()
                .map_err(|_| PotrSignerServiceError::Unavailable)? =
                PotrRuntimeProviderQualificationV1::new(2, [0xD7; 32]);
            Ok(signature)
        }
    }
    struct PostSignQualificationDriftingProviderSigner {
        provider_id: [u8; 32],
        key: KeyPair,
        qualification: Mutex<PotrRuntimeProviderQualificationV1>,
        calls: Arc<AtomicUsize>,
    }
    impl PotrProviderSignerV1 for PostSignQualificationDriftingProviderSigner {
        fn handle(&self) -> &str {
            PROVIDER_HANDLE
        }
        fn signer_id(&self) -> [u8; 32] {
            PROVIDER_SIGNER_ID
        }
        fn qualification(
            &self,
        ) -> Result<PotrRuntimeProviderQualificationV1, PotrSignerServiceError> {
            self.qualification
                .lock()
                .map(|qualification| *qualification)
                .map_err(|_| PotrSignerServiceError::Unavailable)
        }
        fn provider_id(&self) -> Result<[u8; 32], PotrSignerServiceError> {
            Ok(self.provider_id)
        }
        fn public_key(&self) -> Result<Vec<u8>, PotrSignerServiceError> {
            self.key
                .public_key()
                .try_to_bytes()
                .map(|(_, bytes)| bytes.to_vec())
                .map_err(|_| PotrSignerServiceError::Refused)
        }
        fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, PotrSignerServiceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let signature = Signature::try_new(self.key.private_key(), payload)
                .map_err(|_| PotrSignerServiceError::Refused)?
                .payload()
                .to_vec();
            *self
                .qualification
                .lock()
                .map_err(|_| PotrSignerServiceError::Unavailable)? =
                PotrRuntimeProviderQualificationV1::new(2, [0xD8; 32]);
            Ok(signature)
        }
    }
    struct RotatingProviderSigner {
        signer_id: [u8; 32],
        provider_id: [u8; 32],
        key: Mutex<KeyPair>,
        qualification: Mutex<PotrRuntimeProviderQualificationV1>,
        calls: Arc<AtomicUsize>,
    }
    impl RotatingProviderSigner {
        fn rotate(&self, key: KeyPair, qualification: PotrRuntimeProviderQualificationV1) {
            *self.key.lock().expect("provider signer key lock") = key;
            *self
                .qualification
                .lock()
                .expect("provider signer qualification lock") = qualification;
        }
    }
    impl PotrProviderSignerV1 for RotatingProviderSigner {
        fn handle(&self) -> &str {
            PROVIDER_HANDLE
        }
        fn signer_id(&self) -> [u8; 32] {
            self.signer_id
        }
        fn qualification(
            &self,
        ) -> Result<PotrRuntimeProviderQualificationV1, PotrSignerServiceError> {
            self.qualification
                .lock()
                .map(|qualification| *qualification)
                .map_err(|_| PotrSignerServiceError::Unavailable)
        }
        fn provider_id(&self) -> Result<[u8; 32], PotrSignerServiceError> {
            Ok(self.provider_id)
        }
        fn public_key(&self) -> Result<Vec<u8>, PotrSignerServiceError> {
            self.key
                .lock()
                .map_err(|_| PotrSignerServiceError::Unavailable)?
                .public_key()
                .try_to_bytes()
                .map(|(_, bytes)| bytes.to_vec())
                .map_err(|_| PotrSignerServiceError::Refused)
        }
        fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, PotrSignerServiceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let key = self
                .key
                .lock()
                .map_err(|_| PotrSignerServiceError::Unavailable)?;
            Signature::try_new(key.private_key(), payload)
                .map(|signature| signature.payload().to_vec())
                .map_err(|_| PotrSignerServiceError::Refused)
        }
    }
    struct TestFixture {
        gateway_key: SigningKey,
        provider_key: KeyPair,
        admission: AdmissionRecord,
        admission_policy: PotrAdmissionPolicyBindingV1,
        receipt: PotrReceiptV1,
    }
    fn fixture() -> TestFixture {
        let gateway_key = SigningKey::from_bytes(&[0x11; 32]);
        let provider_key = KeyPair::try_from_seed(vec![0x31; 32], Algorithm::MlDsa)
            .expect("derive independent provider ML-DSA-65 key");
        let (algorithm, provider_public_key) = provider_key
            .public_key()
            .try_to_bytes()
            .expect("encode provider key");
        assert_eq!(algorithm, Algorithm::MlDsa);
        let mut envelope: ProviderAdmissionEnvelopeV1 = norito::decode_from_bytes(include_bytes!(
            "../../../../fixtures/sorafs_manifest/provider_admission/envelope_v1.to"
        ))
        .expect("decode canonical provider admission fixture");
        let capability = CapabilityTlv {
            cap_type: CapabilityType::PotrMlDsa,
            payload: provider_public_key.to_vec(),
        };
        envelope
            .proposal
            .capabilities
            .retain(|entry| entry.cap_type != CapabilityType::PotrMlDsa);
        envelope.proposal.capabilities.push(capability.clone());
        envelope
            .advert_body
            .capabilities
            .retain(|entry| entry.cap_type != CapabilityType::PotrMlDsa);
        envelope.advert_body.capabilities.push(capability);
        envelope.proposal_digest =
            compute_proposal_digest(&envelope.proposal).expect("proposal digest");
        envelope.advert_body_digest =
            compute_advert_body_digest(&envelope.advert_body).expect("advert body digest");
        let council_key = SigningKey::from_bytes(&[0x45; 32]);
        envelope.council_signatures.clear();
        let authorization_digest =
            compute_envelope_authorization_digest(&envelope).expect("authorization digest");
        envelope.council_signatures.push(CouncilSignature {
            signer: council_key.verifying_key().to_bytes(),
            signature: council_key.sign(&authorization_digest).to_bytes().to_vec(),
        });
        let policy =
            ProviderAdmissionCouncilPolicy::new([council_key.verifying_key().to_bytes()], 1)
                .expect("single-signer council policy");
        let admission = AdmissionRecord::new(envelope, &policy)
            .expect("council-verified PoTR provider admission");
        let requested_at_ms = admission.envelope().issued_at.saturating_add(10) * 1_000;
        let qos = admission.envelope().advert_body.qos;
        let receipt = PotrReceiptV1 {
            version: POTR_RECEIPT_VERSION_V1,
            manifest_digest: [0x77; 32],
            provider_id: *admission.provider_id(),
            tier: proof_stream_tier_for_availability(qos.availability),
            deadline_ms: qos.max_retrieval_latency_ms,
            latency_ms: 42,
            status: PotrStatus::Success,
            requested_at_ms,
            responded_at_ms: requested_at_ms + 42,
            recorded_at_ms: requested_at_ms + 42,
            range_start: 0,
            range_end: 4_095,
            request_id: Some([0x55; 16]),
            trace_id: None,
            note: None,
            gateway_signature: None,
            provider_signature: None,
        };
        let admission_policy = PotrAdmissionPolicyBindingV1 {
            provider_id: receipt.provider_id,
            policy_identity: ADMISSION_POLICY_IDENTITY,
            policy_digest: [0xE5; 32],
            policy_sequence: 1,
            finalized_height: 101,
            finalized_block_hash: [0xF6; 32],
            admission_envelope_digest: *admission.envelope_digest(),
        };
        TestFixture {
            gateway_key,
            provider_key,
            admission,
            admission_policy,
            receipt,
        }
    }
    fn admission_snapshot(
        admission: &AdmissionRecord,
        binding: PotrAdmissionPolicyBindingV1,
    ) -> PotrAdmissionSnapshotV1 {
        PotrAdmissionSnapshotV1 {
            binding,
            admission: Arc::new(admission.clone()),
        }
    }
    fn admission_reader(
        admission: &AdmissionRecord,
        binding: PotrAdmissionPolicyBindingV1,
    ) -> Arc<dyn PotrAdmissionReaderV1> {
        Arc::new(TestAdmissionReader::stable(admission_snapshot(
            admission, binding,
        )))
    }
    fn gateway_binding() -> PotrRuntimeProviderBindingV1 {
        PotrRuntimeProviderBindingV1::try_new(
            GATEWAY_HANDLE,
            GATEWAY_SIGNER_ID,
            GATEWAY_QUALIFICATION,
        )
        .expect("valid gateway runtime binding")
    }
    fn provider_binding(
        admission_policy: PotrAdmissionPolicyBindingV1,
    ) -> PotrRuntimeProviderBindingV1 {
        PotrRuntimeProviderBindingV1::try_new(
            PROVIDER_HANDLE,
            PROVIDER_SIGNER_ID,
            PotrRuntimeProviderQualificationV1::from_admission_binding(admission_policy),
        )
        .expect("valid provider runtime binding")
    }
    fn reader_bindings() -> PotrRuntimeReaderBindingsV1 {
        PotrRuntimeReaderBindingsV1::try_new(
            ADMISSION_READER_ID,
            FINALIZED_SOURCE_ID,
            ADMISSION_RESOLVER_ID,
        )
        .expect("valid finalized-reader runtime bindings")
    }
    fn configured_runtime_binding(
        fixture: &TestFixture,
    ) -> iroha_config::parameters::actual::SorafsPotrRuntimeBinding {
        let policy = fixture.admission_policy;
        iroha_config::parameters::actual::SorafsPotrRuntimeBinding {
            gateway_signer: iroha_config::parameters::actual::SorafsPotrRuntimeSignerBinding {
                handle: GATEWAY_HANDLE.to_owned(),
                signer_id: GATEWAY_SIGNER_ID,
                revision: GATEWAY_QUALIFICATION.revision(),
                policy_digest: GATEWAY_QUALIFICATION.policy_digest(),
            },
            provider_signer: iroha_config::parameters::actual::SorafsPotrRuntimeSignerBinding {
                handle: PROVIDER_HANDLE.to_owned(),
                signer_id: PROVIDER_SIGNER_ID,
                revision: policy.policy_sequence,
                policy_digest: policy.policy_digest,
            },
            gateway_public_key: fixture.gateway_key.verifying_key().to_bytes(),
            reader_id: ADMISSION_READER_ID,
            source_id: FINALIZED_SOURCE_ID,
            resolver_id: ADMISSION_RESOLVER_ID,
            baseline_admission_policy:
                iroha_config::parameters::actual::SorafsPotrAdmissionPolicyBinding {
                    provider_id: policy.provider_id,
                    policy_identity: policy.policy_identity,
                    policy_digest: policy.policy_digest,
                    policy_sequence: policy.policy_sequence,
                    finalized_height: policy.finalized_height,
                    finalized_block_hash: policy.finalized_block_hash,
                    admission_envelope_digest: policy.admission_envelope_digest,
                },
        }
    }
    fn finalized_policy_snapshot(
        fixture: &TestFixture,
        admission: &AdmissionRecord,
        binding: PotrAdmissionPolicyBindingV1,
    ) -> PotrFinalizedPolicySnapshotV1 {
        let activation_key = KeyPair::try_from_seed(vec![0x5A; 32], Algorithm::Ed25519)
            .expect("activation account key");
        let policy = ProofOutcomeSignerPolicyV1 {
            version: iroha_data_model::sorafs::proof_ledger::PROOF_OUTCOME_SIGNER_POLICY_VERSION_V1,
            provider_id: ProviderId::new(binding.provider_id),
            revision: binding.policy_sequence,
            predecessor_digest: (binding.policy_sequence > 1).then_some([0xA8; 32]),
            admission_envelope_digest: binding.admission_envelope_digest,
            pdp_public_key: fixture.gateway_key.verifying_key().to_bytes(),
            potr_mldsa_public_key: admission
                .potr_mldsa_key()
                .expect("fixture admission has governed PoTR key")
                .to_vec(),
            gateway_public_key: fixture.gateway_key.verifying_key().to_bytes(),
            valid_from_unix: admission.envelope().issued_at,
            valid_until_unix: admission.envelope().retention_epoch,
        };
        PotrFinalizedPolicySnapshotV1 {
            finalized_cursor: ProofOutcomeFinalizedCursorV1 {
                height: binding.finalized_height,
                block_hash: binding.finalized_block_hash,
            },
            finalized_at_unix_ms: fixture.receipt.recorded_at_ms.saturating_add(1_000),
            policy: ProofOutcomeSignerPolicyRecordV1 {
                policy,
                policy_digest: binding.policy_digest,
                activated_by: AccountId::new(activation_key.public_key().clone()),
                activated_at_unix_ms: fixture.receipt.requested_at_ms.saturating_sub(1),
            },
        }
    }
    fn finalized_reader(
        fixture: &TestFixture,
        source: Arc<TestFinalizedPolicySource>,
        resolver: Arc<TestAdmissionMaterialResolver>,
    ) -> PotrFinalizedAdmissionReaderV1 {
        let source_trait: Arc<dyn PotrFinalizedPolicySourceV1> = source;
        let resolver_trait: Arc<dyn PotrAdmissionMaterialResolverV1> = resolver;
        PotrFinalizedAdmissionReaderV1::try_new(
            ADMISSION_READER_ID,
            ADMISSION_POLICY_IDENTITY,
            fixture.gateway_key.verifying_key().to_bytes(),
            source_trait,
            resolver_trait,
        )
        .expect("valid finalized admission reader")
    }
    fn admission_with_provider_key(
        base: &AdmissionRecord,
        provider_key: &KeyPair,
    ) -> AdmissionRecord {
        let (algorithm, public_key) = provider_key
            .public_key()
            .try_to_bytes()
            .expect("encode rotated provider key");
        assert_eq!(algorithm, Algorithm::MlDsa);
        let capability = CapabilityTlv {
            cap_type: CapabilityType::PotrMlDsa,
            payload: public_key.to_vec(),
        };
        let mut envelope = base.envelope().clone();
        envelope
            .proposal
            .capabilities
            .retain(|entry| entry.cap_type != CapabilityType::PotrMlDsa);
        envelope.proposal.capabilities.push(capability.clone());
        envelope
            .advert_body
            .capabilities
            .retain(|entry| entry.cap_type != CapabilityType::PotrMlDsa);
        envelope.advert_body.capabilities.push(capability);
        envelope.proposal_digest =
            compute_proposal_digest(&envelope.proposal).expect("rotated proposal digest");
        envelope.advert_body_digest =
            compute_advert_body_digest(&envelope.advert_body).expect("rotated advert digest");
        let council_key = SigningKey::from_bytes(&[0x45; 32]);
        envelope.council_signatures.clear();
        let authorization_digest =
            compute_envelope_authorization_digest(&envelope).expect("rotated authorization digest");
        envelope.council_signatures.push(CouncilSignature {
            signer: council_key.verifying_key().to_bytes(),
            signature: council_key.sign(&authorization_digest).to_bytes().to_vec(),
        });
        let policy =
            ProviderAdmissionCouncilPolicy::new([council_key.verifying_key().to_bytes()], 1)
                .expect("rotated council policy");
        AdmissionRecord::new(envelope, &policy).expect("rotated council admission")
    }
    fn runtime_signers(
        fixture: &TestFixture,
        gateway_unavailable: bool,
        provider_unavailable: bool,
    ) -> (PotrRuntimeSignersV1, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        runtime_signers_with_reader(
            fixture,
            Arc::new(TestAdmissionReader::stable(admission_snapshot(
                &fixture.admission,
                fixture.admission_policy,
            ))),
            gateway_unavailable,
            provider_unavailable,
        )
    }
    fn runtime_signers_with_reader(
        fixture: &TestFixture,
        admission_reader: Arc<dyn PotrAdmissionReaderV1>,
        gateway_unavailable: bool,
        provider_unavailable: bool,
    ) -> (PotrRuntimeSignersV1, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let gateway_calls = Arc::new(AtomicUsize::new(0));
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::clone(&gateway_calls),
        });
        let provider = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::clone(&provider_calls),
        });
        let signers = PotrRuntimeSignersV1::try_new(
            gateway.clone(),
            provider.clone(),
            gateway_binding(),
            provider_binding(fixture.admission_policy),
            admission_reader,
            fixture.gateway_key.verifying_key().to_bytes(),
            fixture.admission_policy,
        )
        .expect("independent runtime signers");
        gateway
            .unavailable
            .store(gateway_unavailable, Ordering::SeqCst);
        provider
            .unavailable
            .store(provider_unavailable, Ordering::SeqCst);
        (signers, gateway_calls, provider_calls)
    }
    #[test]
    fn finalized_reader_accepts_exact_committed_policy_and_governed_rotation() {
        let fixture = fixture();
        let source = Arc::new(TestFinalizedPolicySource::stable(
            finalized_policy_snapshot(&fixture, &fixture.admission, fixture.admission_policy),
        ));
        let resolver = Arc::new(TestAdmissionMaterialResolver::new([fixture
            .admission
            .clone()]));
        let reader = finalized_reader(&fixture, source, resolver);
        let initial = reader
            .active_admission(
                fixture.receipt.provider_id,
                fixture.receipt.requested_at_ms,
                fixture.receipt.recorded_at_ms,
                &fixture.admission_policy,
            )
            .expect("exact finalized policy");
        assert_eq!(initial.binding, fixture.admission_policy);
        assert_eq!(
            initial.admission.envelope_digest(),
            fixture.admission.envelope_digest()
        );
        let rotated_key =
            KeyPair::try_from_seed(vec![0xA7; 32], Algorithm::MlDsa).expect("rotated provider key");
        let rotated_admission = admission_with_provider_key(&fixture.admission, &rotated_key);
        let mut rotated_binding = fixture.admission_policy;
        rotated_binding.policy_sequence = 2;
        rotated_binding.policy_digest = [0x91; 32];
        rotated_binding.finalized_height = 102;
        rotated_binding.finalized_block_hash = [0x92; 32];
        rotated_binding.admission_envelope_digest = *rotated_admission.envelope_digest();
        let source = Arc::new(TestFinalizedPolicySource::stable(
            finalized_policy_snapshot(&fixture, &rotated_admission, rotated_binding),
        ));
        let resolver = Arc::new(TestAdmissionMaterialResolver::new([
            fixture.admission.clone(),
            rotated_admission.clone(),
        ]));
        let reader = finalized_reader(&fixture, source, resolver);
        let rotated = reader
            .active_admission(
                fixture.receipt.provider_id,
                fixture.receipt.requested_at_ms,
                fixture.receipt.recorded_at_ms,
                &fixture.admission_policy,
            )
            .expect("governed successor policy");
        assert_eq!(rotated.binding, rotated_binding);
        assert_eq!(
            rotated.admission.envelope_digest(),
            rotated_admission.envelope_digest()
        );
    }
    #[test]
    fn finalized_reader_rejects_stale_fork_and_identity_substitution() {
        let fixture = fixture();
        let make_reader = |binding| {
            let source = Arc::new(TestFinalizedPolicySource::stable(
                finalized_policy_snapshot(&fixture, &fixture.admission, binding),
            ));
            let resolver = Arc::new(TestAdmissionMaterialResolver::new([fixture
                .admission
                .clone()]));
            finalized_reader(&fixture, source, resolver)
        };
        let mut newer_floor = fixture.admission_policy;
        newer_floor.policy_sequence = 2;
        newer_floor.policy_digest = [0xA1; 32];
        newer_floor.finalized_height = 102;
        newer_floor.finalized_block_hash = [0xA2; 32];
        assert_eq!(
            make_reader(fixture.admission_policy)
                .active_admission(
                    fixture.receipt.provider_id,
                    fixture.receipt.requested_at_ms,
                    fixture.receipt.recorded_at_ms,
                    &newer_floor,
                )
                .expect_err("rollback below durable floor"),
            PotrAdmissionReaderError::Stale
        );
        let mut fork = fixture.admission_policy;
        fork.finalized_block_hash = [0xA3; 32];
        assert_eq!(
            make_reader(fork)
                .active_admission(
                    fixture.receipt.provider_id,
                    fixture.receipt.requested_at_ms,
                    fixture.receipt.recorded_at_ms,
                    &fixture.admission_policy,
                )
                .expect_err("same-height fork"),
            PotrAdmissionReaderError::Stale
        );
        let mut substitution = fixture.admission_policy;
        substitution.policy_digest = [0xA4; 32];
        assert_eq!(
            make_reader(substitution)
                .active_admission(
                    fixture.receipt.provider_id,
                    fixture.receipt.requested_at_ms,
                    fixture.receipt.recorded_at_ms,
                    &fixture.admission_policy,
                )
                .expect_err("same-revision policy substitution"),
            PotrAdmissionReaderError::Stale
        );
        let mut foreign_identity = fixture.admission_policy;
        foreign_identity.policy_identity = [0xA5; 32];
        assert_eq!(
            make_reader(fixture.admission_policy)
                .active_admission(
                    fixture.receipt.provider_id,
                    fixture.receipt.requested_at_ms,
                    fixture.receipt.recorded_at_ms,
                    &foreign_identity,
                )
                .expect_err("foreign policy series"),
            PotrAdmissionReaderError::Stale
        );
    }
    #[test]
    fn finalized_reader_rejects_revocation_outage_and_key_substitution() {
        let fixture = fixture();
        for source_error in [
            PotrAdmissionReaderError::Unavailable,
            PotrAdmissionReaderError::Revoked,
        ] {
            let source = Arc::new(TestFinalizedPolicySource::with_error(source_error));
            let resolver = Arc::new(TestAdmissionMaterialResolver::new([fixture
                .admission
                .clone()]));
            assert_eq!(
                finalized_reader(&fixture, source, resolver)
                    .active_admission(
                        fixture.receipt.provider_id,
                        fixture.receipt.requested_at_ms,
                        fixture.receipt.recorded_at_ms,
                        &fixture.admission_policy,
                    )
                    .expect_err("source failure"),
                source_error
            );
        }
        let mut expired =
            finalized_policy_snapshot(&fixture, &fixture.admission, fixture.admission_policy);
        expired.policy.policy.valid_until_unix =
            (fixture.receipt.requested_at_ms / 1_000).saturating_sub(1);
        let source = Arc::new(TestFinalizedPolicySource::stable(expired));
        let resolver = Arc::new(TestAdmissionMaterialResolver::new([fixture
            .admission
            .clone()]));
        assert_eq!(
            finalized_reader(&fixture, source, resolver)
                .active_admission(
                    fixture.receipt.provider_id,
                    fixture.receipt.requested_at_ms,
                    fixture.receipt.recorded_at_ms,
                    &fixture.admission_policy,
                )
                .expect_err("expired native policy"),
            PotrAdmissionReaderError::Revoked
        );
        let mut backdated =
            finalized_policy_snapshot(&fixture, &fixture.admission, fixture.admission_policy);
        backdated.policy.activated_at_unix_ms = fixture.receipt.requested_at_ms.saturating_add(1);
        let source = Arc::new(TestFinalizedPolicySource::stable(backdated));
        let resolver = Arc::new(TestAdmissionMaterialResolver::new([fixture
            .admission
            .clone()]));
        assert_eq!(
            finalized_reader(&fixture, source, resolver)
                .active_admission(
                    fixture.receipt.provider_id,
                    fixture.receipt.requested_at_ms,
                    fixture.receipt.recorded_at_ms,
                    &fixture.admission_policy,
                )
                .expect_err("policy activated after request"),
            PotrAdmissionReaderError::Revoked
        );
        let mut gateway_substitution =
            finalized_policy_snapshot(&fixture, &fixture.admission, fixture.admission_policy);
        gateway_substitution.policy.policy.gateway_public_key = SigningKey::from_bytes(&[0xBD; 32])
            .verifying_key()
            .to_bytes();
        let source = Arc::new(TestFinalizedPolicySource::stable(gateway_substitution));
        let resolver = Arc::new(TestAdmissionMaterialResolver::new([fixture
            .admission
            .clone()]));
        assert_eq!(
            finalized_reader(&fixture, source, resolver)
                .active_admission(
                    fixture.receipt.provider_id,
                    fixture.receipt.requested_at_ms,
                    fixture.receipt.recorded_at_ms,
                    &fixture.admission_policy,
                )
                .expect_err("committed gateway key substitution"),
            PotrAdmissionReaderError::Refused
        );
        let mut substituted =
            finalized_policy_snapshot(&fixture, &fixture.admission, fixture.admission_policy);
        let attacker_key =
            KeyPair::try_from_seed(vec![0xBC; 32], Algorithm::MlDsa).expect("attacker ML-DSA key");
        substituted.policy.policy.potr_mldsa_public_key = attacker_key
            .public_key()
            .try_to_bytes()
            .expect("attacker public key")
            .1
            .to_vec();
        let source = Arc::new(TestFinalizedPolicySource::stable(substituted));
        let resolver = Arc::new(TestAdmissionMaterialResolver::new([fixture
            .admission
            .clone()]));
        assert_eq!(
            finalized_reader(&fixture, source, resolver)
                .active_admission(
                    fixture.receipt.provider_id,
                    fixture.receipt.requested_at_ms,
                    fixture.receipt.recorded_at_ms,
                    &fixture.admission_policy,
                )
                .expect_err("committed key does not match council envelope"),
            PotrAdmissionReaderError::Refused
        );
    }
    #[test]
    fn finalized_reader_fails_closed_on_source_or_resolver_identity_drift() {
        let fixture = fixture();
        let source = Arc::new(TestFinalizedPolicySource::stable(
            finalized_policy_snapshot(&fixture, &fixture.admission, fixture.admission_policy),
        ));
        let resolver = Arc::new(TestAdmissionMaterialResolver::new([fixture
            .admission
            .clone()]));
        let reader = finalized_reader(&fixture, Arc::clone(&source), Arc::clone(&resolver));
        source.drift_identity();
        assert_eq!(
            reader
                .active_admission(
                    fixture.receipt.provider_id,
                    fixture.receipt.requested_at_ms,
                    fixture.receipt.recorded_at_ms,
                    &fixture.admission_policy,
                )
                .expect_err("source identity drift"),
            PotrAdmissionReaderError::Refused
        );
        let source = Arc::new(TestFinalizedPolicySource::stable(
            finalized_policy_snapshot(&fixture, &fixture.admission, fixture.admission_policy),
        ));
        let reader = finalized_reader(&fixture, Arc::clone(&source), Arc::clone(&resolver));
        resolver.drift_identity();
        assert_eq!(
            reader
                .active_admission(
                    fixture.receipt.provider_id,
                    fixture.receipt.requested_at_ms,
                    fixture.receipt.recorded_at_ms,
                    &fixture.admission_policy,
                )
                .expect_err("resolver identity drift"),
            PotrAdmissionReaderError::Refused
        );
    }
    #[test]
    fn signer_roles_pin_reader_components_without_accepting_a_local_reader() {
        let fixture = fixture();
        let gateway: Arc<dyn PotrGatewaySignerV1> = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let provider: Arc<dyn PotrProviderSignerV1> = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let roles = Arc::new(
            PotrRuntimeSignerRolesV1::try_new(
                Arc::clone(&gateway),
                Arc::clone(&provider),
                gateway_binding(),
                provider_binding(fixture.admission_policy),
                fixture.gateway_key.verifying_key().to_bytes(),
                fixture.admission_policy,
                reader_bindings(),
            )
            .expect("distinct signer and reader component identities"),
        );
        let configured = configured_runtime_binding(&fixture);
        assert_eq!(
            crate::require_sorafs_potr_finalized_reader_inputs(
                false,
                None,
                Some(Arc::clone(&roles)),
                None,
            )
            .expect_err("injected roles require enabled exact configuration"),
            PotrRuntimeSignerConfigError::RuntimeSignerRolesNotConfigured
        );
        assert_eq!(
            crate::require_sorafs_potr_finalized_reader_inputs(
                false,
                Some(&configured),
                None,
                None,
            )
            .expect_err("disabled service must reject stale runtime fields"),
            PotrRuntimeSignerConfigError::DisabledRuntimeConfiguration
        );
        assert_eq!(
            crate::require_sorafs_potr_finalized_reader_inputs(true, None, None, None)
                .expect_err("enabled service requires an exact public binding"),
            PotrRuntimeSignerConfigError::MissingRuntimeConfiguration
        );
        assert_eq!(
            crate::require_sorafs_potr_finalized_reader_inputs(
                true,
                Some(&configured),
                None,
                None,
            )
            .expect_err("enabled exact configuration requires injected roles"),
            PotrRuntimeSignerConfigError::MissingRuntimeSignerRoles
        );
        let substitutions: &[fn(
            &mut iroha_config::parameters::actual::SorafsPotrRuntimeBinding,
        )] = &[
            |binding| binding.gateway_signer.handle.push_str("-substituted"),
            |binding| binding.gateway_signer.signer_id[0] ^= 1,
            |binding| binding.gateway_signer.revision += 1,
            |binding| binding.gateway_signer.policy_digest[0] ^= 1,
            |binding| binding.provider_signer.handle.push_str("-substituted"),
            |binding| binding.provider_signer.signer_id[0] ^= 1,
            |binding| binding.provider_signer.revision += 1,
            |binding| binding.provider_signer.policy_digest[0] ^= 1,
            |binding| binding.gateway_public_key[0] ^= 1,
            |binding| binding.reader_id[0] ^= 1,
            |binding| binding.source_id[0] ^= 1,
            |binding| binding.resolver_id[0] ^= 1,
            |binding| binding.baseline_admission_policy.provider_id[0] ^= 1,
            |binding| binding.baseline_admission_policy.policy_identity[0] ^= 1,
            |binding| binding.baseline_admission_policy.policy_digest[0] ^= 1,
            |binding| binding.baseline_admission_policy.policy_sequence += 1,
            |binding| binding.baseline_admission_policy.finalized_height += 1,
            |binding| binding.baseline_admission_policy.finalized_block_hash[0] ^= 1,
            |binding| {
                binding.baseline_admission_policy.admission_envelope_digest[0] ^= 1;
            },
        ];
        for substitute in substitutions {
            let mut substituted = configured.clone();
            substitute(&mut substituted);
            assert_eq!(
                crate::require_sorafs_potr_finalized_reader_inputs(
                    true,
                    Some(&substituted),
                    Some(Arc::clone(&roles)),
                    None,
                )
                .expect_err("every substituted public field must fail before reader binding"),
                PotrRuntimeSignerConfigError::RuntimeConfigurationMismatch
            );
        }
        assert_eq!(
            crate::require_sorafs_potr_finalized_reader_inputs(
                true,
                Some(&configured),
                Some(roles),
                None,
            )
            .expect_err("startup must reject signer roles without verified admission material"),
            PotrRuntimeSignerConfigError::MissingAdmissionRegistry
        );
        assert_eq!(
            PotrRuntimeSignerRolesV1::try_new(
                gateway,
                provider,
                gateway_binding(),
                provider_binding(fixture.admission_policy),
                fixture.gateway_key.verifying_key().to_bytes(),
                fixture.admission_policy,
                PotrRuntimeReaderBindingsV1::try_new(
                    GATEWAY_SIGNER_ID,
                    FINALIZED_SOURCE_ID,
                    ADMISSION_RESOLVER_ID,
                )
                .expect("internally distinct reader bindings"),
            )
            .expect_err("reader identity cannot reuse a signer identity"),
            PotrRuntimeSignerConfigError::RuntimeIdentityCollision
        );
    }
    #[test]
    fn role_separated_runtime_signers_produce_governed_receipt() {
        let fixture = fixture();
        let (signers, gateway_calls, provider_calls) = runtime_signers(&fixture, false, false);
        let signed = signers
            .sign_receipt(fixture.receipt, None)
            .expect("role-separated receipt signing");
        let (receipt, admission, admission_policy) = signed.into_parts();
        assert_eq!(admission_policy, fixture.admission_policy);
        receipt
            .validate_with_governed_keys(
                &fixture.gateway_key.verifying_key().to_bytes(),
                admission.as_ref(),
            )
            .expect("receipt remains governed");
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn runtime_signing_rejects_caller_selected_deadline_and_tier() {
        let fixture = fixture();
        let (signers, gateway_calls, provider_calls) = runtime_signers(&fixture, false, false);
        let mut wrong_deadline = fixture.receipt.clone();
        wrong_deadline.deadline_ms = wrong_deadline.deadline_ms.saturating_add(1);
        assert_eq!(
            signers
                .sign_receipt(wrong_deadline, None)
                .expect_err("caller deadline must not override governed QoS"),
            PotrReceiptRuntimeSigningError::AdmissionDeadlineMismatch
        );
        let mut wrong_tier = fixture.receipt.clone();
        wrong_tier.tier = match wrong_tier.tier {
            ProofStreamTier::Hot => ProofStreamTier::Warm,
            ProofStreamTier::Warm | ProofStreamTier::Archive => ProofStreamTier::Hot,
        };
        assert_eq!(
            signers
                .sign_receipt(wrong_tier, None)
                .expect_err("caller tier must not override governed QoS"),
            PotrReceiptRuntimeSigningError::AdmissionTierMismatch
        );
        let mut invalid_status = fixture.receipt.clone();
        invalid_status.status = PotrStatus::MissedDeadline;
        assert!(matches!(
            signers.sign_receipt(invalid_status, None),
            Err(PotrReceiptRuntimeSigningError::InvalidUnsignedReceipt(
                PotrReceiptValidationError::MissedDeadlineWithoutBreach { .. }
            ))
        ));
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn runtime_bindings_use_central_handle_grammar_and_reject_invalid_qualification() {
        PotrRuntimeProviderBindingV1::try_new(
            "provider:prod/potr.gateway-v1_slot-a",
            GATEWAY_SIGNER_ID,
            GATEWAY_QUALIFICATION,
        )
        .expect("canonical production provider handle");
        for handle in [
            "https://operator:secret@potr-signer",
            "https://potr-signer/path?credential=secret",
            "https://potr-signer/path#fragment",
            "provider:prod/%70otr-signer",
            "provider:prod\\potr-signer",
        ] {
            assert_eq!(
                PotrRuntimeProviderBindingV1::try_new(
                    handle,
                    GATEWAY_SIGNER_ID,
                    GATEWAY_QUALIFICATION,
                )
                .expect_err("forbidden runtime-handle character must fail closed"),
                PotrRuntimeSignerConfigError::InvalidProviderHandle
            );
        }
        assert_eq!(
            PotrRuntimeProviderBindingV1::try_new(
                "provider:dummy:potr",
                GATEWAY_SIGNER_ID,
                GATEWAY_QUALIFICATION,
            )
            .expect_err("test-marked provider handles must fail closed"),
            PotrRuntimeSignerConfigError::TestMarkedProviderHandle
        );
        for qualification in [
            PotrRuntimeProviderQualificationV1::new(0, [0xA7; 32]),
            PotrRuntimeProviderQualificationV1::new(1, [0; 32]),
        ] {
            assert_eq!(
                PotrRuntimeProviderBindingV1::try_new(
                    GATEWAY_HANDLE,
                    GATEWAY_SIGNER_ID,
                    qualification,
                )
                .expect_err("zero qualification components must fail closed"),
                PotrRuntimeSignerConfigError::InvalidProviderQualification
            );
        }
        assert_eq!(
            PotrRuntimeReaderBindingsV1::try_new(
                [0; 32],
                FINALIZED_SOURCE_ID,
                ADMISSION_RESOLVER_ID,
            )
            .expect_err("zero reader identity must fail closed"),
            PotrRuntimeSignerConfigError::ZeroAdmissionReaderId
        );
        assert_eq!(
            PotrRuntimeReaderBindingsV1::try_new(
                ADMISSION_READER_ID,
                FINALIZED_SOURCE_ID,
                FINALIZED_SOURCE_ID,
            )
            .expect_err("reader component identities must be distinct"),
            PotrRuntimeSignerConfigError::RuntimeIdentityCollision
        );
    }
    #[test]
    fn provider_qualification_must_match_the_configured_admission_anchor() {
        let fixture = fixture();
        let gateway: Arc<dyn PotrGatewaySignerV1> = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let provider: Arc<dyn PotrProviderSignerV1> = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let mismatched_provider_binding = PotrRuntimeProviderBindingV1::try_new(
            PROVIDER_HANDLE,
            PROVIDER_SIGNER_ID,
            PotrRuntimeProviderQualificationV1::new(2, [0xE6; 32]),
        )
        .expect("structurally valid mismatched provider binding");
        assert_eq!(
            PotrRuntimeSignersV1::try_new(
                gateway,
                provider,
                gateway_binding(),
                mismatched_provider_binding,
                admission_reader(&fixture.admission, fixture.admission_policy),
                fixture.gateway_key.verifying_key().to_bytes(),
                fixture.admission_policy,
            )
            .expect_err("provider qualification must be independently anchored"),
            PotrRuntimeSignerConfigError::ProviderQualificationPolicyMismatch
        );
    }
    #[test]
    fn unavailable_signer_services_fail_startup_qualification() {
        let fixture = fixture();
        let gateway = |unavailable| {
            Arc::new(TestGatewaySigner {
                signer_id: GATEWAY_SIGNER_ID,
                qualification: GATEWAY_QUALIFICATION,
                key: fixture.gateway_key.clone(),
                public_key_override: None,
                unavailable: AtomicBool::new(unavailable),
                corrupt_signature: false,
                calls: Arc::new(AtomicUsize::new(0)),
            })
        };
        let provider = |unavailable| {
            Arc::new(TestProviderSigner {
                signer_id: PROVIDER_SIGNER_ID,
                qualification: PROVIDER_BASELINE_QUALIFICATION,
                provider_id: fixture.receipt.provider_id,
                key: fixture.provider_key.clone(),
                public_key_override: None,
                unavailable: AtomicBool::new(unavailable),
                corrupt_signature: false,
                calls: Arc::new(AtomicUsize::new(0)),
            })
        };
        for (gateway_unavailable, provider_unavailable) in [(true, false), (false, true)] {
            assert_eq!(
                PotrRuntimeSignersV1::try_new(
                    gateway(gateway_unavailable),
                    provider(provider_unavailable),
                    gateway_binding(),
                    provider_binding(fixture.admission_policy),
                    admission_reader(&fixture.admission, fixture.admission_policy),
                    fixture.gateway_key.verifying_key().to_bytes(),
                    fixture.admission_policy,
                )
                .expect_err("unavailable signer must fail startup"),
                PotrRuntimeSignerConfigError::SignerQualificationUnavailable
            );
        }
    }
    #[test]
    fn post_signature_qualification_drift_discards_the_receipt() {
        let fixture = fixture();
        let gateway_calls = Arc::new(AtomicUsize::new(0));
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let gateway: Arc<dyn PotrGatewaySignerV1> =
            Arc::new(PostSignQualificationDriftingGatewaySigner {
                key: fixture.gateway_key.clone(),
                qualification: Mutex::new(GATEWAY_QUALIFICATION),
                calls: Arc::clone(&gateway_calls),
            });
        let provider: Arc<dyn PotrProviderSignerV1> = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::clone(&provider_calls),
        });
        let signers = PotrRuntimeSignersV1::try_new(
            gateway,
            provider,
            gateway_binding(),
            provider_binding(fixture.admission_policy),
            admission_reader(&fixture.admission, fixture.admission_policy),
            fixture.gateway_key.verifying_key().to_bytes(),
            fixture.admission_policy,
        )
        .expect("qualified gateway signer");
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt.clone(), None)
                .expect_err("post-sign gateway qualification drift must discard the receipt"),
            PotrReceiptRuntimeSigningError::GatewaySignerIdentityDrift
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
        let gateway_calls = Arc::new(AtomicUsize::new(0));
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let gateway: Arc<dyn PotrGatewaySignerV1> = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::clone(&gateway_calls),
        });
        let provider: Arc<dyn PotrProviderSignerV1> =
            Arc::new(PostSignQualificationDriftingProviderSigner {
                provider_id: fixture.receipt.provider_id,
                key: fixture.provider_key.clone(),
                qualification: Mutex::new(PROVIDER_BASELINE_QUALIFICATION),
                calls: Arc::clone(&provider_calls),
            });
        let signers = PotrRuntimeSignersV1::try_new(
            gateway,
            provider,
            gateway_binding(),
            provider_binding(fixture.admission_policy),
            admission_reader(&fixture.admission, fixture.admission_policy),
            fixture.gateway_key.verifying_key().to_bytes(),
            fixture.admission_policy,
        )
        .expect("qualified provider signer");
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt, None)
                .expect_err("post-sign provider qualification drift must discard the receipt"),
            PotrReceiptRuntimeSigningError::ProviderSignerIdentityDrift
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn invalid_gateway_output_is_rejected_before_provider_signing() {
        let fixture = fixture();
        let gateway_calls = Arc::new(AtomicUsize::new(0));
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: true,
            calls: Arc::clone(&gateway_calls),
        });
        let provider = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key,
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::clone(&provider_calls),
        });
        let signers = PotrRuntimeSignersV1::try_new(
            gateway,
            provider,
            gateway_binding(),
            provider_binding(fixture.admission_policy),
            admission_reader(&fixture.admission, fixture.admission_policy),
            fixture.gateway_key.verifying_key().to_bytes(),
            fixture.admission_policy,
        )
        .expect("independent runtime signers");
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt, None)
                .expect_err("invalid gateway output must fail closed"),
            PotrReceiptRuntimeSigningError::InvalidSignedReceipt
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            provider_calls.load(Ordering::SeqCst),
            0,
            "provider signer must not sign after an invalid gateway result"
        );
    }
    #[test]
    fn signer_identity_and_object_reuse_are_rejected() {
        let fixture = fixture();
        let invalid_policy_gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let invalid_policy_provider = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        assert_eq!(
            PotrRuntimeSignersV1::try_new(
                invalid_policy_gateway,
                invalid_policy_provider,
                gateway_binding(),
                provider_binding(fixture.admission_policy),
                admission_reader(&fixture.admission, fixture.admission_policy),
                [0; 32],
                fixture.admission_policy,
            )
            .expect_err("inert gateway policy anchor must fail"),
            PotrRuntimeSignerConfigError::InvalidGatewayPolicyKey
        );
        let shared_identity_gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let shared_identity_provider = Arc::new(TestProviderSigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key,
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        assert_eq!(
            PotrRuntimeSignersV1::try_new(
                shared_identity_gateway,
                shared_identity_provider,
                gateway_binding(),
                PotrRuntimeProviderBindingV1::try_new(
                    PROVIDER_HANDLE,
                    GATEWAY_SIGNER_ID,
                    PROVIDER_BASELINE_QUALIFICATION,
                )
                .expect("valid shared-identity provider binding"),
                admission_reader(&fixture.admission, fixture.admission_policy),
                fixture.gateway_key.verifying_key().to_bytes(),
                fixture.admission_policy,
            )
            .expect_err("shared runtime identity must fail"),
            PotrRuntimeSignerConfigError::SharedSignerIdentity
        );
        struct DualRoleSigner;
        impl PotrGatewaySignerV1 for DualRoleSigner {
            fn handle(&self) -> &str {
                GATEWAY_HANDLE
            }
            fn signer_id(&self) -> [u8; 32] {
                GATEWAY_SIGNER_ID
            }
            fn qualification(
                &self,
            ) -> Result<PotrRuntimeProviderQualificationV1, PotrSignerServiceError> {
                Ok(GATEWAY_QUALIFICATION)
            }
            fn public_key(&self) -> Result<[u8; 32], PotrSignerServiceError> {
                Err(PotrSignerServiceError::Refused)
            }
            fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, PotrSignerServiceError> {
                Err(PotrSignerServiceError::Refused)
            }
        }
        impl PotrProviderSignerV1 for DualRoleSigner {
            fn handle(&self) -> &str {
                PROVIDER_HANDLE
            }
            fn signer_id(&self) -> [u8; 32] {
                PROVIDER_SIGNER_ID
            }
            fn qualification(
                &self,
            ) -> Result<PotrRuntimeProviderQualificationV1, PotrSignerServiceError> {
                Ok(PROVIDER_BASELINE_QUALIFICATION)
            }
            fn provider_id(&self) -> Result<[u8; 32], PotrSignerServiceError> {
                Err(PotrSignerServiceError::Refused)
            }
            fn public_key(&self) -> Result<Vec<u8>, PotrSignerServiceError> {
                Err(PotrSignerServiceError::Refused)
            }
            fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, PotrSignerServiceError> {
                Err(PotrSignerServiceError::Refused)
            }
        }
        let shared = Arc::new(DualRoleSigner);
        let gateway: Arc<dyn PotrGatewaySignerV1> = shared.clone();
        let provider: Arc<dyn PotrProviderSignerV1> = shared;
        assert_eq!(
            PotrRuntimeSignersV1::try_new(
                gateway,
                provider,
                gateway_binding(),
                provider_binding(fixture.admission_policy),
                admission_reader(&fixture.admission, fixture.admission_policy),
                fixture.gateway_key.verifying_key().to_bytes(),
                fixture.admission_policy,
            )
            .expect_err("one object must not sign both roles"),
            PotrRuntimeSignerConfigError::SharedSignerObject
        );
    }
    #[test]
    fn admission_reader_cannot_reuse_or_drift_into_a_signer_trust_domain() {
        let fixture = fixture();
        let gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let provider = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let colliding_reader: Arc<dyn PotrAdmissionReaderV1> = Arc::new(TestAdmissionReader {
            reader_id: GATEWAY_SIGNER_ID,
            responses: Mutex::new(vec![Ok(admission_snapshot(
                &fixture.admission,
                fixture.admission_policy,
            ))]),
            calls: AtomicUsize::new(0),
        });
        assert_eq!(
            PotrRuntimeSignersV1::try_new(
                gateway,
                provider,
                gateway_binding(),
                provider_binding(fixture.admission_policy),
                colliding_reader,
                fixture.gateway_key.verifying_key().to_bytes(),
                fixture.admission_policy,
            )
            .expect_err("reader and signer identities must remain distinct"),
            PotrRuntimeSignerConfigError::AdmissionReaderSharesSignerIdentity
        );
        struct DriftingAdmissionReader {
            identity_reads: AtomicUsize,
            snapshot: PotrAdmissionSnapshotV1,
            query_calls: Arc<AtomicUsize>,
        }
        impl PotrAdmissionReaderV1 for DriftingAdmissionReader {
            fn reader_id(&self) -> [u8; 32] {
                if self.identity_reads.fetch_add(1, Ordering::SeqCst) == 0 {
                    ADMISSION_READER_ID
                } else {
                    [0x77; 32]
                }
            }
            fn active_admission(
                &self,
                _provider_id: [u8; 32],
                _requested_at_ms: u64,
                _recorded_at_ms: u64,
                _minimum: &PotrAdmissionPolicyBindingV1,
            ) -> Result<PotrAdmissionSnapshotV1, PotrAdmissionReaderError> {
                self.query_calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.snapshot.clone())
            }
        }
        let query_calls = Arc::new(AtomicUsize::new(0));
        let drifting_reader = Arc::new(DriftingAdmissionReader {
            identity_reads: AtomicUsize::new(0),
            snapshot: admission_snapshot(&fixture.admission, fixture.admission_policy),
            query_calls: Arc::clone(&query_calls),
        });
        let gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let provider = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key,
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let signers = PotrRuntimeSignersV1::try_new(
            gateway,
            provider,
            gateway_binding(),
            provider_binding(fixture.admission_policy),
            drifting_reader,
            fixture.gateway_key.verifying_key().to_bytes(),
            fixture.admission_policy,
        )
        .expect("initial reader identity");
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt, None)
                .expect_err("reader identity substitution must fail closed"),
            PotrReceiptRuntimeSigningError::AdmissionReaderIdentityDrift
        );
        assert_eq!(query_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn runtime_signer_identity_drift_fails_before_key_or_signature_use() {
        struct DriftingGatewaySigner {
            identity_reads: AtomicUsize,
            key: SigningKey,
            service_calls: Arc<AtomicUsize>,
        }
        impl PotrGatewaySignerV1 for DriftingGatewaySigner {
            fn handle(&self) -> &str {
                GATEWAY_HANDLE
            }
            fn signer_id(&self) -> [u8; 32] {
                if self.identity_reads.fetch_add(1, Ordering::SeqCst) < 3 {
                    GATEWAY_SIGNER_ID
                } else {
                    [0xC3; 32]
                }
            }
            fn qualification(
                &self,
            ) -> Result<PotrRuntimeProviderQualificationV1, PotrSignerServiceError> {
                Ok(GATEWAY_QUALIFICATION)
            }
            fn public_key(&self) -> Result<[u8; 32], PotrSignerServiceError> {
                self.service_calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.key.verifying_key().to_bytes())
            }
            fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, PotrSignerServiceError> {
                self.service_calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.key.sign(payload).to_bytes().to_vec())
            }
        }
        struct DriftingProviderSigner {
            identity_reads: AtomicUsize,
            provider_id: [u8; 32],
            key: KeyPair,
            service_calls: Arc<AtomicUsize>,
        }
        impl PotrProviderSignerV1 for DriftingProviderSigner {
            fn handle(&self) -> &str {
                PROVIDER_HANDLE
            }
            fn signer_id(&self) -> [u8; 32] {
                if self.identity_reads.fetch_add(1, Ordering::SeqCst) < 4 {
                    PROVIDER_SIGNER_ID
                } else {
                    [0xD4; 32]
                }
            }
            fn qualification(
                &self,
            ) -> Result<PotrRuntimeProviderQualificationV1, PotrSignerServiceError> {
                Ok(PROVIDER_BASELINE_QUALIFICATION)
            }
            fn provider_id(&self) -> Result<[u8; 32], PotrSignerServiceError> {
                self.service_calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.provider_id)
            }
            fn public_key(&self) -> Result<Vec<u8>, PotrSignerServiceError> {
                self.service_calls.fetch_add(1, Ordering::SeqCst);
                self.key
                    .public_key()
                    .try_to_bytes()
                    .map(|(_, bytes)| bytes.to_vec())
                    .map_err(|_| PotrSignerServiceError::Refused)
            }
            fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, PotrSignerServiceError> {
                self.service_calls.fetch_add(1, Ordering::SeqCst);
                Signature::try_new(self.key.private_key(), payload)
                    .map(|signature| signature.payload().to_vec())
                    .map_err(|_| PotrSignerServiceError::Refused)
            }
        }
        let fixture = fixture();
        let gateway_service_calls = Arc::new(AtomicUsize::new(0));
        let drifting_gateway = Arc::new(DriftingGatewaySigner {
            identity_reads: AtomicUsize::new(0),
            key: fixture.gateway_key.clone(),
            service_calls: Arc::clone(&gateway_service_calls),
        });
        let provider = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let signers = PotrRuntimeSignersV1::try_new(
            drifting_gateway,
            provider,
            gateway_binding(),
            provider_binding(fixture.admission_policy),
            admission_reader(&fixture.admission, fixture.admission_policy),
            fixture.gateway_key.verifying_key().to_bytes(),
            fixture.admission_policy,
        )
        .expect("initial signer identities are distinct");
        gateway_service_calls.store(0, Ordering::SeqCst);
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt.clone(), None)
                .expect_err("gateway identity drift must fail closed"),
            PotrReceiptRuntimeSigningError::GatewaySignerIdentityDrift
        );
        assert_eq!(gateway_service_calls.load(Ordering::SeqCst), 0);
        let gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let provider_service_calls = Arc::new(AtomicUsize::new(0));
        let drifting_provider = Arc::new(DriftingProviderSigner {
            identity_reads: AtomicUsize::new(0),
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key,
            service_calls: Arc::clone(&provider_service_calls),
        });
        let signers = PotrRuntimeSignersV1::try_new(
            gateway,
            drifting_provider,
            gateway_binding(),
            provider_binding(fixture.admission_policy),
            admission_reader(&fixture.admission, fixture.admission_policy),
            fixture.gateway_key.verifying_key().to_bytes(),
            fixture.admission_policy,
        )
        .expect("initial signer identities are distinct");
        provider_service_calls.store(0, Ordering::SeqCst);
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt, None)
                .expect_err("provider identity drift must fail closed"),
            PotrReceiptRuntimeSigningError::ProviderSignerIdentityDrift
        );
        assert_eq!(provider_service_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn provider_identity_key_and_algorithm_mismatches_fail_before_signing() {
        let fixture = fixture();
        let gateway_calls = Arc::new(AtomicUsize::new(0));
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::clone(&gateway_calls),
        });
        let wrong_identity = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: [0xEE; 32],
            key: fixture.provider_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::clone(&provider_calls),
        });
        assert_eq!(
            PotrRuntimeSignersV1::try_new(
                gateway,
                wrong_identity,
                gateway_binding(),
                provider_binding(fixture.admission_policy),
                admission_reader(&fixture.admission, fixture.admission_policy),
                fixture.gateway_key.verifying_key().to_bytes(),
                fixture.admission_policy,
            )
            .expect_err("wrong provider identity must fail at startup"),
            PotrRuntimeSignerConfigError::SignerBindingMismatch
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
        let gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let wrong_algorithm = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key.clone(),
            public_key_override: Some(
                SigningKey::from_bytes(&[0x91; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            ),
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        assert_eq!(
            PotrRuntimeSignersV1::try_new(
                gateway,
                wrong_algorithm,
                gateway_binding(),
                provider_binding(fixture.admission_policy),
                admission_reader(&fixture.admission, fixture.admission_policy),
                fixture.gateway_key.verifying_key().to_bytes(),
                fixture.admission_policy,
            )
            .expect_err("Ed25519 provider material must fail at startup"),
            PotrRuntimeSignerConfigError::SignerBindingMismatch
        );
        let rotated_provider_key =
            KeyPair::try_from_seed(vec![0x82; 32], Algorithm::MlDsa).expect("rotated provider key");
        let gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let stale_policy = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: rotated_provider_key,
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let signers = PotrRuntimeSignersV1::try_new(
            gateway,
            stale_policy,
            gateway_binding(),
            provider_binding(fixture.admission_policy),
            admission_reader(&fixture.admission, fixture.admission_policy),
            fixture.gateway_key.verifying_key().to_bytes(),
            fixture.admission_policy,
        )
        .expect("distinct signers");
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt, None)
                .expect_err("unapproved provider rotation must fail"),
            PotrReceiptRuntimeSigningError::ProviderPolicyMismatch
        );
    }
    #[test]
    fn signer_outages_are_independent_and_fail_closed() {
        let fixture = fixture();
        let (gateway_out, gateway_calls, provider_calls) = runtime_signers(&fixture, true, false);
        assert_eq!(
            gateway_out
                .sign_receipt(fixture.receipt.clone(), None)
                .expect_err("gateway outage must fail closed"),
            PotrReceiptRuntimeSigningError::GatewayService(PotrSignerServiceError::Unavailable)
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
        let (provider_out, gateway_calls, provider_calls) = runtime_signers(&fixture, false, true);
        assert_eq!(
            provider_out
                .sign_receipt(fixture.receipt, None)
                .expect_err("provider outage must fail closed"),
            PotrReceiptRuntimeSigningError::ProviderService(PotrSignerServiceError::Unavailable)
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn live_admission_reader_outage_and_revocation_fail_before_signing() {
        for reader_error in [
            PotrAdmissionReaderError::Unavailable,
            PotrAdmissionReaderError::Revoked,
        ] {
            let fixture = fixture();
            let reader: Arc<dyn PotrAdmissionReaderV1> =
                Arc::new(TestAdmissionReader::with_responses(vec![Err(reader_error)]));
            let (signers, gateway_calls, provider_calls) =
                runtime_signers_with_reader(&fixture, reader, false, false);
            assert_eq!(
                signers
                    .sign_receipt(fixture.receipt, None)
                    .expect_err("unavailable or revoked admission must fail closed"),
                PotrReceiptRuntimeSigningError::AdmissionReader(reader_error)
            );
            assert_eq!(gateway_calls.load(Ordering::SeqCst), 0);
            assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn live_reader_must_return_council_trusted_policy_active_through_recording() {
        let fixture = fixture();
        let untrusted =
            AdmissionRecord::new_untrusted_signers(fixture.admission.envelope().clone())
                .expect("integrity-only admission");
        let reader: Arc<dyn PotrAdmissionReaderV1> =
            Arc::new(TestAdmissionReader::stable(PotrAdmissionSnapshotV1 {
                binding: fixture.admission_policy,
                admission: Arc::new(untrusted),
            }));
        let (signers, gateway_calls, provider_calls) =
            runtime_signers_with_reader(&fixture, reader, false, false);
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt.clone(), None)
                .expect_err("integrity-only admission must not authorize signing"),
            PotrReceiptRuntimeSigningError::UntrustedAdmission
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
        let (signers, gateway_calls, provider_calls) = runtime_signers(&fixture, false, false);
        let mut expired_before_recording = fixture.receipt;
        expired_before_recording.recorded_at_ms = fixture
            .admission
            .envelope()
            .retention_epoch
            .saturating_add(1)
            .saturating_mul(1_000);
        assert_eq!(
            signers
                .sign_receipt(expired_before_recording, None)
                .expect_err("admission must remain active through durable recording time"),
            PotrReceiptRuntimeSigningError::InactiveAdmission
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn durable_policy_floor_rejects_stale_and_substituted_reader_results() {
        let fixture = fixture();
        let mut durable_floor = fixture.admission_policy;
        durable_floor.policy_sequence = 2;
        durable_floor.policy_digest = [0x91; 32];
        durable_floor.finalized_height = 102;
        durable_floor.finalized_block_hash = [0x92; 32];
        let stale_reader: Arc<dyn PotrAdmissionReaderV1> = Arc::new(TestAdmissionReader::stable(
            admission_snapshot(&fixture.admission, fixture.admission_policy),
        ));
        let (signers, gateway_calls, provider_calls) =
            runtime_signers_with_reader(&fixture, stale_reader, false, false);
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt.clone(), Some(&durable_floor))
                .expect_err("stale policy sequence must fail closed"),
            PotrReceiptRuntimeSigningError::AdmissionPolicyProgress(
                PotrAdmissionPolicyProgressError::SequenceRollback
            )
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
        let mut fork_substitution = fixture.admission_policy;
        fork_substitution.policy_sequence = 2;
        fork_substitution.policy_digest = [0x97; 32];
        fork_substitution.finalized_block_hash = [0x98; 32];
        let fork_reader: Arc<dyn PotrAdmissionReaderV1> = Arc::new(TestAdmissionReader::stable(
            admission_snapshot(&fixture.admission, fork_substitution),
        ));
        let (signers, gateway_calls, provider_calls) =
            runtime_signers_with_reader(&fixture, fork_reader, false, false);
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt.clone(), None)
                .expect_err("same-height finalized fork substitution must fail closed"),
            PotrReceiptRuntimeSigningError::AdmissionPolicyProgress(
                PotrAdmissionPolicyProgressError::FinalizedBlockConflict
            )
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
        let mut substituted = durable_floor;
        substituted.policy_digest[0] ^= 0x80;
        let substituted_reader: Arc<dyn PotrAdmissionReaderV1> = Arc::new(
            TestAdmissionReader::stable(admission_snapshot(&fixture.admission, substituted)),
        );
        let (signers, gateway_calls, provider_calls) =
            runtime_signers_with_reader(&fixture, substituted_reader, false, false);
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt, Some(&durable_floor))
                .expect_err("same-sequence policy substitution must fail closed"),
            PotrReceiptRuntimeSigningError::AdmissionPolicyProgress(
                PotrAdmissionPolicyProgressError::SequenceConflict
            )
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn admission_change_or_outage_after_signing_discards_both_signatures() {
        let fixture = fixture();
        let mut rotated_policy = fixture.admission_policy;
        rotated_policy.policy_sequence = 2;
        rotated_policy.policy_digest = [0x93; 32];
        rotated_policy.finalized_height = 102;
        rotated_policy.finalized_block_hash = [0x94; 32];
        let changed_reader: Arc<dyn PotrAdmissionReaderV1> =
            Arc::new(TestAdmissionReader::with_responses(vec![
                Ok(admission_snapshot(
                    &fixture.admission,
                    fixture.admission_policy,
                )),
                Ok(admission_snapshot(&fixture.admission, rotated_policy)),
            ]));
        let (signers, gateway_calls, provider_calls) =
            runtime_signers_with_reader(&fixture, changed_reader, false, false);
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt.clone(), None)
                .expect_err("policy rotation during signing must discard the receipt"),
            PotrReceiptRuntimeSigningError::AdmissionChangedDuringSigning
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        let outage_reader: Arc<dyn PotrAdmissionReaderV1> =
            Arc::new(TestAdmissionReader::with_responses(vec![
                Ok(admission_snapshot(
                    &fixture.admission,
                    fixture.admission_policy,
                )),
                Err(PotrAdmissionReaderError::Unavailable),
            ]));
        let (signers, gateway_calls, provider_calls) =
            runtime_signers_with_reader(&fixture, outage_reader, false, false);
        assert_eq!(
            signers
                .sign_receipt(fixture.receipt, None)
                .expect_err("post-signature reader outage must discard the receipt"),
            PotrReceiptRuntimeSigningError::AdmissionReader(PotrAdmissionReaderError::Unavailable)
        );
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn governed_provider_key_rotation_uses_one_live_reader_and_stable_signer_boundary() {
        let fixture = fixture();
        let rotated_key =
            KeyPair::try_from_seed(vec![0xA7; 32], Algorithm::MlDsa).expect("rotated provider key");
        let rotated_admission = admission_with_provider_key(&fixture.admission, &rotated_key);
        let mut rotated_policy = fixture.admission_policy;
        rotated_policy.policy_sequence = 2;
        rotated_policy.policy_digest = [0x95; 32];
        rotated_policy.finalized_height = 102;
        rotated_policy.finalized_block_hash = [0x96; 32];
        rotated_policy.admission_envelope_digest = *rotated_admission.envelope_digest();
        let gateway_calls = Arc::new(AtomicUsize::new(0));
        let gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: GATEWAY_QUALIFICATION,
            key: fixture.gateway_key.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::clone(&gateway_calls),
        });
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(RotatingProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            provider_id: fixture.receipt.provider_id,
            key: Mutex::new(fixture.provider_key.clone()),
            qualification: Mutex::new(PROVIDER_BASELINE_QUALIFICATION),
            calls: Arc::clone(&provider_calls),
        });
        let reader = Arc::new(TestAdmissionReader::stable(admission_snapshot(
            &fixture.admission,
            fixture.admission_policy,
        )));
        let signers = PotrRuntimeSignersV1::try_new(
            gateway,
            provider.clone(),
            gateway_binding(),
            provider_binding(fixture.admission_policy),
            reader.clone(),
            fixture.gateway_key.verifying_key().to_bytes(),
            fixture.admission_policy,
        )
        .expect("live rotation boundary");
        let first = signers
            .sign_receipt(fixture.receipt.clone(), None)
            .expect("initial governed key")
            .into_parts();
        assert_eq!(first.2, fixture.admission_policy);
        provider.rotate(
            rotated_key,
            PotrRuntimeProviderQualificationV1::from_admission_binding(rotated_policy),
        );
        reader.replace_responses(vec![Ok(PotrAdmissionSnapshotV1 {
            binding: rotated_policy,
            admission: Arc::new(rotated_admission.clone()),
        })]);
        let mut rotated_receipt = fixture.receipt;
        rotated_receipt.request_id = Some([0x56; 16]);
        rotated_receipt.range_start = 4_096;
        rotated_receipt.range_end = 8_191;
        let (receipt, accepted_admission, accepted_policy) = signers
            .sign_receipt(rotated_receipt, Some(&fixture.admission_policy))
            .expect("governed provider rotation")
            .into_parts();
        assert_eq!(accepted_policy, rotated_policy);
        receipt
            .validate_with_governed_keys(
                &fixture.gateway_key.verifying_key().to_bytes(),
                accepted_admission.as_ref(),
            )
            .expect("rotated receipt remains governed");
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 2);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn gateway_rotation_requires_independent_policy_update() {
        let fixture = fixture();
        let rotated_gateway = SigningKey::from_bytes(&[0x73; 32]);
        let rotated_qualification = PotrRuntimeProviderQualificationV1::new(2, [0x74; 32]);
        let rotated_binding = PotrRuntimeProviderBindingV1::try_new(
            GATEWAY_HANDLE,
            GATEWAY_SIGNER_ID,
            rotated_qualification,
        )
        .expect("rotated gateway binding");
        let gateway = Arc::new(TestGatewaySigner {
            signer_id: GATEWAY_SIGNER_ID,
            qualification: rotated_qualification,
            key: rotated_gateway.clone(),
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(TestProviderSigner {
            signer_id: PROVIDER_SIGNER_ID,
            qualification: PROVIDER_BASELINE_QUALIFICATION,
            provider_id: fixture.receipt.provider_id,
            key: fixture.provider_key,
            public_key_override: None,
            unavailable: AtomicBool::new(false),
            corrupt_signature: false,
            calls: Arc::clone(&provider_calls),
        });
        let stale_policy_signers = PotrRuntimeSignersV1::try_new(
            gateway.clone(),
            provider.clone(),
            rotated_binding.clone(),
            provider_binding(fixture.admission_policy),
            admission_reader(&fixture.admission, fixture.admission_policy),
            fixture.gateway_key.verifying_key().to_bytes(),
            fixture.admission_policy,
        );
        assert_eq!(
            stale_policy_signers.expect_err("stale gateway policy must reject rotation at startup"),
            PotrRuntimeSignerConfigError::SignerBindingMismatch
        );
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
        let rotated_policy_signers = PotrRuntimeSignersV1::try_new(
            gateway,
            provider,
            rotated_binding,
            provider_binding(fixture.admission_policy),
            admission_reader(&fixture.admission, fixture.admission_policy),
            rotated_gateway.verifying_key().to_bytes(),
            fixture.admission_policy,
        )
        .expect("updated non-secret gateway policy");
        rotated_policy_signers
            .sign_receipt(fixture.receipt, None)
            .expect("gateway rotation succeeds after its independent policy update");
    }
}
