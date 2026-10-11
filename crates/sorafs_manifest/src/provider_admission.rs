#![allow(unexpected_cfgs)]
//! Provider admission schemas and validators for SoraFS.
//!
//! Governance-approved providers publish a `ProviderAdmissionProposalV1` capturing their
//! advertisement key, chunker profile, stake pointer, and attested endpoints. Councillors co-sign
//! the canonical digest inside a `ProviderAdmissionEnvelopeV1`, which Torii and gateways use to
//! authorise incoming `ProviderAdvertV1` payloads.
#[cfg(test)]
use crate::provider_advert::TransportProtocol;
use crate::{
    CouncilSignature, chunker_registry,
    provider_advert::{
        AdvertEndpoint, CapabilityTlv, CapabilityType, EndpointKind, PotrMldsaCapabilityError,
        PqCapabilityError, ProviderAdvertBodyV1, ProviderAdvertV1, ProviderCapabilityRangeV1,
        ProviderCapabilitySoranetPqV1, RangeCapabilityError, StakePointer, StreamBudgetError,
        StreamBudgetV1, TransportHintError, TransportHintV1, validate_potr_mldsa_capability,
    },
};
use blake3::Hasher;
use iroha_crypto::{Algorithm, PublicKey};
use norito::{
    core::Error as NoritoError,
    derive::{NoritoDeserialize, NoritoSerialize},
};
use std::{collections::BTreeSet, num::NonZeroUsize};
use thiserror::Error;
/// Current proposal schema version.
pub const PROVIDER_ADMISSION_PROPOSAL_VERSION_V1: u8 = 1;
/// Current envelope schema version.
pub const PROVIDER_ADMISSION_ENVELOPE_VERSION_V1: u8 = 1;
/// Endpoint attestation schema version.
pub const ENDPOINT_ATTESTATION_VERSION_V1: u8 = 1;
/// Admission renewal schema version.
pub const PROVIDER_ADMISSION_RENEWAL_VERSION_V1: u8 = 1;
/// Admission revocation schema version.
pub const PROVIDER_ADMISSION_REVOCATION_VERSION_V1: u8 = 1;
const PROPOSAL_DIGEST_DOMAIN: &[u8] = b"sorafs-provider-admission-v1";
const ADVERT_BODY_DIGEST_DOMAIN: &[u8] = b"sorafs-provider-advert-body-v1";
const ENVELOPE_AUTHORIZATION_DIGEST_DOMAIN: &[u8] = b"sorafs-provider-admission-authorization-v1";
const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"sorafs-provider-admission-envelope-v1";
const REVOCATION_DIGEST_DOMAIN: &[u8] = b"sorafs-provider-admission-revocation-v1";
/// Trusted council keys and quorum required to authorise provider admission changes.
///
/// Keys embedded in an envelope are never trust roots. The current local-key constructors are a
/// provisional admission boundary; production authorization requires an exact finalized
/// State/Kura council-policy projection matching the signed policy identity, revision, and digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAdmissionCouncilPolicy {
    trusted_signers: BTreeSet<[u8; 32]>,
    signature_threshold: NonZeroUsize,
}
impl ProviderAdmissionCouncilPolicy {
    /// Construct a council policy after validating every trusted Ed25519 key and the quorum.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderAdmissionCouncilPolicyError`] when the trust set is empty, contains a
    /// duplicate or malformed key, or the threshold is zero or exceeds the number of keys.
    pub fn new<I>(
        trusted_signers: I,
        signature_threshold: usize,
    ) -> Result<Self, ProviderAdmissionCouncilPolicyError>
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        let mut trusted = BTreeSet::new();
        for signer in trusted_signers {
            crate::checked_ed25519_verifying_key_from_bytes(&signer).map_err(|reason| {
                ProviderAdmissionCouncilPolicyError::InvalidPublicKey { signer, reason }
            })?;
            if !trusted.insert(signer) {
                return Err(ProviderAdmissionCouncilPolicyError::DuplicateSigner { signer });
            }
        }
        if trusted.is_empty() {
            return Err(ProviderAdmissionCouncilPolicyError::EmptyTrustedSigners);
        }
        let signature_threshold = NonZeroUsize::new(signature_threshold)
            .ok_or(ProviderAdmissionCouncilPolicyError::ZeroThreshold)?;
        if signature_threshold.get() > trusted.len() {
            return Err(
                ProviderAdmissionCouncilPolicyError::UnsatisfiableThreshold {
                    threshold: signature_threshold.get(),
                    trusted_signers: trusted.len(),
                },
            );
        }
        Ok(Self {
            trusted_signers: trusted,
            signature_threshold,
        })
    }
    /// Return whether the policy trusts the supplied canonical Ed25519 key.
    #[must_use]
    pub fn trusts(&self, signer: &[u8; 32]) -> bool {
        self.trusted_signers.contains(signer)
    }
    /// Return the number of distinct trusted council keys.
    #[must_use]
    pub fn trusted_signer_count(&self) -> usize {
        self.trusted_signers.len()
    }
    /// Return the number of distinct signatures required for authorisation.
    #[must_use]
    pub fn signature_threshold(&self) -> NonZeroUsize {
        self.signature_threshold
    }
}
/// Invalid provider-admission council policy configuration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProviderAdmissionCouncilPolicyError {
    /// No trust anchor was configured.
    #[error("provider admission council trust set must not be empty")]
    EmptyTrustedSigners,
    /// A configured trust anchor is not a canonical strong Ed25519 key.
    #[error("trusted council signer {signer:02x?} has invalid public key: {reason}")]
    InvalidPublicKey {
        /// Rejected raw key.
        signer: [u8; 32],
        /// Validation failure.
        reason: String,
    },
    /// A configured trust anchor was repeated.
    #[error("trusted council signer {signer:02x?} is configured more than once")]
    DuplicateSigner {
        /// Repeated raw key.
        signer: [u8; 32],
    },
    /// A zero signature quorum cannot authorise production admissions.
    #[error("provider admission council signature threshold must be non-zero")]
    ZeroThreshold,
    /// The requested quorum cannot be reached by the configured trust set.
    #[error(
        "provider admission council signature threshold {threshold} exceeds {trusted_signers} trusted signers"
    )]
    UnsatisfiableThreshold {
        /// Requested distinct signature count.
        threshold: usize,
        /// Available distinct trusted key count.
        trusted_signers: usize,
    },
}
/// Norito payload submitted by candidate storage providers.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_admission::ProviderAdmissionProposalV1")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct ProviderAdmissionProposalV1 {
    /// Schema version (`PROVIDER_ADMISSION_PROPOSAL_VERSION_V1`).
    pub version: u8,
    /// Governance-controlled provider identifier (BLAKE3-256 digest).
    pub provider_id: [u8; 32],
    /// Canonical chunker handle (`namespace.name@semver`).
    pub profile_id: String,
    /// Optional aliases recognised for negotiation.
    #[norito(default)]
    pub profile_aliases: Option<Vec<String>>,
    /// Stake pointer advertised by the provider.
    pub stake: StakePointer,
    /// Capability TLVs the provider intends to publish.
    pub capabilities: Vec<CapabilityTlv>,
    /// Endpoint bundle paired with attestations.
    pub endpoints: Vec<EndpointAdmissionV1>,
    /// Ed25519 advertisement public key.
    pub advert_key: [u8; 32],
    /// Council-approved BLS public key used for provider PoR VRF proofs.
    pub por_vrf_key: ProviderVrfPublicKeyV1,
    /// ISO-3166 alpha-2 jurisdiction code.
    pub jurisdiction_code: String,
    /// Optional contact URI (mailto:, https://, etc.).
    #[norito(default)]
    pub contact_uri: Option<String>,
    /// Optional stream budget advertised by the provider.
    #[norito(default)]
    pub stream_budget: Option<StreamBudgetV1>,
    /// Optional transport hints for ranged fetches.
    #[norito(default)]
    pub transport_hints: Option<Vec<TransportHintV1>>,
}
impl ProviderAdmissionProposalV1 {
    /// Validates the proposal against registry policy.
    pub fn validate(&self) -> Result<(), ProviderAdmissionValidationError> {
        if self.version != PROVIDER_ADMISSION_PROPOSAL_VERSION_V1 {
            return Err(
                ProviderAdmissionValidationError::UnsupportedProposalVersion {
                    found: self.version,
                },
            );
        }
        if self.provider_id.iter().all(|&byte| byte == 0) {
            return Err(ProviderAdmissionValidationError::InvalidProviderId);
        }
        if self.advert_key.iter().all(|&byte| byte == 0) {
            return Err(ProviderAdmissionValidationError::InvalidAdvertKey);
        }
        crate::checked_ed25519_verifying_key_from_bytes(&self.advert_key).map_err(|reason| {
            ProviderAdmissionValidationError::InvalidAdvertKeyMaterial { reason }
        })?;
        self.por_vrf_key.validate()?;
        let descriptor = chunker_registry::lookup_by_handle(&self.profile_id).ok_or(
            ProviderAdmissionValidationError::UnknownChunkerHandle {
                handle: self.profile_id.clone(),
            },
        )?;
        let canonical_handle = format!(
            "{}.{}@{}",
            descriptor.namespace, descriptor.name, descriptor.semver
        );
        if self.profile_id != canonical_handle {
            return Err(
                ProviderAdmissionValidationError::NonCanonicalProfileHandle {
                    provided: self.profile_id.clone(),
                    canonical: canonical_handle,
                },
            );
        }
        if let Some(aliases) = &self.profile_aliases {
            validate_aliases(aliases, descriptor)?;
        }
        if !self.stake.is_positive() {
            return Err(ProviderAdmissionValidationError::StakeAmountZero);
        }
        if self.capabilities.is_empty() {
            return Err(ProviderAdmissionValidationError::MissingCapabilities);
        }
        if self.endpoints.is_empty() {
            return Err(ProviderAdmissionValidationError::MissingEndpoints);
        }
        crate::provider_advert::account_read::RegisteredAccountReadV1::from_capabilities(
            &self.capabilities,
        )
        .map_err(|_| ProviderAdmissionValidationError::InvalidAccountReadCapability)?;
        let mut seen_range_capability = false;
        let mut seen_pq_capability = false;
        let mut seen_potr_mldsa_capability = false;
        for capability in &self.capabilities {
            if capability.cap_type == CapabilityType::ChunkRangeFetch {
                if seen_range_capability {
                    return Err(ProviderAdmissionValidationError::DuplicateRangeCapability);
                }
                let range_cap = ProviderCapabilityRangeV1::from_bytes(&capability.payload)
                    .map_err(|_| ProviderAdmissionValidationError::InvalidRangeCapabilityPayload)?;
                range_cap
                    .validate()
                    .map_err(ProviderAdmissionValidationError::InvalidRangeCapability)?;
                seen_range_capability = true;
                continue;
            }
            if capability.cap_type == CapabilityType::SoraNetHybridPq {
                if seen_pq_capability {
                    return Err(ProviderAdmissionValidationError::DuplicateSoranetPqCapability);
                }
                let pq_cap = ProviderCapabilitySoranetPqV1::from_bytes(&capability.payload)
                    .map_err(ProviderAdmissionValidationError::InvalidSoranetPqCapability)?;
                pq_cap
                    .validate()
                    .map_err(ProviderAdmissionValidationError::InvalidSoranetPqCapability)?;
                seen_pq_capability = true;
                continue;
            }
            if capability.cap_type == CapabilityType::PotrMlDsa {
                if seen_potr_mldsa_capability {
                    return Err(ProviderAdmissionValidationError::DuplicatePotrMldsaCapability);
                }
                validate_potr_mldsa_capability(&capability.payload)
                    .map_err(ProviderAdmissionValidationError::InvalidPotrMldsaCapability)?;
                seen_potr_mldsa_capability = true;
            }
        }
        validate_jurisdiction_code(&self.jurisdiction_code)?;
        if self
            .contact_uri
            .as_ref()
            .is_some_and(|uri| uri.trim().is_empty())
        {
            return Err(ProviderAdmissionValidationError::InvalidContactUri);
        }
        let mut has_stream_budget = false;
        if let Some(budget) = &self.stream_budget {
            has_stream_budget = true;
            budget
                .validate()
                .map_err(ProviderAdmissionValidationError::InvalidStreamBudget)?;
        }
        let mut has_transport_hints = false;
        if let Some(hints) = &self.transport_hints {
            if hints.is_empty() {
                return Err(ProviderAdmissionValidationError::EmptyTransportHints);
            }
            has_transport_hints = true;
            let mut seen = std::collections::HashSet::new();
            for hint in hints {
                hint.validate()
                    .map_err(ProviderAdmissionValidationError::InvalidTransportHint)?;
                if !seen.insert(hint.protocol) {
                    return Err(ProviderAdmissionValidationError::DuplicateTransportProtocol);
                }
            }
        }
        if (has_stream_budget || has_transport_hints) && !seen_range_capability {
            return Err(ProviderAdmissionValidationError::RangeMetadataWithoutCapability);
        }
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            endpoint.validate().map_err(|source| {
                ProviderAdmissionValidationError::EndpointInvalid { index, source }
            })?;
        }
        Ok(())
    }
    /// Computes the canonical BLAKE3 digest over the proposal payload.
    pub fn digest(&self) -> Result<[u8; 32], NoritoError> {
        compute_proposal_digest(self)
    }
}
/// Council-approved BLS public-key variant for provider PoR VRF proofs.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_admission::ProviderVrfPublicKeyV1")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub enum ProviderVrfPublicKeyV1 {
    /// Normal BLS: a 48-byte compressed G1 public key and 96-byte G2 proof.
    BlsNormal([u8; 48]),
    /// Small-signature BLS: a 96-byte compressed G2 public key and 48-byte G1 proof.
    BlsSmall([u8; 96]),
}
impl ProviderVrfPublicKeyV1 {
    /// Return the canonical compressed public-key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::BlsNormal(bytes) => bytes,
            Self::BlsSmall(bytes) => bytes,
        }
    }
    /// Validate the public key's length, curve encoding, subgroup, and identity.
    pub fn validate(&self) -> Result<(), ProviderAdmissionValidationError> {
        let valid = match self {
            Self::BlsNormal(bytes) => iroha_crypto::vrf::is_valid_normal_public_key_bytes(bytes),
            Self::BlsSmall(bytes) => iroha_crypto::vrf::is_valid_small_public_key_bytes(bytes),
        };
        if !valid {
            return Err(ProviderAdmissionValidationError::InvalidPorVrfKey);
        }
        Ok(())
    }
}
/// Endpoint record paired with its attestation.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_admission::EndpointAdmissionV1")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct EndpointAdmissionV1 {
    /// Advertised endpoint.
    pub endpoint: AdvertEndpoint,
    /// Admitted transport certificate material tied to the endpoint.
    pub attestation: EndpointAttestationV1,
}
impl EndpointAdmissionV1 {
    fn validate(&self) -> Result<(), EndpointAdmissionError> {
        if self.endpoint.host_pattern.trim().is_empty() {
            return Err(EndpointAdmissionError::EmptyHostPattern);
        }
        let expected_kind = match self.endpoint.kind {
            EndpointKind::Torii | EndpointKind::NoritoRpc => EndpointAttestationKind::Tls,
            EndpointKind::Quic => EndpointAttestationKind::Quic,
        };
        if self.attestation.kind != expected_kind {
            return Err(EndpointAdmissionError::KindMismatch {
                endpoint: self.endpoint.kind,
                attestation: self.attestation.kind,
                expected: expected_kind,
            });
        }
        self.attestation.validate()?;
        Ok(())
    }
}
/// Supported endpoint certificate-material kinds.
///
/// Signed admission authenticates the selected material. It does not establish a live
/// TLS handshake, current endpoint reachability or client certificate authentication.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_admission::EndpointAttestationKind")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointAttestationKind {
    /// X.509 server certificate material for TLS; client authentication is separate.
    Tls = 1,
    /// QUIC + TLS 1.3 certificate report.
    Quic = 2,
}
/// Certificate material and optional attestation evidence for a provider endpoint.
///
/// Structural validation checks this record's shape and validity interval. TLS clients
/// must still validate their selected root, server name and certificate lifetime at use.
/// This record grants no client authentication or current reachability guarantee.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_admission::EndpointAttestationV1")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct EndpointAttestationV1 {
    /// Schema version (`ENDPOINT_ATTESTATION_VERSION_V1`).
    pub version: u8,
    /// Transport attestation kind.
    pub kind: EndpointAttestationKind,
    /// Unix timestamp (seconds) when the attestation was generated.
    pub attested_at: u64,
    /// Unix timestamp (seconds) when the attestation expires.
    pub expires_at: u64,
    /// DER-encoded leaf certificate presented by the endpoint.
    pub leaf_certificate: Vec<u8>,
    /// Optional intermediate certificates (DER) required to build the chain.
    #[norito(default)]
    pub intermediate_certificates: Vec<Vec<u8>>,
    /// ALPN identifiers observed during attestation (e.g., `h2`, `h3`).
    #[norito(default)]
    pub alpn_ids: Vec<String>,
    /// Optional raw attestation transcript (e.g., TLS handshake, QUIC transport parameters).
    #[norito(default)]
    pub report: Vec<u8>,
}
impl EndpointAttestationV1 {
    fn validate(&self) -> Result<(), EndpointAttestationError> {
        if self.version != ENDPOINT_ATTESTATION_VERSION_V1 {
            return Err(EndpointAttestationError::UnsupportedVersion {
                found: self.version,
            });
        }
        if self.attested_at >= self.expires_at {
            return Err(EndpointAttestationError::InvalidValidity {
                attested_at: self.attested_at,
                expires_at: self.expires_at,
            });
        }
        if self.leaf_certificate.is_empty() {
            return Err(EndpointAttestationError::EmptyLeafCertificate);
        }
        for (index, cert) in self.intermediate_certificates.iter().enumerate() {
            if cert.is_empty() {
                return Err(EndpointAttestationError::EmptyIntermediateCertificate { index });
            }
        }
        for alpn in &self.alpn_ids {
            if alpn.trim().is_empty() {
                return Err(EndpointAttestationError::EmptyAlpn);
            }
        }
        Ok(())
    }
}
/// Network-independent provider material authenticated only by its containing signed genesis.
/// Constructing or decoding this template does not establish provider admission authority.
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq, norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_admission::ProviderAdmissionGenesisMaterialV1")]
pub struct ProviderAdmissionGenesisMaterialV1 {
    /// Canonical provider proposal.
    pub proposal: ProviderAdmissionProposalV1,
    /// Exact advertisement body admitted by genesis.
    pub advert_body: ProviderAdvertBodyV1,
    /// Beginning of admission validity in Unix seconds.
    pub issued_at: u64,
    /// Exclusive end of admission validity in Unix seconds.
    pub retention_epoch: u64,
}
impl ProviderAdmissionGenesisMaterialV1 {
    /// Validate material without claiming that signed genesis authorized it.
    pub fn validate(&self) -> Result<(), ProviderAdmissionValidationError> {
        self.proposal.validate()?;
        compare_core_fields(&self.proposal, &self.advert_body)?;
        if self.issued_at >= self.retention_epoch {
            return Err(ProviderAdmissionValidationError::InvalidRetentionEpoch {
                issued_at: self.issued_at,
                retention_epoch: self.retention_epoch,
            });
        }
        Ok(())
    }
    /// Build the unsigned, network-bound material projection retained by native admission.
    /// Its empty council signatures deliberately prevent use as a council-approved envelope.
    pub fn project(
        &self,
        network_id: [u8; 32],
        policy_id: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<ProviderAdmissionEnvelopeV1, ProviderAdmissionEnvelopeError> {
        self.validate()
            .map_err(ProviderAdmissionEnvelopeError::Validation)?;
        if network_id == [0; 32] || policy_id == [0; 32] || policy_digest == [0; 32] {
            return Err(ProviderAdmissionEnvelopeError::Validation(
                ProviderAdmissionValidationError::InvalidPolicyBinding,
            ));
        }
        Ok(ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id,
            policy_id,
            policy_revision: 1,
            policy_digest,
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal: self.proposal.clone(),
            proposal_digest: compute_proposal_digest(&self.proposal).map_err(|source| {
                ProviderAdmissionEnvelopeError::Serialization {
                    context: ProviderAdmissionSerializationContext::GenesisProposal,
                    source,
                }
            })?,
            advert_body: self.advert_body.clone(),
            advert_body_digest: compute_advert_body_digest(&self.advert_body).map_err(
                |source| ProviderAdmissionEnvelopeError::Serialization {
                    context: ProviderAdmissionSerializationContext::GenesisAdvert,
                    source,
                },
            )?,
            issued_at: self.issued_at,
            retention_epoch: self.retention_epoch,
            council_signatures: Vec::new(),
            notes: None,
        })
    }
}
/// Governance envelope binding proposals, adverts, and council signatures.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_admission::ProviderAdmissionEnvelopeV1")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct ProviderAdmissionEnvelopeV1 {
    /// Schema version (`PROVIDER_ADMISSION_ENVELOPE_VERSION_V1`).
    pub version: u8,
    /// Exact genesis block-header hash identifying the network for this council approval.
    pub network_id: [u8; 32],
    /// Claimed identity of the council policy, covered by the signature but requiring finalized
    /// State/Kura verification before production authorization.
    pub policy_id: [u8; 32],
    /// Monotonic revision of that council policy.
    pub policy_revision: u64,
    /// Digest of the exact council policy claimed by this signed event.
    pub policy_digest: [u8; 32],
    /// Monotonic admission-event revision, starting at one.
    pub admission_revision: u64,
    /// Exact current admission-event digest expected by this transition; absent at admission.
    pub expected_current_event_digest: Option<[u8; 32]>,
    /// Canonical proposal bundle.
    pub proposal: ProviderAdmissionProposalV1,
    /// BLAKE3 digest of the canonical proposal payload.
    pub proposal_digest: [u8; 32],
    /// Provider advertisement body that must match the active gossip payload.
    pub advert_body: ProviderAdvertBodyV1,
    /// BLAKE3 digest of the canonical advertisement body.
    pub advert_body_digest: [u8; 32],
    /// Unix timestamp (seconds) when governance approved the envelope.
    pub issued_at: u64,
    /// Unix timestamp (seconds) through which this admission remains valid.
    pub retention_epoch: u64,
    /// Council signatures authorising the admission bundle.
    pub council_signatures: Vec<CouncilSignature>,
    /// Optional free-form notes for governance rotation metadata.
    #[norito(default)]
    pub notes: Option<String>,
}
impl ProviderAdmissionEnvelopeV1 {
    /// Validates structural invariants and digest bindings.
    pub fn validate(&self) -> Result<(), ProviderAdmissionValidationError> {
        if self.version != PROVIDER_ADMISSION_ENVELOPE_VERSION_V1 {
            return Err(
                ProviderAdmissionValidationError::UnsupportedEnvelopeVersion {
                    found: self.version,
                },
            );
        }
        if self.network_id == [0; 32] {
            return Err(ProviderAdmissionValidationError::InvalidNetworkId);
        }
        if self.policy_id == [0; 32] || self.policy_digest == [0; 32] || self.policy_revision == 0 {
            return Err(ProviderAdmissionValidationError::InvalidPolicyBinding);
        }
        if self.admission_revision == 0
            || (self.admission_revision == 1 && self.expected_current_event_digest.is_some())
            || (self.admission_revision > 1
                && self
                    .expected_current_event_digest
                    .is_none_or(|digest| digest == [0; 32]))
        {
            return Err(ProviderAdmissionValidationError::InvalidEventLineage);
        }
        self.proposal.validate()?;
        let expected_proposal_digest =
            compute_proposal_digest(&self.proposal).map_err(|source| {
                ProviderAdmissionValidationError::SerializationError {
                    context: ProviderAdmissionSerializationContext::Proposal,
                    source,
                }
            })?;
        if self.proposal_digest != expected_proposal_digest {
            return Err(ProviderAdmissionValidationError::ProposalDigestMismatch);
        }
        let expected_advert_digest =
            compute_advert_body_digest(&self.advert_body).map_err(|source| {
                ProviderAdmissionValidationError::SerializationError {
                    context: ProviderAdmissionSerializationContext::AdvertBody,
                    source,
                }
            })?;
        if self.advert_body_digest != expected_advert_digest {
            return Err(ProviderAdmissionValidationError::AdvertDigestMismatch);
        }
        if self.council_signatures.is_empty() {
            return Err(ProviderAdmissionValidationError::MissingCouncilSignatures);
        }
        if self.issued_at > self.retention_epoch {
            return Err(ProviderAdmissionValidationError::InvalidRetentionEpoch {
                issued_at: self.issued_at,
                retention_epoch: self.retention_epoch,
            });
        }
        compare_core_fields(&self.proposal, &self.advert_body)?;
        Ok(())
    }
}
fn compare_core_fields(
    proposal: &ProviderAdmissionProposalV1,
    advert_body: &ProviderAdvertBodyV1,
) -> Result<(), ProviderAdmissionValidationError> {
    if proposal.provider_id != advert_body.provider_id {
        return Err(ProviderAdmissionValidationError::FieldMismatch {
            field: "provider_id",
        });
    }
    if proposal.profile_id != advert_body.profile_id {
        return Err(ProviderAdmissionValidationError::FieldMismatch {
            field: "profile_id",
        });
    }
    if proposal.profile_aliases.as_ref() != advert_body.profile_aliases.as_ref() {
        return Err(ProviderAdmissionValidationError::FieldMismatch {
            field: "profile_aliases",
        });
    }
    if proposal.stake != advert_body.stake {
        return Err(ProviderAdmissionValidationError::FieldMismatch { field: "stake" });
    }
    if proposal.capabilities != advert_body.capabilities {
        return Err(ProviderAdmissionValidationError::FieldMismatch {
            field: "capabilities",
        });
    }
    let proposal_endpoints: Vec<AdvertEndpoint> = proposal
        .endpoints
        .iter()
        .map(|entry| entry.endpoint.clone())
        .collect();
    if proposal_endpoints != advert_body.endpoints {
        return Err(ProviderAdmissionValidationError::FieldMismatch { field: "endpoints" });
    }
    if proposal.stream_budget.as_ref() != advert_body.stream_budget.as_ref() {
        return Err(ProviderAdmissionValidationError::FieldMismatch {
            field: "stream_budget",
        });
    }
    if proposal.transport_hints.as_ref() != advert_body.transport_hints.as_ref() {
        return Err(ProviderAdmissionValidationError::FieldMismatch {
            field: "transport_hints",
        });
    }
    Ok(())
}
fn validate_aliases(
    aliases: &[String],
    descriptor: &'static chunker_registry::ChunkerProfileDescriptor,
) -> Result<(), ProviderAdmissionValidationError> {
    if aliases.is_empty() {
        return Err(ProviderAdmissionValidationError::InvalidProfileAliases);
    }
    if aliases.iter().any(|alias| alias.trim() != alias) {
        return Err(ProviderAdmissionValidationError::InvalidProfileAliases);
    }
    let expected: std::collections::BTreeSet<_> = descriptor
        .aliases
        .iter()
        .map(|alias| alias.to_string())
        .collect();
    let provided: std::collections::BTreeSet<_> =
        aliases.iter().map(|alias| alias.to_owned()).collect();
    if provided.iter().any(|alias| alias.is_empty()) {
        return Err(ProviderAdmissionValidationError::InvalidProfileAliases);
    }
    if !provided.contains(descriptor.aliases[0]) {
        return Err(ProviderAdmissionValidationError::MissingCanonicalAlias {
            canonical: descriptor.aliases[0].to_owned(),
        });
    }
    for alias in &provided {
        if !expected.contains(alias) {
            return Err(ProviderAdmissionValidationError::UnknownProfileAlias {
                alias: alias.clone(),
            });
        }
    }
    Ok(())
}
fn validate_jurisdiction_code(code: &str) -> Result<(), ProviderAdmissionValidationError> {
    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(ProviderAdmissionValidationError::InvalidJurisdictionCode {
            code: code.to_owned(),
        });
    }
    Ok(())
}
/// Computes the proposal digest using BLAKE3 with an admission-specific domain separator.
pub fn compute_proposal_digest(
    proposal: &ProviderAdmissionProposalV1,
) -> Result<[u8; 32], NoritoError> {
    let bytes = norito::encode_canonical(proposal)?;
    let mut hasher = Hasher::new();
    hasher.update(PROPOSAL_DIGEST_DOMAIN);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
/// Computes the advertisement body digest using the admission domain separator.
pub fn compute_advert_body_digest(
    advert_body: &ProviderAdvertBodyV1,
) -> Result<[u8; 32], NoritoError> {
    let bytes = norito::encode_canonical(advert_body)?;
    let mut hasher = Hasher::new();
    hasher.update(ADVERT_BODY_DIGEST_DOMAIN);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
/// Computes the digest council members sign to authorise an admission envelope.
///
/// The digest covers every envelope field except the signatures themselves, including validity
/// bounds, the complete provider advert body, and governance notes. Callers should compute this
/// digest while `council_signatures` is empty, sign it, then attach signatures in ascending signer
/// key order.
pub fn compute_envelope_authorization_digest(
    envelope: &ProviderAdmissionEnvelopeV1,
) -> Result<[u8; 32], NoritoError> {
    let mut unsigned_envelope = envelope.clone();
    unsigned_envelope.council_signatures.clear();
    let bytes = norito::encode_canonical(&unsigned_envelope)?;
    let mut hasher = Hasher::new();
    hasher.update(ENVELOPE_AUTHORIZATION_DIGEST_DOMAIN);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
/// Computes the canonical digest for an admission envelope.
pub fn compute_envelope_digest(
    envelope: &ProviderAdmissionEnvelopeV1,
) -> Result<[u8; 32], NoritoError> {
    let bytes = norito::encode_canonical(envelope)?;
    let mut hasher = Hasher::new();
    hasher.update(ENVELOPE_DIGEST_DOMAIN);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
/// Admission registry entry produced from a verified envelope.
#[derive(Debug, Clone)]
pub struct AdmissionRecord {
    /// Governance envelope authorising the provider advert.
    envelope: ProviderAdmissionEnvelopeV1,
    /// Canonical digest of the provider advert body.
    advert_body_digest: [u8; 32],
    /// Canonical digest of the governance envelope.
    envelope_digest: [u8; 32],
    trust: AdmissionRecordTrust,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionRecordTrust {
    CouncilVerified,
    UntrustedSigners,
    GenesisMaterial,
}
impl AdmissionRecord {
    /// Construct an integrity-checked genesis material projection, without authenticating genesis.
    /// Only a caller that verifies the exact containing signed genesis and current native
    /// admission/owner/revocation state may use this value for production admission.
    pub fn from_genesis_material(
        material: &ProviderAdmissionGenesisMaterialV1,
        network_id: [u8; 32],
        policy_id: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<Self, ProviderAdmissionEnvelopeError> {
        let envelope = material.project(network_id, policy_id, policy_digest)?;
        let advert_body_digest = envelope.advert_body_digest;
        Self::from_verified_envelope(
            envelope,
            advert_body_digest,
            AdmissionRecordTrust::GenesisMaterial,
        )
    }
    /// Whether the record contains structurally valid signed-genesis material.
    /// This does not prove genesis membership or provide standalone authorization.
    #[must_use]
    pub fn is_genesis_material(&self) -> bool {
        self.trust == AdmissionRecordTrust::GenesisMaterial
    }
    /// Verify signed material selected by an authoritative retained admission head.
    ///
    /// Unlike initial admission, a retained head can name a renewal. This only authenticates
    /// material: the caller must independently prove the current finalized head, its lineage,
    /// policy and revocation status. A caller-supplied digest is not admission authority.
    pub fn from_retained_envelope(
        envelope: ProviderAdmissionEnvelopeV1,
        policy: &ProviderAdmissionCouncilPolicy,
        expected_digest: [u8; 32],
    ) -> Result<Self, ProviderAdmissionEnvelopeError> {
        let advert_body_digest = verify_envelope(&envelope, policy)?;
        let envelope_digest = compute_envelope_digest(&envelope).map_err(|source| {
            ProviderAdmissionEnvelopeError::Serialization {
                context: ProviderAdmissionSerializationContext::RetainedEnvelope,
                source,
            }
        })?;
        if envelope_digest != expected_digest {
            return Err(ProviderAdmissionEnvelopeError::Validation(
                ProviderAdmissionValidationError::FieldMismatch {
                    field: "retained envelope digest",
                },
            ));
        }
        Ok(Self {
            envelope,
            advert_body_digest,
            envelope_digest,
            trust: AdmissionRecordTrust::CouncilVerified,
        })
    }
    /// Constructs a verified admission record under the configured council trust policy.
    pub fn new(
        envelope: ProviderAdmissionEnvelopeV1,
        policy: &ProviderAdmissionCouncilPolicy,
    ) -> Result<Self, ProviderAdmissionEnvelopeError> {
        let advert_digest = verify_envelope(&envelope, policy)?;
        Self::from_verified_envelope(
            envelope,
            advert_digest,
            AdmissionRecordTrust::CouncilVerified,
        )
    }
    /// Constructs an integrity-checked record without establishing signer trust.
    ///
    /// This is reserved for reference validators and offline fixture tooling. Production
    /// admission decisions must use [`Self::new`].
    pub fn new_untrusted_signers(
        envelope: ProviderAdmissionEnvelopeV1,
    ) -> Result<Self, ProviderAdmissionEnvelopeError> {
        let advert_digest = verify_envelope_untrusted_signers(&envelope)?;
        Self::from_verified_envelope(
            envelope,
            advert_digest,
            AdmissionRecordTrust::UntrustedSigners,
        )
    }
    fn from_verified_envelope(
        envelope: ProviderAdmissionEnvelopeV1,
        advert_digest: [u8; 32],
        trust: AdmissionRecordTrust,
    ) -> Result<Self, ProviderAdmissionEnvelopeError> {
        if envelope.admission_revision != 1 {
            return Err(ProviderAdmissionEnvelopeError::NonInitialEvent {
                revision: envelope.admission_revision,
            });
        }
        let envelope_digest = compute_envelope_digest(&envelope).map_err(|err| {
            ProviderAdmissionEnvelopeError::Serialization {
                context: ProviderAdmissionSerializationContext::Envelope,
                source: err,
            }
        })?;
        Ok(Self {
            envelope,
            advert_body_digest: advert_digest,
            envelope_digest,
            trust,
        })
    }
    /// Returns the immutable admission material projection. Genesis projections have no council signatures.
    #[must_use]
    pub fn envelope(&self) -> &ProviderAdmissionEnvelopeV1 {
        &self.envelope
    }
    /// Returns the canonical digest of the admitted provider advert body.
    #[must_use]
    pub fn advert_body_digest(&self) -> &[u8; 32] {
        &self.advert_body_digest
    }
    /// Whether this record was established under a configured council trust policy.
    ///
    /// Integrity-only records created for reference fixtures deliberately return
    /// `false` and must never authorize production provider operations.
    #[must_use]
    pub fn is_council_verified(&self) -> bool {
        self.trust == AdmissionRecordTrust::CouncilVerified
    }
    /// Returns the provider identifier associated with this record.
    #[must_use]
    pub fn provider_id(&self) -> &[u8; 32] {
        &self.envelope.proposal.provider_id
    }
    /// Returns the admission-approved advert key.
    #[must_use]
    pub fn advert_key(&self) -> &[u8; 32] {
        &self.envelope.proposal.advert_key
    }
    /// Returns the council-approved provider PoR VRF public key.
    #[must_use]
    pub fn por_vrf_key(&self) -> &ProviderVrfPublicKeyV1 {
        &self.envelope.proposal.por_vrf_key
    }
    /// Returns the council-approved ML-DSA-65 key used for PoTR receipts.
    ///
    /// Absence means the provider is not authorised to emit production PoTR
    /// receipts, even when another admission capability is present.
    #[must_use]
    pub fn potr_mldsa_key(&self) -> Option<&[u8]> {
        self.envelope
            .proposal
            .capabilities
            .iter()
            .find(|capability| capability.cap_type == CapabilityType::PotrMlDsa)
            .map(|capability| capability.payload.as_slice())
    }
    /// Returns the canonical envelope digest.
    #[must_use]
    pub fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope_digest
    }
    /// Apply a governance-approved renewal and return the updated admission record.
    pub fn apply_renewal(
        &self,
        renewal: &ProviderAdmissionRenewalV1,
        policy: &ProviderAdmissionCouncilPolicy,
    ) -> Result<Self, ProviderAdmissionRenewalError> {
        if !self.is_council_verified() {
            return Err(ProviderAdmissionRenewalError::UntrustedBaseRecord);
        }
        self.apply_renewal_inner(
            renewal,
            |envelope| verify_envelope(envelope, policy),
            AdmissionRecordTrust::CouncilVerified,
        )
    }
    /// Apply a renewal after checking signatures cryptographically without establishing trust.
    ///
    /// This is reserved for reference validators and offline fixture tooling. Production
    /// admission decisions must use [`Self::apply_renewal`].
    pub fn apply_renewal_untrusted_signers(
        &self,
        renewal: &ProviderAdmissionRenewalV1,
    ) -> Result<Self, ProviderAdmissionRenewalError> {
        self.apply_renewal_inner(
            renewal,
            verify_envelope_untrusted_signers,
            AdmissionRecordTrust::UntrustedSigners,
        )
    }
    fn apply_renewal_inner<F>(
        &self,
        renewal: &ProviderAdmissionRenewalV1,
        verify: F,
        trust: AdmissionRecordTrust,
    ) -> Result<Self, ProviderAdmissionRenewalError>
    where
        F: FnOnce(&ProviderAdmissionEnvelopeV1) -> Result<[u8; 32], ProviderAdmissionEnvelopeError>,
    {
        if renewal.version != PROVIDER_ADMISSION_RENEWAL_VERSION_V1 {
            return Err(ProviderAdmissionRenewalError::UnsupportedVersion {
                found: renewal.version,
            });
        }
        if renewal.provider_id != *self.provider_id() {
            return Err(ProviderAdmissionRenewalError::ProviderMismatch {
                renewal: renewal.provider_id,
                record: *self.provider_id(),
            });
        }
        let expected_prev = *self.envelope_digest();
        if renewal.previous_envelope_digest != expected_prev {
            return Err(ProviderAdmissionRenewalError::PreviousDigestMismatch {
                expected: expected_prev,
                provided: renewal.previous_envelope_digest,
            });
        }
        if renewal.envelope.expected_current_event_digest != Some(expected_prev) {
            return Err(ProviderAdmissionRenewalError::SignedPredecessorMismatch);
        }
        if self.envelope.admission_revision.checked_add(1)
            != Some(renewal.envelope.admission_revision)
        {
            return Err(ProviderAdmissionRenewalError::AdmissionRevisionMismatch);
        }
        if renewal.envelope.policy_id != self.envelope.policy_id
            || renewal.envelope.policy_revision != self.envelope.policy_revision
            || renewal.envelope.policy_digest != self.envelope.policy_digest
        {
            return Err(ProviderAdmissionRenewalError::PolicyLineageMismatch);
        }
        if renewal.envelope.network_id != self.envelope.network_id {
            return Err(ProviderAdmissionRenewalError::NetworkMismatch {
                expected: self.envelope.network_id,
                provided: renewal.envelope.network_id,
            });
        }
        let computed_digest = compute_envelope_digest(&renewal.envelope).map_err(|err| {
            ProviderAdmissionRenewalError::Envelope(ProviderAdmissionEnvelopeError::Serialization {
                context: ProviderAdmissionSerializationContext::Envelope,
                source: err,
            })
        })?;
        if computed_digest != renewal.envelope_digest {
            return Err(ProviderAdmissionRenewalError::EnvelopeDigestMismatch {
                expected: renewal.envelope_digest,
                computed: computed_digest,
            });
        }
        if renewal.envelope.proposal.provider_id != renewal.provider_id {
            return Err(ProviderAdmissionRenewalError::ProviderMismatch {
                renewal: renewal.envelope.proposal.provider_id,
                record: renewal.provider_id,
            });
        }
        let new_advert_digest = verify(&renewal.envelope)?;
        if renewal.envelope.proposal.profile_id != self.envelope.proposal.profile_id {
            return Err(ProviderAdmissionRenewalError::ProfileIdChanged {
                previous: self.envelope.proposal.profile_id.clone(),
                updated: renewal.envelope.proposal.profile_id.clone(),
            });
        }
        if renewal.envelope.proposal.profile_aliases != self.envelope.proposal.profile_aliases {
            return Err(ProviderAdmissionRenewalError::ProfileAliasesChanged);
        }
        if renewal.envelope.advert_body.capabilities != self.envelope.advert_body.capabilities {
            return Err(ProviderAdmissionRenewalError::CapabilitiesChanged);
        }
        if renewal.envelope.proposal.advert_key != self.envelope.proposal.advert_key {
            return Err(ProviderAdmissionRenewalError::AdvertKeyChanged);
        }
        if renewal.envelope.proposal.por_vrf_key != self.envelope.proposal.por_vrf_key {
            return Err(ProviderAdmissionRenewalError::PorVrfKeyChanged);
        }
        if renewal.envelope.retention_epoch < self.envelope.retention_epoch {
            return Err(ProviderAdmissionRenewalError::RetentionNotExtended {
                previous: self.envelope.retention_epoch,
                updated: renewal.envelope.retention_epoch,
            });
        }
        if renewal.envelope.issued_at < self.envelope.issued_at {
            return Err(ProviderAdmissionRenewalError::IssuedAtRegression {
                previous: self.envelope.issued_at,
                updated: renewal.envelope.issued_at,
            });
        }
        Ok(Self {
            envelope: renewal.envelope.clone(),
            advert_body_digest: new_advert_digest,
            envelope_digest: computed_digest,
            trust,
        })
    }
    /// Verify a governance revocation record against this admission entry.
    pub fn verify_revocation(
        &self,
        revocation: &ProviderAdmissionRevocationV1,
        policy: &ProviderAdmissionCouncilPolicy,
    ) -> Result<(), ProviderAdmissionRevocationError> {
        self.verify_revocation_inner(revocation, |revocation| {
            verify_revocation_signatures(revocation, policy)
        })
    }
    /// Verify revocation integrity without establishing signer trust.
    ///
    /// This is reserved for reference validators and offline fixture tooling. Production
    /// admission decisions must use [`Self::verify_revocation`].
    pub fn verify_revocation_untrusted_signers(
        &self,
        revocation: &ProviderAdmissionRevocationV1,
    ) -> Result<(), ProviderAdmissionRevocationError> {
        self.verify_revocation_inner(revocation, verify_revocation_signatures_untrusted_signers)
    }
    fn verify_revocation_inner<F>(
        &self,
        revocation: &ProviderAdmissionRevocationV1,
        verify: F,
    ) -> Result<(), ProviderAdmissionRevocationError>
    where
        F: FnOnce(
            &ProviderAdmissionRevocationV1,
        ) -> Result<[u8; 32], ProviderAdmissionRevocationError>,
    {
        if revocation.provider_id != *self.provider_id() {
            return Err(ProviderAdmissionRevocationError::ProviderMismatch {
                revocation: revocation.provider_id,
                record: *self.provider_id(),
            });
        }
        if revocation.envelope_digest != *self.envelope_digest() {
            return Err(ProviderAdmissionRevocationError::EnvelopeDigestMismatch {
                expected: *self.envelope_digest(),
                provided: revocation.envelope_digest,
            });
        }
        if revocation.expected_current_event_digest != *self.envelope_digest() {
            return Err(ProviderAdmissionRevocationError::SignedPredecessorMismatch);
        }
        if self.envelope.admission_revision.checked_add(1) != Some(revocation.transition_revision) {
            return Err(ProviderAdmissionRevocationError::AdmissionRevisionMismatch);
        }
        if revocation.policy_id != self.envelope.policy_id
            || revocation.policy_revision != self.envelope.policy_revision
            || revocation.policy_digest != self.envelope.policy_digest
        {
            return Err(ProviderAdmissionRevocationError::PolicyLineageMismatch);
        }
        if revocation.network_id != self.envelope.network_id {
            return Err(ProviderAdmissionRevocationError::NetworkMismatch {
                expected: self.envelope.network_id,
                provided: revocation.network_id,
            });
        }
        verify(revocation)?;
        Ok(())
    }
}
/// Verifies an admission envelope against the configured council trust policy.
pub fn verify_envelope(
    envelope: &ProviderAdmissionEnvelopeV1,
    policy: &ProviderAdmissionCouncilPolicy,
) -> Result<[u8; 32], ProviderAdmissionEnvelopeError> {
    envelope
        .validate()
        .map_err(ProviderAdmissionEnvelopeError::Validation)?;
    let digest = compute_envelope_authorization_digest(envelope).map_err(|source| {
        ProviderAdmissionEnvelopeError::Serialization {
            context: ProviderAdmissionSerializationContext::EnvelopeAuthorization,
            source,
        }
    })?;
    verify_council_signatures_over_digest(&envelope.council_signatures, &digest, policy)
        .map_err(ProviderAdmissionEnvelopeError::Signature)?;
    Ok(envelope.advert_body_digest)
}
/// Verifies envelope integrity without establishing that any signer is trusted.
///
/// This API exists for language-neutral reference validators and deterministic fixture tools.
/// It must not be used to authorise a provider in a node, gateway, or registry.
pub fn verify_envelope_untrusted_signers(
    envelope: &ProviderAdmissionEnvelopeV1,
) -> Result<[u8; 32], ProviderAdmissionEnvelopeError> {
    envelope
        .validate()
        .map_err(ProviderAdmissionEnvelopeError::Validation)?;
    let digest = compute_envelope_authorization_digest(envelope).map_err(|source| {
        ProviderAdmissionEnvelopeError::Serialization {
            context: ProviderAdmissionSerializationContext::EnvelopeAuthorization,
            source,
        }
    })?;
    verify_council_signatures_without_trust(&envelope.council_signatures, &digest)
        .map_err(ProviderAdmissionEnvelopeError::Signature)?;
    Ok(envelope.advert_body_digest)
}
/// Validates that a provider advert matches the governance admission record.
pub fn verify_advert_against_record(
    advert: &ProviderAdvertV1,
    record: &AdmissionRecord,
) -> Result<(), ProviderAdmissionAdvertError> {
    if advert.network_id != record.envelope.network_id {
        return Err(ProviderAdmissionAdvertError::NetworkMismatch {
            expected: record.envelope.network_id,
            provided: advert.network_id,
        });
    }
    if advert.body != record.envelope.advert_body {
        return Err(ProviderAdmissionAdvertError::BodyMismatch);
    }
    if advert.signature.public_key.as_slice() != record.advert_key() {
        return Err(ProviderAdmissionAdvertError::AdvertKeyMismatch);
    }
    let digest =
        compute_advert_body_digest(&advert.body).map_err(ProviderAdmissionAdvertError::Digest)?;
    if digest != record.advert_body_digest {
        return Err(ProviderAdmissionAdvertError::BodyDigestMismatch {
            expected: record.advert_body_digest,
            computed: digest,
        });
    }
    if advert.expires_at > record.envelope.retention_epoch {
        return Err(ProviderAdmissionAdvertError::ExpiryAfterRetention {
            expires_at: advert.expires_at,
            retention_epoch: record.envelope.retention_epoch,
        });
    }
    Ok(())
}
pub(crate) fn verify_council_signatures_over_digest(
    signatures: &[CouncilSignature],
    digest: &[u8; 32],
    policy: &ProviderAdmissionCouncilPolicy,
) -> Result<(), ProviderAdmissionSignatureError> {
    if signatures.len() > policy.trusted_signer_count() {
        return Err(ProviderAdmissionSignatureError::TooManySignatures {
            provided: signatures.len(),
            trusted_signers: policy.trusted_signer_count(),
        });
    }
    verify_council_signatures_inner(signatures, digest, Some(policy))?;
    if signatures.len() < policy.signature_threshold().get() {
        return Err(ProviderAdmissionSignatureError::ThresholdNotMet {
            required: policy.signature_threshold().get(),
            verified: signatures.len(),
        });
    }
    Ok(())
}
pub(crate) fn verify_council_signatures_without_trust(
    signatures: &[CouncilSignature],
    digest: &[u8; 32],
) -> Result<(), ProviderAdmissionSignatureError> {
    verify_council_signatures_inner(signatures, digest, None)
}
fn verify_council_signatures_inner(
    signatures: &[CouncilSignature],
    digest: &[u8; 32],
    policy: Option<&ProviderAdmissionCouncilPolicy>,
) -> Result<(), ProviderAdmissionSignatureError> {
    let mut previous_signer = None;
    for signature in signatures {
        if previous_signer == Some(signature.signer) {
            return Err(ProviderAdmissionSignatureError::DuplicateSigner {
                signer: signature.signer,
            });
        }
        if previous_signer.is_some_and(|previous| previous > signature.signer) {
            return Err(ProviderAdmissionSignatureError::NonCanonicalSignerOrder);
        }
        previous_signer = Some(signature.signer);
        if signature.signature.len() != 64 {
            return Err(ProviderAdmissionSignatureError::InvalidLength {
                signer: signature.signer,
                length: signature.signature.len(),
            });
        }
        crate::checked_ed25519_verifying_key_from_bytes(&signature.signer).map_err(|reason| {
            ProviderAdmissionSignatureError::InvalidPublicKey {
                signer: signature.signer,
                reason,
            }
        })?;
        if policy.is_some_and(|policy| !policy.trusts(&signature.signer)) {
            return Err(ProviderAdmissionSignatureError::UntrustedSigner {
                signer: signature.signer,
            });
        }
        let signature_bytes: [u8; ed25519_dalek::SIGNATURE_LENGTH] =
            signature.signature.as_slice().try_into().map_err(|err| {
                ProviderAdmissionSignatureError::Verification {
                    signer: signature.signer,
                    reason: format!("invalid signature material: {err}"),
                }
            })?;
        crate::checked_ed25519_signature_from_bytes(&signature_bytes).map_err(|reason| {
            ProviderAdmissionSignatureError::Verification {
                signer: signature.signer,
                reason,
            }
        })?;
        let public_key =
            PublicKey::from_bytes(Algorithm::Ed25519, &signature.signer).map_err(|err| {
                ProviderAdmissionSignatureError::InvalidPublicKey {
                    signer: signature.signer,
                    reason: err.to_string(),
                }
            })?;
        let sig = iroha_crypto::ed25519_parse_signature(&signature.signature).map_err(|err| {
            ProviderAdmissionSignatureError::Verification {
                signer: signature.signer,
                reason: format!("invalid signature material: {err}"),
            }
        })?;
        sig.verify(&public_key, digest).map_err(|err| {
            ProviderAdmissionSignatureError::Verification {
                signer: signature.signer,
                reason: err.to_string(),
            }
        })?;
    }
    Ok(())
}
/// Canonical admission value whose serialization was refused.
///
/// The closed set keeps diagnostics inline beside their original codec cause;
/// constructing an error never needs a new allocation for its context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderAdmissionSerializationContext {
    /// Initial proposal in a genesis admission.
    GenesisProposal,
    /// Initial advert in a genesis admission.
    GenesisAdvert,
    /// Provider admission proposal.
    Proposal,
    /// Provider advertisement body.
    AdvertBody,
    /// Authenticated retained admission envelope.
    RetainedEnvelope,
    /// Provider admission envelope.
    Envelope,
    /// Council-signed envelope authorization preimage.
    EnvelopeAuthorization,
}
impl std::fmt::Display for ProviderAdmissionSerializationContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::GenesisProposal => "genesis proposal",
            Self::GenesisAdvert => "genesis advert",
            Self::Proposal => "proposal",
            Self::AdvertBody => "advert_body",
            Self::RetainedEnvelope => "retained envelope",
            Self::Envelope => "envelope",
            Self::EnvelopeAuthorization => "envelope authorization",
        })
    }
}
/// Errors raised during proposal and envelope validation.
#[derive(Debug, Error)]
pub enum ProviderAdmissionValidationError {
    #[error("unsupported proposal version {found}")]
    UnsupportedProposalVersion { found: u8 },
    #[error("unsupported envelope version {found}")]
    UnsupportedEnvelopeVersion { found: u8 },
    #[error("provider admission network id must be the nonzero genesis block-header hash")]
    InvalidNetworkId,
    #[error("provider admission policy id, revision, and digest must be nonzero")]
    InvalidPolicyBinding,
    #[error(
        "provider admission revision and expected current event digest have invalid lineage shape"
    )]
    InvalidEventLineage,
    #[error("provider id must be non-zero")]
    InvalidProviderId,
    #[error("advertisement key must be non-zero")]
    InvalidAdvertKey,
    #[error("advertisement key must be a canonical strong Ed25519 key: {reason}")]
    InvalidAdvertKeyMaterial { reason: String },
    #[error("PoR VRF key must be a canonical non-identity BLS public key for its variant")]
    InvalidPorVrfKey,
    #[error("chunker handle `{handle}` is not registered")]
    UnknownChunkerHandle { handle: String },
    #[error("profile handle `{provided}` is not canonical (expected `{canonical}`)")]
    NonCanonicalProfileHandle { provided: String, canonical: String },
    #[error("profile aliases must include canonical handle")]
    MissingCanonicalAlias { canonical: String },
    #[error("profile aliases contain an invalid entry")]
    InvalidProfileAliases,
    #[error("profile alias `{alias}` is not recognised by the registry")]
    UnknownProfileAlias { alias: String },
    #[error("stake amount must be greater than zero")]
    StakeAmountZero,
    #[error("capabilities list must not be empty")]
    MissingCapabilities,
    #[error("endpoint list must not be empty")]
    MissingEndpoints,
    #[error("jurisdiction code must be uppercase ISO 3166-1 alpha-2: `{code}`")]
    InvalidJurisdictionCode { code: String },
    #[error("contact URI must not be empty when provided")]
    InvalidContactUri,
    #[error("range capability payload missing or malformed")]
    InvalidRangeCapabilityPayload,
    #[error("range capability payload invalid: {0}")]
    InvalidRangeCapability(RangeCapabilityError),
    #[error("duplicate range capability TLV detected")]
    DuplicateRangeCapability,
    #[error("duplicate soranet_pq capability TLV detected")]
    DuplicateSoranetPqCapability,
    #[error("soranet_pq capability invalid: {0}")]
    InvalidSoranetPqCapability(#[source] PqCapabilityError),
    #[error("duplicate PoTR ML-DSA capability TLV detected")]
    DuplicatePotrMldsaCapability,
    #[error("registered-account read capability is duplicate or invalid")]
    InvalidAccountReadCapability,
    #[error("PoTR ML-DSA capability invalid: {0}")]
    InvalidPotrMldsaCapability(#[source] PotrMldsaCapabilityError),
    #[error("stream budget or transport hints require chunk_range_fetch capability")]
    RangeMetadataWithoutCapability,
    #[error("stream budget invalid: {0}")]
    InvalidStreamBudget(StreamBudgetError),
    #[error("transport hints must not be empty when provided")]
    EmptyTransportHints,
    #[error("transport hints must have unique protocols")]
    DuplicateTransportProtocol,
    #[error("transport hint invalid: {0}")]
    InvalidTransportHint(TransportHintError),
    #[error("endpoint #{index} validation failed: {source}")]
    EndpointInvalid {
        index: usize,
        #[source]
        source: EndpointAdmissionError,
    },
    #[error("proposal digest does not match canonical encoding")]
    ProposalDigestMismatch,
    #[error("advert body digest does not match canonical encoding")]
    AdvertDigestMismatch,
    #[error("validation failed to serialize {context} for digest computation: {source}")]
    SerializationError {
        context: ProviderAdmissionSerializationContext,
        #[source]
        source: NoritoError,
    },
    #[error("council signatures list must not be empty")]
    MissingCouncilSignatures,
    #[error("issued_at ({issued_at}) must be <= retention_epoch ({retention_epoch})")]
    InvalidRetentionEpoch {
        issued_at: u64,
        retention_epoch: u64,
    },
    #[error("proposal and advert mismatch on field `{field}`")]
    FieldMismatch { field: &'static str },
}
#[cfg(test)]
impl PartialEq for ProviderAdmissionValidationError {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
            && self.to_string() == other.to_string()
    }
}
#[cfg(test)]
impl Eq for ProviderAdmissionValidationError {}
/// Errors surfaced while verifying admission envelopes.
#[derive(Debug, Error)]
pub enum ProviderAdmissionEnvelopeError {
    #[error("admission revision {revision} requires its exact signed predecessor event")]
    NonInitialEvent { revision: u64 },
    #[error("envelope validation failed: {0}")]
    Validation(#[source] ProviderAdmissionValidationError),
    #[error("council signature validation failed: {0}")]
    Signature(#[source] ProviderAdmissionSignatureError),
    #[error("failed to serialize {context}: {source}")]
    Serialization {
        context: ProviderAdmissionSerializationContext,
        #[source]
        source: NoritoError,
    },
}
/// Errors surfaced when verifying council signatures.
#[derive(Debug, Error)]
pub enum ProviderAdmissionSignatureError {
    #[error("council signer {signer:02x?} has invalid public key: {reason}")]
    InvalidPublicKey { signer: [u8; 32], reason: String },
    #[error("council signer {signer:02x?} is not trusted by provider admission policy")]
    UntrustedSigner { signer: [u8; 32] },
    #[error("council signer {signer:02x?} appears more than once")]
    DuplicateSigner { signer: [u8; 32] },
    #[error("council signatures must be ordered by ascending signer key")]
    NonCanonicalSignerOrder,
    #[error(
        "council signature list has {provided} entries but policy contains only {trusted_signers} trusted signers"
    )]
    TooManySignatures {
        provided: usize,
        trusted_signers: usize,
    },
    #[error(
        "council signature threshold not met: required {required} distinct trusted signatures, verified {verified}"
    )]
    ThresholdNotMet { required: usize, verified: usize },
    #[error("council signature for signer {signer:02x?} has invalid length {length}")]
    InvalidLength { signer: [u8; 32], length: usize },
    #[error("council signature verification failed for signer {signer:02x?}: {reason}")]
    Verification { signer: [u8; 32], reason: String },
}
/// Errors surfaced when verifying provider adverts against governance records.
#[derive(Debug, Error)]
pub enum ProviderAdmissionAdvertError {
    #[error("advert network id {provided:02x?} differs from admission network {expected:02x?}")]
    NetworkMismatch {
        expected: [u8; 32],
        provided: [u8; 32],
    },
    #[error("failed to compute advert digest: {0}")]
    Digest(#[source] NoritoError),
    #[error("advert body does not match governance envelope")]
    BodyMismatch,
    #[error("advert body digest mismatch (expected {expected:02x?}, computed {computed:02x?})")]
    BodyDigestMismatch {
        expected: [u8; 32],
        computed: [u8; 32],
    },
    #[error("advert signature public key does not match governance record")]
    AdvertKeyMismatch,
    #[error(
        "advert expires at {expires_at} which exceeds registry retention epoch {retention_epoch}"
    )]
    ExpiryAfterRetention {
        expires_at: u64,
        retention_epoch: u64,
    },
}
/// Governance-approved renewal of a provider admission envelope.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_admission::ProviderAdmissionRenewalV1")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct ProviderAdmissionRenewalV1 {
    /// Schema version (`PROVIDER_ADMISSION_RENEWAL_VERSION_V1`).
    pub version: u8,
    /// Provider identifier being renewed.
    pub provider_id: [u8; 32],
    /// Digest of the previously approved envelope.
    pub previous_envelope_digest: [u8; 32],
    /// Digest of the new governance envelope.
    pub envelope_digest: [u8; 32],
    /// Renewed governance envelope (with updated stake/endpoints as needed).
    pub envelope: ProviderAdmissionEnvelopeV1,
    /// Optional governance notes (rotation ticket, incident reference, etc.).
    #[norito(default)]
    pub notes: Option<String>,
}
impl ProviderAdmissionRenewalV1 {
    /// Returns the provider identifier associated with this renewal.
    #[must_use]
    pub fn provider_id(&self) -> &[u8; 32] {
        &self.provider_id
    }
}
/// Errors surfaced when applying a provider admission renewal.
#[derive(Debug, Error)]
pub enum ProviderAdmissionRenewalError {
    #[error("renewal network id {provided:02x?} differs from admission network {expected:02x?}")]
    NetworkMismatch {
        expected: [u8; 32],
        provided: [u8; 32],
    },
    #[error("council-verified renewal requires a council-verified base admission record")]
    UntrustedBaseRecord,
    #[error("unsupported renewal version {found}")]
    UnsupportedVersion { found: u8 },
    #[error("renewal envelope validation failed: {0}")]
    Envelope(#[from] ProviderAdmissionEnvelopeError),
    #[error(
        "renewal envelope digest mismatch (expected {expected:02x?}, computed {computed:02x?})"
    )]
    EnvelopeDigestMismatch {
        expected: [u8; 32],
        computed: [u8; 32],
    },
    #[error(
        "previous envelope digest mismatch (expected {expected:02x?}, provided {provided:02x?})"
    )]
    PreviousDigestMismatch {
        expected: [u8; 32],
        provided: [u8; 32],
    },
    #[error("renewal outer predecessor differs from the council-signed expected current event")]
    SignedPredecessorMismatch,
    #[error("renewal admission revision is not the next revision")]
    AdmissionRevisionMismatch,
    #[error("renewal council policy binding differs from the active admission")]
    PolicyLineageMismatch,
    #[error("provider id mismatch between renewal ({renewal:02x?}) and record ({record:02x?})")]
    ProviderMismatch { renewal: [u8; 32], record: [u8; 32] },
    #[error("profile id changed from `{previous}` to `{updated}` during renewal")]
    ProfileIdChanged { previous: String, updated: String },
    #[error("profile aliases changed during renewal")]
    ProfileAliasesChanged,
    #[error("capabilities changed during renewal")]
    CapabilitiesChanged,
    #[error("advert key changed during renewal")]
    AdvertKeyChanged,
    #[error("PoR VRF key changed during renewal without a new council admission")]
    PorVrfKeyChanged,
    #[error("retention epoch must not decrease (previous {previous}, updated {updated})")]
    RetentionNotExtended { previous: u64, updated: u64 },
    #[error("issued_at must not decrease (previous {previous}, updated {updated})")]
    IssuedAtRegression { previous: u64, updated: u64 },
}
/// Governance-approved revocation of an admission envelope.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_admission::ProviderAdmissionRevocationV1")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct ProviderAdmissionRevocationV1 {
    /// Schema version (`PROVIDER_ADMISSION_REVOCATION_VERSION_V1`).
    pub version: u8,
    /// Exact genesis block-header hash covered by the council revocation signature.
    pub network_id: [u8; 32],
    /// Identity of the enacted council policy claimed by this signed event.
    pub policy_id: [u8; 32],
    /// Monotonic revision of that council policy.
    pub policy_revision: u64,
    /// Digest of the exact council policy claimed by this signed event.
    pub policy_digest: [u8; 32],
    /// Next admission-event revision consumed by this terminal transition.
    pub transition_revision: u64,
    /// Exact current admission-event digest expected by this revocation.
    pub expected_current_event_digest: [u8; 32],
    /// Provider identifier being revoked.
    pub provider_id: [u8; 32],
    /// Digest of the envelope being revoked.
    pub envelope_digest: [u8; 32],
    /// Unix timestamp (seconds) when governance issued the revocation.
    pub revoked_at: u64,
    /// Human-readable reason for the revocation.
    pub reason: String,
    /// Council signatures authorising the revocation.
    pub council_signatures: Vec<CouncilSignature>,
    /// Optional governance notes (incident tracker, remediation steps, etc.).
    #[norito(default)]
    pub notes: Option<String>,
}
/// Errors surfaced when verifying a revocation record.
#[derive(Debug, Error)]
pub enum ProviderAdmissionRevocationError {
    #[error("unsupported revocation version {found}")]
    UnsupportedVersion { found: u8 },
    #[error("provider admission revocation network id must be nonzero")]
    InvalidNetworkId,
    #[error("provider admission revocation policy id, revision, and digest must be nonzero")]
    InvalidPolicyBinding,
    #[error("provider admission revocation event lineage must be nonzero")]
    InvalidEventLineage,
    #[error("revocation network id {provided:02x?} differs from admission network {expected:02x?}")]
    NetworkMismatch {
        expected: [u8; 32],
        provided: [u8; 32],
    },
    #[error(
        "provider id mismatch between revocation ({revocation:02x?}) and record ({record:02x?})"
    )]
    ProviderMismatch {
        revocation: [u8; 32],
        record: [u8; 32],
    },
    #[error("reason must not be empty")]
    ReasonEmpty,
    #[error("revocation requires at least one council signature")]
    MissingSignatures,
    #[error("revocation signature verification failed: {0}")]
    Signature(#[source] ProviderAdmissionSignatureError),
    #[error("failed to serialize revocation body: {0}")]
    Serialization(#[from] NoritoError),
    #[error("envelope digest mismatch (expected {expected:02x?}, provided {provided:02x?})")]
    EnvelopeDigestMismatch {
        expected: [u8; 32],
        provided: [u8; 32],
    },
    #[error("revocation signed expected current event differs from the active admission")]
    SignedPredecessorMismatch,
    #[error("revocation transition revision is not the next admission revision")]
    AdmissionRevisionMismatch,
    #[error("revocation council policy binding differs from the active admission")]
    PolicyLineageMismatch,
}
impl ProviderAdmissionRevocationV1 {
    /// Validate the revocation's structural fields and require signature material.
    ///
    /// This check does not authenticate council signers. Admission decisions must
    /// still use [`verify_revocation_signatures`] with the active trust policy.
    ///
    /// # Errors
    /// Rejects an unsupported version, missing network, policy or event bindings,
    /// an empty reason, or absent council signatures.
    pub fn validate(&self) -> Result<(), ProviderAdmissionRevocationError> {
        if self.version != PROVIDER_ADMISSION_REVOCATION_VERSION_V1 {
            return Err(ProviderAdmissionRevocationError::UnsupportedVersion {
                found: self.version,
            });
        }
        if self.network_id == [0; 32] {
            return Err(ProviderAdmissionRevocationError::InvalidNetworkId);
        }
        if self.policy_id == [0; 32] || self.policy_digest == [0; 32] || self.policy_revision == 0 {
            return Err(ProviderAdmissionRevocationError::InvalidPolicyBinding);
        }
        if self.transition_revision == 0 || self.expected_current_event_digest == [0; 32] {
            return Err(ProviderAdmissionRevocationError::InvalidEventLineage);
        }
        if self.reason.trim().is_empty() {
            return Err(ProviderAdmissionRevocationError::ReasonEmpty);
        }
        if self.council_signatures.is_empty() {
            return Err(ProviderAdmissionRevocationError::MissingSignatures);
        }
        Ok(())
    }

    /// Computes the canonical digest signed by council members.
    pub fn digest(&self) -> Result<[u8; 32], NoritoError> {
        #[derive(NoritoSerialize, norito::NoritoSchema)]
        #[norito_schema(
            name = "sorafs_manifest::provider_admission::ProviderAdmissionRevocationV1::digest::RevocationBody"
        )]
        struct RevocationBody<'a> {
            version: u8,
            network_id: [u8; 32],
            policy_id: [u8; 32],
            policy_revision: u64,
            policy_digest: [u8; 32],
            transition_revision: u64,
            expected_current_event_digest: [u8; 32],
            provider_id: [u8; 32],
            envelope_digest: [u8; 32],
            revoked_at: u64,
            reason: &'a str,
            #[norito(default)]
            notes: Option<&'a str>,
        }
        let body = RevocationBody {
            version: self.version,
            network_id: self.network_id,
            policy_id: self.policy_id,
            policy_revision: self.policy_revision,
            policy_digest: self.policy_digest,
            transition_revision: self.transition_revision,
            expected_current_event_digest: self.expected_current_event_digest,
            provider_id: self.provider_id,
            envelope_digest: self.envelope_digest,
            revoked_at: self.revoked_at,
            reason: self.reason.as_str(),
            notes: self.notes.as_deref(),
        };
        let bytes = norito::encode_canonical(&body)?;
        let mut hasher = Hasher::new();
        hasher.update(REVOCATION_DIGEST_DOMAIN);
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}
/// Verify revocation signatures under the configured council trust policy and return its digest.
pub fn verify_revocation_signatures(
    revocation: &ProviderAdmissionRevocationV1,
    policy: &ProviderAdmissionCouncilPolicy,
) -> Result<[u8; 32], ProviderAdmissionRevocationError> {
    verify_revocation_signatures_inner(revocation, |signatures, digest| {
        verify_council_signatures_over_digest(signatures, digest, policy)
    })
}
/// Verify revocation integrity without establishing that any signer is trusted.
///
/// This API exists for reference validators and deterministic fixture tools. Production
/// admission decisions must use [`verify_revocation_signatures`].
pub fn verify_revocation_signatures_untrusted_signers(
    revocation: &ProviderAdmissionRevocationV1,
) -> Result<[u8; 32], ProviderAdmissionRevocationError> {
    verify_revocation_signatures_inner(revocation, verify_council_signatures_without_trust)
}
fn verify_revocation_signatures_inner<F>(
    revocation: &ProviderAdmissionRevocationV1,
    verify: F,
) -> Result<[u8; 32], ProviderAdmissionRevocationError>
where
    F: FnOnce(&[CouncilSignature], &[u8; 32]) -> Result<(), ProviderAdmissionSignatureError>,
{
    revocation.validate()?;
    let digest = revocation.digest()?;
    verify(&revocation.council_signatures, &digest)
        .map_err(ProviderAdmissionRevocationError::Signature)?;
    Ok(digest)
}
/// Errors surfaced when validating endpoint admission records.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EndpointAdmissionError {
    #[error("endpoint host pattern must not be empty")]
    EmptyHostPattern,
    #[error(
        "endpoint kind {endpoint:?} requires {expected:?} attestation but found {attestation:?}"
    )]
    KindMismatch {
        endpoint: EndpointKind,
        attestation: EndpointAttestationKind,
        expected: EndpointAttestationKind,
    },
    #[error(transparent)]
    Attestation(#[from] EndpointAttestationError),
}
/// Errors surfaced when validating endpoint attestation payloads.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EndpointAttestationError {
    #[error("unsupported attestation version {found}")]
    UnsupportedVersion { found: u8 },
    #[error(
        "attestation validity window is invalid (attested_at={attested_at}, expires_at={expires_at})"
    )]
    InvalidValidity { attested_at: u64, expires_at: u64 },
    #[error("leaf certificate must not be empty")]
    EmptyLeafCertificate,
    #[error("intermediate certificate at index {index} must not be empty")]
    EmptyIntermediateCertificate { index: usize },
    #[error("ALPN identifier must not be empty")]
    EmptyAlpn,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdvertSignature, PROVIDER_ADVERT_VERSION_V1, SignatureAlgorithm,
        provider_advert::{
            AvailabilityTier, CapabilityType, PathDiversityPolicy, ProviderCapabilityRangeV1,
            QosHints, RendezvousTopic,
        },
    };
    use ed25519_dalek::{Signer, SigningKey};
    const SMALL_ORDER_R: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const NONCANONICAL_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    #[test]
    fn admission_serialization_errors_preserve_context_and_original_source() {
        use std::error::Error as _;
        for (context, label) in [
            (
                ProviderAdmissionSerializationContext::GenesisProposal,
                "genesis proposal",
            ),
            (
                ProviderAdmissionSerializationContext::GenesisAdvert,
                "genesis advert",
            ),
            (ProviderAdmissionSerializationContext::Proposal, "proposal"),
            (
                ProviderAdmissionSerializationContext::AdvertBody,
                "advert_body",
            ),
            (
                ProviderAdmissionSerializationContext::RetainedEnvelope,
                "retained envelope",
            ),
            (ProviderAdmissionSerializationContext::Envelope, "envelope"),
            (
                ProviderAdmissionSerializationContext::EnvelopeAuthorization,
                "envelope authorization",
            ),
        ] {
            let resource = norito::core::DecodeResourceError::AllocationFailed { bytes: 97 };
            let error = ProviderAdmissionRenewalError::Envelope(
                ProviderAdmissionEnvelopeError::Validation(
                    ProviderAdmissionValidationError::SerializationError {
                        context,
                        source: resource.into(),
                    },
                ),
            );
            assert_eq!(context.to_string(), label);
            assert_eq!(
                error.to_string(),
                format!(
                    "renewal envelope validation failed: envelope validation failed: validation failed to serialize {label} for digest computation: {}",
                    NoritoError::from(resource),
                )
            );
            let ProviderAdmissionRenewalError::Envelope(
                ProviderAdmissionEnvelopeError::Validation(
                    ProviderAdmissionValidationError::SerializationError { source, .. },
                ),
            ) = &error
            else {
                panic!("original typed validation cause")
            };
            let returned = error
                .source()
                .expect("envelope")
                .source()
                .expect("validation")
                .source()
                .expect("original codec")
                .downcast_ref::<NoritoError>()
                .expect("typed codec cause");
            assert!(core::ptr::eq(returned, source));
            assert_eq!(returned.decode_resource_error(), Some(resource));

            let error = ProviderAdmissionEnvelopeError::Serialization {
                context,
                source: resource.into(),
            };
            assert_eq!(
                error.to_string(),
                format!(
                    "failed to serialize {label}: {}",
                    NoritoError::from(resource)
                )
            );
            assert_eq!(
                error
                    .source()
                    .expect("codec")
                    .downcast_ref::<NoritoError>()
                    .expect("typed codec cause")
                    .decode_resource_error(),
                Some(resource)
            );
        }
        let error = ProviderAdmissionEnvelopeError::Signature(
            ProviderAdmissionSignatureError::ThresholdNotMet {
                required: 3,
                verified: 2,
            },
        );
        let ProviderAdmissionEnvelopeError::Signature(source) = &error else {
            panic!("signature cause")
        };
        assert!(core::ptr::eq(
            error
                .source()
                .expect("signature")
                .downcast_ref::<ProviderAdmissionSignatureError>()
                .expect("typed signature cause"),
            source
        ));
    }
    fn council_signature() -> CouncilSignature {
        CouncilSignature {
            signer: [0xAA; 32],
            signature: vec![0x55; 64],
        }
    }
    fn sample_endpoint() -> (EndpointAdmissionV1, AdvertEndpoint) {
        let endpoint = AdvertEndpoint {
            kind: EndpointKind::Torii,
            host_pattern: "storage.example.com".to_owned(),
            metadata: vec![],
        };
        let attestation = EndpointAttestationV1 {
            version: ENDPOINT_ATTESTATION_VERSION_V1,
            kind: EndpointAttestationKind::Tls,
            attested_at: 1,
            expires_at: 1 + 86_400,
            leaf_certificate: vec![0x01, 0x02, 0x03],
            intermediate_certificates: vec![vec![0x04, 0x05]],
            alpn_ids: vec!["h2".to_owned()],
            report: vec![0x10, 0x11],
        };
        (
            EndpointAdmissionV1 {
                endpoint: endpoint.clone(),
                attestation,
            },
            endpoint,
        )
    }
    #[test]
    fn tls_endpoint_material_has_one_canonical_kind_and_frame() {
        assert_eq!(EndpointAttestationKind::Tls as u8, 1);
        assert_eq!(EndpointAttestationKind::Quic as u8, 2);
        for kind in [EndpointAttestationKind::Tls, EndpointAttestationKind::Quic] {
            let frame = norito::encode_canonical(&kind).unwrap();
            let decoded = norito::decode_from_bytes::<EndpointAttestationKind>(&frame).unwrap();
            assert_eq!(decoded, kind);
            assert_eq!(norito::encode_canonical(&decoded).unwrap(), frame);
        }
        // This is structural codec evidence, not a certificate or handshake fixture.
        let (mut endpoint, _) = sample_endpoint();
        endpoint.attestation.report.clear();
        endpoint.validate().unwrap();
        let frame = norito::encode_canonical(&endpoint).unwrap();
        let decoded = norito::decode_from_bytes::<EndpointAdmissionV1>(&frame).unwrap();
        assert_eq!(decoded, endpoint);
        assert_eq!(decoded.attestation.kind, EndpointAttestationKind::Tls);
        assert_eq!(norito::encode_canonical(&decoded).unwrap(), frame);
    }

    #[test]
    fn endpoint_certificate_kind_must_match_selected_transport() {
        for transport in [
            EndpointKind::Torii,
            EndpointKind::NoritoRpc,
            EndpointKind::Quic,
        ] {
            let (mut endpoint, _) = sample_endpoint();
            endpoint.endpoint.kind = transport;
            let expected = match transport {
                EndpointKind::Torii | EndpointKind::NoritoRpc => EndpointAttestationKind::Tls,
                EndpointKind::Quic => EndpointAttestationKind::Quic,
            };
            endpoint.attestation.kind = expected;
            endpoint.validate().unwrap();
            let other = match expected {
                EndpointAttestationKind::Tls => EndpointAttestationKind::Quic,
                EndpointAttestationKind::Quic => EndpointAttestationKind::Tls,
            };
            endpoint.attestation.kind = other;
            assert_eq!(
                endpoint.validate(),
                Err(EndpointAdmissionError::KindMismatch {
                    endpoint: transport,
                    attestation: other,
                    expected,
                })
            );
        }
    }

    fn sample_capability() -> CapabilityTlv {
        CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: vec![],
        }
    }
    fn sample_range_capability() -> CapabilityTlv {
        CapabilityTlv {
            cap_type: CapabilityType::ChunkRangeFetch,
            payload: ProviderCapabilityRangeV1 {
                max_chunk_span: 32,
                min_granularity: 8,
                supports_sparse_offsets: true,
                requires_alignment: false,
                supports_merkle_proof: true,
            }
            .to_bytes()
            .expect("encode range capability"),
        }
    }
    fn sample_vrf_key() -> ProviderVrfPublicKeyV1 {
        let (public, private) =
            iroha_crypto::BlsNormal::try_keypair(iroha_crypto::KeyGenOption::UseSeed(vec![
                0x34;
                32
            ]))
            .expect("fixture BLS keypair");
        let pair: iroha_crypto::KeyPair = (public, private).into();
        ProviderVrfPublicKeyV1::BlsNormal(
            pair.public_key()
                .to_bytes()
                .1
                .try_into()
                .expect("Normal BLS public key is 48 bytes"),
        )
    }
    fn sample_proposal() -> ProviderAdmissionProposalV1 {
        let descriptor =
            chunker_registry::lookup_by_handle("sorafs.sf1@1.0.0").expect("registered profile");
        let aliases: Vec<String> = descriptor
            .aliases
            .iter()
            .map(|alias| alias.to_string())
            .collect();
        let (endpoint_entry, _) = sample_endpoint();
        ProviderAdmissionProposalV1 {
            version: PROVIDER_ADMISSION_PROPOSAL_VERSION_V1,
            provider_id: [0x11; 32],
            profile_id: "sorafs.sf1@1.0.0".to_owned(),
            profile_aliases: Some(aliases),
            stake: StakePointer {
                pool_id: [0x22; 32],
                stake_amount: crate::deal::XorQuantity::try_from_micro(5_000)
                    .expect("fixture stake is representable"),
            },
            capabilities: vec![sample_capability(), sample_range_capability()],
            endpoints: vec![endpoint_entry],
            advert_key: [0x33; 32],
            por_vrf_key: sample_vrf_key(),
            jurisdiction_code: "JP".to_owned(),
            contact_uri: Some("mailto:ops@example.com".to_owned()),
            stream_budget: Some(StreamBudgetV1 {
                max_in_flight: 6,
                max_bytes_per_sec: 8_000_000,
                burst_bytes: Some(4_000_000),
            }),
            transport_hints: Some(vec![TransportHintV1 {
                protocol: TransportProtocol::ToriiHttpRange,
                priority: 0,
            }]),
        }
    }
    fn advert_body_from_proposal(proposal: &ProviderAdmissionProposalV1) -> ProviderAdvertBodyV1 {
        let (_, endpoint) = sample_endpoint();
        ProviderAdvertBodyV1 {
            provider_id: proposal.provider_id,
            profile_id: proposal.profile_id.clone(),
            profile_aliases: proposal.profile_aliases.clone(),
            stake: proposal.stake.clone(),
            qos: QosHints {
                availability: AvailabilityTier::Hot,
                max_retrieval_latency_ms: 1_500,
                max_concurrent_streams: 32,
            },
            capabilities: proposal.capabilities.clone(),
            endpoints: vec![endpoint],
            rendezvous_topics: vec![RendezvousTopic {
                topic: "sorafs.sf1.primary".to_owned(),
                region: "global".to_owned(),
            }],
            path_policy: PathDiversityPolicy {
                min_guard_weight: 10,
                max_same_asn_per_path: 1,
                max_same_pool_per_path: 1,
            },
            notes: None,
            stream_budget: proposal.stream_budget,
            transport_hints: proposal.transport_hints.clone(),
        }
    }
    fn sample_advert_body() -> ProviderAdvertBodyV1 {
        let proposal = sample_proposal();
        advert_body_from_proposal(&proposal)
    }
    fn council_signature_from_key(key: &SigningKey, digest: &[u8; 32]) -> CouncilSignature {
        let signature = key.sign(digest);
        CouncilSignature {
            signer: *key.verifying_key().as_bytes(),
            signature: signature.to_bytes().to_vec(),
        }
    }
    fn council_policy(keys: &[&SigningKey], threshold: usize) -> ProviderAdmissionCouncilPolicy {
        ProviderAdmissionCouncilPolicy::new(
            keys.iter().map(|key| *key.verifying_key().as_bytes()),
            threshold,
        )
        .expect("valid council policy")
    }
    fn sign_envelope(envelope: &mut ProviderAdmissionEnvelopeV1, keys: &[&SigningKey]) {
        envelope.council_signatures.clear();
        let digest =
            compute_envelope_authorization_digest(envelope).expect("envelope authorization digest");
        envelope.council_signatures = keys
            .iter()
            .map(|key| council_signature_from_key(key, &digest))
            .collect();
        envelope
            .council_signatures
            .sort_unstable_by_key(|signature| signature.signer);
    }
    fn signed_sample_envelope(keys: &[&SigningKey]) -> ProviderAdmissionEnvelopeV1 {
        let proposal = sample_proposal();
        let advert_body = advert_body_from_proposal(&proposal);
        let proposal_digest = compute_proposal_digest(&proposal).expect("proposal digest");
        let advert_body_digest =
            compute_advert_body_digest(&advert_body).expect("advert body digest");
        let mut envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal,
            proposal_digest,
            advert_body,
            advert_body_digest,
            issued_at: 10,
            retention_epoch: 100,
            council_signatures: Vec::new(),
            notes: None,
        };
        sign_envelope(&mut envelope, keys);
        envelope
    }
    #[test]
    fn genesis_material_is_canonical_and_never_a_council_envelope() {
        let mut proposal = sample_proposal();
        proposal.advert_key = SigningKey::from_bytes(&[0x21; 32])
            .verifying_key()
            .to_bytes();
        let material = ProviderAdmissionGenesisMaterialV1 {
            advert_body: advert_body_from_proposal(&proposal),
            proposal,
            issued_at: 1000,
            retention_epoch: 2000,
        };
        material.validate().unwrap();
        let bytes = norito::encode_canonical(&material).unwrap();
        assert_eq!(
            norito::decode_canonical::<ProviderAdmissionGenesisMaterialV1>(&bytes).unwrap(),
            material
        );
        let record =
            AdmissionRecord::from_genesis_material(&material, [1; 32], [2; 32], [3; 32]).unwrap();
        assert!(record.is_genesis_material());
        assert!(!record.is_council_verified());
        assert!(verify_envelope_untrusted_signers(record.envelope()).is_err());
        let other =
            AdmissionRecord::from_genesis_material(&material, [4; 32], [2; 32], [3; 32]).unwrap();
        assert_ne!(record.envelope_digest(), other.envelope_digest());
        let mut invalid = material;
        invalid.advert_body.provider_id = [9; 32];
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn retained_envelope_checks_the_exact_selected_digest_and_council() {
        let key = SigningKey::from_bytes(&[0xa9; 32]);
        let policy = council_policy(&[&key], 1);
        let mut envelope = signed_sample_envelope(&[&key]);
        envelope.admission_revision = 2;
        envelope.expected_current_event_digest = Some([0xab; 32]);
        sign_envelope(&mut envelope, &[&key]);
        let digest = compute_envelope_digest(&envelope).unwrap();
        assert!(AdmissionRecord::new(envelope.clone(), &policy).is_err());
        assert_eq!(
            AdmissionRecord::from_retained_envelope(envelope.clone(), &policy, digest)
                .unwrap()
                .envelope(),
            &envelope
        );
        assert!(
            AdmissionRecord::from_retained_envelope(envelope.clone(), &policy, [0; 32]).is_err()
        );
        let other = SigningKey::from_bytes(&[0xaa; 32]);
        assert!(
            AdmissionRecord::from_retained_envelope(
                envelope,
                &council_policy(&[&other], 1),
                digest
            )
            .is_err()
        );
    }
    fn sign_advert(key: &SigningKey, advert: &mut ProviderAdvertV1) {
        advert.signature = AdvertSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: key.verifying_key().as_bytes().to_vec(),
            signature: vec![0; 64],
        };
        let payload = advert
            .signature_payload_bytes()
            .expect("encode advert signature envelope");
        advert.signature.signature = key.sign(&payload).to_bytes().to_vec();
    }
    #[test]
    fn admission_record_provenance_survives_clone_and_cannot_be_upgraded_by_renewal() {
        let council_key = SigningKey::from_bytes(&[0xA9; 32]);
        let policy = council_policy(&[&council_key], 1);
        let base_envelope = signed_sample_envelope(&[&council_key]);
        let trusted = AdmissionRecord::new(base_envelope.clone(), &policy).expect("trusted record");
        let untrusted = AdmissionRecord::new_untrusted_signers(base_envelope.clone())
            .expect("integrity-only record");
        assert!(trusted.is_council_verified());
        assert!(trusted.clone().is_council_verified());
        assert!(!untrusted.is_council_verified());
        assert!(!untrusted.clone().is_council_verified());
        let mut renewed_envelope = base_envelope;
        renewed_envelope.issued_at += 1;
        renewed_envelope.retention_epoch += 1;
        renewed_envelope.admission_revision = 2;
        renewed_envelope.expected_current_event_digest = Some(*trusted.envelope_digest());
        sign_envelope(&mut renewed_envelope, &[&council_key]);
        let renewal = ProviderAdmissionRenewalV1 {
            version: PROVIDER_ADMISSION_RENEWAL_VERSION_V1,
            provider_id: *trusted.provider_id(),
            previous_envelope_digest: *trusted.envelope_digest(),
            envelope_digest: compute_envelope_digest(&renewed_envelope)
                .expect("renewed envelope digest"),
            envelope: renewed_envelope,
            notes: None,
        };
        let renewed_trusted = trusted
            .apply_renewal(&renewal, &policy)
            .expect("governed renewal");
        assert!(renewed_trusted.is_council_verified());
        assert_eq!(renewed_trusted.envelope(), &renewal.envelope);
        let original_untrusted_digest = *untrusted.envelope_digest();
        assert!(matches!(
            untrusted.apply_renewal(&renewal, &policy),
            Err(ProviderAdmissionRenewalError::UntrustedBaseRecord)
        ));
        assert_eq!(*untrusted.envelope_digest(), original_untrusted_digest);
        let renewed_untrusted = untrusted
            .apply_renewal_untrusted_signers(&renewal)
            .expect("integrity-only renewal");
        assert!(!renewed_untrusted.is_council_verified());
        assert_eq!(renewed_untrusted.envelope(), &renewal.envelope);
    }
    #[test]
    fn compare_core_fields_detects_stream_budget_mismatch() {
        let proposal = sample_proposal();
        let mut advert = advert_body_from_proposal(&proposal);
        advert.stream_budget = None;
        let err = compare_core_fields(&proposal, &advert).unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionValidationError::FieldMismatch { field }
                if field == "stream_budget"
        ));
    }
    #[test]
    fn compare_core_fields_detects_transport_hint_mismatch() {
        let proposal = sample_proposal();
        let mut advert = advert_body_from_proposal(&proposal);
        advert.transport_hints = None;
        let err = compare_core_fields(&proposal, &advert).unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionValidationError::FieldMismatch { field }
                if field == "transport_hints"
        ));
    }
    #[test]
    fn proposal_rejects_duplicate_transport_protocols() {
        let mut proposal = sample_proposal();
        proposal.transport_hints = Some(vec![
            TransportHintV1 {
                protocol: TransportProtocol::ToriiHttpRange,
                priority: 0,
            },
            TransportHintV1 {
                protocol: TransportProtocol::ToriiHttpRange,
                priority: 1,
            },
        ]);
        let err = proposal.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionValidationError::DuplicateTransportProtocol
        ));
    }
    #[test]
    fn proposal_rejects_invalid_transport_hint_priority() {
        let mut proposal = sample_proposal();
        proposal.transport_hints = Some(vec![TransportHintV1 {
            protocol: TransportProtocol::ToriiHttpRange,
            priority: 99,
        }]);
        let err = proposal.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionValidationError::InvalidTransportHint(
                TransportHintError::InvalidPriority
            )
        ));
    }
    #[test]
    fn proposal_requires_range_capability_for_stream_budget() {
        let mut proposal = sample_proposal();
        proposal
            .capabilities
            .retain(|cap| cap.cap_type != CapabilityType::ChunkRangeFetch);
        let err = proposal.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionValidationError::RangeMetadataWithoutCapability
        ));
    }
    #[test]
    fn proposal_requires_range_capability_for_transport_hints() {
        let mut proposal = sample_proposal();
        proposal.stream_budget = None;
        proposal
            .capabilities
            .retain(|cap| cap.cap_type != CapabilityType::ChunkRangeFetch);
        let err = proposal.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionValidationError::RangeMetadataWithoutCapability
        ));
    }
    #[test]
    fn proposal_rejects_empty_transport_hints() {
        let mut proposal = sample_proposal();
        proposal.transport_hints = Some(vec![]);
        let err = proposal.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionValidationError::EmptyTransportHints
        ));
    }
    #[test]
    fn proposal_validation_succeeds() {
        let proposal = sample_proposal();
        proposal.validate().expect("proposal must be valid");
    }
    #[test]
    fn proposal_validation_rejects_unknown_chunker() {
        let mut proposal = sample_proposal();
        proposal.profile_id = "unknown.profile@1.0.0".to_owned();
        let err = proposal.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionValidationError::UnknownChunkerHandle { .. }
        ));
    }
    #[test]
    fn proposal_rejects_inert_or_noncanonical_advert_key() {
        let mut proposal = sample_proposal();
        proposal.advert_key = [0; 32];
        assert!(matches!(
            proposal.validate(),
            Err(ProviderAdmissionValidationError::InvalidAdvertKey)
        ));
        proposal.advert_key = NONCANONICAL_R;
        assert!(matches!(
            proposal.validate(),
            Err(ProviderAdmissionValidationError::InvalidAdvertKeyMaterial { .. })
        ));
    }
    #[test]
    fn endpoint_attestation_checks_validity_window() {
        let mut proposal = sample_proposal();
        proposal.endpoints[0].attestation.expires_at =
            proposal.endpoints[0].attestation.attested_at;
        let err = proposal.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionValidationError::EndpointInvalid {
                source: EndpointAdmissionError::Attestation(
                    EndpointAttestationError::InvalidValidity { .. }
                ),
                ..
            }
        ));
    }
    #[test]
    fn envelope_validation_succeeds() {
        let proposal = sample_proposal();
        let advert_body = sample_advert_body();
        let proposal_digest = compute_proposal_digest(&proposal).expect("digest");
        let advert_digest = compute_advert_body_digest(&advert_body).expect("digest");
        let envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal,
            proposal_digest,
            advert_body,
            advert_body_digest: advert_digest,
            issued_at: 10,
            retention_epoch: 100,
            council_signatures: vec![council_signature()],
            notes: None,
        };
        envelope.validate().expect("envelope must validate");
    }
    #[test]
    fn envelope_validation_detects_digest_mismatch() {
        let proposal = sample_proposal();
        let advert_body = sample_advert_body();
        let proposal_digest = compute_proposal_digest(&proposal).expect("digest");
        let mut envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal,
            proposal_digest,
            advert_body,
            advert_body_digest: [0u8; 32],
            issued_at: 10,
            retention_epoch: 100,
            council_signatures: vec![council_signature()],
            notes: None,
        };
        envelope.advert_body_digest[0] = 0xFF;
        let err = envelope.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionValidationError::AdvertDigestMismatch
        ));
    }
    #[test]
    fn verify_envelope_accepts_valid_signature() {
        let mut proposal = sample_proposal();
        let provider_key = SigningKey::from_bytes(&[0x11; 32]);
        proposal.advert_key = *provider_key.verifying_key().as_bytes();
        let advert_body = advert_body_from_proposal(&proposal);
        let advert_digest = compute_advert_body_digest(&advert_body).expect("digest");
        let proposal_digest = compute_proposal_digest(&proposal).expect("digest");
        let council_key = SigningKey::from_bytes(&[0x22; 32]);
        let mut envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal,
            proposal_digest,
            advert_body,
            advert_body_digest: advert_digest,
            issued_at: 100,
            retention_epoch: 200,
            council_signatures: Vec::new(),
            notes: None,
        };
        sign_envelope(&mut envelope, &[&council_key]);
        let policy = council_policy(&[&council_key], 1);
        let digest = verify_envelope(&envelope, &policy).expect("envelope verifies");
        assert_eq!(digest, envelope.advert_body_digest);
    }
    #[test]
    fn verify_envelope_rejects_invalid_signature() {
        let mut proposal = sample_proposal();
        let provider_key = SigningKey::from_bytes(&[0x33; 32]);
        proposal.advert_key = *provider_key.verifying_key().as_bytes();
        let advert_body = advert_body_from_proposal(&proposal);
        let advert_digest = compute_advert_body_digest(&advert_body).expect("digest");
        let proposal_digest = compute_proposal_digest(&proposal).expect("digest");
        let council_key = SigningKey::from_bytes(&[0x44; 32]);
        let mut envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal,
            proposal_digest,
            advert_body,
            advert_body_digest: advert_digest,
            issued_at: 50,
            retention_epoch: 150,
            council_signatures: Vec::new(),
            notes: None,
        };
        sign_envelope(&mut envelope, &[&council_key]);
        envelope.council_signatures[0].signature[0] ^= 0x01;
        let policy = council_policy(&[&council_key], 1);
        let err = verify_envelope(&envelope, &policy).unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionEnvelopeError::Signature(
                ProviderAdmissionSignatureError::Verification { .. }
            )
        ));
    }
    #[test]
    fn verify_envelope_rejects_all_zero_signature_material() {
        let mut proposal = sample_proposal();
        let provider_key = SigningKey::from_bytes(&[0x33; 32]);
        proposal.advert_key = *provider_key.verifying_key().as_bytes();
        let advert_body = advert_body_from_proposal(&proposal);
        let advert_digest = compute_advert_body_digest(&advert_body).expect("digest");
        let proposal_digest = compute_proposal_digest(&proposal).expect("digest");
        let council_key = SigningKey::from_bytes(&[0x44; 32]);
        let mut envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal,
            proposal_digest,
            advert_body,
            advert_body_digest: advert_digest,
            issued_at: 50,
            retention_epoch: 150,
            council_signatures: Vec::new(),
            notes: None,
        };
        sign_envelope(&mut envelope, &[&council_key]);
        envelope.council_signatures[0].signature.fill(0);
        let policy = council_policy(&[&council_key], 1);
        let err = verify_envelope(&envelope, &policy).unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionEnvelopeError::Signature(
                ProviderAdmissionSignatureError::Verification { .. }
            )
        ));
    }
    #[test]
    fn verify_envelope_rejects_malformed_signature_r() {
        for (label, replacement_r, expected_reason) in [
            ("small-order", SMALL_ORDER_R, "small-order"),
            ("noncanonical", NONCANONICAL_R, "not a canonical"),
        ] {
            let mut proposal = sample_proposal();
            let provider_key = SigningKey::from_bytes(&[0x33; 32]);
            proposal.advert_key = *provider_key.verifying_key().as_bytes();
            let advert_body = advert_body_from_proposal(&proposal);
            let advert_digest = compute_advert_body_digest(&advert_body).expect("digest");
            let proposal_digest = compute_proposal_digest(&proposal).expect("digest");
            let council_key = SigningKey::from_bytes(&[0x44; 32]);
            let mut envelope = ProviderAdmissionEnvelopeV1 {
                version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
                network_id: [0xA1; 32],
                policy_id: [0xC1; 32],
                policy_revision: 1,
                policy_digest: [0xD1; 32],
                admission_revision: 1,
                expected_current_event_digest: None,
                proposal,
                proposal_digest,
                advert_body,
                advert_body_digest: advert_digest,
                issued_at: 50,
                retention_epoch: 150,
                council_signatures: Vec::new(),
                notes: None,
            };
            sign_envelope(&mut envelope, &[&council_key]);
            envelope.council_signatures[0].signature[..32].copy_from_slice(&replacement_r);
            let policy = council_policy(&[&council_key], 1);
            let err = verify_envelope(&envelope, &policy).unwrap_err();
            assert!(
                matches!(
                    &err,
                    ProviderAdmissionEnvelopeError::Signature(
                        ProviderAdmissionSignatureError::Verification { reason, .. }
                    ) if reason.contains(expected_reason)
                ),
                "{label} signature R produced unexpected error: {err}"
            );
        }
    }
    #[test]
    fn council_policy_rejects_invalid_or_unsatisfiable_configuration() {
        let key = SigningKey::from_bytes(&[0x91; 32]);
        let signer = *key.verifying_key().as_bytes();
        assert!(matches!(
            ProviderAdmissionCouncilPolicy::new([], 1),
            Err(ProviderAdmissionCouncilPolicyError::EmptyTrustedSigners)
        ));
        assert!(matches!(
            ProviderAdmissionCouncilPolicy::new([signer], 0),
            Err(ProviderAdmissionCouncilPolicyError::ZeroThreshold)
        ));
        assert!(matches!(
            ProviderAdmissionCouncilPolicy::new([signer], 2),
            Err(ProviderAdmissionCouncilPolicyError::UnsatisfiableThreshold { .. })
        ));
        assert!(matches!(
            ProviderAdmissionCouncilPolicy::new([signer, signer], 1),
            Err(ProviderAdmissionCouncilPolicyError::DuplicateSigner { .. })
        ));
        assert!(matches!(
            ProviderAdmissionCouncilPolicy::new([[0; 32]], 1),
            Err(ProviderAdmissionCouncilPolicyError::InvalidPublicKey { .. })
        ));
        assert!(matches!(
            ProviderAdmissionCouncilPolicy::new([NONCANONICAL_R], 1),
            Err(ProviderAdmissionCouncilPolicyError::InvalidPublicKey { .. })
        ));
    }
    #[test]
    fn trusted_policy_rejects_self_signed_rogue_envelope() {
        let trusted = SigningKey::from_bytes(&[0x92; 32]);
        let rogue = SigningKey::from_bytes(&[0x93; 32]);
        let envelope = signed_sample_envelope(&[&rogue]);
        let policy = council_policy(&[&trusted], 1);
        let error = verify_envelope(&envelope, &policy).unwrap_err();
        assert!(matches!(
            error,
            ProviderAdmissionEnvelopeError::Signature(
                ProviderAdmissionSignatureError::UntrustedSigner { .. }
            )
        ));
    }
    #[test]
    fn trusted_policy_rejects_mixed_trusted_and_untrusted_signers() {
        let trusted_a = SigningKey::from_bytes(&[0x94; 32]);
        let trusted_b = SigningKey::from_bytes(&[0x95; 32]);
        let rogue = SigningKey::from_bytes(&[0x96; 32]);
        let envelope = signed_sample_envelope(&[&trusted_a, &rogue]);
        let policy = council_policy(&[&trusted_a, &trusted_b], 1);
        let error = verify_envelope(&envelope, &policy).unwrap_err();
        assert!(matches!(
            error,
            ProviderAdmissionEnvelopeError::Signature(
                ProviderAdmissionSignatureError::UntrustedSigner { .. }
            )
        ));
    }
    #[test]
    fn trusted_policy_rejects_duplicate_threshold_padding() {
        let trusted_a = SigningKey::from_bytes(&[0x97; 32]);
        let trusted_b = SigningKey::from_bytes(&[0x98; 32]);
        let mut envelope = signed_sample_envelope(&[&trusted_a]);
        envelope
            .council_signatures
            .push(envelope.council_signatures[0].clone());
        let policy = council_policy(&[&trusted_a, &trusted_b], 2);
        let error = verify_envelope(&envelope, &policy).unwrap_err();
        assert!(matches!(
            error,
            ProviderAdmissionEnvelopeError::Signature(
                ProviderAdmissionSignatureError::DuplicateSigner { .. }
            )
        ));
    }
    #[test]
    fn trusted_policy_rejects_below_threshold_and_noncanonical_order() {
        let trusted_a = SigningKey::from_bytes(&[0x99; 32]);
        let trusted_b = SigningKey::from_bytes(&[0x9a; 32]);
        let policy = council_policy(&[&trusted_a, &trusted_b], 2);
        let below_threshold = signed_sample_envelope(&[&trusted_a]);
        let error = verify_envelope(&below_threshold, &policy).unwrap_err();
        assert!(matches!(
            error,
            ProviderAdmissionEnvelopeError::Signature(
                ProviderAdmissionSignatureError::ThresholdNotMet {
                    required: 2,
                    verified: 1
                }
            )
        ));
        let mut reversed = signed_sample_envelope(&[&trusted_a, &trusted_b]);
        reversed.council_signatures.reverse();
        let error = verify_envelope(&reversed, &policy).unwrap_err();
        assert!(matches!(
            error,
            ProviderAdmissionEnvelopeError::Signature(
                ProviderAdmissionSignatureError::NonCanonicalSignerOrder
            )
        ));
    }
    #[test]
    fn council_signature_binds_validity_and_complete_advert_body() {
        let trusted = SigningKey::from_bytes(&[0x9b; 32]);
        let policy = council_policy(&[&trusted], 1);
        let envelope = signed_sample_envelope(&[&trusted]);
        let mut extended_retention = envelope.clone();
        extended_retention.retention_epoch += 1;
        let error = verify_envelope(&extended_retention, &policy).unwrap_err();
        assert!(matches!(
            error,
            ProviderAdmissionEnvelopeError::Signature(
                ProviderAdmissionSignatureError::Verification { .. }
            )
        ));
        let mut rerouted = envelope;
        rerouted.advert_body.path_policy.min_guard_weight += 1;
        rerouted.advert_body_digest =
            compute_advert_body_digest(&rerouted.advert_body).expect("updated advert digest");
        let error = verify_envelope(&rerouted, &policy).unwrap_err();
        assert!(matches!(
            error,
            ProviderAdmissionEnvelopeError::Signature(
                ProviderAdmissionSignatureError::Verification { .. }
            )
        ));
    }
    #[test]
    fn council_key_rotation_fails_closed_for_retired_key() {
        let retired = SigningKey::from_bytes(&[0x9c; 32]);
        let replacement = SigningKey::from_bytes(&[0x9d; 32]);
        let old_envelope = signed_sample_envelope(&[&retired]);
        let old_policy = council_policy(&[&retired], 1);
        verify_envelope(&old_envelope, &old_policy).expect("old policy accepts old envelope");
        let rotated_policy = council_policy(&[&replacement], 1);
        let error = verify_envelope(&old_envelope, &rotated_policy).unwrap_err();
        assert!(matches!(
            error,
            ProviderAdmissionEnvelopeError::Signature(
                ProviderAdmissionSignatureError::UntrustedSigner { .. }
            )
        ));
        let replacement_envelope = signed_sample_envelope(&[&replacement]);
        verify_envelope(&replacement_envelope, &rotated_policy)
            .expect("rotated policy accepts replacement key");
    }
    #[test]
    fn envelope_rejects_all_zero_and_noncanonical_embedded_signer_keys() {
        let trusted = SigningKey::from_bytes(&[0x9e; 32]);
        let policy = council_policy(&[&trusted], 1);
        for malformed in [[0; 32], NONCANONICAL_R] {
            let mut envelope = signed_sample_envelope(&[&trusted]);
            envelope.council_signatures[0].signer = malformed;
            let error = verify_envelope(&envelope, &policy).unwrap_err();
            assert!(matches!(
                error,
                ProviderAdmissionEnvelopeError::Signature(
                    ProviderAdmissionSignatureError::InvalidPublicKey { .. }
                )
            ));
        }
    }
    #[test]
    fn verify_advert_against_record_succeeds() {
        let mut proposal = sample_proposal();
        let provider_key = SigningKey::from_bytes(&[0x55; 32]);
        proposal.advert_key = *provider_key.verifying_key().as_bytes();
        let advert_body = advert_body_from_proposal(&proposal);
        let mut advert = ProviderAdvertV1 {
            version: PROVIDER_ADVERT_VERSION_V1,
            network_id: [0xA1; 32],
            issued_at: 10,
            expires_at: 40,
            body: advert_body.clone(),
            signature: AdvertSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: Vec::new(),
                signature: Vec::new(),
            },
            signature_strict: true,
            allow_unknown_capabilities: false,
        };
        sign_advert(&provider_key, &mut advert);
        let proposal_digest = compute_proposal_digest(&proposal).expect("digest");
        let advert_digest = compute_advert_body_digest(&advert_body).expect("digest");
        let council_key = SigningKey::from_bytes(&[0x66; 32]);
        let mut envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal,
            proposal_digest,
            advert_body,
            advert_body_digest: advert_digest,
            issued_at: 5,
            retention_epoch: 50,
            council_signatures: Vec::new(),
            notes: None,
        };
        sign_envelope(&mut envelope, &[&council_key]);
        let policy = council_policy(&[&council_key], 1);
        let record = AdmissionRecord::new(envelope, &policy).expect("record");
        advert
            .verify_signature()
            .expect("provider advert signature verifies");
        verify_advert_against_record(&advert, &record).expect("verification succeeds");
    }
    #[test]
    fn verify_advert_against_record_detects_key_mismatch() {
        let mut proposal = sample_proposal();
        let provider_key = SigningKey::from_bytes(&[0x77; 32]);
        proposal.advert_key = *provider_key.verifying_key().as_bytes();
        let advert_body = advert_body_from_proposal(&proposal);
        let mut advert = ProviderAdvertV1 {
            version: PROVIDER_ADVERT_VERSION_V1,
            network_id: [0xA1; 32],
            issued_at: 20,
            expires_at: 60,
            body: advert_body.clone(),
            signature: AdvertSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: Vec::new(),
                signature: Vec::new(),
            },
            signature_strict: true,
            allow_unknown_capabilities: false,
        };
        sign_advert(&provider_key, &mut advert);
        let proposal_digest = compute_proposal_digest(&proposal).expect("digest");
        let advert_digest = compute_advert_body_digest(&advert_body).expect("digest");
        let council_key = SigningKey::from_bytes(&[0x88; 32]);
        let mut envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal,
            proposal_digest,
            advert_body,
            advert_body_digest: advert_digest,
            issued_at: 15,
            retention_epoch: 55,
            council_signatures: Vec::new(),
            notes: None,
        };
        sign_envelope(&mut envelope, &[&council_key]);
        let policy = council_policy(&[&council_key], 1);
        let record = AdmissionRecord::new(envelope, &policy).expect("record");
        advert.signature.public_key[0] ^= 0xFF;
        let err = verify_advert_against_record(&advert, &record).unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionAdvertError::AdvertKeyMismatch
        ));
    }
    #[test]
    fn renewal_applies_updated_stake_and_endpoints() {
        let council_key = SigningKey::from_bytes(&[0x45; 32]);
        let base_proposal = sample_proposal();
        let base_advert = advert_body_from_proposal(&base_proposal);
        let base_proposal_digest = compute_proposal_digest(&base_proposal).expect("digest");
        let base_advert_digest = compute_advert_body_digest(&base_advert).expect("digest");
        let mut base_envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal: base_proposal.clone(),
            proposal_digest: base_proposal_digest,
            advert_body: base_advert.clone(),
            advert_body_digest: base_advert_digest,
            issued_at: 100,
            retention_epoch: 500,
            council_signatures: Vec::new(),
            notes: None,
        };
        sign_envelope(&mut base_envelope, &[&council_key]);
        let policy = council_policy(&[&council_key], 1);
        let record = AdmissionRecord::new(base_envelope.clone(), &policy).expect("record");
        let mut renewal_proposal = base_envelope.proposal.clone();
        renewal_proposal.stake.stake_amount = renewal_proposal
            .stake
            .stake_amount
            .checked_add(
                &crate::deal::XorQuantity::try_from_micro(10_000)
                    .expect("fixture increment is representable"),
            )
            .expect("fixture stake addition is representable");
        renewal_proposal.endpoints[0].attestation.expires_at += 3_600;
        let mut renewal_advert = base_envelope.advert_body.clone();
        renewal_advert.stake = renewal_proposal.stake.clone();
        renewal_advert.endpoints = renewal_proposal
            .endpoints
            .iter()
            .map(|entry| entry.endpoint.clone())
            .collect();
        let renewal_proposal_digest =
            compute_proposal_digest(&renewal_proposal).expect("renewal proposal digest");
        let renewal_advert_digest =
            compute_advert_body_digest(&renewal_advert).expect("renewal advert digest");
        let mut renewal_envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 2,
            expected_current_event_digest: Some(*record.envelope_digest()),
            proposal: renewal_proposal,
            proposal_digest: renewal_proposal_digest,
            advert_body: renewal_advert,
            advert_body_digest: renewal_advert_digest,
            issued_at: 150,
            retention_epoch: 900,
            council_signatures: Vec::new(),
            notes: Some("stake top-up".to_owned()),
        };
        sign_envelope(&mut renewal_envelope, &[&council_key]);
        let renewal_envelope_digest =
            compute_envelope_digest(&renewal_envelope).expect("renewal envelope digest");
        let renewal = ProviderAdmissionRenewalV1 {
            version: PROVIDER_ADMISSION_RENEWAL_VERSION_V1,
            provider_id: *record.provider_id(),
            previous_envelope_digest: *record.envelope_digest(),
            envelope_digest: renewal_envelope_digest,
            envelope: renewal_envelope,
            notes: Some("stake top-up".to_owned()),
        };
        let updated_record = record
            .apply_renewal(&renewal, &policy)
            .expect("renewal applied");
        assert_eq!(
            updated_record.envelope.proposal.stake.stake_amount,
            base_proposal
                .stake
                .stake_amount
                .checked_add(
                    &crate::deal::XorQuantity::try_from_micro(10_000)
                        .expect("fixture increment is representable"),
                )
                .expect("fixture stake addition is representable")
        );
        assert_eq!(
            updated_record.envelope.advert_body.endpoints[0].host_pattern,
            base_advert.endpoints[0].host_pattern
        );
        assert_eq!(*updated_record.envelope_digest(), renewal.envelope_digest);
    }
    #[test]
    fn renewal_rejects_capability_change() {
        let council_key = SigningKey::from_bytes(&[0x55; 32]);
        let mut base_proposal = sample_proposal();
        let mut base_advert = advert_body_from_proposal(&base_proposal);
        let extra_capability = CapabilityTlv {
            cap_type: CapabilityType::VendorReserved,
            payload: vec![0x01],
        };
        base_proposal.capabilities.push(extra_capability.clone());
        base_advert.capabilities.push(extra_capability);
        let base_proposal_digest = compute_proposal_digest(&base_proposal).expect("digest");
        let base_advert_digest = compute_advert_body_digest(&base_advert).expect("digest");
        let mut base_envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal: base_proposal,
            proposal_digest: base_proposal_digest,
            advert_body: base_advert.clone(),
            advert_body_digest: base_advert_digest,
            issued_at: 1,
            retention_epoch: 10,
            council_signatures: Vec::new(),
            notes: None,
        };
        sign_envelope(&mut base_envelope, &[&council_key]);
        let policy = council_policy(&[&council_key], 1);
        let record = AdmissionRecord::new(base_envelope.clone(), &policy).expect("record");
        let mut renewal_envelope = base_envelope.clone();
        let torii_capability = renewal_envelope
            .advert_body
            .capabilities
            .iter()
            .find(|cap| cap.cap_type == CapabilityType::ToriiGateway)
            .cloned()
            .expect("torii capability present");
        let range_capability = renewal_envelope
            .advert_body
            .capabilities
            .iter()
            .find(|cap| cap.cap_type == CapabilityType::ChunkRangeFetch)
            .cloned()
            .expect("range capability present");
        renewal_envelope.advert_body.capabilities =
            vec![torii_capability, range_capability.clone()];
        renewal_envelope.proposal.capabilities = vec![
            renewal_envelope.advert_body.capabilities[0].clone(),
            range_capability,
        ];
        let renewal_proposal_digest =
            compute_proposal_digest(&renewal_envelope.proposal).expect("digest");
        let renewal_advert_digest =
            compute_advert_body_digest(&renewal_envelope.advert_body).expect("digest");
        renewal_envelope.proposal_digest = renewal_proposal_digest;
        renewal_envelope.advert_body_digest = renewal_advert_digest;
        renewal_envelope.issued_at += 1;
        renewal_envelope.retention_epoch += 100;
        renewal_envelope.admission_revision = 2;
        renewal_envelope.expected_current_event_digest = Some(*record.envelope_digest());
        sign_envelope(&mut renewal_envelope, &[&council_key]);
        let renewal_envelope_digest = compute_envelope_digest(&renewal_envelope).expect("digest");
        let renewal = ProviderAdmissionRenewalV1 {
            version: PROVIDER_ADMISSION_RENEWAL_VERSION_V1,
            provider_id: *record.provider_id(),
            previous_envelope_digest: *record.envelope_digest(),
            envelope_digest: renewal_envelope_digest,
            envelope: renewal_envelope,
            notes: None,
        };
        let err = record.apply_renewal(&renewal, &policy).unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionRenewalError::CapabilitiesChanged
        ));
    }
    #[test]
    fn renewal_and_revocation_require_current_trusted_quorum() {
        let trusted_a = SigningKey::from_bytes(&[0xa1; 32]);
        let trusted_b = SigningKey::from_bytes(&[0xa2; 32]);
        let rogue = SigningKey::from_bytes(&[0xa3; 32]);
        let policy = council_policy(&[&trusted_a, &trusted_b], 2);
        let base_envelope = signed_sample_envelope(&[&trusted_a, &trusted_b]);
        let record = AdmissionRecord::new(base_envelope.clone(), &policy).expect("base record");
        let mut renewed_envelope = base_envelope;
        renewed_envelope.issued_at += 1;
        renewed_envelope.retention_epoch += 1;
        renewed_envelope.admission_revision = 2;
        renewed_envelope.expected_current_event_digest = Some(*record.envelope_digest());
        sign_envelope(&mut renewed_envelope, &[&rogue]);
        let renewal = ProviderAdmissionRenewalV1 {
            version: PROVIDER_ADMISSION_RENEWAL_VERSION_V1,
            provider_id: *record.provider_id(),
            previous_envelope_digest: *record.envelope_digest(),
            envelope_digest: compute_envelope_digest(&renewed_envelope)
                .expect("renewed envelope digest"),
            envelope: renewed_envelope,
            notes: None,
        };
        let error = record.apply_renewal(&renewal, &policy).unwrap_err();
        assert!(matches!(
            error,
            ProviderAdmissionRenewalError::Envelope(ProviderAdmissionEnvelopeError::Signature(
                ProviderAdmissionSignatureError::UntrustedSigner { .. }
            ))
        ));
        let mut revocation = ProviderAdmissionRevocationV1 {
            version: PROVIDER_ADMISSION_REVOCATION_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            transition_revision: 2,
            expected_current_event_digest: *record.envelope_digest(),
            provider_id: *record.provider_id(),
            envelope_digest: *record.envelope_digest(),
            revoked_at: 200,
            reason: "key compromise".to_owned(),
            council_signatures: Vec::new(),
            notes: None,
        };
        let digest = revocation.digest().expect("revocation digest");
        revocation.council_signatures = vec![council_signature_from_key(&trusted_a, &digest)];
        let error = record.verify_revocation(&revocation, &policy).unwrap_err();
        assert!(matches!(
            error,
            ProviderAdmissionRevocationError::Signature(
                ProviderAdmissionSignatureError::ThresholdNotMet {
                    required: 2,
                    verified: 1
                }
            )
        ));
        revocation
            .council_signatures
            .push(revocation.council_signatures[0].clone());
        let error = record.verify_revocation(&revocation, &policy).unwrap_err();
        assert!(matches!(
            error,
            ProviderAdmissionRevocationError::Signature(
                ProviderAdmissionSignatureError::DuplicateSigner { .. }
            )
        ));
    }
    #[test]
    fn revocation_structural_validation_preserves_signature_verification() {
        let council_key = SigningKey::from_bytes(&[0x65; 32]);
        let policy = council_policy(&[&council_key], 1);
        let mut revocation = ProviderAdmissionRevocationV1 {
            version: PROVIDER_ADMISSION_REVOCATION_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            transition_revision: 2,
            expected_current_event_digest: [0xE1; 32],
            provider_id: [0xF1; 32],
            envelope_digest: [0xE1; 32],
            revoked_at: 10,
            reason: "endpoint compromise".to_owned(),
            council_signatures: Vec::new(),
            notes: None,
        };
        let digest = revocation.digest().expect("revocation digest");
        revocation.council_signatures = vec![council_signature_from_key(&council_key, &digest)];
        revocation
            .validate()
            .expect("structurally valid revocation");
        verify_revocation_signatures(&revocation, &policy).expect("trusted revocation");

        macro_rules! rejects {
            ($field:ident = $value:expr, $error:pat) => {{
                let mut invalid = revocation.clone();
                invalid.$field = $value;
                assert!(matches!(invalid.validate(), Err($error)));
                assert!(matches!(
                    verify_revocation_signatures(&invalid, &policy),
                    Err($error)
                ));
            }};
        }
        rejects!(
            version = 0,
            ProviderAdmissionRevocationError::UnsupportedVersion { found: 0 }
        );
        rejects!(
            network_id = [0; 32],
            ProviderAdmissionRevocationError::InvalidNetworkId
        );
        rejects!(
            policy_id = [0; 32],
            ProviderAdmissionRevocationError::InvalidPolicyBinding
        );
        rejects!(
            policy_digest = [0; 32],
            ProviderAdmissionRevocationError::InvalidPolicyBinding
        );
        rejects!(
            policy_revision = 0,
            ProviderAdmissionRevocationError::InvalidPolicyBinding
        );
        rejects!(
            transition_revision = 0,
            ProviderAdmissionRevocationError::InvalidEventLineage
        );
        rejects!(
            expected_current_event_digest = [0; 32],
            ProviderAdmissionRevocationError::InvalidEventLineage
        );
        rejects!(
            reason = " \t\n".to_owned(),
            ProviderAdmissionRevocationError::ReasonEmpty
        );
        rejects!(
            council_signatures = Vec::new(),
            ProviderAdmissionRevocationError::MissingSignatures
        );

        revocation.council_signatures[0].signature[0] ^= 1;
        revocation
            .validate()
            .expect("structure does not establish trust");
        assert!(matches!(
            verify_revocation_signatures(&revocation, &policy),
            Err(ProviderAdmissionRevocationError::Signature(_))
        ));
    }

    #[test]
    fn revocation_signatures_and_registry_checks() {
        let council_key = SigningKey::from_bytes(&[0x65; 32]);
        let proposal = sample_proposal();
        let advert = advert_body_from_proposal(&proposal);
        let proposal_digest = compute_proposal_digest(&proposal).expect("digest");
        let advert_digest = compute_advert_body_digest(&advert).expect("digest");
        let mut envelope = ProviderAdmissionEnvelopeV1 {
            version: PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            admission_revision: 1,
            expected_current_event_digest: None,
            proposal,
            proposal_digest,
            advert_body: advert,
            advert_body_digest: advert_digest,
            issued_at: 1,
            retention_epoch: 5,
            council_signatures: Vec::new(),
            notes: None,
        };
        sign_envelope(&mut envelope, &[&council_key]);
        let policy = council_policy(&[&council_key], 1);
        let record = AdmissionRecord::new(envelope, &policy).expect("record");
        let mut revocation = ProviderAdmissionRevocationV1 {
            version: PROVIDER_ADMISSION_REVOCATION_VERSION_V1,
            network_id: [0xA1; 32],
            policy_id: [0xC1; 32],
            policy_revision: 1,
            policy_digest: [0xD1; 32],
            transition_revision: 2,
            expected_current_event_digest: *record.envelope_digest(),
            provider_id: *record.provider_id(),
            envelope_digest: *record.envelope_digest(),
            revoked_at: 10,
            reason: "endpoint compromise".to_owned(),
            council_signatures: Vec::new(),
            notes: Some("rotation".to_owned()),
        };
        let revocation_digest = revocation.digest().expect("digest");
        revocation.council_signatures =
            vec![council_signature_from_key(&council_key, &revocation_digest)];
        verify_revocation_signatures(&revocation, &policy).expect("signatures");
        record
            .verify_revocation(&revocation, &policy)
            .expect("registry checks");
        let mut mismatched = revocation.clone();
        mismatched.envelope_digest[0] ^= 0xFF;
        let err = record.verify_revocation(&mismatched, &policy).unwrap_err();
        assert!(matches!(
            err,
            ProviderAdmissionRevocationError::EnvelopeDigestMismatch { .. }
        ));
    }
    #[test]
    fn signed_lineage_refuses_outer_predecessor_substitution() {
        let council_key = SigningKey::from_bytes(&[0x65; 32]);
        let policy = council_policy(&[&council_key], 1);
        let base = signed_sample_envelope(&[&council_key]);
        let first = AdmissionRecord::new(base.clone(), &policy).expect("first admission");
        let mut malformed_policy = base.clone();
        malformed_policy.policy_id = [0; 32];
        assert!(matches!(
            malformed_policy.validate(),
            Err(ProviderAdmissionValidationError::InvalidPolicyBinding)
        ));
        let mut missing_predecessor = base.clone();
        missing_predecessor.admission_revision = 2;
        assert!(matches!(
            missing_predecessor.validate(),
            Err(ProviderAdmissionValidationError::InvalidEventLineage)
        ));
        let mut alternate = base.clone();
        alternate.notes = Some("alternate admitted event".to_owned());
        sign_envelope(&mut alternate, &[&council_key]);
        let second = AdmissionRecord::new(alternate, &policy).expect("second admission");

        let mut successor = base;
        successor.admission_revision = 2;
        successor.expected_current_event_digest = Some(*first.envelope_digest());
        successor.issued_at += 1;
        successor.retention_epoch += 1;
        sign_envelope(&mut successor, &[&council_key]);
        assert!(matches!(
            AdmissionRecord::new(successor.clone(), &policy),
            Err(ProviderAdmissionEnvelopeError::NonInitialEvent { revision: 2 })
        ));
        let mut renewal = ProviderAdmissionRenewalV1 {
            version: PROVIDER_ADMISSION_RENEWAL_VERSION_V1,
            provider_id: *first.provider_id(),
            previous_envelope_digest: *second.envelope_digest(),
            envelope_digest: compute_envelope_digest(&successor).expect("successor digest"),
            envelope: successor.clone(),
            notes: None,
        };
        assert!(matches!(
            second.apply_renewal(&renewal, &policy),
            Err(ProviderAdmissionRenewalError::SignedPredecessorMismatch)
        ));
        renewal.previous_envelope_digest = *first.envelope_digest();
        first
            .apply_renewal(&renewal, &policy)
            .expect("exact predecessor");
        let mut substituted_policy = successor;
        substituted_policy.policy_digest[0] ^= 1;
        assert!(matches!(
            verify_envelope(&substituted_policy, &policy),
            Err(ProviderAdmissionEnvelopeError::Signature(_))
        ));

        let mut revocation = ProviderAdmissionRevocationV1 {
            version: PROVIDER_ADMISSION_REVOCATION_VERSION_V1,
            network_id: first.envelope().network_id,
            policy_id: first.envelope().policy_id,
            policy_revision: first.envelope().policy_revision,
            policy_digest: first.envelope().policy_digest,
            transition_revision: 2,
            expected_current_event_digest: *first.envelope_digest(),
            provider_id: *first.provider_id(),
            envelope_digest: *second.envelope_digest(),
            revoked_at: 200,
            reason: "key compromise".to_owned(),
            council_signatures: Vec::new(),
            notes: None,
        };
        let digest = revocation.digest().expect("revocation digest");
        revocation.council_signatures = vec![council_signature_from_key(&council_key, &digest)];
        let mut invalid_revocation_lineage = revocation.clone();
        invalid_revocation_lineage.transition_revision = 0;
        assert!(matches!(
            verify_revocation_signatures(&invalid_revocation_lineage, &policy),
            Err(ProviderAdmissionRevocationError::InvalidEventLineage)
        ));
        assert!(matches!(
            second.verify_revocation(&revocation, &policy),
            Err(ProviderAdmissionRevocationError::SignedPredecessorMismatch)
        ));
        revocation.envelope_digest = *first.envelope_digest();
        assert!(matches!(
            verify_revocation_signatures(&revocation, &policy),
            Err(ProviderAdmissionRevocationError::Signature(_))
        ));
    }
    include!("provider_admission/tests/canonical_preimages.rs");
}

#[cfg(test)]
include!("provider_admission/captured_owner_identity_tests.rs");
