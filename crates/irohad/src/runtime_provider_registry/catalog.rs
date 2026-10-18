//! Canonical, secret-free handoff artifact for deployment-owned provider brokers.
use super::*;
use norito::codec::{Decode, Encode};
use std::{cmp::Ordering, fmt};
/// Hard byte ceiling for one canonical V1 runtime-provider catalog artifact.
///
/// The ceiling covers the complete first-release slot inventory, including
/// bounded public keys and policy material, while keeping untrusted decode
/// allocation proportional to a small, deployment-owned input.
pub const RUNTIME_PROVIDER_CATALOG_MAX_BYTES_V1: usize = 256 * 1024;
const RUNTIME_PROVIDER_CATALOG_MAGIC_V1: [u8; 8] = *b"IRPCAT01";
const RUNTIME_PROVIDER_CATALOG_VERSION_V1: u16 = 1;
const RUNTIME_PROVIDER_HANDLE_MAX_BYTES_V1: usize = 1024;
const EVIDENCE_VIEWER_ARCHIVE_MAX_BYTES_V1: u64 =
    sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_CHECKPOINT_BYTES_V1 + 16 * 1024;
/// Failure while exporting or loading a canonical public provider catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IrohaRuntimeProviderCatalogErrorV1 {
    /// No bytes were supplied to the loader.
    EmptyArtifact,
    /// The encoded artifact exceeds the fixed V1 byte ceiling.
    ArtifactTooLarge,
    /// The bytes are not the exact canonical Norito encoding for this schema.
    NonCanonicalEncoding,
    /// The artifact magic does not identify a runtime-provider catalog.
    InvalidMagic,
    /// The artifact advertises a catalog version other than V1.
    UnsupportedVersion,
    /// The catalog chain identifier is not canonical.
    InvalidChainId,
    /// A broker handoff catalog contains no provider bindings.
    EmptyCatalog,
    /// The binding sequence is not strictly canonical or exceeds slot multiplicity.
    InvalidOrder,
    /// A binding is malformed, zero-qualified, substituted, or test-marked.
    InvalidBinding,
}
impl fmt::Display for IrohaRuntimeProviderCatalogErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyArtifact => "runtime-provider catalog artifact is empty",
            Self::ArtifactTooLarge => "runtime-provider catalog artifact exceeds the V1 limit",
            Self::NonCanonicalEncoding => "runtime-provider catalog is not exact canonical Norito",
            Self::InvalidMagic => "runtime-provider catalog magic is invalid",
            Self::UnsupportedVersion => "runtime-provider catalog version is unsupported",
            Self::InvalidChainId => "runtime-provider catalog chain id is invalid",
            Self::EmptyCatalog => "runtime-provider catalog contains no bindings",
            Self::InvalidOrder => {
                "runtime-provider catalog binding order or multiplicity is invalid"
            }
            Self::InvalidBinding => "runtime-provider catalog contains an invalid binding",
        })
    }
}
impl std::error::Error for IrohaRuntimeProviderCatalogErrorV1 {}
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(name = "irohad::runtime_provider_registry::catalog::RuntimeProviderCatalogWireV1")]
struct RuntimeProviderCatalogWireV1 {
    magic: [u8; 8],
    version: u16,
    chain_id: String,
    network_id: NetworkId,
    credential_max_memory_bytes: u64,
    bindings: Vec<RuntimeProviderBindingWireV1>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "irohad::runtime_provider_registry::catalog::RuntimeProviderBindingWireV1")]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
struct RuntimeProviderBindingWireV1 {
    slot: u16,
    handle: String,
    revision: Option<u64>,
    policy_digest: Option<[u8; 32]>,
    stream_token_signer_binding: Option<StreamTokenSignerRuntimeBindingV1>,
    appeal_finance_signer_binding: Option<AppealFinanceSignerBindingWireV1>,
    appeal_finance_checkpoint_binding: Option<AppealFinanceCheckpointBindingWireV1>,
    appeal_finance_checkpoint_max_bytes: Option<u64>,
    pop_credential_runtime_binding: Option<PopCredentialRuntimeBindingWireV1>,
    por_replay_archive_binding: Option<sorafs_node::PorFinalizedReplayArchiveBindingV1>,
    por_replay_archive_proof_limits: Option<PorReplayArchiveProofLimitsWireV1>,
    potr_runtime_binding: Option<PotrRuntimeBindingWireV1>,
    native_signer_binding: Option<NativeTransactionSignerBindingWireV1>,
    governance_dag_publisher_peer_id: Option<Vec<u8>>,
    governance_dag_publisher_public_key: Option<[u8; 32]>,
    governance_request_ingress_binding: Option<GovernanceRequestIngressBindingWireV1>,
    provider_ingest_signer_binding: Option<ProviderIngestSignerBindingWireV1>,
    provider_ingest_source_limits: Option<ProviderIngestSourceLimitsWireV1>,
    provider_ingest_checkpoint_max_bytes: Option<u64>,
    provider_ingest_max_signed_transaction_bytes: Option<u64>,
    evidence_viewer_webauthn_binding: Option<EvidenceViewerWebAuthnBindingWireV1>,
    evidence_viewer_grant_ttl_ms: Option<u64>,
    evidence_viewer_receipt_signer_public_key: Option<[u8; 32]>,
    evidence_viewer_transparency_publisher_public_key: Option<[u8; 32]>,
    evidence_viewer_checkpoint_max_bytes: Option<u64>,
    moderation_checkpoint_max_bytes: Option<u64>,
    moderation_checkpoint_attestation_public_key: Option<[u8; 32]>,
    evidence_viewer_archive_id: Option<[u8; 32]>,
    evidence_viewer_archive_public_key: Option<[u8; 32]>,
    evidence_viewer_archive_max_bytes: Option<u64>,
    moderation_panel_notification_archive_binding:
        Option<ModerationPanelNotificationArchiveBindingWireV1>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_registry::catalog::GovernanceRequestIngressBindingWireV1"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode)]
struct GovernanceRequestIngressBindingWireV1 {
    scope: u8,
    endpoint_binding: [u8; 32],
    public_key: [u8; 32],
    max_body_bytes: u64,
    max_envelope_lifetime_secs: u64,
    max_future_skew_secs: u64,
}
impl From<sorafs_node::GovernanceDagRequestIngressBindingV1>
    for GovernanceRequestIngressBindingWireV1
{
    fn from(binding: sorafs_node::GovernanceDagRequestIngressBindingV1) -> Self {
        let scope = match binding.scope() {
            sorafs_node::GovernanceDagAuthenticationScope::Ipfs => 1,
            sorafs_node::GovernanceDagAuthenticationScope::SignedHead => 2,
        };
        Self {
            scope,
            endpoint_binding: binding.endpoint_binding(),
            public_key: binding.public_key(),
            max_body_bytes: binding.max_body_bytes(),
            max_envelope_lifetime_secs: binding.max_envelope_lifetime_secs(),
            max_future_skew_secs: binding.max_future_skew_secs(),
        }
    }
}
impl GovernanceRequestIngressBindingWireV1 {
    fn try_into_binding(
        self,
    ) -> Result<sorafs_node::GovernanceDagRequestIngressBindingV1, IrohaRuntimeProviderCatalogErrorV1>
    {
        let scope = match self.scope {
            1 => sorafs_node::GovernanceDagAuthenticationScope::Ipfs,
            2 => sorafs_node::GovernanceDagAuthenticationScope::SignedHead,
            _ => return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding),
        };
        sorafs_node::GovernanceDagRequestIngressBindingV1::try_new(
            scope,
            self.endpoint_binding,
            self.public_key,
            self.max_body_bytes,
            self.max_envelope_lifetime_secs,
            self.max_future_skew_secs,
        )
        .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_registry::catalog::ModerationPanelNotificationArchiveBindingWireV1"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode)]
struct ModerationPanelNotificationArchiveBindingWireV1 {
    archive_id: [u8; 32],
    bootstrap_public_key: [u8; 32],
    public_key: [u8; 32],
    max_bytes: u64,
    max_records: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_registry::catalog::AppealFinanceSignerBindingWireV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
struct AppealFinanceSignerBindingWireV1 {
    authority: iroha_data_model::account::AccountId,
    public_key: iroha_crypto::PublicKey,
    valid_from_block_height: u64,
    revoked_at_block_height: Option<u64>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_registry::catalog::AppealFinanceCheckpointBindingWireV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
struct AppealFinanceCheckpointBindingWireV1 {
    public_key: iroha_crypto::PublicKey,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_registry::catalog::PopCredentialRuntimeBindingWireV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
struct PopCredentialRuntimeBindingWireV1 {
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
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_registry::catalog::PorReplayArchiveProofLimitsWireV1"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode)]
struct PorReplayArchiveProofLimitsWireV1 {
    max_successor_receipts: u32,
    max_successor_proof_bytes: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_registry::catalog::PotrAdmissionPolicyBindingWireV1"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode)]
struct PotrAdmissionPolicyBindingWireV1 {
    provider_id: [u8; 32],
    policy_identity: [u8; 32],
    policy_digest: [u8; 32],
    policy_sequence: u64,
    finalized_height: u64,
    finalized_block_hash: [u8; 32],
    admission_envelope_digest: [u8; 32],
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "irohad::runtime_provider_registry::catalog::PotrRuntimeBindingWireV1")]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
struct PotrRuntimeBindingWireV1 {
    gateway_handle: String,
    gateway_signer_id: [u8; 32],
    gateway_revision: u64,
    gateway_policy_digest: [u8; 32],
    provider_handle: String,
    provider_signer_id: [u8; 32],
    provider_revision: u64,
    provider_policy_digest: [u8; 32],
    gateway_public_key: [u8; 32],
    reader_id: [u8; 32],
    source_id: [u8; 32],
    resolver_id: [u8; 32],
    baseline_admission_policy: PotrAdmissionPolicyBindingWireV1,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_registry::catalog::NativeTransactionSignerBindingWireV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
struct NativeTransactionSignerBindingWireV1 {
    role: u8,
    authority: iroha_data_model::account::AccountId,
    public_key: iroha_crypto::PublicKey,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_registry::catalog::EvidenceViewerWebAuthnBindingWireV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
struct EvidenceViewerWebAuthnBindingWireV1 {
    rp_id: String,
    allowed_origins: Vec<String>,
    challenge_ttl_ms: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_registry::catalog::ProviderIngestSourceLimitsWireV1"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode)]
struct ProviderIngestSourceLimitsWireV1 {
    operation_timeout_ms: u64,
    max_content_bytes: u64,
    max_source_providers: u32,
    max_concurrent_streams: u32,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_registry::catalog::ProviderIngestSignerBindingWireV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
struct ProviderIngestSignerBindingWireV1 {
    runtime_handle: String,
    adapter_revision: u64,
    signer_policy_id: [u8; 32],
    signer_policy_revision: u64,
    signer_policy_predecessor_digest: Option<[u8; 32]>,
    signer_policy_digest: [u8; 32],
    algorithm: u8,
    public_key: Vec<u8>,
}
impl IrohaRuntimeProviderBindingsV1 {
    /// Export this sanitized provider projection as an exact canonical V1
    /// broker handoff artifact.
    ///
    /// Only the display-chain identity, exact genesis-derived network identity,
    /// the explicit local credential-memory bound, and public binding fields are serialized.
    /// Credentials, private keys, tokens, vendor
    /// connection settings, and the full daemon configuration are not inputs
    /// to this API.
    ///
    /// # Errors
    ///
    /// Rejects empty catalogs, invalid or test-marked bindings, noncanonical
    /// order, excess slot multiplicity, and artifacts above the fixed byte
    /// ceiling.
    pub fn export_canonical_v1(&self) -> Result<Vec<u8>, IrohaRuntimeProviderCatalogErrorV1> {
        let wire = RuntimeProviderCatalogWireV1::try_from_bindings(self)?;
        let bytes = norito::encode_canonical(&wire)
            .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::NonCanonicalEncoding)?;
        if bytes.is_empty() || bytes.len() > RUNTIME_PROVIDER_CATALOG_MAX_BYTES_V1 {
            return Err(IrohaRuntimeProviderCatalogErrorV1::ArtifactTooLarge);
        }
        Ok(bytes)
    }
    /// Load an exact canonical V1 broker handoff artifact without receiving
    /// or reconstructing the daemon's complete configuration.
    ///
    /// Decode allocation is bounded by the fixed artifact ceiling and
    /// Norito's payload-derived canonical limits. The exact canonical decode
    /// rejects compression, alternate layouts, padding/trailing bytes, and
    /// noncanonical re-encodings before semantic validation.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, malformed, noncanonical, wrong-version,
    /// unordered, duplicate, test-marked, zero-qualified, or otherwise
    /// substituted catalog.
    pub fn load_canonical_v1(bytes: &[u8]) -> Result<Self, IrohaRuntimeProviderCatalogErrorV1> {
        if bytes.is_empty() {
            return Err(IrohaRuntimeProviderCatalogErrorV1::EmptyArtifact);
        }
        if bytes.len() > RUNTIME_PROVIDER_CATALOG_MAX_BYTES_V1 {
            return Err(IrohaRuntimeProviderCatalogErrorV1::ArtifactTooLarge);
        }
        let wire: RuntimeProviderCatalogWireV1 = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::NonCanonicalEncoding)?;
        wire.try_into_bindings()
    }
}
impl RuntimeProviderCatalogWireV1 {
    fn try_from_bindings(
        bindings: &IrohaRuntimeProviderBindingsV1,
    ) -> Result<Self, IrohaRuntimeProviderCatalogErrorV1> {
        validate_chain_id(bindings.chain_id())?;
        validate_binding_sequence(bindings.iter().map(IrohaRuntimeProviderBindingV1::slot))?;
        validate_catalog_relationships(bindings)?;
        let projected = bindings
            .iter()
            .map(RuntimeProviderBindingWireV1::try_from_binding)
            .collect::<Result<Vec<_>, _>>()?;
        validate_wire_order(&projected)?;
        let wire = Self {
            magic: RUNTIME_PROVIDER_CATALOG_MAGIC_V1,
            version: RUNTIME_PROVIDER_CATALOG_VERSION_V1,
            chain_id: bindings.chain_id().to_owned(),
            network_id: *bindings.network_id(),
            credential_max_memory_bytes: u64::try_from(bindings.credential_max_memory_bytes())
                .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?,
            bindings: projected,
        };
        // Reconstruct once before export. This prevents an internally
        // hand-built projection from bypassing the same validation applied by
        // the external broker-side loader.
        let reconstructed = wire.clone().try_into_bindings()?;
        if reconstructed != *bindings {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
        Ok(wire)
    }
    fn try_into_bindings(
        self,
    ) -> Result<IrohaRuntimeProviderBindingsV1, IrohaRuntimeProviderCatalogErrorV1> {
        if self.magic != RUNTIME_PROVIDER_CATALOG_MAGIC_V1 {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidMagic);
        }
        if self.version != RUNTIME_PROVIDER_CATALOG_VERSION_V1 {
            return Err(IrohaRuntimeProviderCatalogErrorV1::UnsupportedVersion);
        }
        validate_chain_id(&self.chain_id)?;
        validate_wire_order(&self.bindings)?;
        validate_binding_sequence(self.bindings.iter().map(|binding| {
            IrohaRuntimeProviderSlotV1::from_wire_id(binding.slot)
                .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)
        }))?;
        let bindings = self
            .bindings
            .into_iter()
            .map(RuntimeProviderBindingWireV1::try_into_binding)
            .collect::<Result<Vec<_>, _>>()?;
        let reconstructed = IrohaRuntimeProviderBindingsV1 {
            chain_id: self.chain_id,
            network_id: self.network_id,
            credential_max_memory_bytes: usize::try_from(self.credential_max_memory_bytes)
                .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?,
            bindings,
        };
        if reconstructed.credential_max_memory_bytes == 0
            && reconstructed.iter().any(|binding| {
                binding.slot() == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner
            })
        {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
        validate_catalog_relationships(&reconstructed)?;
        Ok(reconstructed)
    }
}
fn validate_chain_id(chain_id: &str) -> Result<(), IrohaRuntimeProviderCatalogErrorV1> {
    let parsed = chain_id
        .parse::<iroha_model_base::chain::ChainId>()
        .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidChainId)?;
    if parsed.to_string() != chain_id {
        return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidChainId);
    }
    Ok(())
}
trait CatalogSlotResultV1 {
    fn into_catalog_slot(
        self,
    ) -> Result<IrohaRuntimeProviderSlotV1, IrohaRuntimeProviderCatalogErrorV1>;
}
impl CatalogSlotResultV1 for IrohaRuntimeProviderSlotV1 {
    fn into_catalog_slot(
        self,
    ) -> Result<IrohaRuntimeProviderSlotV1, IrohaRuntimeProviderCatalogErrorV1> {
        Ok(self)
    }
}
impl CatalogSlotResultV1
    for Result<IrohaRuntimeProviderSlotV1, IrohaRuntimeProviderCatalogErrorV1>
{
    fn into_catalog_slot(
        self,
    ) -> Result<IrohaRuntimeProviderSlotV1, IrohaRuntimeProviderCatalogErrorV1> {
        self
    }
}
fn validate_binding_sequence<S>(
    slots: impl IntoIterator<Item = S>,
) -> Result<(), IrohaRuntimeProviderCatalogErrorV1>
where
    S: CatalogSlotResultV1,
{
    let mut multiplicities = [0_usize; IrohaRuntimeProviderSlotV1::ALL.len()];
    let mut count = 0_usize;
    for slot in slots {
        let slot = slot.into_catalog_slot()?;
        count = count
            .checked_add(1)
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidOrder)?;
        if count > RUNTIME_PROVIDER_CATALOG_MAX_ENTRIES_V1 {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidOrder);
        }
        // Wire IDs are sparse. Count only positions in the canonical inventory.
        let index = IrohaRuntimeProviderSlotV1::ALL
            .binary_search(&slot)
            .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidOrder)?;
        multiplicities[index] = multiplicities[index]
            .checked_add(1)
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidOrder)?;
        if multiplicities[index] > slot.max_configured_multiplicity() {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidOrder);
        }
    }
    if count == 0 {
        return Err(IrohaRuntimeProviderCatalogErrorV1::EmptyCatalog);
    }
    Ok(())
}
fn validate_catalog_relationships(
    catalog: &IrohaRuntimeProviderBindingsV1,
) -> Result<(), IrohaRuntimeProviderCatalogErrorV1> {
    let find = |slot| catalog.iter().find(|binding| binding.slot() == slot);
    if let Some(binding) = find(IrohaRuntimeProviderSlotV1::StreamTokenSigner) {
        binding
            .stream_token_signer_binding()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?
            .validate_network(catalog.chain_id(), catalog.network_id().as_bytes())
            .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
    }
    let appeal_signers = catalog
        .iter()
        .filter(|binding| {
            binding.slot() == IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner
        })
        .collect::<Vec<_>>();
    let appeal_checkpoint = find(IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint);
    if appeal_signers.is_empty() != appeal_checkpoint.is_none() {
        return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
    }
    for (index, signer) in appeal_signers.iter().enumerate() {
        let exact = signer
            .appeal_finance_signer_binding()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        if appeal_signers[index + 1..]
            .iter()
            .any(|other| signer.handle() == other.handle())
        {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
        for other in &appeal_signers[index + 1..] {
            let other = other
                .appeal_finance_signer_binding()
                .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            if exact.authority != other.authority {
                continue;
            }
            let (earlier, later) = if exact.valid_from_block_height <= other.valid_from_block_height
            {
                (exact, other)
            } else {
                (other, exact)
            };
            if earlier
                .revoked_at_block_height
                .is_none_or(|revoked_at| later.valid_from_block_height < revoked_at)
            {
                return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
            }
        }
    }
    if let Some(checkpoint) = appeal_checkpoint {
        let checkpoint_exact = checkpoint
            .appeal_finance_checkpoint_binding()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        for signer in appeal_signers {
            let signer_exact = signer
                .appeal_finance_signer_binding()
                .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            if signer.handle() == checkpoint.handle()
                || signer_exact.public_key == checkpoint_exact.public_key
            {
                return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
            }
        }
    }
    let potr_gateway = find(IrohaRuntimeProviderSlotV1::PotrGatewaySigner);
    let potr_provider = find(IrohaRuntimeProviderSlotV1::PotrProviderSigner);
    match (potr_gateway, potr_provider) {
        (None, None) => {}
        (Some(gateway), Some(provider)) => {
            let gateway_runtime = gateway
                .potr_runtime_binding()
                .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            let provider_runtime = provider
                .potr_runtime_binding()
                .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            if gateway_runtime != provider_runtime {
                return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
            }
            let identities = [
                gateway_runtime.gateway_signer.signer_id,
                gateway_runtime.provider_signer.signer_id,
                gateway_runtime.reader_id,
                gateway_runtime.source_id,
                gateway_runtime.resolver_id,
            ];
            if identities.iter().enumerate().any(|(index, identity)| {
                identities[index + 1..]
                    .iter()
                    .any(|other| identity == other)
            }) {
                return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
            }
        }
        _ => return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding),
    }
    let fenced_publisher = find(IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher);
    let fenced_reader = find(IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader);
    match (fenced_publisher, fenced_reader) {
        (None, None) => {}
        (Some(publisher), Some(reader))
            if publisher.handle() == reader.handle()
                && publisher.revision() == reader.revision()
                && publisher.policy_digest() == reader.policy_digest() => {}
        _ => return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding),
    }
    let provider_source = find(IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource);
    let provider_resolver =
        find(IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver);
    let provider_signer = find(IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner);
    let provider_checkpoint = find(IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore);
    let provider_retention = find(IrohaRuntimeProviderSlotV1::ProviderIngestRetentionAuthority);
    if provider_source.is_some()
        || provider_resolver.is_some()
        || provider_signer.is_some()
        || provider_checkpoint.is_some()
        || provider_retention.is_some()
    {
        let (Some(_source), Some(resolver), Some(signer), Some(checkpoint)) = (
            provider_source,
            provider_resolver,
            provider_signer,
            provider_checkpoint,
        ) else {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        };
        let resolver_signer = resolver
            .provider_ingest_signer_binding()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        let signer_signer = signer
            .provider_ingest_signer_binding()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        let resolver_max_bytes = resolver
            .provider_ingest_max_signed_transaction_bytes()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        let signer_max_bytes = signer
            .provider_ingest_max_signed_transaction_bytes()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        let checkpoint_max_bytes = checkpoint
            .provider_ingest_checkpoint_max_bytes()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        if resolver_signer != signer_signer
            || resolver_max_bytes != signer_max_bytes
            || signer_max_bytes > checkpoint_max_bytes
        {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
    }
    let moderation_checkpoint = find(IrohaRuntimeProviderSlotV1::ModerationCheckpointStore);
    let moderation_archive = find(IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive);
    if let (Some(checkpoint), Some(archive)) = (moderation_checkpoint, moderation_archive) {
        let checkpoint_key = checkpoint
            .moderation_checkpoint_attestation_public_key()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        if checkpoint.handle() == archive.handle()
            || archive
                .moderation_panel_notification_archive_bootstrap_public_key()
                .is_some_and(|key| key == checkpoint_key)
            || archive
                .moderation_panel_notification_archive_public_key()
                .is_some_and(|key| key == checkpoint_key)
        {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
    }
    let evidence_checkpoint = find(IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore);
    let evidence_archive = find(IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive);
    if let (Some(checkpoint), Some(archive)) = (evidence_checkpoint, evidence_archive) {
        let checkpoint_max_bytes = checkpoint
            .evidence_viewer_checkpoint_max_bytes()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        let expected_archive_max_bytes = checkpoint_max_bytes
            .checked_add(16 * 1024)
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        if archive.evidence_viewer_archive_max_bytes() != Some(expected_archive_max_bytes) {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
    }
    let governance_ipfs = find(IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator);
    let governance_head = find(IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator);
    if let (Some(ipfs), Some(head)) = (governance_ipfs, governance_head) {
        let ipfs = ipfs
            .governance_request_ingress_binding()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        let head = head
            .governance_request_ingress_binding()
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        if ipfs.max_envelope_lifetime_secs() != head.max_envelope_lifetime_secs()
            || ipfs.max_future_skew_secs() != head.max_future_skew_secs()
        {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
    }
    Ok(())
}
fn compare_wire_bindings(
    left: &RuntimeProviderBindingWireV1,
    right: &RuntimeProviderBindingWireV1,
) -> Ordering {
    left.slot
        .cmp(&right.slot)
        .then_with(|| left.handle.cmp(&right.handle))
        .then_with(|| left.revision.cmp(&right.revision))
        .then_with(|| left.policy_digest.cmp(&right.policy_digest))
}
fn validate_wire_order(
    bindings: &[RuntimeProviderBindingWireV1],
) -> Result<(), IrohaRuntimeProviderCatalogErrorV1> {
    if bindings
        .windows(2)
        .any(|pair| compare_wire_bindings(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidOrder);
    }
    Ok(())
}
impl RuntimeProviderBindingWireV1 {
    fn try_from_binding(
        binding: &IrohaRuntimeProviderBindingV1,
    ) -> Result<Self, IrohaRuntimeProviderCatalogErrorV1> {
        if binding.handle().is_empty()
            || binding.handle().len() > RUNTIME_PROVIDER_HANDLE_MAX_BYTES_V1
            || binding.handle().as_bytes().contains(&0)
            || !is_production_runtime_handle(binding.handle())
        {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
        exact_qualification(binding.revision(), binding.policy_digest())?;
        Ok(Self {
            slot: binding.slot().wire_id(),
            handle: binding.handle().to_owned(),
            revision: binding.revision(),
            policy_digest: binding.policy_digest(),
            stream_token_signer_binding: binding.stream_token_signer_binding().cloned(),
            appeal_finance_signer_binding: binding.appeal_finance_signer_binding().map(|signer| {
                AppealFinanceSignerBindingWireV1 {
                    authority: signer.authority.clone(),
                    public_key: signer.public_key.clone(),
                    valid_from_block_height: signer.valid_from_block_height,
                    revoked_at_block_height: signer.revoked_at_block_height,
                }
            }),
            appeal_finance_checkpoint_binding: binding.appeal_finance_checkpoint_binding().map(
                |checkpoint| AppealFinanceCheckpointBindingWireV1 {
                    public_key: checkpoint.public_key.clone(),
                },
            ),
            appeal_finance_checkpoint_max_bytes: binding.appeal_finance_checkpoint_max_bytes(),
            pop_credential_runtime_binding: binding
                .pop_credential_runtime_binding()
                .map(PopCredentialRuntimeBindingWireV1::from),
            por_replay_archive_binding: binding.por_replay_archive_binding(),
            por_replay_archive_proof_limits: binding
                .por_replay_archive_proof_limits()
                .map(PorReplayArchiveProofLimitsWireV1::from),
            potr_runtime_binding: binding
                .potr_runtime_binding()
                .map(PotrRuntimeBindingWireV1::from),
            native_signer_binding: binding
                .native_signer_binding()
                .map(NativeTransactionSignerBindingWireV1::from_native)
                .or_else(|| {
                    binding
                        .soracloud_runtime_signer_binding()
                        .map(NativeTransactionSignerBindingWireV1::from_soracloud)
                }),
            governance_dag_publisher_peer_id: binding
                .governance_dag_publisher_peer_id()
                .map(<[u8]>::to_vec),
            governance_dag_publisher_public_key: binding.governance_dag_publisher_public_key(),
            governance_request_ingress_binding: binding
                .governance_request_ingress_binding()
                .map(GovernanceRequestIngressBindingWireV1::from),
            provider_ingest_signer_binding: binding
                .provider_ingest_signer_binding()
                .map(ProviderIngestSignerBindingWireV1::try_from_binding)
                .transpose()?,
            provider_ingest_source_limits: binding
                .provider_ingest_source_limits()
                .map(ProviderIngestSourceLimitsWireV1::from),
            provider_ingest_checkpoint_max_bytes: binding.provider_ingest_checkpoint_max_bytes(),
            provider_ingest_max_signed_transaction_bytes: binding
                .provider_ingest_max_signed_transaction_bytes(),
            evidence_viewer_webauthn_binding: binding
                .evidence_viewer_webauthn_binding()
                .map(EvidenceViewerWebAuthnBindingWireV1::from),
            evidence_viewer_grant_ttl_ms: binding.evidence_viewer_grant_ttl_ms(),
            evidence_viewer_receipt_signer_public_key: binding
                .evidence_viewer_receipt_signer_public_key(),
            evidence_viewer_transparency_publisher_public_key: binding
                .evidence_viewer_transparency_publisher_public_key(),
            evidence_viewer_checkpoint_max_bytes: binding.evidence_viewer_checkpoint_max_bytes(),
            moderation_checkpoint_max_bytes: binding.moderation_checkpoint_max_bytes(),
            moderation_checkpoint_attestation_public_key: binding
                .moderation_checkpoint_attestation_public_key(),
            evidence_viewer_archive_id: binding.evidence_viewer_archive_id(),
            evidence_viewer_archive_public_key: binding.evidence_viewer_archive_public_key(),
            evidence_viewer_archive_max_bytes: binding.evidence_viewer_archive_max_bytes(),
            moderation_panel_notification_archive_binding: binding
                .moderation_panel_notification_archive_id()
                .zip(binding.moderation_panel_notification_archive_bootstrap_public_key())
                .zip(binding.moderation_panel_notification_archive_public_key())
                .zip(binding.moderation_panel_notification_archive_max_bytes())
                .zip(binding.moderation_panel_notification_archive_max_records())
                .map(
                    |(
                        (((archive_id, bootstrap_public_key), public_key), max_bytes),
                        max_records,
                    )| ModerationPanelNotificationArchiveBindingWireV1 {
                        archive_id,
                        bootstrap_public_key,
                        public_key,
                        max_bytes,
                        max_records,
                    },
                ),
        })
    }
    fn try_into_binding(
        self,
    ) -> Result<IrohaRuntimeProviderBindingV1, IrohaRuntimeProviderCatalogErrorV1> {
        let expected = self.clone();
        let slot = IrohaRuntimeProviderSlotV1::from_wire_id(self.slot)
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        if self.handle.is_empty()
            || self.handle.len() > RUNTIME_PROVIDER_HANDLE_MAX_BYTES_V1
            || self.handle.as_bytes().contains(&0)
            || !is_production_runtime_handle(&self.handle)
        {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
        let (revision, policy_digest) = exact_qualification(self.revision, self.policy_digest)?;
        let mut binding = IrohaRuntimeProviderBindingV1::try_new(
            slot,
            self.handle.clone(),
            Some(revision),
            Some(policy_digest),
        )
        .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        match slot {
            IrohaRuntimeProviderSlotV1::GovernanceDagSigner => {
                let peer_id = self
                    .governance_dag_publisher_peer_id
                    .as_deref()
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                let public_key = self
                    .governance_dag_publisher_public_key
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                binding = IrohaRuntimeProviderBindingV1::try_new_governance_dag_signer(
                    self.handle.clone(),
                    revision,
                    policy_digest,
                    peer_id,
                    &hex::encode(public_key),
                )
                .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            }
            IrohaRuntimeProviderSlotV1::StreamTokenSigner => {
                binding = IrohaRuntimeProviderBindingV1::try_new_stream_token_signer(
                    self.stream_token_signer_binding
                        .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?,
                )
                .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            }
            IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner => {
                let exact = self
                    .appeal_finance_signer_binding
                    .as_ref()
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                binding = IrohaRuntimeProviderBindingV1::try_new_appeal_finance_signer(
                    &iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                        handle: self.handle.clone(),
                        authority: exact.authority.clone(),
                        public_key: exact.public_key.clone(),
                        revision,
                        policy_digest,
                        valid_from_block_height: exact.valid_from_block_height,
                        revoked_at_block_height: exact.revoked_at_block_height,
                    },
                )
                .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            }
            IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint => {
                let exact = self
                    .appeal_finance_checkpoint_binding
                    .as_ref()
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                let checkpoint_max_bytes = self
                    .appeal_finance_checkpoint_max_bytes
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                if !(torii_defaults::
                    SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MIN_BYTES_V1
                    ..=torii_defaults::
                        SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MAX_BYTES_LIMIT_V1)
                    .contains(&checkpoint_max_bytes)
                {
                    return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
                }
                binding = IrohaRuntimeProviderBindingV1::try_new_appeal_finance_checkpoint(
                    &iroha_config::parameters::actual::SorafsAppealFinanceCheckpointBinding {
                        handle: self.handle.clone(),
                        public_key: exact.public_key.clone(),
                        revision,
                        policy_digest,
                    },
                    checkpoint_max_bytes,
                )
                .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            }
            IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry => {
                let exact = self
                    .pop_credential_runtime_binding
                    .as_ref()
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                validate_pop_binding(exact)?;
                binding.pop_credential_runtime_binding = Some(PopCredentialRuntimeBindingV1 {
                    issuer_policy_digest: exact.issuer_policy_digest,
                    issuer_id: exact.issuer_id.clone(),
                    issuer_signer_handle: exact.issuer_signer_handle.clone(),
                    issuer_public_key: exact.issuer_public_key,
                    enrollment_recipient_key_id: exact.enrollment_recipient_key_id.clone(),
                    enrollment_recipient_public_key_digest: exact
                        .enrollment_recipient_public_key_digest,
                    wallet_recipient_key_id: exact.wallet_recipient_key_id.clone(),
                    wallet_recipient_public_key_digest: exact.wallet_recipient_public_key_digest,
                    wallet_wrapping_key_id: exact.wallet_wrapping_key_id.clone(),
                });
            }
            IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive => {
                let exact = self
                    .por_replay_archive_binding
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                let limits = self
                    .por_replay_archive_proof_limits
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                validate_por_binding(&self.handle, revision, policy_digest, exact, limits)?;
                binding.por_replay_archive_binding = Some(exact);
                binding.por_replay_archive_proof_limits = Some(PorReplayArchiveProofLimitsV1 {
                    max_successor_receipts: limits.max_successor_receipts,
                    max_successor_proof_bytes: limits.max_successor_proof_bytes,
                });
            }
            IrohaRuntimeProviderSlotV1::PotrGatewaySigner
            | IrohaRuntimeProviderSlotV1::PotrProviderSigner => {
                let runtime = self
                    .potr_runtime_binding
                    .as_ref()
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?
                    .to_binding();
                binding = IrohaRuntimeProviderBindingV1::try_new_potr_signer(slot, &runtime)
                    .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            }
            IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator
            | IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator => {
                binding = IrohaRuntimeProviderBindingV1::try_new_governance_request_auth(
                    slot,
                    self.handle.clone(),
                    revision,
                    policy_digest,
                    self.governance_request_ingress_binding
                        .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?
                        .try_into_binding()?,
                )
                .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            }
            IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner
            | IrohaRuntimeProviderSlotV1::RepairTransactionSigner
            | IrohaRuntimeProviderSlotV1::ReserveTransactionSigner
            | IrohaRuntimeProviderSlotV1::OrderbookTransactionSigner => {
                let exact = self
                    .native_signer_binding
                    .as_ref()
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                let native = exact.to_native_binding(
                    slot,
                    &self.handle,
                    revision,
                    policy_digest,
                )?;
                binding = IrohaRuntimeProviderBindingV1::try_new_native_signer(slot, native)
                    .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            }
            IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner => {
                let exact = self
                    .native_signer_binding
                    .as_ref()
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                if exact.role != 5 {
                    return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
                }
                let signer = crate::soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1::try_new(
                    self.handle.clone(),
                    exact.authority.clone(),
                    exact.public_key.clone(),
                    crate::soracloud_runtime_signer::SoracloudRuntimeSignerQualificationV1::new(
                        revision,
                        policy_digest,
                        true,
                        false,
                    ),
                )
                .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                binding.soracloud_runtime_signer_binding = Some(signer);
            }
            IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource => {
                let limits = self
                    .provider_ingest_source_limits
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                binding = IrohaRuntimeProviderBindingV1::try_new_provider_ingest_source(
                    self.handle.clone(),
                    revision,
                    policy_digest,
                    ProviderIngestSourceLimitsV1::from(limits),
                )
                .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            }
            IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver
            | IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner => {
                let signer = self
                    .provider_ingest_signer_binding
                    .as_ref()
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?
                    .to_binding()?;
                if slot == IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner
                    && (self.handle != signer.runtime_handle
                        || revision != signer.qualification.adapter_revision
                        || policy_digest != signer.qualification.signer_policy.policy_digest)
                {
                    return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
                }
                binding = IrohaRuntimeProviderBindingV1::try_new_provider_ingest_signer(
                    slot,
                    self.handle.clone(),
                    revision,
                    policy_digest,
                    signer,
                    self.provider_ingest_max_signed_transaction_bytes
                        .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?,
                )
                .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            }
            IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore => {
                binding = IrohaRuntimeProviderBindingV1::try_new_provider_ingest_checkpoint(
                    self.handle.clone(),
                    revision,
                    policy_digest,
                    self.provider_ingest_checkpoint_max_bytes
                        .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?,
                )
                .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
            }
            IrohaRuntimeProviderSlotV1::ModerationCheckpointStore => {
                let max_bytes = self
                    .moderation_checkpoint_max_bytes
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                let public_key = self
                    .moderation_checkpoint_attestation_public_key
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                if max_bytes == 0
                    || max_bytes
                        > sorafs_node::moderation_orchestrator::
                            MODERATION_ORCHESTRATOR_CHECKPOINT_MAX_BYTES_V1
                    || !valid_ed25519(public_key)
                {
                    return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
                }
                binding.moderation_checkpoint_max_bytes = Some(max_bytes);
                binding.moderation_checkpoint_attestation_public_key = Some(public_key);
            }
            IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive => {
                let archive = self
                    .moderation_panel_notification_archive_binding
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                validate_moderation_archive(archive)?;
                binding.moderation_panel_notification_archive_id = Some(archive.archive_id);
                binding.moderation_panel_notification_archive_bootstrap_public_key =
                    Some(archive.bootstrap_public_key);
                binding.moderation_panel_notification_archive_public_key = Some(archive.public_key);
                binding.moderation_panel_notification_archive_max_bytes = Some(archive.max_bytes);
                binding.moderation_panel_notification_archive_max_records =
                    Some(archive.max_records);
            }
            IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn => {
                let webauthn = self
                    .evidence_viewer_webauthn_binding
                    .as_ref()
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                validate_webauthn(webauthn)?;
                binding.evidence_viewer_webauthn_binding = Some(EvidenceViewerWebAuthnBindingV1 {
                    rp_id: webauthn.rp_id.clone(),
                    allowed_origins: webauthn.allowed_origins.clone(),
                    challenge_ttl_ms: webauthn.challenge_ttl_ms,
                });
            }
            IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority => {
                let ttl = self
                    .evidence_viewer_grant_ttl_ms
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                if ttl == 0
                    || ttl
                        > sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_SESSION_TTL_MS_V1
                {
                    return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
                }
                binding.evidence_viewer_grant_ttl_ms = Some(ttl);
            }
            IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner => {
                let public_key = self
                    .evidence_viewer_receipt_signer_public_key
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                if !valid_ed25519(public_key) {
                    return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
                }
                binding.evidence_viewer_receipt_signer_public_key = Some(public_key);
            }
            IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore => {
                let max_bytes = self
                    .evidence_viewer_checkpoint_max_bytes
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                if max_bytes == 0
                    || max_bytes
                        > sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_CHECKPOINT_BYTES_V1
                {
                    return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
                }
                binding.evidence_viewer_checkpoint_max_bytes = Some(max_bytes);
            }
            IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive => {
                let archive_id = self
                    .evidence_viewer_archive_id
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                let public_key = self
                    .evidence_viewer_archive_public_key
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                let max_bytes = self
                    .evidence_viewer_archive_max_bytes
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                if archive_id == [0; 32]
                    || !valid_ed25519(public_key)
                    || max_bytes == 0
                    || max_bytes > EVIDENCE_VIEWER_ARCHIVE_MAX_BYTES_V1
                {
                    return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
                }
                binding.evidence_viewer_archive_id = Some(archive_id);
                binding.evidence_viewer_archive_public_key = Some(public_key);
                binding.evidence_viewer_archive_max_bytes = Some(max_bytes);
            }
            IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher => {
                let public_key = self
                    .evidence_viewer_transparency_publisher_public_key
                    .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
                if !valid_ed25519(public_key) {
                    return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
                }
                binding.evidence_viewer_transparency_publisher_public_key = Some(public_key);
            }
            IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint => {
                if revision
                    != sorafs_node::reputation::runtime::
                        REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1
                {
                    return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
                }
            }
            _ => {}
        }
        if RuntimeProviderBindingWireV1::try_from_binding(&binding)? != expected {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
        Ok(binding)
    }
}
fn exact_qualification(
    revision: Option<u64>,
    policy_digest: Option<[u8; 32]>,
) -> Result<(u64, [u8; 32]), IrohaRuntimeProviderCatalogErrorV1> {
    match (revision, policy_digest) {
        (Some(revision), Some(policy_digest)) if revision != 0 && policy_digest != [0; 32] => {
            Ok((revision, policy_digest))
        }
        _ => Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding),
    }
}
fn valid_ed25519(public_key: [u8; 32]) -> bool {
    public_key != [0; 32] && iroha_crypto::ed25519_parse_public_key(&public_key).is_ok()
}
fn validate_pop_binding(
    binding: &PopCredentialRuntimeBindingWireV1,
) -> Result<(), IrohaRuntimeProviderCatalogErrorV1> {
    if binding.issuer_policy_digest == [0; 32]
        || binding.issuer_id.is_empty()
        || binding.issuer_id.len()
            > sorafs_manifest::pop_credentials::POP_IDENTITY_TEXT_MAX_BYTES_V1
        || binding.issuer_id.trim() != binding.issuer_id
        || binding.issuer_id.chars().any(char::is_control)
        || !is_production_runtime_handle(&binding.issuer_signer_handle)
        || !is_production_runtime_handle(&binding.enrollment_recipient_key_id)
        || !is_production_runtime_handle(&binding.wallet_recipient_key_id)
        || !is_production_runtime_handle(&binding.wallet_wrapping_key_id)
        || binding.enrollment_recipient_public_key_digest == [0; 32]
        || binding.wallet_recipient_public_key_digest == [0; 32]
        || !valid_ed25519(binding.issuer_public_key)
    {
        return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
    }
    Ok(())
}
fn validate_por_binding(
    handle: &str,
    revision: u64,
    policy_digest: [u8; 32],
    binding: sorafs_node::PorFinalizedReplayArchiveBindingV1,
    limits: PorReplayArchiveProofLimitsWireV1,
) -> Result<(), IrohaRuntimeProviderCatalogErrorV1> {
    if binding.revision != revision || binding.policy_digest != policy_digest {
        return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
    }
    sorafs_node::PorFinalizedReplayArchiveBindingV1::try_new(
        binding.archive_id,
        binding.revision,
        binding.policy_digest,
        binding.signing_public_key,
    )
    .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
    sorafs_node::PorFinalizedReplayArchiveProofBoundsV1::try_new(
        limits.max_successor_receipts,
        limits.max_successor_proof_bytes,
    )
    .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
    if !is_production_runtime_handle(handle)
        || limits.max_successor_receipts
            > iroha_config::parameters::defaults::sorafs::storage::por_replay_archive::
                MAX_SUCCESSOR_RECEIPTS_LIMIT
        || limits.max_successor_proof_bytes
            > iroha_config::parameters::defaults::sorafs::storage::por_replay_archive::
                MAX_SUCCESSOR_PROOF_BYTES_LIMIT
    {
        return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
    }
    Ok(())
}
fn validate_moderation_archive(
    archive: ModerationPanelNotificationArchiveBindingWireV1,
) -> Result<(), IrohaRuntimeProviderCatalogErrorV1> {
    let max_records = u64::try_from(
        sorafs_node::moderation_orchestrator::MODERATION_PANEL_NOTIFICATION_ARCHIVE_MAX_RECORDS_V1,
    )
    .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
    if archive.archive_id == [0; 32]
        || !valid_ed25519(archive.bootstrap_public_key)
        || !valid_ed25519(archive.public_key)
        || !(moderation_defaults::PANEL_NOTIFICATION_ARCHIVE_MIN_BYTES_V1
            ..=moderation_defaults::PANEL_NOTIFICATION_ARCHIVE_MAX_BYTES_LIMIT_V1)
            .contains(&archive.max_bytes)
        || archive.max_records == 0
        || archive.max_records > max_records
    {
        return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
    }
    Ok(())
}
fn validate_webauthn(
    binding: &EvidenceViewerWebAuthnBindingWireV1,
) -> Result<(), IrohaRuntimeProviderCatalogErrorV1> {
    let mut canonical_origins = binding.allowed_origins.clone();
    canonical_origins.sort();
    canonical_origins.dedup();
    if validate_webauthn_rp_id_v1(&binding.rp_id).is_err()
        || binding.allowed_origins.is_empty()
        || binding.allowed_origins.len() > 16
        || canonical_origins != binding.allowed_origins
        || binding
            .allowed_origins
            .iter()
            .any(|origin| validate_webauthn_origin_v1(origin, &binding.rp_id).is_err())
        || binding.challenge_ttl_ms == 0
        || binding.challenge_ttl_ms
            > sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_SESSION_TTL_MS_V1
    {
        return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
    }
    Ok(())
}
impl From<&PopCredentialRuntimeBindingV1> for PopCredentialRuntimeBindingWireV1 {
    fn from(binding: &PopCredentialRuntimeBindingV1) -> Self {
        Self {
            issuer_policy_digest: binding.issuer_policy_digest,
            issuer_id: binding.issuer_id.clone(),
            issuer_signer_handle: binding.issuer_signer_handle.clone(),
            issuer_public_key: binding.issuer_public_key,
            enrollment_recipient_key_id: binding.enrollment_recipient_key_id.clone(),
            enrollment_recipient_public_key_digest: binding.enrollment_recipient_public_key_digest,
            wallet_recipient_key_id: binding.wallet_recipient_key_id.clone(),
            wallet_recipient_public_key_digest: binding.wallet_recipient_public_key_digest,
            wallet_wrapping_key_id: binding.wallet_wrapping_key_id.clone(),
        }
    }
}
impl From<PorReplayArchiveProofLimitsV1> for PorReplayArchiveProofLimitsWireV1 {
    fn from(limits: PorReplayArchiveProofLimitsV1) -> Self {
        Self {
            max_successor_receipts: limits.max_successor_receipts,
            max_successor_proof_bytes: limits.max_successor_proof_bytes,
        }
    }
}
impl From<&iroha_config::parameters::actual::SorafsPotrRuntimeBinding>
    for PotrRuntimeBindingWireV1
{
    fn from(binding: &iroha_config::parameters::actual::SorafsPotrRuntimeBinding) -> Self {
        let admission = &binding.baseline_admission_policy;
        Self {
            gateway_handle: binding.gateway_signer.handle.clone(),
            gateway_signer_id: binding.gateway_signer.signer_id,
            gateway_revision: binding.gateway_signer.revision,
            gateway_policy_digest: binding.gateway_signer.policy_digest,
            provider_handle: binding.provider_signer.handle.clone(),
            provider_signer_id: binding.provider_signer.signer_id,
            provider_revision: binding.provider_signer.revision,
            provider_policy_digest: binding.provider_signer.policy_digest,
            gateway_public_key: binding.gateway_public_key,
            reader_id: binding.reader_id,
            source_id: binding.source_id,
            resolver_id: binding.resolver_id,
            baseline_admission_policy: PotrAdmissionPolicyBindingWireV1 {
                provider_id: admission.provider_id,
                policy_identity: admission.policy_identity,
                policy_digest: admission.policy_digest,
                policy_sequence: admission.policy_sequence,
                finalized_height: admission.finalized_height,
                finalized_block_hash: admission.finalized_block_hash,
                admission_envelope_digest: admission.admission_envelope_digest,
            },
        }
    }
}
impl PotrRuntimeBindingWireV1 {
    fn to_binding(&self) -> iroha_config::parameters::actual::SorafsPotrRuntimeBinding {
        iroha_config::parameters::actual::SorafsPotrRuntimeBinding {
            gateway_signer: iroha_config::parameters::actual::SorafsPotrRuntimeSignerBinding {
                handle: self.gateway_handle.clone(),
                signer_id: self.gateway_signer_id,
                revision: self.gateway_revision,
                policy_digest: self.gateway_policy_digest,
            },
            provider_signer: iroha_config::parameters::actual::SorafsPotrRuntimeSignerBinding {
                handle: self.provider_handle.clone(),
                signer_id: self.provider_signer_id,
                revision: self.provider_revision,
                policy_digest: self.provider_policy_digest,
            },
            gateway_public_key: self.gateway_public_key,
            reader_id: self.reader_id,
            source_id: self.source_id,
            resolver_id: self.resolver_id,
            baseline_admission_policy:
                iroha_config::parameters::actual::SorafsPotrAdmissionPolicyBinding {
                    provider_id: self.baseline_admission_policy.provider_id,
                    policy_identity: self.baseline_admission_policy.policy_identity,
                    policy_digest: self.baseline_admission_policy.policy_digest,
                    policy_sequence: self.baseline_admission_policy.policy_sequence,
                    finalized_height: self.baseline_admission_policy.finalized_height,
                    finalized_block_hash: self.baseline_admission_policy.finalized_block_hash,
                    admission_envelope_digest: self
                        .baseline_admission_policy
                        .admission_envelope_digest,
                },
        }
    }
}
const fn native_role_to_wire(role: iroha_torii::SorafsNativeTransactionSignerRoleV1) -> u8 {
    match role {
        iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome => 1,
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Repair => 2,
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Reserve => 3,
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Orderbook => 4,
    }
}
fn native_role_from_slot(
    slot: IrohaRuntimeProviderSlotV1,
) -> Option<iroha_torii::SorafsNativeTransactionSignerRoleV1> {
    use iroha_torii::SorafsNativeTransactionSignerRoleV1 as Role;
    match slot {
        IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner => Some(Role::ProofOutcome),
        IrohaRuntimeProviderSlotV1::RepairTransactionSigner => Some(Role::Repair),
        IrohaRuntimeProviderSlotV1::ReserveTransactionSigner => Some(Role::Reserve),
        IrohaRuntimeProviderSlotV1::OrderbookTransactionSigner => Some(Role::Orderbook),
        _ => None,
    }
}
impl NativeTransactionSignerBindingWireV1 {
    fn from_native(binding: &iroha_torii::SorafsNativeTransactionSignerBindingV1) -> Self {
        Self {
            role: native_role_to_wire(binding.role()),
            authority: binding.authority().clone(),
            public_key: binding.public_key().clone(),
        }
    }
    fn from_soracloud(
        binding: &crate::soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1,
    ) -> Self {
        Self {
            role: 5,
            authority: binding.authority().clone(),
            public_key: binding.public_key().clone(),
        }
    }
    fn to_native_binding(
        &self,
        slot: IrohaRuntimeProviderSlotV1,
        handle: &str,
        revision: u64,
        policy_digest: [u8; 32],
    ) -> Result<
        iroha_torii::SorafsNativeTransactionSignerBindingV1,
        IrohaRuntimeProviderCatalogErrorV1,
    > {
        let role = native_role_from_slot(slot)
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        if self.role != native_role_to_wire(role) {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
        iroha_torii::SorafsNativeTransactionSignerBindingV1::try_new(
            role,
            handle,
            self.authority.clone(),
            self.public_key.clone(),
            iroha_torii::SorafsNativeTransactionSignerQualificationV1::new(revision, policy_digest),
        )
        .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)
    }
}
impl From<&EvidenceViewerWebAuthnBindingV1> for EvidenceViewerWebAuthnBindingWireV1 {
    fn from(binding: &EvidenceViewerWebAuthnBindingV1) -> Self {
        Self {
            rp_id: binding.rp_id.clone(),
            allowed_origins: binding.allowed_origins.clone(),
            challenge_ttl_ms: binding.challenge_ttl_ms,
        }
    }
}
impl From<ProviderIngestSourceLimitsV1> for ProviderIngestSourceLimitsWireV1 {
    fn from(limits: ProviderIngestSourceLimitsV1) -> Self {
        Self {
            operation_timeout_ms: limits.operation_timeout_ms,
            max_content_bytes: limits.max_content_bytes,
            max_source_providers: limits.max_source_providers,
            max_concurrent_streams: limits.max_concurrent_streams,
        }
    }
}
impl From<ProviderIngestSourceLimitsWireV1> for ProviderIngestSourceLimitsV1 {
    fn from(limits: ProviderIngestSourceLimitsWireV1) -> Self {
        Self {
            operation_timeout_ms: limits.operation_timeout_ms,
            max_content_bytes: limits.max_content_bytes,
            max_source_providers: limits.max_source_providers,
            max_concurrent_streams: limits.max_concurrent_streams,
        }
    }
}
impl ProviderIngestSignerBindingWireV1 {
    fn try_from_binding(
        binding: &sorafs_node::ProviderIngestCompletionSignerBindingV1,
    ) -> Result<Self, IrohaRuntimeProviderCatalogErrorV1> {
        binding
            .validate()
            .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        let (algorithm, public_key) = binding
            .qualification
            .public_key
            .try_to_bytes()
            .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        let algorithm = provider_ingest_algorithm_to_wire(algorithm)
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        if public_key.is_empty() || public_key.len() > 16 * 1024 {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
        Ok(Self {
            runtime_handle: binding.runtime_handle.clone(),
            adapter_revision: binding.qualification.adapter_revision,
            signer_policy_id: binding.qualification.signer_policy.policy_id,
            signer_policy_revision: binding.qualification.signer_policy.revision,
            signer_policy_predecessor_digest: binding
                .qualification
                .signer_policy
                .predecessor_digest,
            signer_policy_digest: binding.qualification.signer_policy.policy_digest,
            algorithm,
            public_key: public_key.to_vec(),
        })
    }
    fn to_binding(
        &self,
    ) -> Result<
        sorafs_node::ProviderIngestCompletionSignerBindingV1,
        IrohaRuntimeProviderCatalogErrorV1,
    > {
        let algorithm = provider_ingest_algorithm_from_wire(self.algorithm)
            .ok_or(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        if !is_production_runtime_handle(&self.runtime_handle)
            || self.adapter_revision == 0
            || self.signer_policy_id == [0; 32]
            || self.signer_policy_revision == 0
            || self.signer_policy_digest == [0; 32]
            || self.public_key.is_empty()
            || self.public_key.len() > 16 * 1024
        {
            return Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding);
        }
        let public_key = iroha_crypto::PublicKey::from_bytes(algorithm, &self.public_key)
            .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        let binding = sorafs_node::ProviderIngestCompletionSignerBindingV1::new(
            self.runtime_handle.clone(),
            sorafs_node::ProviderIngestCompletionSignerQualificationV1::new(
                self.adapter_revision,
                iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1 {
                    policy_id: self.signer_policy_id,
                    revision: self.signer_policy_revision,
                    predecessor_digest: self.signer_policy_predecessor_digest,
                    policy_digest: self.signer_policy_digest,
                },
                algorithm,
                public_key,
            ),
        );
        binding
            .validate()
            .map_err(|_| IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)?;
        Ok(binding)
    }
}
const fn provider_ingest_algorithm_to_wire(algorithm: iroha_crypto::Algorithm) -> Option<u8> {
    match algorithm {
        iroha_crypto::Algorithm::Ed25519 => Some(1),
        iroha_crypto::Algorithm::MlDsa => Some(2),
        _ => None,
    }
}
const fn provider_ingest_algorithm_from_wire(wire: u8) -> Option<iroha_crypto::Algorithm> {
    match wire {
        1 => Some(iroha_crypto::Algorithm::Ed25519),
        2 => Some(iroha_crypto::Algorithm::MlDsa),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "irohad::runtime_provider_registry::catalog::tests::RetiredRuntimeProviderCatalogWireV1"
    )]
    #[derive(Encode)]
    struct RetiredRuntimeProviderCatalogWireV1 {
        magic: [u8; 8],
        version: u16,
        chain_id: String,
        network_id: Option<NetworkId>,
        bindings: Vec<RuntimeProviderBindingWireV1>,
    }
    fn generic_catalog() -> IrohaRuntimeProviderBindingsV1 {
        IrohaRuntimeProviderBindingsV1::qualified_for_test(
            "sorafs-catalog-test",
            IrohaRuntimeProviderSlotV1::BillingFinalizedQuery,
            "ledger://billing/finalized-query/primary",
            7,
            [0x31; 32],
        )
    }
    fn canonical_wire() -> RuntimeProviderCatalogWireV1 {
        RuntimeProviderCatalogWireV1::try_from_bindings(&generic_catalog())
            .expect("project canonical test catalog")
    }
    fn webauthn_wire(
        rp_id: &str,
        allowed_origins: impl IntoIterator<Item = &'static str>,
    ) -> RuntimeProviderCatalogWireV1 {
        let mut wire = canonical_wire();
        let binding = wire.bindings.first_mut().expect("one catalog binding");
        binding.slot = IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn.wire_id();
        binding.handle = "webauthn://sorafs/evidence-viewer/primary".to_owned();
        binding.revision = Some(11);
        binding.policy_digest = Some([0xA1; 32]);
        binding.evidence_viewer_webauthn_binding = Some(EvidenceViewerWebAuthnBindingWireV1 {
            rp_id: rp_id.to_owned(),
            allowed_origins: allowed_origins.into_iter().map(str::to_owned).collect(),
            challenge_ttl_ms: 60_000,
        });
        wire
    }
    fn load_wire(
        wire: &RuntimeProviderCatalogWireV1,
    ) -> Result<IrohaRuntimeProviderBindingsV1, IrohaRuntimeProviderCatalogErrorV1> {
        let bytes = norito::encode_canonical(wire).expect("encode catalog fixture");
        IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes)
    }
    fn catalog_from_bindings(
        mut bindings: Vec<IrohaRuntimeProviderBindingV1>,
    ) -> IrohaRuntimeProviderBindingsV1 {
        bindings.sort_unstable_by(|left, right| {
            left.slot()
                .cmp(&right.slot())
                .then_with(|| left.handle().cmp(right.handle()))
                .then_with(|| left.revision().cmp(&right.revision()))
                .then_with(|| left.policy_digest().cmp(&right.policy_digest()))
        });
        IrohaRuntimeProviderBindingsV1 {
            chain_id: "sorafs-catalog-test".to_owned(),
            network_id: runtime_provider_test_network_id(),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings,
        }
    }
    fn wire_from_bindings(
        bindings: Vec<IrohaRuntimeProviderBindingV1>,
    ) -> RuntimeProviderCatalogWireV1 {
        RuntimeProviderCatalogWireV1::try_from_bindings(&catalog_from_bindings(bindings))
            .expect("project valid relationship fixture")
    }
    fn assert_invalid_wire(wire: &RuntimeProviderCatalogWireV1) {
        let bytes = norito::encode_canonical(wire).expect("encode canonical negative fixture");
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes),
            Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)
        );
    }
    fn assert_valid_wire(wire: &RuntimeProviderCatalogWireV1) {
        let bytes = norito::encode_canonical(wire).expect("encode canonical positive fixture");
        IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes)
            .expect("load canonical positive fixture");
    }
    fn wire_binding_mut(
        wire: &mut RuntimeProviderCatalogWireV1,
        slot: IrohaRuntimeProviderSlotV1,
    ) -> &mut RuntimeProviderBindingWireV1 {
        wire.bindings
            .iter_mut()
            .find(|binding| binding.slot == slot.wire_id())
            .expect("wire fixture contains requested slot")
    }
    fn ed25519_key(seed: u8) -> iroha_crypto::PublicKey {
        iroha_crypto::KeyPair::try_from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("derive deterministic Ed25519 fixture")
            .public_key()
            .clone()
    }
    fn ed25519_bytes(seed: u8) -> [u8; 32] {
        ed25519_key(seed)
            .to_bytes()
            .1
            .try_into()
            .expect("Ed25519 fixture key width")
    }
    fn appeal_signer(
        seed: u8,
        handle: &str,
        revision: u64,
        valid_from_block_height: u64,
        revoked_at_block_height: Option<u64>,
    ) -> IrohaRuntimeProviderBindingV1 {
        let public_key = ed25519_key(seed);
        IrohaRuntimeProviderBindingV1::try_new_appeal_finance_signer(
            &iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                handle: handle.to_owned(),
                authority: iroha_data_model::account::AccountId::new(public_key.clone()),
                public_key,
                revision,
                policy_digest: [u8::try_from(revision).expect("test revision fits u8"); 32],
                valid_from_block_height,
                revoked_at_block_height,
            },
        )
        .expect("construct appeal-finance signer fixture")
    }
    fn appeal_checkpoint(seed: u8) -> IrohaRuntimeProviderBindingV1 {
        IrohaRuntimeProviderBindingV1::try_new_appeal_finance_checkpoint(
            &iroha_config::parameters::actual::SorafsAppealFinanceCheckpointBinding {
                handle: "sealed://sorafs/appeal-finance/checkpoint-primary".to_owned(),
                public_key: ed25519_key(seed),
                revision: 9,
                policy_digest: [0xA9; 32],
            },
            64 * 1024,
        )
        .expect("construct appeal-finance checkpoint fixture")
    }
    fn valid_potr_runtime() -> iroha_config::parameters::actual::SorafsPotrRuntimeBinding {
        iroha_config::parameters::actual::SorafsPotrRuntimeBinding {
            gateway_signer: iroha_config::parameters::actual::SorafsPotrRuntimeSignerBinding {
                handle: "software://sorafs/potr/gateway-primary".to_owned(),
                signer_id: [0x11; 32],
                revision: 3,
                policy_digest: [0x22; 32],
            },
            provider_signer: iroha_config::parameters::actual::SorafsPotrRuntimeSignerBinding {
                handle: "software://sorafs/potr/provider-primary".to_owned(),
                signer_id: [0x33; 32],
                revision: 7,
                policy_digest: [0x44; 32],
            },
            gateway_public_key: ed25519_bytes(0x71),
            reader_id: [0x55; 32],
            source_id: [0x66; 32],
            resolver_id: [0x77; 32],
            baseline_admission_policy:
                iroha_config::parameters::actual::SorafsPotrAdmissionPolicyBinding {
                    provider_id: [0x88; 32],
                    policy_identity: [0x99; 32],
                    policy_digest: [0x44; 32],
                    policy_sequence: 7,
                    finalized_height: 41,
                    finalized_block_hash: [0xAA; 32],
                    admission_envelope_digest: [0xBB; 32],
                },
        }
    }
    fn potr_wire() -> RuntimeProviderCatalogWireV1 {
        let runtime = valid_potr_runtime();
        wire_from_bindings(
            [
                IrohaRuntimeProviderSlotV1::PotrGatewaySigner,
                IrohaRuntimeProviderSlotV1::PotrProviderSigner,
            ]
            .into_iter()
            .map(|slot| {
                IrohaRuntimeProviderBindingV1::try_new_potr_signer(slot, &runtime)
                    .expect("construct PoTR fixture")
            })
            .collect(),
        )
    }
    fn provider_ingest_wire() -> RuntimeProviderCatalogWireV1 {
        let signer = sorafs_node::ProviderIngestCompletionSignerBindingV1::new(
            "software://sorafs/provider-ingest/signer-primary",
            sorafs_node::ProviderIngestCompletionSignerQualificationV1::new(
                3,
                iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1 {
                    policy_id: [0xA1; 32],
                    revision: 1,
                    predecessor_digest: None,
                    policy_digest: [0xA2; 32],
                },
                iroha_crypto::Algorithm::Ed25519,
                ed25519_key(0x61),
            ),
        );
        let max_signed_transaction_bytes =
            provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN;
        wire_from_bindings(vec![
            IrohaRuntimeProviderBindingV1::try_new_provider_ingest_source(
                "network://sorafs/provider-ingest/source-primary",
                5,
                [0xB1; 32],
                ProviderIngestSourceLimitsV1 {
                    operation_timeout_ms: 30_000,
                    max_content_bytes: 8 * 1024 * 1024,
                    max_source_providers: 16,
                    max_concurrent_streams: 4,
                },
            )
            .expect("construct provider-ingest source fixture"),
            IrohaRuntimeProviderBindingV1::try_new_provider_ingest_signer(
                IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver,
                "resolver://sorafs/provider-ingest/primary",
                6,
                [0xB2; 32],
                signer.clone(),
                max_signed_transaction_bytes,
            )
            .expect("construct provider-ingest resolver fixture"),
            IrohaRuntimeProviderBindingV1::try_new_provider_ingest_signer(
                IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner,
                signer.runtime_handle.clone(),
                signer.qualification.adapter_revision,
                signer.qualification.signer_policy.policy_digest,
                signer,
                max_signed_transaction_bytes,
            )
            .expect("construct provider-ingest signer fixture"),
            IrohaRuntimeProviderBindingV1::try_new_provider_ingest_checkpoint(
                "sealed://sorafs/provider-ingest/checkpoint-primary",
                7,
                [0xA7; 32],
                4 * max_signed_transaction_bytes,
            )
            .expect("construct provider-ingest checkpoint fixture"),
        ])
    }
    fn moderation_wire() -> RuntimeProviderCatalogWireV1 {
        let checkpoint_key = ed25519_bytes(0x41);
        let archive_key = ed25519_bytes(0x42);
        let mut checkpoint = IrohaRuntimeProviderBindingV1::try_new(
            IrohaRuntimeProviderSlotV1::ModerationCheckpointStore,
            "sealed://sorafs/moderation/checkpoint-primary",
            Some(3),
            Some([0x31; 32]),
        )
        .expect("construct moderation checkpoint fixture");
        checkpoint.moderation_checkpoint_max_bytes = Some(4 * 1024 * 1024);
        checkpoint.moderation_checkpoint_attestation_public_key = Some(checkpoint_key);
        let mut archive = IrohaRuntimeProviderBindingV1::try_new(
            IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
            "object-lock://sorafs/moderation/archive-primary",
            Some(4),
            Some([0x32; 32]),
        )
        .expect("construct moderation archive fixture");
        archive.moderation_panel_notification_archive_id = Some([0x43; 32]);
        archive.moderation_panel_notification_archive_bootstrap_public_key = Some(archive_key);
        archive.moderation_panel_notification_archive_public_key = Some(archive_key);
        archive.moderation_panel_notification_archive_max_bytes = Some(5 * 1024 * 1024);
        archive.moderation_panel_notification_archive_max_records = Some(128);
        wire_from_bindings(vec![checkpoint, archive])
    }
    fn evidence_wire() -> RuntimeProviderCatalogWireV1 {
        let checkpoint_max_bytes = 4 * 1024 * 1024;
        let mut checkpoint = IrohaRuntimeProviderBindingV1::try_new(
            IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore,
            "sealed://sorafs/evidence/checkpoint-primary",
            Some(3),
            Some([0x51; 32]),
        )
        .expect("construct evidence checkpoint fixture");
        checkpoint.evidence_viewer_checkpoint_max_bytes = Some(checkpoint_max_bytes);
        let mut archive = IrohaRuntimeProviderBindingV1::try_new(
            IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive,
            "object-lock://sorafs/evidence/archive-primary",
            Some(4),
            Some([0x52; 32]),
        )
        .expect("construct evidence archive fixture");
        archive.evidence_viewer_archive_id = Some([0x53; 32]);
        archive.evidence_viewer_archive_public_key = Some(ed25519_bytes(0x53));
        archive.evidence_viewer_archive_max_bytes = Some(checkpoint_max_bytes + 16 * 1024);
        wire_from_bindings(vec![checkpoint, archive])
    }
    #[test]
    fn canonical_catalog_roundtrip_is_byte_stable() {
        let network_id = NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0xA7; 32])
        ));
        let catalog = generic_catalog().with_network_id_for_test(network_id);
        let first = catalog
            .export_canonical_v1()
            .expect("export canonical catalog");
        let wire: RuntimeProviderCatalogWireV1 =
            norito::decode_canonical(&first).expect("catalog wire");
        crate::frame_test_support::assert_current_frame(
            &wire,
            "irohad::runtime_provider_registry::catalog::RuntimeProviderCatalogWireV1",
            "irohad::runtime_provider_registry::catalog::RuntimeProviderCatalogWireV1",
        );
        let second = catalog
            .export_canonical_v1()
            .expect("repeat canonical export");
        assert_eq!(first, second);
        let other_network_id = NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0xA8; 32]),
        ));
        let other_network = generic_catalog()
            .with_network_id_for_test(other_network_id)
            .export_canonical_v1()
            .expect("export same-label catalog for another network");
        assert_ne!(first, other_network);
        assert!(first.len() <= RUNTIME_PROVIDER_CATALOG_MAX_BYTES_V1);
        let decoded = IrohaRuntimeProviderBindingsV1::load_canonical_v1(&first)
            .expect("load canonical catalog");
        assert_eq!(decoded, catalog);
        assert_eq!(decoded.network_id(), &network_id);
        assert_eq!(
            decoded
                .export_canonical_v1()
                .expect("re-export decoded catalog"),
            first
        );
    }
    #[test]
    fn native_public_identity_roundtrips_without_private_material() {
        let keypair =
            iroha_crypto::KeyPair::try_from_seed(vec![0x52; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("derive native signer fixture");
        let public_key = keypair.public_key().clone();
        let authority = iroha_data_model::account::AccountId::new(public_key.clone());
        let native = iroha_torii::SorafsNativeTransactionSignerBindingV1::try_new(
            iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "software://sorafs/proof-outcome/primary",
            authority,
            public_key,
            iroha_torii::SorafsNativeTransactionSignerQualificationV1::new(9, [0x52; 32]),
        )
        .expect("construct native signer fixture");
        let catalog = IrohaRuntimeProviderBindingsV1::qualified_native_transaction_signers_for_test(
            "sorafs-catalog-test",
            [(
                IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner,
                native,
            )],
        );
        let bytes = catalog
            .export_canonical_v1()
            .expect("export native signer catalog");
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes)
                .expect("load native signer catalog"),
            catalog
        );
    }
    #[test]
    fn loader_rejects_invalid_appeal_finance_relationships() {
        let valid = || {
            wire_from_bindings(vec![
                appeal_signer(
                    0x21,
                    "software://sorafs/appeal-finance/signer-a",
                    1,
                    1,
                    Some(10),
                ),
                appeal_signer(
                    0x21,
                    "software://sorafs/appeal-finance/signer-b",
                    2,
                    10,
                    None,
                ),
                appeal_checkpoint(0x22),
            ])
        };
        let mut missing_checkpoint = valid();
        missing_checkpoint.bindings.retain(|binding| {
            binding.slot != IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint.wire_id()
        });
        assert_invalid_wire(&missing_checkpoint);
        let mut duplicate_handle = valid();
        let signer_handle = duplicate_handle
            .bindings
            .iter()
            .find(|binding| {
                binding.slot == IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner.wire_id()
            })
            .expect("first appeal signer")
            .handle
            .clone();
        duplicate_handle
            .bindings
            .iter_mut()
            .filter(|binding| {
                binding.slot == IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner.wire_id()
            })
            .nth(1)
            .expect("second appeal signer")
            .handle = signer_handle;
        assert_invalid_wire(&duplicate_handle);
        let mut overlapping_windows = valid();
        overlapping_windows
            .bindings
            .iter_mut()
            .filter(|binding| {
                binding.slot == IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner.wire_id()
            })
            .nth(1)
            .and_then(|binding| binding.appeal_finance_signer_binding.as_mut())
            .expect("second appeal signer metadata")
            .valid_from_block_height = 9;
        assert_invalid_wire(&overlapping_windows);
        let mut reused_checkpoint_handle = valid();
        wire_binding_mut(
            &mut reused_checkpoint_handle,
            IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint,
        )
        .handle = "software://sorafs/appeal-finance/signer-a".to_owned();
        assert_invalid_wire(&reused_checkpoint_handle);
        let mut reused_checkpoint_key = valid();
        let signer_key = reused_checkpoint_key
            .bindings
            .iter()
            .find_map(|binding| binding.appeal_finance_signer_binding.as_ref())
            .expect("appeal signer key")
            .public_key
            .clone();
        wire_binding_mut(
            &mut reused_checkpoint_key,
            IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint,
        )
        .appeal_finance_checkpoint_binding
        .as_mut()
        .expect("appeal checkpoint metadata")
        .public_key = signer_key;
        assert_invalid_wire(&reused_checkpoint_key);
    }
    #[test]
    fn loader_rejects_invalid_potr_and_fenced_relationships() {
        let mut missing_potr_peer = potr_wire();
        missing_potr_peer.bindings.retain(|binding| {
            binding.slot != IrohaRuntimeProviderSlotV1::PotrProviderSigner.wire_id()
        });
        assert_invalid_wire(&missing_potr_peer);
        let mut mismatched_potr_metadata = potr_wire();
        wire_binding_mut(
            &mut mismatched_potr_metadata,
            IrohaRuntimeProviderSlotV1::PotrProviderSigner,
        )
        .potr_runtime_binding
        .as_mut()
        .expect("PoTR provider metadata")
        .reader_id = [0x56; 32];
        assert_invalid_wire(&mismatched_potr_metadata);
        let mut reused_potr_identity = potr_wire();
        for binding in &mut reused_potr_identity.bindings {
            let runtime = binding
                .potr_runtime_binding
                .as_mut()
                .expect("PoTR runtime metadata");
            runtime.reader_id = runtime.gateway_signer_id;
        }
        assert_invalid_wire(&reused_potr_identity);
        let fenced_binding = |slot| {
            IrohaRuntimeProviderBindingV1::try_new(
                slot,
                "governance-cas://sorafs/privacy/fenced-primary",
                Some(7),
                Some([0x71; 32]),
            )
            .expect("construct fenced privacy fixture")
        };
        let valid_fenced = || {
            wire_from_bindings(vec![
                fenced_binding(IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher),
                fenced_binding(IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader),
            ])
        };
        let mut missing_fenced_peer = valid_fenced();
        missing_fenced_peer.bindings.pop();
        assert_invalid_wire(&missing_fenced_peer);
        let mut substituted_fenced_peer = valid_fenced();
        wire_binding_mut(
            &mut substituted_fenced_peer,
            IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader,
        )
        .policy_digest = Some([0x72; 32]);
        assert_invalid_wire(&substituted_fenced_peer);
    }
    #[test]
    fn loader_rejects_invalid_provider_ingest_relationships() {
        let mut incomplete = provider_ingest_wire();
        incomplete.bindings.retain(|binding| {
            binding.slot != IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore.wire_id()
        });
        assert_invalid_wire(&incomplete);
        let mut mismatched_signer = provider_ingest_wire();
        wire_binding_mut(
            &mut mismatched_signer,
            IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver,
        )
        .provider_ingest_signer_binding
        .as_mut()
        .expect("provider-ingest resolver signer metadata")
        .runtime_handle = "software://sorafs/provider-ingest/signer-secondary".to_owned();
        assert_invalid_wire(&mismatched_signer);
        let mut mismatched_bound = provider_ingest_wire();
        wire_binding_mut(
            &mut mismatched_bound,
            IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver,
        )
        .provider_ingest_max_signed_transaction_bytes =
            Some(provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN * 2);
        assert_invalid_wire(&mismatched_bound);
        let mut transaction_exceeds_checkpoint = provider_ingest_wire();
        wire_binding_mut(
            &mut transaction_exceeds_checkpoint,
            IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore,
        )
        .provider_ingest_checkpoint_max_bytes =
            Some(provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN - 1);
        assert_invalid_wire(&transaction_exceeds_checkpoint);
    }
    #[test]
    fn loader_rejects_cross_service_bound_and_identity_substitution() {
        let mut moderation_handle_collision = moderation_wire();
        wire_binding_mut(
            &mut moderation_handle_collision,
            IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
        )
        .handle = "sealed://sorafs/moderation/checkpoint-primary".to_owned();
        assert_invalid_wire(&moderation_handle_collision);
        let mut moderation_key_collision = moderation_wire();
        let checkpoint_key = wire_binding_mut(
            &mut moderation_key_collision,
            IrohaRuntimeProviderSlotV1::ModerationCheckpointStore,
        )
        .moderation_checkpoint_attestation_public_key
        .expect("moderation checkpoint key");
        wire_binding_mut(
            &mut moderation_key_collision,
            IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
        )
        .moderation_panel_notification_archive_binding
        .as_mut()
        .expect("moderation archive metadata")
        .bootstrap_public_key = checkpoint_key;
        assert_invalid_wire(&moderation_key_collision);
        let mut evidence_bound = evidence_wire();
        wire_binding_mut(
            &mut evidence_bound,
            IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive,
        )
        .evidence_viewer_archive_max_bytes = Some(4 * 1024 * 1024 + 16 * 1024 + 1);
        assert_invalid_wire(&evidence_bound);
        let governance_key = ed25519_bytes(0x70);
        let governance = |slot, max_body_bytes| {
            let scope = match slot {
                IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator => {
                    sorafs_node::GovernanceDagAuthenticationScope::Ipfs
                }
                IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator => {
                    sorafs_node::GovernanceDagAuthenticationScope::SignedHead
                }
                _ => unreachable!(),
            };
            let ingress_binding = sorafs_node::GovernanceDagRequestIngressBindingV1::try_new(
                scope,
                [slot.wire_id().to_le_bytes()[0]; 32],
                governance_key,
                max_body_bytes,
                30,
                5,
            )
            .expect("construct Governance request-ingress fixture");
            IrohaRuntimeProviderBindingV1::try_new_governance_request_auth(
                slot,
                match slot {
                    IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator => {
                        "network://sorafs/governance/ipfs-auth-primary"
                    }
                    IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator => {
                        "network://sorafs/governance/head-auth-primary"
                    }
                    _ => unreachable!(),
                },
                3,
                [slot.wire_id().to_le_bytes()[0]; 32],
                ingress_binding,
            )
            .expect("construct Governance request-auth fixture")
        };
        let mut governance_bound = wire_from_bindings(vec![
            governance(
                IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator,
                1024 * 1024,
            ),
            governance(
                IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator,
                1024 * 1024,
            ),
        ]);
        let ipns_request = wire_from_bindings(vec![governance(
            IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator,
            1024 * 1024,
        )]);
        assert_valid_wire(&ipns_request);
        let mut missing_ingress = ipns_request.clone();
        wire_binding_mut(
            &mut missing_ingress,
            IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator,
        )
        .governance_request_ingress_binding = None;
        assert_invalid_wire(&missing_ingress);
        let mut substituted_scope = ipns_request;
        wire_binding_mut(
            &mut substituted_scope,
            IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator,
        )
        .governance_request_ingress_binding
        .as_mut()
        .expect("Governance IPFS ingress binding")
        .scope = 2;
        assert_invalid_wire(&substituted_scope);
        wire_binding_mut(
            &mut governance_bound,
            IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator,
        )
        .governance_request_ingress_binding
        .as_mut()
        .expect("Governance head ingress binding")
        .max_future_skew_secs = 6;
        assert_invalid_wire(&governance_bound);
    }
    #[test]
    fn catalog_binding_sequence_enforces_every_sparse_slot_multiplicity() {
        for slot in IrohaRuntimeProviderSlotV1::ALL {
            let maximum = slot.max_configured_multiplicity();
            assert_eq!(
                validate_binding_sequence(std::iter::repeat_n(slot, maximum)),
                Ok(()),
                "valid multiplicity for wire ID {}",
                slot.wire_id(),
            );
            assert_eq!(
                validate_binding_sequence(std::iter::repeat_n(slot, maximum + 1)),
                Err(IrohaRuntimeProviderCatalogErrorV1::InvalidOrder),
                "excess multiplicity for wire ID {}",
                slot.wire_id(),
            );
        }
    }
    #[test]
    fn catalog_bounds_match_config_validation() {
        let mut appeal = wire_from_bindings(vec![
            appeal_signer(
                0x31,
                "software://sorafs/appeal-finance/signer-primary",
                1,
                1,
                None,
            ),
            appeal_checkpoint(0x32),
        ]);
        for valid in [
            torii_defaults::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MIN_BYTES_V1,
            torii_defaults::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MAX_BYTES_LIMIT_V1,
        ] {
            wire_binding_mut(
                &mut appeal,
                IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint,
            )
            .appeal_finance_checkpoint_max_bytes = Some(valid);
            assert_valid_wire(&appeal);
        }
        for invalid in [
            torii_defaults::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MIN_BYTES_V1 - 1,
            torii_defaults::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MAX_BYTES_LIMIT_V1
                + 1,
        ] {
            wire_binding_mut(
                &mut appeal,
                IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint,
            )
            .appeal_finance_checkpoint_max_bytes = Some(invalid);
            assert_invalid_wire(&appeal);
        }
        let mut moderation = moderation_wire();
        for valid in [
            moderation_defaults::PANEL_NOTIFICATION_ARCHIVE_MIN_BYTES_V1,
            moderation_defaults::PANEL_NOTIFICATION_ARCHIVE_MAX_BYTES_LIMIT_V1,
        ] {
            wire_binding_mut(
                &mut moderation,
                IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
            )
            .moderation_panel_notification_archive_binding
            .as_mut()
            .expect("moderation archive metadata")
            .max_bytes = valid;
            assert_valid_wire(&moderation);
        }
        for invalid in [
            moderation_defaults::PANEL_NOTIFICATION_ARCHIVE_MIN_BYTES_V1 - 1,
            moderation_defaults::PANEL_NOTIFICATION_ARCHIVE_MAX_BYTES_LIMIT_V1 + 1,
        ] {
            wire_binding_mut(
                &mut moderation,
                IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
            )
            .moderation_panel_notification_archive_binding
            .as_mut()
            .expect("moderation archive metadata")
            .max_bytes = invalid;
            assert_invalid_wire(&moderation);
        }
        let mut provider = provider_ingest_wire();
        let source = wire_binding_mut(
            &mut provider,
            IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource,
        );
        let limits = source
            .provider_ingest_source_limits
            .as_mut()
            .expect("provider-ingest source limits");
        limits.operation_timeout_ms =
            provider_ingest_defaults::SOURCE_OPERATION_TIMEOUT_MS_LIMIT_V1;
        limits.max_source_providers = u32::try_from(provider_ingest_defaults::MAX_SOURCE_PROVIDERS)
            .expect("configured source-provider limit fits u32");
        assert_valid_wire(&provider);
        wire_binding_mut(
            &mut provider,
            IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource,
        )
        .provider_ingest_source_limits
        .as_mut()
        .expect("provider-ingest source limits")
        .operation_timeout_ms = provider_ingest_defaults::SOURCE_OPERATION_TIMEOUT_MS_LIMIT_V1 + 1;
        assert_invalid_wire(&provider);
        let limits = wire_binding_mut(
            &mut provider,
            IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource,
        )
        .provider_ingest_source_limits
        .as_mut()
        .expect("provider-ingest source limits");
        limits.operation_timeout_ms =
            provider_ingest_defaults::SOURCE_OPERATION_TIMEOUT_MS_LIMIT_V1;
        limits.max_source_providers = 1_025;
        assert_invalid_wire(&provider);
    }
    #[test]
    fn exporter_rejects_projection_loss() {
        let mut partial_archive = IrohaRuntimeProviderBindingV1::try_new(
            IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
            "object-lock://sorafs/moderation/archive-primary",
            Some(4),
            Some([0x42; 32]),
        )
        .expect("construct partial moderation archive binding");
        partial_archive.moderation_panel_notification_archive_id = Some([0x43; 32]);
        assert_eq!(
            catalog_from_bindings(vec![partial_archive]).export_canonical_v1(),
            Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)
        );
        let native_key = ed25519_key(0x51);
        let native = iroha_torii::SorafsNativeTransactionSignerBindingV1::try_new(
            iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "software://sorafs/proof-outcome/signer-primary",
            iroha_data_model::account::AccountId::new(native_key.clone()),
            native_key,
            iroha_torii::SorafsNativeTransactionSignerQualificationV1::new(3, [0x51; 32]),
        )
        .expect("construct native signer fixture");
        let mut dual = IrohaRuntimeProviderBindingV1::try_new_native_signer(
            IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner,
            native,
        )
        .expect("project native signer fixture");
        let cloud_key = ed25519_key(0x52);
        dual.soracloud_runtime_signer_binding = Some(
            crate::soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1::try_new(
                "software://sorafs/ai/runtime-primary",
                iroha_data_model::account::AccountId::new(cloud_key.clone()),
                cloud_key,
                crate::soracloud_runtime_signer::SoracloudRuntimeSignerQualificationV1::new(
                    4, [0x52; 32], true, false,
                ),
            )
            .expect("construct hidden Soracloud signer fixture"),
        );
        assert_eq!(
            catalog_from_bindings(vec![dual]).export_canonical_v1(),
            Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)
        );
    }
    #[test]
    fn loader_rejects_trailing_bytes_and_oversized_input() {
        let mut trailing = generic_catalog()
            .export_canonical_v1()
            .expect("export canonical catalog");
        trailing.push(0);
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&trailing),
            Err(IrohaRuntimeProviderCatalogErrorV1::NonCanonicalEncoding)
        );
        let oversized = vec![0; RUNTIME_PROVIDER_CATALOG_MAX_BYTES_V1 + 1];
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&oversized),
            Err(IrohaRuntimeProviderCatalogErrorV1::ArtifactTooLarge)
        );
    }
    #[test]
    fn loader_rejects_wrong_magic_and_version() {
        let mut wrong_magic = canonical_wire();
        wrong_magic.magic = *b"BADCAT01";
        let bytes = norito::encode_canonical(&wrong_magic).expect("encode wrong magic fixture");
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes),
            Err(IrohaRuntimeProviderCatalogErrorV1::InvalidMagic)
        );
        let mut wrong_version = canonical_wire();
        wrong_version.version = 2;
        let bytes = norito::encode_canonical(&wrong_version).expect("encode wrong version fixture");
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes),
            Err(IrohaRuntimeProviderCatalogErrorV1::UnsupportedVersion)
        );
    }
    #[test]
    fn loader_rejects_retired_optional_network_catalog_schema() {
        fn current_catalog_frame<T: norito::SerializePayload>(value: &T) -> Vec<u8> {
            let _layout =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            let (payload, flags) = norito::codec::encode_with_header_flags(value);
            norito::core::frame_bare_with_header_flags::<RuntimeProviderCatalogWireV1>(
                &payload, flags,
            )
            .expect("frame payload under the current catalog owner")
        }
        let wire = canonical_wire();
        let healthy = current_catalog_frame(&wire);
        assert_eq!(
            healthy,
            norito::encode_canonical(&wire).expect("canonical current catalog")
        );
        IrohaRuntimeProviderBindingsV1::load_canonical_v1(&healthy).expect("valid current catalog");
        for network_id in [None, Some(wire.network_id)] {
            let retired = RetiredRuntimeProviderCatalogWireV1 {
                magic: wire.magic,
                version: wire.version,
                chain_id: wire.chain_id.clone(),
                network_id,
                bindings: wire.bindings.clone(),
            };
            // The unsupported optional field remains payload-only. A genuine current
            // header ensures rejection checks its body rather than a different owner.
            let bytes = current_catalog_frame(&retired);
            let error = norito::decode_canonical::<RuntimeProviderCatalogWireV1>(&bytes)
                .expect_err("optional-network payload must fail under the current owner");
            assert!(!matches!(error, norito::Error::SchemaMismatch));
            assert_eq!(
                IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes),
                Err(IrohaRuntimeProviderCatalogErrorV1::NonCanonicalEncoding),
                "retired optional-network encoding must fail closed for {network_id:?}",
            );
        }
    }
    #[test]
    fn loader_rejects_empty_duplicate_and_noncanonical_order() {
        let empty = RuntimeProviderCatalogWireV1 {
            magic: RUNTIME_PROVIDER_CATALOG_MAGIC_V1,
            version: RUNTIME_PROVIDER_CATALOG_VERSION_V1,
            chain_id: "sorafs-catalog-test".to_owned(),
            network_id: runtime_provider_test_network_id(),
            credential_max_memory_bytes: 64 * 1024 * 1024,
            bindings: Vec::new(),
        };
        let bytes = norito::encode_canonical(&empty).expect("encode empty fixture");
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes),
            Err(IrohaRuntimeProviderCatalogErrorV1::EmptyCatalog)
        );
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::empty_for_test("sorafs-catalog-test")
                .export_canonical_v1(),
            Err(IrohaRuntimeProviderCatalogErrorV1::EmptyCatalog)
        );
        let mut duplicate = canonical_wire();
        duplicate.bindings.push(duplicate.bindings[0].clone());
        let bytes = norito::encode_canonical(&duplicate).expect("encode duplicate fixture");
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes),
            Err(IrohaRuntimeProviderCatalogErrorV1::InvalidOrder)
        );
        let first = RuntimeProviderBindingWireV1::try_from_binding(
            &IrohaRuntimeProviderBindingV1::try_new(
                IrohaRuntimeProviderSlotV1::BillingFinalizedQuery,
                "ledger://billing/finalized-query/primary",
                Some(1),
                Some([0x61; 32]),
            )
            .expect("construct first binding"),
        )
        .expect("project first binding");
        let second = RuntimeProviderBindingWireV1::try_from_binding(
            &IrohaRuntimeProviderBindingV1::try_new(
                IrohaRuntimeProviderSlotV1::BillingJournalVerifier,
                "ledger://billing/journal-verifier/primary",
                Some(1),
                Some([0x62; 32]),
            )
            .expect("construct second binding"),
        )
        .expect("project second binding");
        let reversed = RuntimeProviderCatalogWireV1 {
            magic: RUNTIME_PROVIDER_CATALOG_MAGIC_V1,
            version: RUNTIME_PROVIDER_CATALOG_VERSION_V1,
            chain_id: "sorafs-catalog-test".to_owned(),
            network_id: runtime_provider_test_network_id(),
            credential_max_memory_bytes: 64 * 1024 * 1024,
            bindings: vec![second, first],
        };
        let bytes = norito::encode_canonical(&reversed).expect("encode reversed fixture");
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes),
            Err(IrohaRuntimeProviderCatalogErrorV1::InvalidOrder)
        );
    }
    #[test]
    fn loader_rejects_test_marked_and_substituted_metadata() {
        let mut test_marked = canonical_wire();
        test_marked.bindings[0].handle = "ledger://test/finalized-query".to_owned();
        let bytes = norito::encode_canonical(&test_marked).expect("encode test-marked fixture");
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes),
            Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)
        );
        let mut substituted = canonical_wire();
        substituted.bindings[0].stream_token_signer_binding =
            Some(super::super::stream_token_signer_binding::tests::fixture());
        let bytes = norito::encode_canonical(&substituted).expect("encode substituted fixture");
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes),
            Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)
        );
    }
    #[test]
    fn loader_enforces_canonical_webauthn_rp_and_origin_fields() {
        load_wire(&webauthn_wire(
            "review.example",
            ["https://login.review.example:8443"],
        ))
        .expect("canonical WebAuthn catalog");
        for rp_id in ["Review.example", "localhost", "127.0.0.1"] {
            assert_eq!(
                load_wire(&webauthn_wire(rp_id, ["https://review.example"])),
                Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding),
                "{rp_id:?} must fail closed"
            );
        }
        for origin in [
            "http://review.example",
            "https://operator:secret@review.example",
            "https://review.example/path",
            "https://review.example?challenge=1",
            "https://review.example#fragment",
            "https://review.example:443",
            "https://foreign.example",
        ] {
            assert_eq!(
                load_wire(&webauthn_wire("review.example", [origin])),
                Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding),
                "{origin:?} must fail closed"
            );
        }
    }
    #[test]
    fn credential_memory_bound_roundtrips_and_partitions_without_resetting() {
        let mut catalog = IrohaRuntimeProviderBindingsV1::qualified_for_test(
            "credential-pool",
            IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
            "software://beacon/registry",
            1,
            [0x37; 32],
        );
        catalog.credential_max_memory_bytes = 123_456;
        let restored = IrohaRuntimeProviderBindingsV1::load_canonical_v1(
            &catalog.export_canonical_v1().unwrap(),
        )
        .unwrap();
        assert_eq!(restored, catalog);
        assert_eq!(restored.credential_max_memory_bytes(), 123_456);
        let (signers, base) = restored.partition_external_software_signers_v1();
        assert_eq!(signers.credential_max_memory_bytes(), 123_456);
        assert_eq!(base.credential_max_memory_bytes(), 123_456);
        assert_eq!(
            restored
                .select_slots(&[IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner])
                .credential_max_memory_bytes(),
            123_456
        );
        let original = restored.new_credential_registry_budget_v1();
        assert_eq!(original.limit_bytes(), 123_456);
        let retained = original.try_reserve_bytes(123_456).unwrap();
        assert!(matches!(
            original.try_reserve_bytes(1),
            Err(iroha_allocation::AllocationRefusal::Capacity { .. })
        ));
        drop(retained);
        assert_eq!(original.reserved_bytes(), 0);
        catalog.credential_max_memory_bytes = 0;
        assert_eq!(
            catalog.export_canonical_v1(),
            Err(IrohaRuntimeProviderCatalogErrorV1::InvalidBinding)
        );
    }

    #[test]
    fn credential_policy_matches_exact_catalog_metadata_and_zero_requires_no_threshold_slot() {
        use iroha_config::parameters::actual::RuntimeProviderBroker;
        let policy = |contents: &str| {
            RuntimeProviderBroker::from_toml_source(iroha_config_base::toml::TomlSource::inline(
                contents.parse().expect("broker policy table"),
            ))
            .expect("validated broker policy")
        };
        for slot in [
            IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
            IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider,
        ] {
            let mut catalog = IrohaRuntimeProviderBindingsV1::qualified_for_test(
                "credential-policy",
                slot,
                "software://credential-policy/primary",
                1,
                [0x39; 32],
            );
            for exact in [policy(""), policy("credential_max_memory_bytes = 123456")] {
                catalog.credential_max_memory_bytes = exact.credential_max_memory_bytes.get();
                let restored = IrohaRuntimeProviderBindingsV1::load_canonical_v1(
                    &catalog.export_canonical_v1().expect("export exact catalog"),
                )
                .expect("reload exact public metadata");
                assert_eq!(
                    restored.validate_credential_memory_policy_v1(&exact),
                    Ok(())
                );
                let limit = exact.credential_max_memory_bytes.get();
                for supplied in [1, limit - 1, limit + 1] {
                    assert_eq!(
                        restored.validate_credential_memory_policy_v1(&policy(&format!(
                            "credential_max_memory_bytes = {supplied}"
                        ))),
                        Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
                    );
                }
            }
            catalog.credential_max_memory_bytes = 0;
            assert_eq!(
                catalog.validate_credential_memory_policy_v1(&policy("")),
                if slot == IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider {
                    Ok(())
                } else {
                    Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
                }
            );
        }
    }

    #[test]
    fn catalog_without_explicit_credential_bound_is_rejected() {
        #[derive(Encode, norito::NoritoSchema)]
        #[norito_schema(
            name = "irohad::runtime_provider_registry::catalog::RuntimeProviderCatalogWireV1"
        )]
        struct MissingBound {
            magic: [u8; 8],
            version: u16,
            chain_id: String,
            network_id: NetworkId,
            bindings: Vec<RuntimeProviderBindingWireV1>,
        }
        let current = canonical_wire();
        let missing = MissingBound {
            magic: current.magic,
            version: current.version,
            chain_id: current.chain_id,
            network_id: current.network_id,
            bindings: current.bindings,
        };
        assert_eq!(
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(
                &norito::encode_canonical(&missing).unwrap()
            ),
            Err(IrohaRuntimeProviderCatalogErrorV1::NonCanonicalEncoding)
        );
    }
}
