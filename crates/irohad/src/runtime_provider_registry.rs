//! Deployment-owned runtime-provider registry boundary for the standard daemon launcher.
//!
//! This module deliberately projects only public provider bindings out of
//! [`iroha_config`]. The deployment registry never receives the full node
//! configuration, because that structure also contains validator keys, API
//! tokens, and other values that runtime-provider discovery must not observe.
//! Gateway admission uses the daemon's local Core authority and is never a
//! broker binding; externally injected gateway providers fail scope validation.
use crate::IrohaRuntimeDeps;
use iroha_config::parameters::{
    actual::Root as Config,
    defaults::{
        sorafs::storage::{
            moderation_orchestrator as moderation_defaults,
            provider_ingest_runtime::{
                self as provider_ingest_defaults, outbox as provider_ingest_outbox_defaults,
            },
        },
        torii as torii_defaults,
    },
    is_production_runtime_handle, validate_webauthn_origin_v1, validate_webauthn_rp_id_v1,
};
use iroha_data_model::NetworkId;
use rand::{rand_core::TryRngCore as _, rngs::OsRng};
use std::fmt;
mod beacon_provisioning;
mod binding_collection;
mod binding_types;
mod catalog;
mod dependency_scope;
mod stream_token_signer;
mod stream_token_signer_binding;
use binding_collection::{
    append_required_governance_request_auth_binding, append_required_governance_service_binding,
    collect_configured_bindings, governance_request_ingress_binding_from_service,
};
pub(crate) use binding_types::{EvidenceViewerWebAuthnBindingV1, PopCredentialRuntimeBindingV1};
pub use catalog::{IrohaRuntimeProviderCatalogErrorV1, RUNTIME_PROVIDER_CATALOG_MAX_BYTES_V1};
use dependency_scope::{dependency_is_present, has_unrequested_dependency};
pub use stream_token_signer_binding::StreamTokenSignerRuntimeBindingV1;
const MAX_PROVIDER_INGEST_SOURCE_STREAMS_V1: u32 = 1_024;
const GOVERNANCE_DAG_SIGNER_STARTUP_CHALLENGE_DOMAIN_V1: &[u8] =
    b"sorafs.governance-dag.registry-startup-possession.v1\0";
/// One runtime-provider role understood by the V1 daemon launcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum IrohaRuntimeProviderSlotV1 {
    /// Moderation quarantine-object data-key wrapper.
    ModerationQuarantineKeyWrapper = 1,
    /// Threshold-PRF provider used by transparency publication.
    PrivacyCyclePrfProvider = 2,
    /// Finalized release-anchor provider used by transparency publication.
    PrivacyReleaseAnchor = 3,
    /// External sealed-CAS leader lease used by transparency publication.
    TransparencyLeaderLease = 4,
    /// Fused privacy Governance target writer.
    FencedPrivacyPublisher = 5,
    /// Authenticated authoritative-head reader paired with the fused writer.
    FencedPrivacyHeadReader = 6,
    /// Authenticated external signer used by the embedded Governance DAG publisher.
    GovernanceDagSigner = 7,
    /// Authenticator used for Governance DAG Kubo/IPFS requests.
    GovernanceDagIpfsAuthenticator = 8,
    /// Authenticator used for signed Governance DAG head compare-and-swap.
    GovernanceDagHeadAuthenticator = 9,
    /// Sealed monotonic Governance DAG service and local-producer state store.
    GovernanceDagCheckpointStore = 10,
    /// Authenticated external signer used for `SoraFS` stream-token issuance.
    StreamTokenSigner = 11,
    /// One appeal-finance transaction signer.
    AppealFinanceTransactionSigner = 12,
    /// Appeal-finance sealed checkpoint provider.
    AppealFinanceCheckpoint = 13,
    /// Native proof-outcome transaction signer.
    ProofOutcomeTransactionSigner = 14,
    /// Native repair transaction signer.
    RepairTransactionSigner = 15,
    /// Native reserve/rent transaction signer.
    ReserveTransactionSigner = 16,
    /// Native orderbook transaction signer.
    OrderbookTransactionSigner = 17,
    /// Moderation native-transaction signer.
    ModerationTransactionSigner = 18,
    /// Moderation settlement durable handoff.
    ModerationSettlementHandoff = 19,
    /// Moderation publication durable handoff.
    ModerationPublicationHandoff = 20,
    /// Moderation panel-notification delivery boundary.
    ModerationPanelNotification = 21,
    /// Evidence-viewer `WebAuthn` boundary.
    EvidenceViewerWebAuthn = 22,
    /// Evidence-viewer finalized grant authority.
    EvidenceViewerGrantAuthority = 23,
    /// Evidence-viewer receipt signer.
    EvidenceViewerReceiptSigner = 24,
    /// Evidence-viewer erasure boundary.
    EvidenceViewerErasure = 25,
    /// Evidence-viewer authoritative checkpoint store.
    EvidenceViewerCheckpointStore = 26,
    /// `PoP` credential provider registry.
    PopCredentialProviderRegistry = 27,
    /// Independently administered `PoTR` gateway signer.
    PotrGatewaySigner = 28,
    /// Independently administered `PoTR` provider signer.
    PotrProviderSigner = 29,
    /// Gateway ACME client.
    GatewayAcmeClient = 30,
    /// Gateway authenticated compliance-feed transport.
    GatewayComplianceFeedTransport = 31,
    /// Reputation native journal-transaction submitter.
    ReputationJournalTransactionSubmitter = 32,
    /// Reputation external threshold signer.
    ReputationThresholdSigner = 33,
    /// Reputation Governance DAG publication/readback provider.
    ReputationGovernanceDag = 34,
    /// Billing immutable finalized-query provider.
    BillingFinalizedQuery = 35,
    /// Billing consensus journal verifier.
    BillingJournalVerifier = 36,
    /// Authenticated external billing statement signer.
    BillingStatementSigner = 37,
    /// Billing immutable statement publisher.
    BillingStatementPublisher = 38,
    /// Billing acknowledgement authority.
    BillingAcknowledgementAuthority = 39,
    /// Billing sealed epoch-witness store.
    BillingEpochWitnessStore = 40,
    /// Provider-ingest authenticated source transport.
    ProviderIngestAuthenticatedSource = 41,
    /// Provider-ingest governed completion-signer resolver.
    ProviderIngestCompletionSignerResolver = 42,
    /// Provider-ingest completion signer resolved by the governed resolver.
    ProviderIngestCompletionSigner = 43,
    /// Provider-ingest sealed monotonic checkpoint store.
    ProviderIngestCheckpointStore = 44,
    /// Provider-ingest finalized-archive retention approval authority.
    ProviderIngestRetentionAuthority = 45,
    /// Authenticated immutable finalized-PoR replay archive.
    PorFinalizedReplayArchive = 46,
    /// Authenticated immutable evidence-viewer compaction archive.
    EvidenceViewerCompactionArchive = 47,
    /// Reputation finalized-archive sealed retention approval authority.
    ReputationFinalizedArchiveRetentionAuthority = 48,
    /// Soracloud runtime mutation and purpose-separated provenance signer.
    SoracloudRuntimeMutationSigner = 49,
    /// Reputation journal externally sealed monotonic checkpoint provider.
    ReputationJournalCheckpoint = 50,
    /// Moderation sealed predecessor-bound monotonic checkpoint store.
    ModerationCheckpointStore = sorafs_node::moderation_orchestrator::MODERATION_PANEL_NOTIFICATION_SOURCE_ATTESTOR_BROKER_SLOT_V1,
    /// Evidence-viewer signed monotonic transparency-head publisher.
    EvidenceViewerTransparencyPublisher = 52,
    /// Authenticated immutable moderation panel-notification receipt archive.
    ModerationPanelNotificationArchive =
        sorafs_node::moderation_orchestrator::MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_SLOT_V1,
    /// Native Bootle/Lantern issuer and opaque-client authentication registry.
    BootleLanternIssuanceProviderRegistry = 55,
    /// Rollback-resistant monotonic clock seal for Musubi provider attestations.
    MusubiProviderAttestationClockSeal = 56,
    /// Approval-only external or threshold signer for Musubi provider attestations.
    MusubiProviderAttestationApprovalSigner = 57,
    /// Authenticated coordinator inventory for Musubi provider attestations.
    MusubiProviderAttestationAuthenticatedInventory = 58,
    /// Runtime-only adaptive global threshold-beacon partial signer.
    GlobalBeaconPartialSigner = 59,
}
impl IrohaRuntimeProviderSlotV1 {
    /// Every first-release runtime-provider slot in wire-ID order.
    pub const ALL: [Self; 58] = [
        Self::ModerationQuarantineKeyWrapper,
        Self::PrivacyCyclePrfProvider,
        Self::PrivacyReleaseAnchor,
        Self::TransparencyLeaderLease,
        Self::FencedPrivacyPublisher,
        Self::FencedPrivacyHeadReader,
        Self::GovernanceDagSigner,
        Self::GovernanceDagIpfsAuthenticator,
        Self::GovernanceDagHeadAuthenticator,
        Self::GovernanceDagCheckpointStore,
        Self::StreamTokenSigner,
        Self::AppealFinanceTransactionSigner,
        Self::AppealFinanceCheckpoint,
        Self::ProofOutcomeTransactionSigner,
        Self::RepairTransactionSigner,
        Self::ReserveTransactionSigner,
        Self::OrderbookTransactionSigner,
        Self::ModerationTransactionSigner,
        Self::ModerationSettlementHandoff,
        Self::ModerationPublicationHandoff,
        Self::ModerationPanelNotification,
        Self::EvidenceViewerWebAuthn,
        Self::EvidenceViewerGrantAuthority,
        Self::EvidenceViewerReceiptSigner,
        Self::EvidenceViewerErasure,
        Self::EvidenceViewerCheckpointStore,
        Self::PopCredentialProviderRegistry,
        Self::PotrGatewaySigner,
        Self::PotrProviderSigner,
        Self::GatewayAcmeClient,
        Self::GatewayComplianceFeedTransport,
        Self::ReputationJournalTransactionSubmitter,
        Self::ReputationThresholdSigner,
        Self::ReputationGovernanceDag,
        Self::BillingFinalizedQuery,
        Self::BillingJournalVerifier,
        Self::BillingStatementSigner,
        Self::BillingStatementPublisher,
        Self::BillingAcknowledgementAuthority,
        Self::BillingEpochWitnessStore,
        Self::ProviderIngestAuthenticatedSource,
        Self::ProviderIngestCompletionSignerResolver,
        Self::ProviderIngestCompletionSigner,
        Self::ProviderIngestCheckpointStore,
        Self::ProviderIngestRetentionAuthority,
        Self::PorFinalizedReplayArchive,
        Self::EvidenceViewerCompactionArchive,
        Self::ReputationFinalizedArchiveRetentionAuthority,
        Self::SoracloudRuntimeMutationSigner,
        Self::ReputationJournalCheckpoint,
        Self::ModerationCheckpointStore,
        Self::EvidenceViewerTransparencyPublisher,
        Self::ModerationPanelNotificationArchive,
        Self::BootleLanternIssuanceProviderRegistry,
        Self::MusubiProviderAttestationClockSeal,
        Self::MusubiProviderAttestationApprovalSigner,
        Self::MusubiProviderAttestationAuthenticatedInventory,
        Self::GlobalBeaconPartialSigner,
    ];
    /// Return the stable first-release broker protocol identifier for this role.
    #[must_use]
    pub const fn wire_id(self) -> u16 {
        self as u16
    }
    /// Decode one stable first-release broker protocol role identifier.
    #[must_use]
    pub const fn from_wire_id(wire_id: u16) -> Option<Self> {
        match wire_id {
            1 => Some(Self::ModerationQuarantineKeyWrapper),
            2 => Some(Self::PrivacyCyclePrfProvider),
            3 => Some(Self::PrivacyReleaseAnchor),
            4 => Some(Self::TransparencyLeaderLease),
            5 => Some(Self::FencedPrivacyPublisher),
            6 => Some(Self::FencedPrivacyHeadReader),
            7 => Some(Self::GovernanceDagSigner),
            8 => Some(Self::GovernanceDagIpfsAuthenticator),
            9 => Some(Self::GovernanceDagHeadAuthenticator),
            10 => Some(Self::GovernanceDagCheckpointStore),
            11 => Some(Self::StreamTokenSigner),
            12 => Some(Self::AppealFinanceTransactionSigner),
            13 => Some(Self::AppealFinanceCheckpoint),
            14 => Some(Self::ProofOutcomeTransactionSigner),
            15 => Some(Self::RepairTransactionSigner),
            16 => Some(Self::ReserveTransactionSigner),
            17 => Some(Self::OrderbookTransactionSigner),
            18 => Some(Self::ModerationTransactionSigner),
            19 => Some(Self::ModerationSettlementHandoff),
            20 => Some(Self::ModerationPublicationHandoff),
            21 => Some(Self::ModerationPanelNotification),
            22 => Some(Self::EvidenceViewerWebAuthn),
            23 => Some(Self::EvidenceViewerGrantAuthority),
            24 => Some(Self::EvidenceViewerReceiptSigner),
            25 => Some(Self::EvidenceViewerErasure),
            26 => Some(Self::EvidenceViewerCheckpointStore),
            27 => Some(Self::PopCredentialProviderRegistry),
            28 => Some(Self::PotrGatewaySigner),
            29 => Some(Self::PotrProviderSigner),
            30 => Some(Self::GatewayAcmeClient),
            31 => Some(Self::GatewayComplianceFeedTransport),
            32 => Some(Self::ReputationJournalTransactionSubmitter),
            33 => Some(Self::ReputationThresholdSigner),
            34 => Some(Self::ReputationGovernanceDag),
            35 => Some(Self::BillingFinalizedQuery),
            36 => Some(Self::BillingJournalVerifier),
            37 => Some(Self::BillingStatementSigner),
            38 => Some(Self::BillingStatementPublisher),
            39 => Some(Self::BillingAcknowledgementAuthority),
            40 => Some(Self::BillingEpochWitnessStore),
            41 => Some(Self::ProviderIngestAuthenticatedSource),
            42 => Some(Self::ProviderIngestCompletionSignerResolver),
            43 => Some(Self::ProviderIngestCompletionSigner),
            44 => Some(Self::ProviderIngestCheckpointStore),
            45 => Some(Self::ProviderIngestRetentionAuthority),
            46 => Some(Self::PorFinalizedReplayArchive),
            47 => Some(Self::EvidenceViewerCompactionArchive),
            48 => Some(Self::ReputationFinalizedArchiveRetentionAuthority),
            49 => Some(Self::SoracloudRuntimeMutationSigner),
            50 => Some(Self::ReputationJournalCheckpoint),
            51 => Some(Self::ModerationCheckpointStore),
            52 => Some(Self::EvidenceViewerTransparencyPublisher),
            54 => Some(Self::ModerationPanelNotificationArchive),
            55 => Some(Self::BootleLanternIssuanceProviderRegistry),
            56 => Some(Self::MusubiProviderAttestationClockSeal),
            57 => Some(Self::MusubiProviderAttestationApprovalSigner),
            58 => Some(Self::MusubiProviderAttestationAuthenticatedInventory),
            59 => Some(Self::GlobalBeaconPartialSigner),
            _ => None,
        }
    }
    /// Return the maximum number of configured bindings for this V1 role.
    #[must_use]
    pub const fn max_configured_multiplicity(self) -> usize {
        match self {
            Self::AppealFinanceTransactionSigner => {
                iroha_config::parameters::SORAFS_APPEAL_FINANCE_MAX_SUBMITTER_SIGNERS_V1
            }
            _ => 1,
        }
    }
}
const fn runtime_provider_catalog_max_entries_v1() -> usize {
    let mut total = 0;
    let mut index = 0;
    while index < IrohaRuntimeProviderSlotV1::ALL.len() {
        total += IrohaRuntimeProviderSlotV1::ALL[index].max_configured_multiplicity();
        index += 1;
    }
    total
}
/// Maximum complete V1 catalog derived from every configured role multiplicity.
pub(crate) const RUNTIME_PROVIDER_CATALOG_MAX_ENTRIES_V1: usize =
    runtime_provider_catalog_max_entries_v1();
/// Public identity and optional exact qualification of one requested provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrohaRuntimeProviderBindingV1 {
    slot: IrohaRuntimeProviderSlotV1,
    handle: String,
    revision: Option<u64>,
    policy_digest: Option<[u8; 32]>,
    bootle_lantern_issuance_bindings:
        Option<iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderBindingsV1>,
    stream_token_signer_binding: Option<StreamTokenSignerRuntimeBindingV1>,
    appeal_finance_signer_binding:
        Option<iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding>,
    appeal_finance_checkpoint_binding:
        Option<iroha_config::parameters::actual::SorafsAppealFinanceCheckpointBinding>,
    appeal_finance_checkpoint_max_bytes: Option<u64>,
    pop_credential_runtime_binding: Option<PopCredentialRuntimeBindingV1>,
    potr_runtime_binding: Option<iroha_config::parameters::actual::SorafsPotrRuntimeBinding>,
    native_signer_binding: Option<iroha_torii::SorafsNativeTransactionSignerBindingV1>,
    soracloud_runtime_signer_binding:
        Option<crate::soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1>,
    provider_ingest_signer_binding: Option<sorafs_node::ProviderIngestCompletionSignerBindingV1>,
    provider_ingest_source_limits: Option<ProviderIngestSourceLimitsV1>,
    provider_ingest_checkpoint_max_bytes: Option<u64>,
    provider_ingest_max_signed_transaction_bytes: Option<u64>,
    por_replay_archive_binding: Option<sorafs_node::PorFinalizedReplayArchiveBindingV1>,
    por_replay_archive_proof_limits: Option<PorReplayArchiveProofLimitsV1>,
    evidence_viewer_webauthn_binding: Option<EvidenceViewerWebAuthnBindingV1>,
    evidence_viewer_grant_ttl_ms: Option<u64>,
    evidence_viewer_receipt_signer_public_key: Option<[u8; 32]>,
    evidence_viewer_transparency_publisher_public_key: Option<[u8; 32]>,
    evidence_viewer_checkpoint_max_bytes: Option<u64>,
    moderation_checkpoint_max_bytes: Option<u64>,
    moderation_checkpoint_attestation_public_key: Option<[u8; 32]>,
    evidence_viewer_archive_id: Option<[u8; 32]>,
    evidence_viewer_archive_public_key: Option<[u8; 32]>,
    evidence_viewer_archive_max_bytes: Option<u64>,
    moderation_panel_notification_archive_id: Option<[u8; 32]>,
    moderation_panel_notification_archive_bootstrap_public_key: Option<[u8; 32]>,
    moderation_panel_notification_archive_public_key: Option<[u8; 32]>,
    moderation_panel_notification_archive_max_bytes: Option<u64>,
    moderation_panel_notification_archive_max_records: Option<u64>,
    governance_dag_publisher_peer_id: Option<Vec<u8>>,
    governance_dag_publisher_public_key: Option<[u8; 32]>,
    governance_request_ingress_binding: Option<sorafs_node::GovernanceDagRequestIngressBindingV1>,
}
/// Public resource limits for the authenticated provider-ingest source broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProviderIngestSourceLimitsV1 {
    /// Exact configured deadline for one source operation.
    pub operation_timeout_ms: u64,
    /// Maximum finalized payload length admitted by local storage.
    pub max_content_bytes: u64,
    /// Maximum governed source identities accepted in one fetch.
    pub max_source_providers: u32,
    /// Maximum independently streamed source fetches.
    pub max_concurrent_streams: u32,
}
/// Public allocation bounds for authenticated finalized-PoR archive proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PorReplayArchiveProofLimitsV1 {
    /// Maximum signed successor receipts admitted before inner decoding.
    pub max_successor_receipts: u32,
    /// Maximum canonical bytes admitted for the successor-receipt proof.
    pub max_successor_proof_bytes: u64,
}
impl IrohaRuntimeProviderBindingV1 {
    fn try_new(
        slot: IrohaRuntimeProviderSlotV1,
        handle: impl Into<String>,
        revision: Option<u64>,
        policy_digest: Option<[u8; 32]>,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let handle = handle.into();
        if !is_production_runtime_handle(&handle) {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        match (revision, policy_digest) {
            (Some(0), _) | (Some(_), None) | (None, Some(_)) => {
                return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
            }
            (_, Some(digest)) if digest == [0; 32] => {
                return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
            }
            (Some(_), Some(_)) | (None, None) => {}
        }
        Ok(Self {
            slot,
            handle,
            revision,
            policy_digest,
            bootle_lantern_issuance_bindings: None,
            stream_token_signer_binding: None,
            appeal_finance_signer_binding: None,
            appeal_finance_checkpoint_binding: None,
            appeal_finance_checkpoint_max_bytes: None,
            pop_credential_runtime_binding: None,
            potr_runtime_binding: None,
            native_signer_binding: None,
            soracloud_runtime_signer_binding: None,
            provider_ingest_signer_binding: None,
            provider_ingest_source_limits: None,
            provider_ingest_checkpoint_max_bytes: None,
            provider_ingest_max_signed_transaction_bytes: None,
            por_replay_archive_binding: None,
            por_replay_archive_proof_limits: None,
            evidence_viewer_webauthn_binding: None,
            evidence_viewer_grant_ttl_ms: None,
            evidence_viewer_receipt_signer_public_key: None,
            evidence_viewer_transparency_publisher_public_key: None,
            evidence_viewer_checkpoint_max_bytes: None,
            moderation_checkpoint_max_bytes: None,
            moderation_checkpoint_attestation_public_key: None,
            evidence_viewer_archive_id: None,
            evidence_viewer_archive_public_key: None,
            evidence_viewer_archive_max_bytes: None,
            moderation_panel_notification_archive_id: None,
            moderation_panel_notification_archive_bootstrap_public_key: None,
            moderation_panel_notification_archive_public_key: None,
            moderation_panel_notification_archive_max_bytes: None,
            moderation_panel_notification_archive_max_records: None,
            governance_dag_publisher_peer_id: None,
            governance_dag_publisher_public_key: None,
            governance_request_ingress_binding: None,
        })
    }
    fn try_new_bootle_lantern_issuance(
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
        bindings: iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderBindingsV1,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry;
        let mut projected = Self::try_new(slot, handle, Some(revision), Some(policy_digest))?;
        projected.bootle_lantern_issuance_bindings = Some(bindings);
        Ok(projected)
    }
    fn try_new_governance_dag_signer(
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
        publisher_peer_id: &str,
        publisher_public_key_hex: &str,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::GovernanceDagSigner;
        if publisher_peer_id.is_empty()
            || publisher_peer_id.len()
                > sorafs_manifest::GOVERNANCE_DAG_PUBLISHER_PEER_ID_MAX_BYTES_V1
            || !publisher_peer_id
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || publisher_public_key_hex.len() != 64
            || !publisher_public_key_hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let public_key = iroha_crypto::PublicKey::from_hex(
            iroha_crypto::Algorithm::Ed25519,
            publisher_public_key_hex,
        )
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        let (algorithm, public_key_bytes) = public_key.to_bytes();
        let public_key_bytes: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        if algorithm != iroha_crypto::Algorithm::Ed25519
            || iroha_crypto::ed25519_parse_public_key(&public_key_bytes).is_err()
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(slot, handle, Some(revision), Some(policy_digest))?;
        projected.governance_dag_publisher_peer_id = Some(publisher_peer_id.as_bytes().to_vec());
        projected.governance_dag_publisher_public_key = Some(public_key_bytes);
        Ok(projected)
    }
    fn try_new_stream_token_signer(
        signer_backend: StreamTokenSignerRuntimeBindingV1,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        signer_backend.validate()?;
        let custody = signer_backend.custody();
        let mut projected = Self::try_new(
            IrohaRuntimeProviderSlotV1::StreamTokenSigner,
            custody.runtime_handle.clone(),
            Some(custody.key_revision),
            Some(custody.policy_digest),
        )?;
        projected.stream_token_signer_binding = Some(signer_backend);
        Ok(projected)
    }
    fn try_new_moderation_checkpoint_store(
        moderation: &iroha_config::parameters::actual::SorafsModerationOrchestrator,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::ModerationCheckpointStore;
        if moderation.checkpoint_max_bytes.0 == 0
            || moderation.checkpoint_max_bytes.0
                > sorafs_node::moderation_orchestrator::
                    MODERATION_ORCHESTRATOR_CHECKPOINT_MAX_BYTES_V1
            || moderation.checkpoint_store_attestation_public_key == [0; 32]
            || iroha_crypto::ed25519_parse_public_key(
                &moderation.checkpoint_store_attestation_public_key,
            )
            .is_err()
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            moderation.checkpoint_store_handle.clone(),
            Some(moderation.checkpoint_store_revision),
            Some(moderation.checkpoint_store_policy_digest),
        )?;
        projected.moderation_checkpoint_max_bytes = Some(moderation.checkpoint_max_bytes.0);
        projected.moderation_checkpoint_attestation_public_key =
            Some(moderation.checkpoint_store_attestation_public_key);
        Ok(projected)
    }
    fn try_new_moderation_panel_notification_archive(
        moderation: &iroha_config::parameters::actual::SorafsModerationOrchestrator,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive;
        if moderation.panel_notification_archive_id == [0; 32]
            || moderation.panel_notification_archive_bootstrap_public_key == [0; 32]
            || moderation.panel_notification_archive_public_key == [0; 32]
            || !(moderation_defaults::PANEL_NOTIFICATION_ARCHIVE_MIN_BYTES_V1
                ..=moderation_defaults::PANEL_NOTIFICATION_ARCHIVE_MAX_BYTES_LIMIT_V1)
                .contains(&moderation.panel_notification_archive_max_bytes.0)
            || moderation.max_handoffs == 0
            || moderation.max_handoffs
                > sorafs_node::moderation_orchestrator::
                    MODERATION_PANEL_NOTIFICATION_ARCHIVE_MAX_RECORDS_V1
            || iroha_crypto::PublicKey::from_bytes(
                iroha_crypto::Algorithm::Ed25519,
                &moderation.panel_notification_archive_public_key,
            )
            .is_err()
            || iroha_crypto::PublicKey::from_bytes(
                iroha_crypto::Algorithm::Ed25519,
                &moderation.panel_notification_archive_bootstrap_public_key,
            )
            .is_err()
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            moderation.panel_notification_archive_handle.clone(),
            Some(moderation.panel_notification_archive_revision),
            Some(moderation.panel_notification_archive_policy_digest),
        )?;
        projected.moderation_panel_notification_archive_id =
            Some(moderation.panel_notification_archive_id);
        projected.moderation_panel_notification_archive_bootstrap_public_key =
            Some(moderation.panel_notification_archive_bootstrap_public_key);
        projected.moderation_panel_notification_archive_public_key =
            Some(moderation.panel_notification_archive_public_key);
        projected.moderation_panel_notification_archive_max_bytes =
            Some(moderation.panel_notification_archive_max_bytes.0);
        projected.moderation_panel_notification_archive_max_records = Some(
            u64::try_from(moderation.max_handoffs)
                .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?,
        );
        Ok(projected)
    }
    fn try_new_pop_credential_registry(
        pop: &iroha_config::parameters::actual::SorafsPopCredentialService,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry;
        let canonical_issuer_id = !pop.issuer_id.is_empty()
            && pop.issuer_id.len()
                <= sorafs_manifest::pop_credentials::POP_IDENTITY_TEXT_MAX_BYTES_V1
            && pop.issuer_id.trim() == pop.issuer_id
            && !pop.issuer_id.chars().any(char::is_control);
        if pop.issuer_policy_digest == [0; 32]
            || !canonical_issuer_id
            || !is_production_runtime_handle(&pop.issuer_signer_handle)
            || !is_production_runtime_handle(&pop.enrollment_recipient_key_id)
            || !is_production_runtime_handle(&pop.wallet_recipient_key_id)
            || !is_production_runtime_handle(&pop.wallet_wrapping_key_id)
            || pop.enrollment_recipient_public_key_digest == [0; 32]
            || pop.wallet_recipient_public_key_digest == [0; 32]
            || pop.issuer_public_key == [0; 32]
            || iroha_crypto::ed25519_parse_public_key(&pop.issuer_public_key).is_err()
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            pop.runtime_provider_registry_handle.clone(),
            Some(pop.runtime_provider_registry_revision),
            Some(pop.runtime_provider_registry_policy_digest),
        )?;
        projected.pop_credential_runtime_binding = Some(PopCredentialRuntimeBindingV1 {
            issuer_policy_digest: pop.issuer_policy_digest,
            issuer_id: pop.issuer_id.clone(),
            issuer_signer_handle: pop.issuer_signer_handle.clone(),
            issuer_public_key: pop.issuer_public_key,
            enrollment_recipient_key_id: pop.enrollment_recipient_key_id.clone(),
            enrollment_recipient_public_key_digest: pop.enrollment_recipient_public_key_digest,
            wallet_recipient_key_id: pop.wallet_recipient_key_id.clone(),
            wallet_recipient_public_key_digest: pop.wallet_recipient_public_key_digest,
            wallet_wrapping_key_id: pop.wallet_wrapping_key_id.clone(),
        });
        Ok(projected)
    }
    fn try_new_appeal_finance_signer(
        binding: &iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner;
        if !matches!(
            binding.public_key.try_algorithm(),
            Ok(iroha_crypto::Algorithm::Ed25519)
        ) || iroha_data_model::account::AccountId::new(binding.public_key.clone())
            != binding.authority
            || binding.valid_from_block_height == 0
            || binding
                .revoked_at_block_height
                .is_some_and(|height| height <= binding.valid_from_block_height)
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            binding.handle.clone(),
            Some(binding.revision),
            Some(binding.policy_digest),
        )?;
        projected.appeal_finance_signer_binding = Some(binding.clone());
        Ok(projected)
    }
    fn try_new_appeal_finance_checkpoint(
        binding: &iroha_config::parameters::actual::SorafsAppealFinanceCheckpointBinding,
        checkpoint_max_bytes: u64,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint;
        if !matches!(
            binding.public_key.try_algorithm(),
            Ok(iroha_crypto::Algorithm::Ed25519)
        ) || !(torii_defaults::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MIN_BYTES_V1
            ..=torii_defaults::
                SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MAX_BYTES_LIMIT_V1)
            .contains(&checkpoint_max_bytes)
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            binding.handle.clone(),
            Some(binding.revision),
            Some(binding.policy_digest),
        )?;
        projected.appeal_finance_checkpoint_binding = Some(binding.clone());
        projected.appeal_finance_checkpoint_max_bytes = Some(checkpoint_max_bytes);
        Ok(projected)
    }
    fn try_new_potr_signer(
        slot: IrohaRuntimeProviderSlotV1,
        runtime: &iroha_config::parameters::actual::SorafsPotrRuntimeBinding,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let signer = match slot {
            IrohaRuntimeProviderSlotV1::PotrGatewaySigner => &runtime.gateway_signer,
            IrohaRuntimeProviderSlotV1::PotrProviderSigner => &runtime.provider_signer,
            _ => return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot)),
        };
        let qualification = iroha_torii::sorafs::PotrRuntimeProviderQualificationV1::new(
            signer.revision,
            signer.policy_digest,
        );
        iroha_torii::sorafs::PotrRuntimeProviderBindingV1::try_new(
            signer.handle.clone(),
            signer.signer_id,
            qualification,
        )
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        iroha_torii::sorafs::PotrRuntimeReaderBindingsV1::try_new(
            runtime.reader_id,
            runtime.source_id,
            runtime.resolver_id,
        )
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        let admission = &runtime.baseline_admission_policy;
        let admission = sorafs_node::PotrAdmissionPolicyBindingV1 {
            provider_id: admission.provider_id,
            policy_identity: admission.policy_identity,
            policy_digest: admission.policy_digest,
            policy_sequence: admission.policy_sequence,
            finalized_height: admission.finalized_height,
            finalized_block_hash: admission.finalized_block_hash,
            admission_envelope_digest: admission.admission_envelope_digest,
        };
        admission
            .validate()
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        if runtime.gateway_signer.handle == runtime.provider_signer.handle
            || runtime.gateway_signer.signer_id == runtime.provider_signer.signer_id
            || runtime.gateway_public_key == [0; 32]
            || iroha_crypto::ed25519_parse_public_key(&runtime.gateway_public_key).is_err()
            || runtime.provider_signer.revision != admission.policy_sequence
            || runtime.provider_signer.policy_digest != admission.policy_digest
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            signer.handle.clone(),
            Some(signer.revision),
            Some(signer.policy_digest),
        )?;
        projected.potr_runtime_binding = Some(runtime.clone());
        Ok(projected)
    }
    fn try_new_governance_request_auth(
        slot: IrohaRuntimeProviderSlotV1,
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
        ingress_binding: sorafs_node::GovernanceDagRequestIngressBindingV1,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let expected_scope = match slot {
            IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator => {
                sorafs_node::GovernanceDagAuthenticationScope::Ipfs
            }
            IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator => {
                sorafs_node::GovernanceDagAuthenticationScope::SignedHead
            }
            _ => return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot)),
        };
        if ingress_binding.scope() != expected_scope {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(slot, handle, Some(revision), Some(policy_digest))?;
        projected.governance_request_ingress_binding = Some(ingress_binding);
        Ok(projected)
    }
    fn try_new_evidence_viewer_webauthn(
        viewer: &iroha_config::parameters::actual::SorafsEvidenceViewer,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn;
        if validate_webauthn_rp_id_v1(&viewer.webauthn_rp_id).is_err()
            || viewer.webauthn_allowed_origins.is_empty()
            || viewer.webauthn_allowed_origins.len() > 16
            || viewer
                .webauthn_allowed_origins
                .iter()
                .any(|origin| validate_webauthn_origin_v1(origin, &viewer.webauthn_rp_id).is_err())
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let challenge_ttl_ms = u64::try_from(viewer.challenge_ttl.as_millis())
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        if challenge_ttl_ms == 0 {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut origins = viewer.webauthn_allowed_origins.clone();
        origins.sort();
        origins.dedup();
        if origins != viewer.webauthn_allowed_origins {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            viewer.webauthn_handle.clone(),
            Some(viewer.webauthn_revision),
            Some(viewer.webauthn_policy_digest),
        )?;
        projected.evidence_viewer_webauthn_binding = Some(EvidenceViewerWebAuthnBindingV1 {
            rp_id: viewer.webauthn_rp_id.clone(),
            allowed_origins: viewer.webauthn_allowed_origins.clone(),
            challenge_ttl_ms,
        });
        Ok(projected)
    }
    fn try_new_evidence_viewer_grants(
        viewer: &iroha_config::parameters::actual::SorafsEvidenceViewer,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority;
        let grant_ttl_ms = u64::try_from(viewer.grant_ttl.as_millis())
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        if grant_ttl_ms == 0 {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            viewer.grant_handle.clone(),
            Some(viewer.grant_revision),
            Some(viewer.grant_policy_digest),
        )?;
        projected.evidence_viewer_grant_ttl_ms = Some(grant_ttl_ms);
        Ok(projected)
    }
    fn try_new_evidence_viewer_receipt_signer(
        viewer: &iroha_config::parameters::actual::SorafsEvidenceViewer,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner;
        if viewer.receipt_signer_public_key == [0; 32]
            || iroha_crypto::PublicKey::from_bytes(
                iroha_crypto::Algorithm::Ed25519,
                &viewer.receipt_signer_public_key,
            )
            .is_err()
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            viewer.receipt_signer_handle.clone(),
            Some(viewer.receipt_signer_revision),
            Some(viewer.receipt_signer_policy_digest),
        )?;
        projected.evidence_viewer_receipt_signer_public_key =
            Some(viewer.receipt_signer_public_key);
        Ok(projected)
    }
    fn try_new_evidence_viewer_checkpoint_store(
        viewer: &iroha_config::parameters::actual::SorafsEvidenceViewer,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore;
        let checkpoint_max_bytes = viewer.checkpoint_max_bytes.0;
        if checkpoint_max_bytes == 0
            || checkpoint_max_bytes
                > sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_CHECKPOINT_BYTES_V1
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            viewer.checkpoint_store_handle.clone(),
            Some(viewer.checkpoint_store_revision),
            Some(viewer.checkpoint_store_policy_digest),
        )?;
        projected.evidence_viewer_checkpoint_max_bytes = Some(checkpoint_max_bytes);
        Ok(projected)
    }
    fn try_new_evidence_viewer_archive(
        viewer: &iroha_config::parameters::actual::SorafsEvidenceViewer,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive;
        let archive_max_bytes = viewer
            .checkpoint_max_bytes
            .0
            .checked_add(16 * 1024)
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        if viewer.compaction_archive_id == [0; 32]
            || viewer.compaction_archive_public_key == [0; 32]
            || viewer.checkpoint_max_bytes.0 == 0
            || viewer.checkpoint_max_bytes.0
                > sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_CHECKPOINT_BYTES_V1
            || iroha_crypto::PublicKey::from_bytes(
                iroha_crypto::Algorithm::Ed25519,
                &viewer.compaction_archive_public_key,
            )
            .is_err()
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            viewer.compaction_archive_handle.clone(),
            Some(viewer.compaction_archive_revision),
            Some(viewer.compaction_archive_policy_digest),
        )?;
        projected.evidence_viewer_archive_id = Some(viewer.compaction_archive_id);
        projected.evidence_viewer_archive_public_key = Some(viewer.compaction_archive_public_key);
        projected.evidence_viewer_archive_max_bytes = Some(archive_max_bytes);
        Ok(projected)
    }
    fn try_new_evidence_viewer_transparency_publisher(
        viewer: &iroha_config::parameters::actual::SorafsEvidenceViewer,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher;
        if viewer.transparency_publisher_public_key == [0; 32]
            || iroha_crypto::PublicKey::from_bytes(
                iroha_crypto::Algorithm::Ed25519,
                &viewer.transparency_publisher_public_key,
            )
            .is_err()
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            viewer.transparency_publisher_handle.clone(),
            Some(viewer.transparency_publisher_revision),
            Some(viewer.transparency_publisher_policy_digest),
        )?;
        projected.evidence_viewer_transparency_publisher_public_key =
            Some(viewer.transparency_publisher_public_key);
        Ok(projected)
    }
    fn try_new_por_replay_archive(
        archive: &iroha_config::parameters::actual::SorafsPorReplayArchive,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive;
        let binding = sorafs_node::PorFinalizedReplayArchiveBindingV1::try_new(
            archive.archive_id,
            archive.revision,
            archive.policy_digest,
            archive.signing_public_key,
        )
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        sorafs_node::PorFinalizedReplayArchiveProofBoundsV1::try_new(
            archive.max_successor_receipts,
            archive.max_successor_proof_bytes,
        )
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        if archive.max_successor_receipts
            > iroha_config::parameters::defaults::sorafs::storage::por_replay_archive::
                MAX_SUCCESSOR_RECEIPTS_LIMIT
            || archive.max_successor_proof_bytes
                > iroha_config::parameters::defaults::sorafs::storage::por_replay_archive::
                    MAX_SUCCESSOR_PROOF_BYTES_LIMIT
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            archive.handle.clone(),
            Some(archive.revision),
            Some(archive.policy_digest),
        )?;
        projected.por_replay_archive_binding = Some(binding);
        projected.por_replay_archive_proof_limits = Some(PorReplayArchiveProofLimitsV1 {
            max_successor_receipts: archive.max_successor_receipts,
            max_successor_proof_bytes: archive.max_successor_proof_bytes,
        });
        Ok(projected)
    }
    fn try_new_provider_ingest_source(
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
        limits: ProviderIngestSourceLimitsV1,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource;
        let max_source_providers = usize::try_from(limits.max_source_providers)
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        if limits.operation_timeout_ms == 0
            || limits.operation_timeout_ms
                > provider_ingest_defaults::SOURCE_OPERATION_TIMEOUT_MS_LIMIT_V1
            || limits.max_content_bytes == 0
            || limits.max_source_providers == 0
            || max_source_providers > provider_ingest_defaults::MAX_SOURCE_PROVIDERS
            || limits.max_concurrent_streams == 0
            || limits.max_concurrent_streams > MAX_PROVIDER_INGEST_SOURCE_STREAMS_V1
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(slot, handle, Some(revision), Some(policy_digest))?;
        projected.provider_ingest_source_limits = Some(limits);
        Ok(projected)
    }
    fn try_new_native_signer(
        slot: IrohaRuntimeProviderSlotV1,
        binding: iroha_torii::SorafsNativeTransactionSignerBindingV1,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        if native_signer_role_for_slot(slot) != Some(binding.role()) {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(
            slot,
            binding.handle(),
            Some(binding.qualification().revision()),
            Some(binding.qualification().policy_digest()),
        )?;
        projected.native_signer_binding = Some(binding);
        Ok(projected)
    }
    fn try_new_soracloud_runtime_signer(
        binding: &iroha_config::parameters::actual::SoracloudRuntimeMutationSignerBinding,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner;
        let exact =
            crate::soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1::try_from_config(
                binding,
            )
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        let mut projected = Self::try_new(
            slot,
            exact.handle(),
            Some(exact.qualification().revision()),
            Some(exact.qualification().policy_digest()),
        )?;
        projected.soracloud_runtime_signer_binding = Some(exact);
        Ok(projected)
    }
    fn try_new_provider_ingest_signer(
        slot: IrohaRuntimeProviderSlotV1,
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
        signer_binding: sorafs_node::ProviderIngestCompletionSignerBindingV1,
        max_signed_transaction_bytes: u64,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        if !matches!(
            slot,
            IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver
                | IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner
        ) || signer_binding.validate().is_err()
            || !(provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN
                ..=provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_LIMIT)
                .contains(&max_signed_transaction_bytes)
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(slot, handle, Some(revision), Some(policy_digest))?;
        projected.provider_ingest_signer_binding = Some(signer_binding);
        projected.provider_ingest_max_signed_transaction_bytes = Some(max_signed_transaction_bytes);
        Ok(projected)
    }
    fn try_new_provider_ingest_checkpoint(
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
        checkpoint_max_bytes: u64,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore;
        if checkpoint_max_bytes == 0
            || checkpoint_max_bytes > provider_ingest_outbox_defaults::CHECKPOINT_MAX_BYTES_LIMIT
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
        }
        let mut projected = Self::try_new(slot, handle, Some(revision), Some(policy_digest))?;
        projected.provider_ingest_checkpoint_max_bytes = Some(checkpoint_max_bytes);
        Ok(projected)
    }
    /// Return the provider role.
    #[must_use]
    pub const fn slot(&self) -> IrohaRuntimeProviderSlotV1 {
        self.slot
    }
    /// Return the stable non-secret provider handle.
    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }
    /// Return the exact configured adapter/public-policy revision, when that
    /// service's V1 configuration defines one.
    #[must_use]
    pub const fn revision(&self) -> Option<u64> {
        self.revision
    }
    /// Return the exact configured public-policy digest, when that service's
    /// V1 configuration defines one.
    #[must_use]
    pub const fn policy_digest(&self) -> Option<[u8; 32]> {
        self.policy_digest
    }
    /// Return the complete public Bootle/Lantern issuer resolution inputs.
    pub(crate) const fn bootle_lantern_issuance_bindings(
        &self,
    ) -> Option<iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderBindingsV1>
    {
        self.bootle_lantern_issuance_bindings
    }
    /// Return complete provider-scoped signer and independent observer public pins.
    #[must_use]
    pub const fn stream_token_signer_binding(&self) -> Option<&StreamTokenSignerRuntimeBindingV1> {
        self.stream_token_signer_binding.as_ref()
    }
    /// Return the exact configured appeal-finance transaction-signer binding.
    pub(crate) const fn appeal_finance_signer_binding(
        &self,
    ) -> Option<&iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding> {
        self.appeal_finance_signer_binding.as_ref()
    }
    /// Return the exact configured appeal-finance checkpoint binding.
    pub(crate) const fn appeal_finance_checkpoint_binding(
        &self,
    ) -> Option<&iroha_config::parameters::actual::SorafsAppealFinanceCheckpointBinding> {
        self.appeal_finance_checkpoint_binding.as_ref()
    }
    /// Return the configured appeal-finance canonical checkpoint byte bound.
    pub(crate) const fn appeal_finance_checkpoint_max_bytes(&self) -> Option<u64> {
        self.appeal_finance_checkpoint_max_bytes
    }
    /// Return the complete public `PoTR` signer, reader, and finalized-policy pins.
    pub(crate) const fn potr_runtime_binding(
        &self,
    ) -> Option<&iroha_config::parameters::actual::SorafsPotrRuntimeBinding> {
        self.potr_runtime_binding.as_ref()
    }
    /// Return the exact public `PoP` provider-registry resolution inputs.
    pub(crate) const fn pop_credential_runtime_binding(
        &self,
    ) -> Option<&PopCredentialRuntimeBindingV1> {
        self.pop_credential_runtime_binding.as_ref()
    }
    /// Return the exact role-separated native transaction-signer binding when
    /// this request represents one of the four native signer roles.
    #[must_use]
    pub const fn native_signer_binding(
        &self,
    ) -> Option<&iroha_torii::SorafsNativeTransactionSignerBindingV1> {
        self.native_signer_binding.as_ref()
    }
    /// Return the configured native signer algorithm, when applicable.
    #[must_use]
    pub fn native_signer_algorithm(&self) -> Option<iroha_crypto::Algorithm> {
        self.native_signer_binding
            .as_ref()?
            .public_key()
            .try_algorithm()
            .ok()
    }
    /// Return the exact Soracloud runtime signer binding, when requested.
    #[must_use]
    pub const fn soracloud_runtime_signer_binding(
        &self,
    ) -> Option<&crate::soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1> {
        self.soracloud_runtime_signer_binding.as_ref()
    }
    /// Return the exact governed provider-ingest completion-signer binding.
    pub(crate) fn provider_ingest_signer_binding(
        &self,
    ) -> Option<&sorafs_node::ProviderIngestCompletionSignerBindingV1> {
        self.provider_ingest_signer_binding.as_ref()
    }
    /// Return the configured authenticated-source deadline and resource bounds.
    pub(crate) const fn provider_ingest_source_limits(
        &self,
    ) -> Option<ProviderIngestSourceLimitsV1> {
        self.provider_ingest_source_limits
    }
    /// Return the configured provider-ingest sealed-checkpoint byte bound.
    pub(crate) const fn provider_ingest_checkpoint_max_bytes(&self) -> Option<u64> {
        self.provider_ingest_checkpoint_max_bytes
    }
    /// Return the configured canonical signed-completion-transaction byte bound.
    pub(crate) const fn provider_ingest_max_signed_transaction_bytes(&self) -> Option<u64> {
        self.provider_ingest_max_signed_transaction_bytes
    }
    /// Return the exact configured Governance DAG publisher peer identity.
    #[must_use]
    pub(crate) fn governance_dag_publisher_peer_id(&self) -> Option<&[u8]> {
        self.governance_dag_publisher_peer_id.as_deref()
    }
    /// Return the exact configured Governance DAG publisher verification key.
    #[must_use]
    pub(crate) const fn governance_dag_publisher_public_key(&self) -> Option<[u8; 32]> {
        self.governance_dag_publisher_public_key
    }
    /// Return the exact finalized-PoR archive identity and verification binding.
    #[must_use]
    pub const fn por_replay_archive_binding(
        &self,
    ) -> Option<sorafs_node::PorFinalizedReplayArchiveBindingV1> {
        self.por_replay_archive_binding
    }
    /// Return exact allocation bounds for authenticated lookup/readback proofs.
    #[must_use]
    pub(crate) const fn por_replay_archive_proof_limits(
        &self,
    ) -> Option<PorReplayArchiveProofLimitsV1> {
        self.por_replay_archive_proof_limits
    }
    /// Return the exact public `WebAuthn` RP/origin policy.
    pub(crate) const fn evidence_viewer_webauthn_binding(
        &self,
    ) -> Option<&EvidenceViewerWebAuthnBindingV1> {
        self.evidence_viewer_webauthn_binding.as_ref()
    }
    /// Return the maximum configured rotating-grant lifetime.
    pub(crate) const fn evidence_viewer_grant_ttl_ms(&self) -> Option<u64> {
        self.evidence_viewer_grant_ttl_ms
    }
    /// Return the exact governed Ed25519 receipt-verification key.
    pub(crate) const fn evidence_viewer_receipt_signer_public_key(&self) -> Option<[u8; 32]> {
        self.evidence_viewer_receipt_signer_public_key
    }
    /// Return the exact governed transparency-publisher verification key.
    pub(crate) const fn evidence_viewer_transparency_publisher_public_key(
        &self,
    ) -> Option<[u8; 32]> {
        self.evidence_viewer_transparency_publisher_public_key
    }
    /// Return the exact configured evidence-viewer checkpoint byte bound.
    pub(crate) const fn evidence_viewer_checkpoint_max_bytes(&self) -> Option<u64> {
        self.evidence_viewer_checkpoint_max_bytes
    }
    /// Return the configured moderation checkpoint byte bound.
    pub(crate) const fn moderation_checkpoint_max_bytes(&self) -> Option<u64> {
        self.moderation_checkpoint_max_bytes
    }
    /// Return the exact Ed25519 key authenticating terminal-set source attestations.
    pub(crate) const fn moderation_checkpoint_attestation_public_key(&self) -> Option<[u8; 32]> {
        self.moderation_checkpoint_attestation_public_key
    }
    /// Return the exact non-secret evidence-viewer archive namespace.
    #[must_use]
    pub const fn evidence_viewer_archive_id(&self) -> Option<[u8; 32]> {
        self.evidence_viewer_archive_id
    }
    /// Return the exact Ed25519 evidence-viewer archive verification key.
    #[must_use]
    pub const fn evidence_viewer_archive_public_key(&self) -> Option<[u8; 32]> {
        self.evidence_viewer_archive_public_key
    }
    /// Return the exact canonical compaction-artifact byte bound.
    pub(crate) const fn evidence_viewer_archive_max_bytes(&self) -> Option<u64> {
        self.evidence_viewer_archive_max_bytes
    }
    /// Return the exact non-secret moderation receipt archive namespace.
    #[must_use]
    pub const fn moderation_panel_notification_archive_id(&self) -> Option<[u8; 32]> {
        self.moderation_panel_notification_archive_id
    }
    /// Return the bootstrap Ed25519 signer anchoring the moderation archive epoch log.
    #[must_use]
    pub const fn moderation_panel_notification_archive_bootstrap_public_key(
        &self,
    ) -> Option<[u8; 32]> {
        self.moderation_panel_notification_archive_bootstrap_public_key
    }
    /// Return the exact Ed25519 moderation receipt archive verification key.
    #[must_use]
    pub const fn moderation_panel_notification_archive_public_key(&self) -> Option<[u8; 32]> {
        self.moderation_panel_notification_archive_public_key
    }
    /// Return the exact canonical moderation receipt archive byte bound.
    pub(crate) const fn moderation_panel_notification_archive_max_bytes(&self) -> Option<u64> {
        self.moderation_panel_notification_archive_max_bytes
    }
    /// Return the terminal-record bound for one moderation receipt archive artifact.
    pub(crate) const fn moderation_panel_notification_archive_max_records(&self) -> Option<u64> {
        self.moderation_panel_notification_archive_max_records
    }
    /// Return the exact endpoint, key, body, and timing policy expected from a
    /// Governance request-ingress provider.
    #[must_use]
    pub const fn governance_request_ingress_binding(
        &self,
    ) -> Option<sorafs_node::GovernanceDagRequestIngressBindingV1> {
        self.governance_request_ingress_binding
    }
}
const fn native_signer_role_for_slot(
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
/// Sanitized, deterministically ordered provider requests for one node launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrohaRuntimeProviderBindingsV1 {
    chain_id: String,
    network_id: NetworkId,
    credential_max_memory_bytes: usize,
    bindings: Vec<IrohaRuntimeProviderBindingV1>,
}
#[derive(Clone, Copy)]
struct GovernanceDagRequestAuthBindingProjectionV1<'a> {
    handle: &'a str,
    qualification: sorafs_node::GovernanceDagRuntimeProviderQualificationV1,
    ingress_binding: sorafs_node::GovernanceDagRequestIngressBindingV1,
}
#[derive(Clone, Copy)]
struct GovernanceDagServiceBindingProjectionV1<'a> {
    ipfs_authenticator: GovernanceDagRequestAuthBindingProjectionV1<'a>,
    head_authenticator: Option<GovernanceDagRequestAuthBindingProjectionV1<'a>>,
    checkpoint_store_handle: &'a str,
    checkpoint_store_qualification: sorafs_node::GovernanceDagRuntimeProviderQualificationV1,
}
impl IrohaRuntimeProviderBindingsV1 {
    /// Project only stable public provider identities from validated node
    /// configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if an in-memory `Config` was manually substituted
    /// after parsing with a noncanonical, zero-qualified, or test-marked
    /// binding.
    pub fn try_from_config(config: &Config) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let mut bindings = Vec::new();
        collect_configured_bindings(config, &mut bindings)?;
        bindings.sort_unstable_by(|left, right| {
            left.slot
                .cmp(&right.slot)
                .then_with(|| left.handle.cmp(&right.handle))
                .then_with(|| left.revision.cmp(&right.revision))
                .then_with(|| left.policy_digest.cmp(&right.policy_digest))
        });
        Ok(Self {
            chain_id: config.common.chain.to_string(),
            network_id: NetworkId::from_genesis_hash(config.genesis.expected_hash),
            credential_max_memory_bytes: config
                .runtime_provider_broker
                .credential_max_memory_bytes
                .get(),
            bindings,
        })
    }
    /// Project the exact public provider catalog requested by a validated
    /// standalone Governance DAG service view.
    ///
    /// Producer-signing fields in the view are deliberately excluded because
    /// the standalone service consumes already signed producer output. The
    /// resulting catalog contains slots 8 and 10 in IPNS mode and slots 8, 9,
    /// and 10 in signed-HTTP mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the service is disabled, its head mode is invalid,
    /// a required public binding is missing, or an in-memory view was manually
    /// substituted with a noncanonical, zero-qualified, or test-marked
    /// binding.
    pub fn try_from_governance_dag_service_view(
        chain_id: &iroha_model_base::chain::ChainId,
        network_id: NetworkId,
        view: &iroha_config::parameters::actual::SorafsGovernanceDagServiceView,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let service = &view.service;
        if !service.enabled {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator,
            ));
        }
        let ipfs_authenticator = match (
            service.ipfs_authenticator_handle.as_deref(),
            service.ipfs_authenticator_revision,
            service.ipfs_authenticator_policy_digest,
        ) {
            (Some(handle), Some(revision), Some(policy_digest)) => {
                GovernanceDagRequestAuthBindingProjectionV1 {
                    handle,
                    qualification: sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                        revision,
                        policy_digest,
                    ),
                    ingress_binding: governance_request_ingress_binding_from_service(
                        service,
                        sorafs_node::GovernanceDagAuthenticationScope::Ipfs,
                    )?,
                }
            }
            _ => {
                return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator,
                ));
            }
        };
        let head_authenticator = match service.head_mode.as_str() {
            "signed_http" if service.ipns_name.is_none() && service.ipns_key_name.is_none() => {
                match (
                    service.head_authenticator_handle.as_deref(),
                    service.head_authenticator_revision,
                    service.head_authenticator_policy_digest,
                ) {
                    (Some(handle), Some(revision), Some(policy_digest)) => {
                        Some(GovernanceDagRequestAuthBindingProjectionV1 {
                            handle,
                            qualification:
                                sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                                    revision,
                                    policy_digest,
                                ),
                            ingress_binding: governance_request_ingress_binding_from_service(
                                service,
                                sorafs_node::GovernanceDagAuthenticationScope::SignedHead,
                            )?,
                        })
                    }
                    _ => {
                        return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                            IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator,
                        ));
                    }
                }
            }
            "ipns"
                if service.signed_head_url.is_none()
                    && service
                        .ipns_name
                        .as_deref()
                        .is_some_and(|name| !name.is_empty())
                    && service
                        .ipns_key_name
                        .as_deref()
                        .is_some_and(|name| !name.is_empty())
                    && service.head_authenticator_handle.is_none()
                    && service.head_authenticator_revision.is_none()
                    && service.head_authenticator_policy_digest.is_none()
                    && service.head_request_auth_public_key.is_none() =>
            {
                None
            }
            _ => {
                return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator,
                ));
            }
        };
        let checkpoint_store_qualification = match (
            service.checkpoint_store_revision,
            service.checkpoint_store_policy_digest,
        ) {
            (Some(revision), Some(policy_digest)) => {
                sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                    revision,
                    policy_digest,
                )
            }
            _ => {
                return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore,
                ));
            }
        };
        let Some(checkpoint_store_handle) = service.checkpoint_store_handle.as_deref() else {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore,
            ));
        };
        Self::try_from_governance_dag_service_projection(
            chain_id,
            network_id,
            &GovernanceDagServiceBindingProjectionV1 {
                ipfs_authenticator,
                head_authenticator,
                checkpoint_store_handle,
                checkpoint_store_qualification,
            },
        )
    }
    /// Construct the exact one-slot catalog for a standalone Bootle/Lantern issuer broker.
    ///
    /// This is the only standalone constructor for slot 55. It deliberately
    /// cannot attach another runtime role, so the broker server's exact-set
    /// check rejects accidental co-location or a partially provisioned node
    /// catalog.
    ///
    /// # Errors
    ///
    /// Rejects a non-production handle, zero revision or policy digest, or
    /// invalid issuer, policy, or authorization-lifetime bindings.
    pub fn try_from_bootle_lantern_issuance_service(
        chain_id: &iroha_model_base::chain::ChainId,
        network_id: NetworkId,
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
        bindings: iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderBindingsV1,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        if network_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry,
            ));
        }
        let binding = IrohaRuntimeProviderBindingV1::try_new_bootle_lantern_issuance(
            handle,
            revision,
            policy_digest,
            bindings,
        )?;
        Ok(Self {
            chain_id: chain_id.to_string(),
            network_id,
            credential_max_memory_bytes: 0,
            bindings: vec![binding],
        })
    }
    /// Project the exact public provider catalog requested by the standalone
    /// Governance DAG service.
    ///
    /// The standalone service does not execute producer signing. This catalog
    /// therefore always contains its IPFS authenticator and sealed checkpoint
    /// store, plus the signed-head CAS authenticator only in signed-HTTP mode.
    ///
    /// # Errors
    ///
    /// Returns an error when a service binding is incomplete, noncanonical,
    /// zero-qualified, test-marked, or carries an invalid Ed25519 public key or
    /// request-size bound.
    pub fn try_from_governance_dag_service(
        chain_id: &iroha_model_base::chain::ChainId,
        network_id: NetworkId,
        service: &sorafs_node::GovernanceDagServiceRuntimeProviderBindingsV1,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let head_authenticator = match (
            service.head_authenticator_handle(),
            service.head_authenticator_qualification(),
            service.head_request_ingress_binding(),
        ) {
            (Some(handle), Some(qualification), Some(ingress_binding)) => {
                Some(GovernanceDagRequestAuthBindingProjectionV1 {
                    handle,
                    qualification,
                    ingress_binding,
                })
            }
            (None, None, None) => None,
            _ => {
                return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator,
                ));
            }
        };
        Self::try_from_governance_dag_service_projection(
            chain_id,
            network_id,
            &GovernanceDagServiceBindingProjectionV1 {
                ipfs_authenticator: GovernanceDagRequestAuthBindingProjectionV1 {
                    handle: service.ipfs_authenticator_handle(),
                    qualification: service.ipfs_authenticator_qualification(),
                    ingress_binding: service.ipfs_request_ingress_binding(),
                },
                head_authenticator,
                checkpoint_store_handle: service.checkpoint_store_handle(),
                checkpoint_store_qualification: service.checkpoint_store_qualification(),
            },
        )
    }
    fn try_from_governance_dag_service_projection(
        chain_id: &iroha_model_base::chain::ChainId,
        network_id: NetworkId,
        service: &GovernanceDagServiceBindingProjectionV1<'_>,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let mut bindings = Vec::with_capacity(3);
        append_required_governance_request_auth_binding(
            &mut bindings,
            IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator,
            Some(service.ipfs_authenticator.handle),
            Some(service.ipfs_authenticator.qualification.revision),
            Some(service.ipfs_authenticator.qualification.policy_digest),
            Some(service.ipfs_authenticator.ingress_binding),
        )?;
        if let Some(head_authenticator) = service.head_authenticator {
            append_required_governance_request_auth_binding(
                &mut bindings,
                IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator,
                Some(head_authenticator.handle),
                Some(head_authenticator.qualification.revision),
                Some(head_authenticator.qualification.policy_digest),
                Some(head_authenticator.ingress_binding),
            )?;
        }
        append_required_governance_service_binding(
            &mut bindings,
            IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore,
            Some(service.checkpoint_store_handle),
            Some(service.checkpoint_store_qualification.revision),
            Some(service.checkpoint_store_qualification.policy_digest),
        )?;
        bindings.sort_unstable_by(|left, right| {
            left.slot
                .cmp(&right.slot)
                .then_with(|| left.handle.cmp(&right.handle))
                .then_with(|| left.revision.cmp(&right.revision))
                .then_with(|| left.policy_digest.cmp(&right.policy_digest))
        });
        Ok(Self {
            chain_id: chain_id.to_string(),
            network_id,
            credential_max_memory_bytes: 0,
            bindings,
        })
    }
    /// Return the public chain identity associated with this resolution.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
    /// Return the exact genesis-derived network identity for this catalog.
    #[must_use]
    pub const fn network_id(&self) -> &NetworkId {
        &self.network_id
    }
    /// Aggregate credential memory allowed for this registry. Zero grants no threshold custody.
    #[must_use]
    pub const fn credential_max_memory_bytes(&self) -> usize {
        self.credential_max_memory_bytes
    }
    /// Check the parsed local memory policy against this public assembly.
    ///
    /// A positive catalog bound must match exactly. Zero is valid only when
    /// the consensus threshold-signing slot is absent and therefore grants
    /// no threshold custody. This compares public metadata only; it does not
    /// qualify a backend, validate credentials, or grant allocation credit.
    /// The bound controls local operational admission, not transaction validity
    /// or gas accounting.
    ///
    /// # Errors
    ///
    /// Returns [`IrohaRuntimeProviderRegistryErrorV1::BindingMismatch`] before
    /// credential input or backend discovery for a differing bound or a zero
    /// bound attached to threshold custody.
    pub fn validate_credential_memory_policy_v1(
        &self,
        policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    ) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
        let has_threshold_custody = self
            .iter()
            .any(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner);
        if (self.credential_max_memory_bytes != 0 || has_threshold_custody)
            && self.credential_max_memory_bytes != policy.credential_max_memory_bytes.get()
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
        }
        Ok(())
    }
    /// Create the original finite pool once at a credential-registry service boundary.
    ///
    /// Pass this same pool to every current and pending credential import for that
    /// registry. Retained public transcripts keep its charges through their last owner.
    #[must_use]
    pub fn new_credential_registry_budget_v1(&self) -> iroha_allocation::AllocationBudget {
        iroha_allocation::AllocationBudget::new(self.credential_max_memory_bytes)
    }
    /// Iterate over the stable, deterministically ordered provider requests.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &IrohaRuntimeProviderBindingV1> {
        self.bindings.iter()
    }
    /// Preserve catalog identity and ordering while selecting backend-owned slots.
    #[cfg(any(test, feature = "test-network-disposable-broker"))]
    pub(crate) fn select_slots(&self, slots: &[IrohaRuntimeProviderSlotV1]) -> Self {
        Self {
            chain_id: self.chain_id.clone(),
            network_id: self.network_id,
            credential_max_memory_bytes: self.credential_max_memory_bytes,
            bindings: self
                .bindings
                .iter()
                .filter(|binding| slots.contains(&binding.slot()))
                .cloned()
                .collect(),
        }
    }
    /// Return whether the validated configuration requests no external
    /// runtime provider.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
    /// Return the number of requested provider bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }
    /// Construct an empty test catalog without loading daemon configuration.
    #[cfg(test)]
    pub(crate) fn empty_for_test(chain_id: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
            network_id: runtime_provider_test_network_id(),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: Vec::new(),
        }
    }
    /// Construct one exactly qualified test catalog.
    #[cfg(test)]
    pub(crate) fn qualified_for_test(
        chain_id: impl Into<String>,
        slot: IrohaRuntimeProviderSlotV1,
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            network_id: runtime_provider_test_network_id(),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: vec![
                IrohaRuntimeProviderBindingV1::try_new(
                    slot,
                    handle,
                    Some(revision),
                    Some(policy_digest),
                )
                .expect("test binding must be production-shaped"),
            ],
        }
    }
    /// Construct one exactly qualified Governance DAG signer test catalog.
    #[cfg(test)]
    pub(crate) fn qualified_governance_dag_signer_for_test(
        chain_id: impl Into<String>,
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
        publisher_peer_id: &str,
        publisher_public_key_hex: &str,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            network_id: runtime_provider_test_network_id(),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: vec![
                IrohaRuntimeProviderBindingV1::try_new_governance_dag_signer(
                    handle,
                    revision,
                    policy_digest,
                    publisher_peer_id,
                    publisher_public_key_hex,
                )
                .expect("test Governance DAG signer binding must be production-shaped"),
            ],
        }
    }
    /// Construct the exact three-provider moderation notification-archive test catalog.
    #[cfg(test)]
    pub(crate) fn qualified_moderation_panel_notification_archive_for_test(
        fixture: &sorafs_node::moderation_orchestrator::
            ModerationPanelNotificationArchiveBrokerFixtureV1,
        publication_handle: impl Into<String>,
        publication_revision: u64,
        publication_policy_digest: [u8; 32],
    ) -> Self {
        let mut checkpoint = IrohaRuntimeProviderBindingV1::try_new(
            IrohaRuntimeProviderSlotV1::ModerationCheckpointStore,
            fixture.checkpoint_handle.clone(),
            Some(fixture.checkpoint_qualification.revision()),
            Some(fixture.checkpoint_qualification.policy_digest()),
        )
        .expect("fixture checkpoint binding must be production-shaped");
        checkpoint.moderation_checkpoint_max_bytes = Some(fixture.checkpoint_max_bytes);
        checkpoint.moderation_checkpoint_attestation_public_key =
            Some(fixture.checkpoint_attestation_public_key);
        let mut archive = IrohaRuntimeProviderBindingV1::try_new(
            IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
            fixture.archive_handle.clone(),
            Some(fixture.archive_qualification.revision()),
            Some(fixture.archive_qualification.policy_digest()),
        )
        .expect("fixture archive binding must be production-shaped");
        archive.moderation_panel_notification_archive_id = Some(fixture.archive_id);
        archive.moderation_panel_notification_archive_bootstrap_public_key =
            Some(fixture.archive_public_key);
        archive.moderation_panel_notification_archive_public_key = Some(fixture.archive_public_key);
        archive.moderation_panel_notification_archive_max_bytes = Some(fixture.archive_max_bytes);
        archive.moderation_panel_notification_archive_max_records = Some(
            u64::try_from(fixture.expectation().max_records)
                .expect("fixture archive record bound must fit u64"),
        );
        let publication = IrohaRuntimeProviderBindingV1::try_new(
            IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff,
            publication_handle,
            Some(publication_revision),
            Some(publication_policy_digest),
        )
        .expect("fixture publication binding must be production-shaped");
        let mut bindings = vec![publication, checkpoint, archive];
        bindings.sort_unstable_by_key(|binding| binding.slot);
        Self {
            chain_id: "server-test-chain".to_owned(),
            network_id: fixture.network_id,
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings,
        }
    }
    /// Construct one exactly qualified evidence-viewer transparency publisher
    /// test catalog.
    #[cfg(test)]
    pub(crate) fn qualified_evidence_viewer_transparency_publisher_for_test(
        chain_id: impl Into<String>,
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
        public_key: [u8; 32],
    ) -> Self {
        let mut binding = IrohaRuntimeProviderBindingV1::try_new(
            IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher,
            handle,
            Some(revision),
            Some(policy_digest),
        )
        .expect("test transparency-publisher binding must be production-shaped");
        binding.evidence_viewer_transparency_publisher_public_key = Some(public_key);
        Self {
            chain_id: chain_id.into(),
            network_id: runtime_provider_test_network_id(),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: vec![binding],
        }
    }
    /// Construct one exactly qualified Governance DAG request-auth test catalog.
    #[cfg(test)]
    pub(crate) fn qualified_governance_request_auth_for_test(
        chain_id: impl Into<String>,
        slot: IrohaRuntimeProviderSlotV1,
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
        public_key: [u8; 32],
        max_body_bytes: u64,
    ) -> Self {
        let scope = if slot == IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator {
            sorafs_node::GovernanceDagAuthenticationScope::Ipfs
        } else {
            sorafs_node::GovernanceDagAuthenticationScope::SignedHead
        };
        let endpoint = if scope == sorafs_node::GovernanceDagAuthenticationScope::Ipfs {
            "https://governance-ingress.invalid/ipfs/"
        } else {
            "https://governance-ingress.invalid/head"
        };
        let endpoint_binding =
            sorafs_node::governance_dag_request_ingress_endpoint_binding_v1(scope, endpoint)
                .expect("test request-ingress endpoint must be canonical");
        let ingress_binding = sorafs_node::GovernanceDagRequestIngressBindingV1::try_new(
            scope,
            endpoint_binding,
            public_key,
            max_body_bytes,
            30,
            5,
        )
        .expect("test request-ingress binding must be production-shaped");
        Self {
            chain_id: chain_id.into(),
            network_id: runtime_provider_test_network_id(),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: vec![
                IrohaRuntimeProviderBindingV1::try_new_governance_request_auth(
                    slot,
                    handle,
                    revision,
                    policy_digest,
                    ingress_binding,
                )
                .expect("test request-auth binding must be production-shaped"),
            ],
        }
    }
    /// Construct an exactly qualified native transaction-signer test catalog.
    #[cfg(test)]
    pub(crate) fn qualified_native_transaction_signers_for_test(
        chain_id: impl Into<String>,
        entries: impl IntoIterator<
            Item = (
                IrohaRuntimeProviderSlotV1,
                iroha_torii::SorafsNativeTransactionSignerBindingV1,
            ),
        >,
    ) -> Self {
        let mut bindings = entries
            .into_iter()
            .map(|(slot, binding)| {
                IrohaRuntimeProviderBindingV1::try_new_native_signer(slot, binding)
                    .expect("test native signer binding must be production-shaped")
            })
            .collect::<Vec<_>>();
        bindings.sort_unstable_by_key(IrohaRuntimeProviderBindingV1::slot);
        Self {
            chain_id: chain_id.into(),
            network_id: runtime_provider_test_network_id(),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings,
        }
    }
    /// Construct one exactly qualified authenticated-source test catalog.
    #[cfg(test)]
    pub(crate) fn qualified_provider_ingest_source_for_test(
        chain_id: impl Into<String>,
        handle: impl Into<String>,
        revision: u64,
        policy_digest: [u8; 32],
        limits: ProviderIngestSourceLimitsV1,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            network_id: runtime_provider_test_network_id(),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: vec![
                IrohaRuntimeProviderBindingV1::try_new_provider_ingest_source(
                    handle,
                    revision,
                    policy_digest,
                    limits,
                )
                .expect("test source binding must be production-shaped"),
            ],
        }
    }
    /// Attach one explicit network identity to a test catalog.
    #[cfg(test)]
    pub(crate) fn with_network_id_for_test(mut self, network_id: NetworkId) -> Self {
        self.network_id = network_id;
        self
    }
}
#[cfg(test)]
pub(crate) fn runtime_provider_test_network_id() -> NetworkId {
    NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0x15; iroha_crypto::Hash::LENGTH]),
        ),
    )
}
include!("runtime_provider_registry/software_signer_partition.rs");
/// Payload-free failure returned by the deployment registry or launcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IrohaRuntimeProviderRegistryErrorV1 {
    /// One configured binding was noncanonical, zero-qualified, or test-marked.
    InvalidBinding(IrohaRuntimeProviderSlotV1),
    /// At least one provider binding was configured but no registry was supplied.
    MissingRegistry,
    /// The deployment registry could not be reached or initialized.
    Unavailable,
    /// A configured or resolved binding has a different handle, policy, or role.
    BindingMismatch,
    /// A configured or resolved provider binding is stale or revoked.
    StaleOrRevoked,
    /// A test/development binding was presented to a production launch.
    TestProviderRejected,
    /// One or more configured provider bindings had no resolved dependency.
    IncompleteResolution,
    /// Dependencies were returned even though no provider binding was configured.
    UnexpectedProviders,
}
impl fmt::Display for IrohaRuntimeProviderRegistryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidBinding(_) => "runtime-provider binding is invalid",
            Self::MissingRegistry => {
                "runtime-provider bindings are configured but no deployment registry was supplied"
            }
            Self::Unavailable => "deployment runtime-provider registry is unavailable",
            Self::BindingMismatch => "runtime-provider binding is substituted",
            Self::StaleOrRevoked => "runtime-provider binding is stale or revoked",
            Self::TestProviderRejected => "runtime-provider binding is test-marked",
            Self::IncompleteResolution => {
                "deployment runtime-provider registry returned an incomplete dependency set"
            }
            Self::UnexpectedProviders => {
                "deployment runtime-provider registry returned dependencies without configured bindings"
            }
        };
        formatter.write_str(message)
    }
}
impl std::error::Error for IrohaRuntimeProviderRegistryErrorV1 {}
/// Deployment-owned factory for runtime-only daemon adapters.
///
/// Implementations should use the stable handles in `bindings` to locate
/// already-provisioned adapters whose credentials and private keys remain
/// inside the deployment runtime. This registry boundary validates only the
/// sanitized request/result shape. Service-owned constructors perform the
/// binding checks their public interfaces support; callers must not treat
/// successful registry resolution as independent provider attestation.
/// The launcher additionally wraps each configured native proof, repair,
/// reserve, and orderbook signer in Torii's immutable exact-binding facade
/// before forwarding the dependency set. The Soracloud mutation signer is
/// likewise bound to its exact authority and key plus an active, non-test
/// qualification before the runtime manager can start.
///
/// Governance DAG signers are independently cross-bound here to the configured
/// handle, qualification, publisher peer identity, and Ed25519 public key.
/// Stream-token resolution checks complete public signer/observer routing pins
/// and any separately supplied approved custody floor as structural claims only.
/// Torii authenticates fresh challenged custody at startup and each prepared
/// operation against independent trust, trusted time and its own finalized history.
pub trait IrohaRuntimeProviderRegistryV1: Send + Sync {
    /// Resolve the complete dependency set for one standard daemon launch.
    ///
    /// # Errors
    ///
    /// Returns a payload-free error when the registry is unavailable or any
    /// requested provider is missing, substituted, stale, revoked, or
    /// test-marked.
    fn resolve(
        &self,
        bindings: &IrohaRuntimeProviderBindingsV1,
    ) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1>;
}
/// Resolve standard-launcher dependencies without exposing the full config to
/// the deployment registry.
///
/// # Errors
///
/// Returns a payload-free error when a configured binding is invalid, no
/// deployment registry is available, or the registry's resolution is not an
/// exact match for the sanitized binding catalog.
pub(crate) fn resolve_runtime_deps(
    config: &Config,
    registry: Option<&dyn IrohaRuntimeProviderRegistryV1>,
) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
    let bindings = IrohaRuntimeProviderBindingsV1::try_from_config(config)?;
    resolve_runtime_deps_from_bindings(&bindings, registry)
}
pub(crate) fn resolve_runtime_deps_from_bindings(
    bindings: &IrohaRuntimeProviderBindingsV1,
    registry: Option<&dyn IrohaRuntimeProviderRegistryV1>,
) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
    validate_fenced_privacy_binding_pair(bindings)?;
    validate_musubi_provider_attestation_binding_set(bindings)?;
    let Some(registry) = registry else {
        return if bindings.is_empty() {
            Ok(IrohaRuntimeDeps::default())
        } else {
            Err(IrohaRuntimeProviderRegistryErrorV1::MissingRegistry)
        };
    };
    let mut dependencies = registry.resolve(bindings)?;
    if has_unrequested_dependency(bindings, &dependencies) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders);
    }
    if bindings
        .iter()
        .any(|binding| !dependency_is_present(&dependencies, binding.slot()))
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution);
    }
    qualify_musubi_provider_attestation_dependencies(bindings, &dependencies)?;
    // This registry probe deliberately performs metadata-only pre/post
    // qualification and no readiness or effects. Before the startup rejection
    // is removed, the activation coordinator must run bounded authenticated
    // readiness and supply the governed operation-time wrappers that fence all
    // three effects and finalized package-owner authority.
    qualify_bootle_lantern_issuance_dependency(bindings, &dependencies)?;
    qualify_fenced_privacy_dependencies(bindings, &dependencies)?;
    qualify_governance_dag_signer_dependency(bindings, &dependencies)?;
    qualify_governance_request_auth_dependencies(bindings, &dependencies)?;
    stream_token_signer::validate_dependency_bindings(bindings, &dependencies)?;
    qualify_native_transaction_signers(bindings, &mut dependencies)?;
    qualify_soracloud_runtime_signer(bindings, &mut dependencies)?;
    qualify_moderation_checkpoint_dependency(bindings, &dependencies)?;
    qualify_provider_ingest_dependencies(bindings, &dependencies)?;
    qualify_reputation_journal_checkpoint_dependency(bindings, &dependencies)?;
    qualify_reputation_retention_dependency(bindings, &dependencies)?;
    qualify_por_replay_archive_dependency(bindings, &dependencies)?;
    qualify_evidence_viewer_archive_dependency(bindings, &dependencies)?;
    qualify_moderation_panel_notification_archive_dependency(bindings, &dependencies)?;
    qualify_evidence_viewer_transparency_publisher_dependency(bindings, &dependencies)?;
    Ok(dependencies)
}
fn qualify_bootle_lantern_issuance_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    use iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderRegistryErrorV1 as ProviderError;
    let slot = IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry;
    let Some(expected) = bindings.iter().find(|binding| binding.slot() == slot) else {
        return Ok(());
    };
    let provider = dependencies
        .bootle_lantern_issuance_provider_registry
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    if provider.handle() != expected.handle() {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    let qualification = provider.qualification().map_err(|error| match error {
        ProviderError::Unavailable => IrohaRuntimeProviderRegistryErrorV1::Unavailable,
        ProviderError::StaleOrRevoked => IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked,
        ProviderError::RejectedBindings => IrohaRuntimeProviderRegistryErrorV1::BindingMismatch,
    })?;
    if Some(qualification.revision) != expected.revision()
        || Some(qualification.policy_digest) != expected.policy_digest()
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    Ok(())
}
fn map_soracloud_runtime_signer_qualification_error(
    error: crate::soracloud_runtime_signer::SoracloudRuntimeSignerQualificationErrorV1,
) -> IrohaRuntimeProviderRegistryErrorV1 {
    use crate::soracloud_runtime_signer::SoracloudRuntimeSignerQualificationErrorV1 as Error;
    match error {
        Error::ProviderUnavailable => IrohaRuntimeProviderRegistryErrorV1::Unavailable,
        Error::InvalidProviderHandle | Error::TestProviderRejected => {
            IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected
        }
        Error::InvalidProviderQualification
        | Error::ProviderInactive
        | Error::RevisionMismatch
        | Error::PolicyDigestMismatch
        | Error::ProviderDrift => IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked,
        Error::UnsupportedProviderKeyAlgorithm
        | Error::HandleMismatch
        | Error::AuthorityMismatch
        | Error::PublicKeyMismatch
        | Error::ProviderAuthorityKeyMismatch => {
            IrohaRuntimeProviderRegistryErrorV1::BindingMismatch
        }
    }
}
fn qualify_moderation_checkpoint_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    let Some(expected) = bindings
        .iter()
        .find(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::ModerationCheckpointStore)
    else {
        return Ok(());
    };
    let store = dependencies
        .sorafs_moderation_checkpoint_store
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    let revision = expected
        .revision()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let policy_digest = expected
        .policy_digest()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let qualification =
        sorafs_node::moderation_orchestrator::ModerationRuntimeProviderQualificationV1::new(
            revision,
            policy_digest,
        );
    let expected_attestation_public_key =
        expected
            .moderation_checkpoint_attestation_public_key()
            .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    sorafs_node::moderation_orchestrator::qualify_moderation_runtime_provider_v1(
        expected.handle(),
        qualification,
        store.as_ref(),
    )
    .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
    if store.attestation_public_key() != expected_attestation_public_key {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    let latest = store.load_latest().map_err(|error| match error {
        sorafs_node::moderation_orchestrator::ModerationCheckpointStoreExternalErrorV1::Unavailable => {
            IrohaRuntimeProviderRegistryErrorV1::Unavailable
        }
        sorafs_node::moderation_orchestrator::ModerationCheckpointStoreExternalErrorV1::Rejected
        | sorafs_node::moderation_orchestrator::ModerationCheckpointStoreExternalErrorV1::Ambiguous => {
            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
        }
    })?;
    if let Some(record) = latest {
        let max_bytes = expected
            .moderation_checkpoint_max_bytes()
            .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
        let encoded = norito::to_bytes(&record)
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
        if !record.has_valid_provider_envelope(expected.handle(), qualification, max_bytes)
            || encoded.len()
                > usize::try_from(max_bytes)
                    .unwrap_or(usize::MAX)
                    .saturating_add(4 * 1024)
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
        }
    }
    sorafs_node::moderation_orchestrator::revalidate_moderation_runtime_provider_v1(
        expected.handle(),
        qualification,
        store.as_ref(),
    )
    .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)?;
    if store.attestation_public_key() != expected_attestation_public_key {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    Ok(())
}
fn qualify_soracloud_runtime_signer(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &mut IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    let slot = IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner;
    let Some(binding) = bindings.iter().find(|binding| binding.slot() == slot) else {
        return Ok(());
    };
    let exact = binding
        .soracloud_runtime_signer_binding()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
    let provider = dependencies
        .soracloud_runtime_mutation_signer
        .take()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    dependencies.soracloud_runtime_mutation_signer = Some(
        crate::soracloud_runtime_signer::qualify_soracloud_runtime_mutation_signer_v1(
            exact.clone(),
            provider,
        )
        .map_err(map_soracloud_runtime_signer_qualification_error)?,
    );
    Ok(())
}
fn qualify_governance_dag_signer_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    let slot = IrohaRuntimeProviderSlotV1::GovernanceDagSigner;
    let Some(expected) = bindings.iter().find(|binding| binding.slot() == slot) else {
        return Ok(());
    };
    let signer = dependencies
        .sorafs_governance_dag_signer
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    let expected_revision = expected
        .revision()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
    let expected_policy_digest = expected
        .policy_digest()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
    let expected_publisher_peer_id = expected
        .governance_dag_publisher_peer_id()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
    let expected_public_key = expected
        .governance_dag_publisher_public_key()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
    let observe = || {
        let handle = signer.handle().to_owned();
        if !is_production_runtime_handle(&handle) {
            return Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected);
        }
        let qualification = signer
            .qualification()
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::Unavailable)?;
        Ok((
            handle,
            qualification,
            signer.publisher_peer_id().to_vec(),
            signer.public_key(),
        ))
    };
    let first = observe()?;
    if first.0 != expected.handle()
        || first.2.as_slice() != expected_publisher_peer_id
        || first.3 != expected_public_key
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    if first.1.revision == 0
        || first.1.policy_digest == [0; 32]
        || first.1.revision != expected_revision
        || first.1.policy_digest != expected_policy_digest
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    let mut nonce = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::Unavailable)?;
    let challenge_digest = governance_dag_signer_startup_challenge_v1(
        nonce,
        bindings.chain_id(),
        expected.handle(),
        expected_revision,
        expected_policy_digest,
        expected_publisher_peer_id,
        expected_public_key,
    )?;
    let challenge =
        sorafs_node::governance_dag_key_transition_signing_payload_v1(1, 2, challenge_digest)
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
    let signature_result = signer.sign(
        sorafs_node::GovernanceDagSigningPurposeV1::KeyTransition,
        &challenge,
    );
    let second = observe()?;
    if second != first {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    let signature_bytes =
        signature_result.map_err(|_| IrohaRuntimeProviderRegistryErrorV1::Unavailable)?;
    let public_key =
        iroha_crypto::PublicKey::from_bytes(iroha_crypto::Algorithm::Ed25519, &expected_public_key)
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
    let signature = iroha_crypto::Signature::try_from_bytes(&signature_bytes)
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
    signature
        .verify(&public_key, &challenge)
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
    Ok(())
}
fn governance_dag_signer_startup_challenge_v1(
    nonce: [u8; 32],
    chain_id: &str,
    handle: &str,
    revision: u64,
    policy_digest: [u8; 32],
    publisher_peer_id: &[u8],
    public_key: [u8; 32],
) -> Result<[u8; 32], IrohaRuntimeProviderRegistryErrorV1> {
    let slot = IrohaRuntimeProviderSlotV1::GovernanceDagSigner;
    let mut hasher = blake3::Hasher::new();
    hasher.update(GOVERNANCE_DAG_SIGNER_STARTUP_CHALLENGE_DOMAIN_V1);
    hasher.update(&nonce);
    for component in [chain_id.as_bytes(), handle.as_bytes(), publisher_peer_id] {
        let length = u64::try_from(component.len())
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        hasher.update(&length.to_le_bytes());
        hasher.update(component);
    }
    hasher.update(&revision.to_le_bytes());
    hasher.update(&policy_digest);
    hasher.update(&public_key);
    Ok(*hasher.finalize().as_bytes())
}
fn qualify_governance_request_auth_dependencies(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    use IrohaRuntimeProviderSlotV1 as Slot;
    for (slot, authenticator) in [
        (
            Slot::GovernanceDagIpfsAuthenticator,
            dependencies
                .sorafs_governance_dag_ipfs_authenticator
                .as_ref(),
        ),
        (
            Slot::GovernanceDagHeadAuthenticator,
            dependencies
                .sorafs_governance_dag_head_authenticator
                .as_ref(),
        ),
    ] {
        let Some(expected) = bindings.iter().find(|binding| binding.slot() == slot) else {
            continue;
        };
        let authenticator =
            authenticator.ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
        if !is_production_runtime_handle(authenticator.handle()) {
            return Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected);
        }
        let expected_revision = expected
            .revision()
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        let expected_policy_digest = expected
            .policy_digest()
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        let expected_ingress = expected
            .governance_request_ingress_binding()
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        let observe = || {
            let qualification = authenticator
                .ingress_qualification()
                .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::Unavailable)?;
            if authenticator.handle() != expected.handle()
                || qualification.binding() != expected_ingress
            {
                return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
            }
            if qualification.provider().revision != expected_revision
                || qualification.provider().policy_digest != expected_policy_digest
            {
                return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
            }
            Ok(qualification)
        };
        let first = observe()?;
        if observe()? != first {
            return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
        }
    }
    Ok(())
}
fn fenced_privacy_binding_pair(
    bindings: &IrohaRuntimeProviderBindingsV1,
) -> Result<
    Option<(
        &IrohaRuntimeProviderBindingV1,
        &IrohaRuntimeProviderBindingV1,
    )>,
    IrohaRuntimeProviderRegistryErrorV1,
> {
    let writer = bindings
        .iter()
        .find(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher);
    let reader = bindings
        .iter()
        .find(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader);
    match (writer, reader) {
        (None, None) => Ok(None),
        (Some(writer), Some(reader)) => Ok(Some((writer, reader))),
        (Some(_), None) | (None, Some(_)) => {
            Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
        }
    }
}
fn validate_fenced_privacy_binding_pair(
    bindings: &IrohaRuntimeProviderBindingsV1,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    let Some((writer, reader)) = fenced_privacy_binding_pair(bindings)? else {
        return Ok(());
    };
    if writer.handle() != reader.handle()
        || writer.revision() != reader.revision()
        || writer.policy_digest() != reader.policy_digest()
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    Ok(())
}
fn validate_musubi_provider_attestation_binding_set(
    bindings: &IrohaRuntimeProviderBindingsV1,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    use IrohaRuntimeProviderSlotV1 as Slot;
    const SLOTS: [Slot; 3] = [
        Slot::MusubiProviderAttestationClockSeal,
        Slot::MusubiProviderAttestationApprovalSigner,
        Slot::MusubiProviderAttestationAuthenticatedInventory,
    ];
    let group = bindings
        .iter()
        .filter(|binding| SLOTS.contains(&binding.slot()))
        .collect::<Vec<_>>();
    if group.is_empty() {
        return Ok(());
    }
    if group.len() != SLOTS.len()
        || SLOTS
            .into_iter()
            .any(|slot| !group.iter().any(|binding| binding.slot() == slot))
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution);
    }
    Ok(())
}
fn musubi_provider_attestation_expected_qualification(
    binding: &IrohaRuntimeProviderBindingV1,
) -> Result<(u64, [u8; 32]), IrohaRuntimeProviderRegistryErrorV1> {
    let revision = binding
        .revision()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(binding.slot()))?;
    let policy_digest = binding
        .policy_digest()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(binding.slot()))?;
    Ok((revision, policy_digest))
}
fn validate_musubi_provider_attestation_runtime_handle(
    binding: &IrohaRuntimeProviderBindingV1,
    runtime_handle: &str,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    if !is_production_runtime_handle(runtime_handle) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected);
    }
    if runtime_handle != binding.handle() {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    Ok(())
}
fn qualify_musubi_provider_attestation_dependencies(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    use IrohaRuntimeProviderSlotV1 as Slot;
    let Some(clock_binding) = bindings
        .iter()
        .find(|binding| binding.slot() == Slot::MusubiProviderAttestationClockSeal)
    else {
        return Ok(());
    };
    let signer_binding = bindings
        .iter()
        .find(|binding| binding.slot() == Slot::MusubiProviderAttestationApprovalSigner)
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    let inventory_binding = bindings
        .iter()
        .find(|binding| binding.slot() == Slot::MusubiProviderAttestationAuthenticatedInventory)
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    let clock = dependencies
        .sorafs_musubi_provider_attestation_clock_seal
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    let clock_handle_before = clock.runtime_handle().to_owned();
    validate_musubi_provider_attestation_runtime_handle(clock_binding, &clock_handle_before)?;
    let (clock_revision, clock_policy_digest) =
        musubi_provider_attestation_expected_qualification(clock_binding)?;
    let clock_qualification_before = clock.qualification().map_err(|error| match error {
        sorafs_node::MusubiProviderAttestationClockSealErrorV1::Unavailable => {
            IrohaRuntimeProviderRegistryErrorV1::Unavailable
        }
        sorafs_node::MusubiProviderAttestationClockSealErrorV1::Rejected
        | sorafs_node::MusubiProviderAttestationClockSealErrorV1::Ambiguous => {
            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
        }
    })?;
    let expected_clock_qualification =
        sorafs_node::MusubiProviderAttestationClockSealQualificationV1::new(
            clock_revision,
            clock_policy_digest,
        );
    if clock_qualification_before != expected_clock_qualification {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    let clock_handle_after = clock.runtime_handle().to_owned();
    validate_musubi_provider_attestation_runtime_handle(clock_binding, &clock_handle_after)?;
    let clock_qualification_after = clock.qualification().map_err(|error| match error {
        sorafs_node::MusubiProviderAttestationClockSealErrorV1::Unavailable => {
            IrohaRuntimeProviderRegistryErrorV1::Unavailable
        }
        sorafs_node::MusubiProviderAttestationClockSealErrorV1::Rejected
        | sorafs_node::MusubiProviderAttestationClockSealErrorV1::Ambiguous => {
            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
        }
    })?;
    if clock_handle_after != clock_handle_before
        || clock_qualification_after != clock_qualification_before
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    let signer = dependencies
        .sorafs_musubi_provider_attestation_approval_signer
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    let signer_handle_before = signer.runtime_handle().to_owned();
    validate_musubi_provider_attestation_runtime_handle(signer_binding, &signer_handle_before)?;
    let (signer_revision, signer_policy_digest) =
        musubi_provider_attestation_expected_qualification(signer_binding)?;
    let signer_qualification_before = signer.qualification().map_err(|error| match error {
        sorafs_node::MusubiProviderAttestationSignerErrorV1::Unavailable => {
            IrohaRuntimeProviderRegistryErrorV1::Unavailable
        }
        sorafs_node::MusubiProviderAttestationSignerErrorV1::Rejected => {
            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
        }
    })?;
    signer_qualification_before
        .validate()
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)?;
    // Owner/controller state and governed signer policy are request-scoped;
    // only the independent deployment-adapter identity is pinned here.
    if signer_qualification_before.adapter_revision() != signer_revision
        || signer_qualification_before.adapter_policy_digest() != signer_policy_digest
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    let signer_handle_after = signer.runtime_handle().to_owned();
    validate_musubi_provider_attestation_runtime_handle(signer_binding, &signer_handle_after)?;
    let signer_qualification_after = signer.qualification().map_err(|error| match error {
        sorafs_node::MusubiProviderAttestationSignerErrorV1::Unavailable => {
            IrohaRuntimeProviderRegistryErrorV1::Unavailable
        }
        sorafs_node::MusubiProviderAttestationSignerErrorV1::Rejected => {
            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
        }
    })?;
    signer_qualification_after
        .validate()
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)?;
    if signer_handle_after != signer_handle_before
        || signer_qualification_after != signer_qualification_before
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    let inventory = dependencies
        .sorafs_musubi_provider_attestation_inventory
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    let inventory_handle_before = inventory.runtime_handle().to_owned();
    validate_musubi_provider_attestation_runtime_handle(
        inventory_binding,
        &inventory_handle_before,
    )?;
    let (inventory_revision, inventory_policy_digest) =
        musubi_provider_attestation_expected_qualification(inventory_binding)?;
    let inventory_qualification_before =
        inventory.qualification().map_err(|error| match error {
            sorafs_node::MusubiProviderAttestationInventoryRuntimeErrorV1::Unavailable => {
                IrohaRuntimeProviderRegistryErrorV1::Unavailable
            }
            sorafs_node::MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected => {
                IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
            }
        })?;
    inventory_qualification_before
        .validate()
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)?;
    if inventory_qualification_before.adapter_revision() != inventory_revision
        || inventory_qualification_before.policy_digest() != inventory_policy_digest
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    let inventory_handle_after = inventory.runtime_handle().to_owned();
    validate_musubi_provider_attestation_runtime_handle(
        inventory_binding,
        &inventory_handle_after,
    )?;
    let inventory_qualification_after = inventory.qualification().map_err(|error| match error {
        sorafs_node::MusubiProviderAttestationInventoryRuntimeErrorV1::Unavailable => {
            IrohaRuntimeProviderRegistryErrorV1::Unavailable
        }
        sorafs_node::MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected => {
            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
        }
    })?;
    inventory_qualification_after
        .validate()
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)?;
    if inventory_handle_after != inventory_handle_before
        || inventory_qualification_after != inventory_qualification_before
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    Ok(())
}
fn validate_fenced_privacy_provider_observation(
    binding: &IrohaRuntimeProviderBindingV1,
    provider_handle: &str,
    qualification: Result<sorafs_node::GovernanceDagRuntimeProviderQualificationV1, String>,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    if !is_production_runtime_handle(provider_handle) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected);
    }
    if provider_handle != binding.handle() {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    let qualification =
        qualification.map_err(|_| IrohaRuntimeProviderRegistryErrorV1::Unavailable)?;
    let expected_revision = binding
        .revision()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(binding.slot()))?;
    let expected_policy_digest = binding
        .policy_digest()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(binding.slot()))?;
    if qualification.revision == 0
        || qualification.policy_digest == [0; 32]
        || qualification.revision != expected_revision
        || qualification.policy_digest != expected_policy_digest
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    Ok(())
}
fn qualify_fenced_privacy_dependencies(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    let Some((writer_binding, reader_binding)) = fenced_privacy_binding_pair(bindings)? else {
        return Ok(());
    };
    let writer = dependencies
        .sorafs_fenced_transparency_publisher
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    validate_fenced_privacy_provider_observation(
        writer_binding,
        writer.handle(),
        writer.qualification(),
    )?;
    let reader = dependencies
        .sorafs_fenced_transparency_head_reader
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    validate_fenced_privacy_provider_observation(
        reader_binding,
        reader.handle(),
        reader.qualification(),
    )?;
    Ok(())
}
fn native_signer_binding_for_slot(
    bindings: &IrohaRuntimeProviderBindingsV1,
    slot: IrohaRuntimeProviderSlotV1,
) -> Result<
    Option<&iroha_torii::SorafsNativeTransactionSignerBindingV1>,
    IrohaRuntimeProviderRegistryErrorV1,
> {
    let Some(binding) = bindings.iter().find(|binding| binding.slot() == slot) else {
        return Ok(None);
    };
    binding
        .native_signer_binding()
        .map(Some)
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))
}
fn map_native_signer_qualification_error(
    error: iroha_torii::SorafsNativeTransactionSignerQualificationErrorV1,
) -> IrohaRuntimeProviderRegistryErrorV1 {
    use iroha_torii::SorafsNativeTransactionSignerQualificationErrorV1 as Error;
    match error {
        Error::ProviderUnavailable => IrohaRuntimeProviderRegistryErrorV1::Unavailable,
        Error::InvalidProviderHandle => IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected,
        Error::InvalidProviderQualification
        | Error::RevisionMismatch
        | Error::PolicyDigestMismatch
        | Error::ProviderDrift => IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked,
        Error::BindingRoleMismatch
        | Error::ProviderRoleMismatch
        | Error::UnsupportedProviderKeyAlgorithm
        | Error::HandleMismatch
        | Error::AuthorityMismatch
        | Error::PublicKeyMismatch
        | Error::ProviderAuthorityKeyMismatch => {
            IrohaRuntimeProviderRegistryErrorV1::BindingMismatch
        }
    }
}
macro_rules! qualify_native_signer_dependency {
    ($bindings:expr, $dependencies:expr, $slot:expr, $field:ident, $qualifier:path) => {
        if let Some(binding) = native_signer_binding_for_slot($bindings, $slot)? {
            let provider = $dependencies
                .$field
                .take()
                .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
            $dependencies.$field = Some(
                $qualifier(*$bindings.network_id(), binding.clone(), provider)
                    .map_err(map_native_signer_qualification_error)?,
            );
        }
    };
}
fn qualify_native_transaction_signers(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &mut IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    qualify_native_signer_dependency!(
        bindings,
        dependencies,
        IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner,
        sorafs_proof_outcome_signer,
        iroha_torii::qualify_sorafs_proof_outcome_transaction_signer_v1
    );
    qualify_native_signer_dependency!(
        bindings,
        dependencies,
        IrohaRuntimeProviderSlotV1::RepairTransactionSigner,
        sorafs_repair_transaction_signer,
        iroha_torii::qualify_sorafs_repair_transaction_signer_v1
    );
    qualify_native_signer_dependency!(
        bindings,
        dependencies,
        IrohaRuntimeProviderSlotV1::ReserveTransactionSigner,
        sorafs_reserve_transaction_signer,
        iroha_torii::qualify_sorafs_reserve_transaction_signer_v1
    );
    qualify_native_signer_dependency!(
        bindings,
        dependencies,
        IrohaRuntimeProviderSlotV1::OrderbookTransactionSigner,
        sorafs_orderbook_transaction_signer,
        iroha_torii::qualify_sorafs_orderbook_transaction_signer_v1
    );
    Ok(())
}
fn qualify_provider_ingest_dependencies(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    use IrohaRuntimeProviderSlotV1 as Slot;
    let binding = |slot| bindings.iter().find(|binding| binding.slot() == slot);
    if let Some(expected) = binding(Slot::ProviderIngestAuthenticatedSource) {
        let source = dependencies
            .sorafs_provider_ingest_authenticated_source
            .as_ref()
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
        let limits = expected
            .provider_ingest_source_limits()
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
        let observe = || {
            let qualification = source.qualification().map_err(|error| match error {
                sorafs_node::ProviderIngestSourceFetchErrorV1::Unavailable => {
                    IrohaRuntimeProviderRegistryErrorV1::Unavailable
                }
                sorafs_node::ProviderIngestSourceFetchErrorV1::ContentRejected
                | sorafs_node::ProviderIngestSourceFetchErrorV1::Rejected => {
                    IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                }
            })?;
            if source.runtime_handle() != expected.handle()
                || expected.revision() != Some(qualification.revision)
                || expected.policy_digest() != Some(qualification.policy_digest)
            {
                return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
            }
            let source_provider_ids = source.source_provider_ids();
            if source_provider_ids.len() < 2
                || source_provider_ids.len()
                    > usize::try_from(limits.max_source_providers)
                        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?
                || source_provider_ids.contains(&[0; 32])
                || source_provider_ids
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
            }
            Ok(source_provider_ids.to_vec())
        };
        let before = observe()?;
        source.check_readiness().map_err(|error| match error {
            sorafs_node::ProviderIngestSourceFetchErrorV1::Unavailable => {
                IrohaRuntimeProviderRegistryErrorV1::Unavailable
            }
            sorafs_node::ProviderIngestSourceFetchErrorV1::ContentRejected
            | sorafs_node::ProviderIngestSourceFetchErrorV1::Rejected => {
                IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
            }
        })?;
        if observe()? != before {
            return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
        }
    }
    match (
        binding(Slot::ProviderIngestCompletionSignerResolver),
        binding(Slot::ProviderIngestCompletionSigner),
    ) {
        (None, None) => {}
        (Some(resolver_binding), Some(signer_binding)) => {
            let resolver = dependencies
                .sorafs_provider_ingest_signer_resolver
                .as_ref()
                .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
            let expected_signer = resolver_binding
                .provider_ingest_signer_binding()
                .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
            if signer_binding.provider_ingest_signer_binding() != Some(expected_signer) {
                return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
            }
            let observe = || {
                let qualification = resolver.qualification().map_err(|error| match error {
                    sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Unavailable => {
                        IrohaRuntimeProviderRegistryErrorV1::Unavailable
                    }
                    sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Rejected => {
                        IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                    }
                })?;
                let actual_signer = resolver.signer_binding().map_err(|error| match error {
                    sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Unavailable => {
                        IrohaRuntimeProviderRegistryErrorV1::Unavailable
                    }
                    sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Rejected => {
                        IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                    }
                })?;
                if resolver.runtime_handle() != resolver_binding.handle()
                    || resolver_binding.revision() != Some(qualification.revision)
                    || resolver_binding.policy_digest() != Some(qualification.policy_digest)
                    || &actual_signer != expected_signer
                {
                    return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
                }
                Ok(())
            };
            observe()?;
            resolver.check_readiness().map_err(|error| match error {
                sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Unavailable => {
                    IrohaRuntimeProviderRegistryErrorV1::Unavailable
                }
                sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Rejected => {
                    IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                }
            })?;
            observe()?;
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution);
        }
    }
    if let Some(expected) = binding(Slot::ProviderIngestCheckpointStore) {
        let store = dependencies
            .sorafs_provider_ingest_checkpoint_runtime
            .as_ref()
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
        let observe = || {
            let qualification = store.qualification().map_err(|error| match error {
                sorafs_node::ProviderIngestCheckpointExternalErrorV1::Unavailable => {
                    IrohaRuntimeProviderRegistryErrorV1::Unavailable
                }
                sorafs_node::ProviderIngestCheckpointExternalErrorV1::Rejected
                | sorafs_node::ProviderIngestCheckpointExternalErrorV1::Ambiguous => {
                    IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                }
            })?;
            if store.handle() != expected.handle()
                || expected.revision() != Some(qualification.revision)
                || expected.policy_digest() != Some(qualification.policy_digest)
            {
                return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
            }
            Ok(())
        };
        observe()?;
        if let Some(record) = store.load_latest().map_err(|error| match error {
            sorafs_node::ProviderIngestCheckpointExternalErrorV1::Unavailable => {
                IrohaRuntimeProviderRegistryErrorV1::Unavailable
            }
            sorafs_node::ProviderIngestCheckpointExternalErrorV1::Rejected
            | sorafs_node::ProviderIngestCheckpointExternalErrorV1::Ambiguous => {
                IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
            }
        })? {
            record
                .validate(
                    expected
                        .provider_ingest_checkpoint_max_bytes()
                        .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?,
                )
                .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
        }
        observe()?;
    }
    if let Some(expected) = binding(Slot::ProviderIngestRetentionAuthority) {
        let authority = dependencies
            .sorafs_provider_ingest_retention_authority
            .as_ref()
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
        let expected_revision = expected
            .revision()
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
        let expected_digest = expected
            .policy_digest()
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
        let observe = || {
            let qualification = authority.qualification().map_err(|error| match error {
                iroha_core::query::provider_ingest_finalized::
                    ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Unavailable => {
                        IrohaRuntimeProviderRegistryErrorV1::Unavailable
                    }
                iroha_core::query::provider_ingest_finalized::
                    ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Rejected
                | iroha_core::query::provider_ingest_finalized::
                    ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous => {
                        IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                    }
            })?;
            if authority.handle() != expected.handle()
                || qualification.revision() != expected_revision
                || qualification.policy_digest() != expected_digest
            {
                return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
            }
            Ok(qualification)
        };
        let expected_qualification = observe()?;
        let network_id = bindings.network_id();
        if authority
            .load_latest(network_id)
            .map_err(|error| {
                match error {
            iroha_core::query::provider_ingest_finalized::
                ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Unavailable => {
                    IrohaRuntimeProviderRegistryErrorV1::Unavailable
                }
            iroha_core::query::provider_ingest_finalized::
                ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Rejected
            | iroha_core::query::provider_ingest_finalized::
                ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous => {
                    IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                }
        }
            })?
            .is_some_and(|record| {
                record.authority_qualification() != expected_qualification
                    || record.to_canonical_bytes().is_err()
            })
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
        }
        observe()?;
    }
    Ok(())
}
fn qualify_reputation_retention_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    let Some(expected) = bindings.iter().find(|binding| {
        binding.slot() == IrohaRuntimeProviderSlotV1::ReputationFinalizedArchiveRetentionAuthority
    }) else {
        return Ok(());
    };
    let authority = dependencies
        .sorafs_reputation_retention_authority
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    let expected_revision = expected
        .revision()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
    let expected_digest = expected
        .policy_digest()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
    let observe = || {
        let qualification = authority.qualification().map_err(|error| {
            match error {
            iroha_core::query::reputation_finalized::
                ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Unavailable => {
                    IrohaRuntimeProviderRegistryErrorV1::Unavailable
                }
            iroha_core::query::reputation_finalized::
                ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Rejected
            | iroha_core::query::reputation_finalized::
                ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous => {
                    IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                }
        }
        })?;
        if authority.handle() != expected.handle()
            || qualification.revision() != expected_revision
            || qualification.policy_digest() != expected_digest
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
        }
        Ok(qualification)
    };
    let expected_qualification = observe()?;
    let network_id = bindings.network_id();
    if authority
        .load_latest(network_id)
        .map_err(|error| {
            match error {
        iroha_core::query::reputation_finalized::
            ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Unavailable => {
                IrohaRuntimeProviderRegistryErrorV1::Unavailable
            }
        iroha_core::query::reputation_finalized::
            ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Rejected
        | iroha_core::query::reputation_finalized::
            ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous => {
                IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
            }
    }
        })?
        .is_some_and(|record| {
            record.authority_qualification() != expected_qualification
                || record.to_canonical_bytes().is_err()
        })
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    observe()?;
    Ok(())
}
fn qualify_reputation_journal_checkpoint_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    let Some(expected) = bindings
        .iter()
        .find(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint)
    else {
        return Ok(());
    };
    let provider = dependencies
        .sorafs_reputation_journal_checkpoint_provider
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    if !is_production_runtime_handle(provider.handle()) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected);
    }
    if provider.handle() != expected.handle() {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    let expected_revision = expected
        .revision()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let expected_policy_digest = expected
        .policy_digest()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    sorafs_node::reputation::runtime::ReputationJournalCheckpointSealingPolicyV1::try_new(
        expected.handle().to_owned(),
        expected_revision,
        expected_policy_digest,
    )
    .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let expected_qualification =
        sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1::new(
            expected_revision,
            expected_policy_digest,
        );
    let first = provider
        .qualification()
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::Unavailable)?;
    if first != expected_qualification || provider.handle() != expected.handle() {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    let record = provider.load_latest().map_err(|error| match error {
        sorafs_node::reputation::runtime::ReputationJournalCheckpointExternalErrorV1::Unavailable => {
            IrohaRuntimeProviderRegistryErrorV1::Unavailable
        }
        sorafs_node::reputation::runtime::ReputationJournalCheckpointExternalErrorV1::Rejected
        | sorafs_node::reputation::runtime::ReputationJournalCheckpointExternalErrorV1::Ambiguous => {
            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
        }
    })?;
    if record.is_some_and(|record| {
        record
            .to_canonical_bytes(
                sorafs_node::reputation::runtime::
                    REPUTATION_JOURNAL_PRODUCER_MAX_CHECKPOINT_BYTES_V1,
            )
            .is_err()
    }) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    let second = provider
        .qualification()
        .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::Unavailable)?;
    if second != first || provider.handle() != expected.handle() {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    Ok(())
}
fn qualify_por_replay_archive_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    let Some(expected) = bindings
        .iter()
        .find(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive)
    else {
        return Ok(());
    };
    let archive = dependencies
        .sorafs_por_finalized_replay_archive
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    if !is_production_runtime_handle(archive.runtime_handle()) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected);
    }
    if archive.runtime_handle() != expected.handle() {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    let expected_binding = expected
        .por_replay_archive_binding()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let observe = || {
        archive.binding().map_err(|error| match error {
            sorafs_node::PorFinalizedReplayArchiveExternalErrorV1::Unavailable => {
                IrohaRuntimeProviderRegistryErrorV1::Unavailable
            }
            sorafs_node::PorFinalizedReplayArchiveExternalErrorV1::Rejected => {
                IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
            }
        })
    };
    let first = observe()?;
    if first != expected_binding {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    archive.check_readiness().map_err(|error| match error {
        sorafs_node::PorFinalizedReplayArchiveExternalErrorV1::Unavailable => {
            IrohaRuntimeProviderRegistryErrorV1::Unavailable
        }
        sorafs_node::PorFinalizedReplayArchiveExternalErrorV1::Rejected => {
            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
        }
    })?;
    if observe()? != first {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    Ok(())
}
fn qualify_evidence_viewer_archive_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    let Some(expected) = bindings.iter().find(|binding| {
        binding.slot() == IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive
    }) else {
        return Ok(());
    };
    let archive = dependencies
        .sorafs_evidence_viewer_compaction_archive
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    if !is_production_runtime_handle(archive.handle()) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected);
    }
    let expected_revision = expected
        .revision()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let expected_policy_digest = expected
        .policy_digest()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let expected_archive_id = expected
        .evidence_viewer_archive_id()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let expected_public_key = expected
        .evidence_viewer_archive_public_key()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let observe = || {
        let qualification = archive.qualification().map_err(|error| match error {
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1::Unavailable => {
                IrohaRuntimeProviderRegistryErrorV1::Unavailable
            }
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1::Rejected => {
                IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
            }
        })?;
        if archive.handle() != expected.handle()
            || qualification.revision() != expected_revision
            || qualification.policy_digest() != expected_policy_digest
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
        }
        Ok(qualification)
    };
    let observe_identity = || {
        let qualification = observe()?;
        let identity = (archive.archive_id(), archive.signing_public_key());
        if observe()? != qualification {
            return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
        }
        Ok((qualification, identity))
    };
    let (first_qualification, first_identity) = observe_identity()?;
    if first_identity != (expected_archive_id, expected_public_key) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    if observe_identity()? != (first_qualification, first_identity) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    Ok(())
}
fn qualify_moderation_panel_notification_archive_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    let Some(expected) = bindings.iter().find(|binding| {
        binding.slot() == IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive
    }) else {
        return Ok(());
    };
    let archive = dependencies
        .sorafs_moderation_panel_notification_archive
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    if !is_production_runtime_handle(archive.handle()) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected);
    }
    let expected_revision = expected
        .revision()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let expected_policy_digest = expected
        .policy_digest()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let expected_archive_id = expected
        .moderation_panel_notification_archive_id()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let expected_public_key = expected
        .moderation_panel_notification_archive_public_key()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let observe = || {
        let qualification = archive.qualification().map_err(|error| match error {
            sorafs_node::moderation_orchestrator::ModerationRuntimeProviderReadinessErrorV1::Unavailable => {
                IrohaRuntimeProviderRegistryErrorV1::Unavailable
            }
            sorafs_node::moderation_orchestrator::ModerationRuntimeProviderReadinessErrorV1::Rejected => {
                IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
            }
        })?;
        if archive.handle() != expected.handle()
            || qualification.revision() != expected_revision
            || qualification.policy_digest() != expected_policy_digest
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
        }
        Ok(qualification)
    };
    let observe_identity = || {
        let qualification = observe()?;
        let identity = (archive.archive_id(), archive.signing_public_key());
        if observe()? != qualification {
            return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
        }
        Ok((qualification, identity))
    };
    let (first_qualification, first_identity) = observe_identity()?;
    if first_identity != (expected_archive_id, expected_public_key) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    if observe_identity()? != (first_qualification, first_identity) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    Ok(())
}
fn qualify_evidence_viewer_transparency_publisher_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    let Some(expected) = bindings.iter().find(|binding| {
        binding.slot() == IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher
    }) else {
        return Ok(());
    };
    let publisher = dependencies
        .sorafs_evidence_viewer_transparency_publisher
        .as_ref()
        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
    if !is_production_runtime_handle(publisher.handle()) {
        return Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected);
    }
    let expected_revision = expected
        .revision()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let expected_policy_digest = expected
        .policy_digest()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let expected_public_key = expected
        .evidence_viewer_transparency_publisher_public_key()
        .ok_or_else(|| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(expected.slot()))?;
    let observe = || {
        let qualification = publisher.qualification().map_err(|error| match error {
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1::Unavailable => {
                IrohaRuntimeProviderRegistryErrorV1::Unavailable
            }
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1::Rejected => {
                IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
            }
        })?;
        if publisher.handle() != expected.handle()
            || qualification.revision() != expected_revision
            || qualification.policy_digest() != expected_policy_digest
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
        }
        Ok((qualification, publisher.public_key()))
    };
    let first = observe()?;
    if first.1 != expected_public_key {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    if observe()? != first {
        return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config_base::{toml::TomlSource, util::Bytes};
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use std::{
        path::Path,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    fn standalone_bootle_lantern_bindings()
    -> iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderBindingsV1 {
        iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderBindingsV1::try_new(
            iroha_data_model::privacy::PrivacyIssuerIdV1::new([0x91; 32]),
            iroha_data_model::privacy::PrivacyPolicyIdV1::new([0x92; 32]),
            64,
        )
        .expect("valid standalone Bootle/Lantern bindings")
    }
    #[test]
    fn standalone_bootle_lantern_catalog_is_exactly_one_qualified_slot() {
        let chain_id = iroha_model_base::chain::ChainId::from("taira");
        let network_id = test_network_id(0x94);
        let exact = standalone_bootle_lantern_bindings();
        let catalog = IrohaRuntimeProviderBindingsV1::try_from_bootle_lantern_issuance_service(
            &chain_id,
            network_id,
            "runtime://privacy/bootle-lantern/taira-primary",
            7,
            [0x93; 32],
            exact,
        )
        .expect("construct exact standalone slot-56 catalog");
        assert_eq!(catalog.chain_id(), "taira");
        assert_eq!(catalog.network_id(), &network_id);
        assert_eq!(catalog.len(), 1);
        let binding = catalog.iter().next().expect("one exact slot");
        assert_eq!(
            binding.slot(),
            IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry
        );
        assert_eq!(
            binding.handle(),
            "runtime://privacy/bootle-lantern/taira-primary"
        );
        assert_eq!(binding.revision(), Some(7));
        assert_eq!(binding.policy_digest(), Some([0x93; 32]));
        assert_eq!(binding.bootle_lantern_issuance_bindings(), Some(exact));
    }
    #[test]
    fn standalone_bootle_lantern_catalog_rejects_unqualified_or_test_bindings() {
        let chain_id = iroha_model_base::chain::ChainId::from("taira");
        let network_id = test_network_id(0x94);
        let exact = standalone_bootle_lantern_bindings();
        for (handle, revision, digest) in [
            ("runtime://privacy/bootle-lantern/test", 7, [0x93; 32]),
            (
                "runtime://privacy/bootle-lantern/taira-primary",
                0,
                [0x93; 32],
            ),
            ("runtime://privacy/bootle-lantern/taira-primary", 7, [0; 32]),
        ] {
            assert!(
                IrohaRuntimeProviderBindingsV1::try_from_bootle_lantern_issuance_service(
                    &chain_id, network_id, handle, revision, digest, exact,
                )
                .is_err(),
                "must reject standalone binding {handle:?}/{revision}/{digest:?}"
            );
        }
        assert!(
            iroha_torii::privacy_issuance_api::
                BootleLanternIssuanceRuntimeProviderBindingsV1::try_new(
                    iroha_data_model::privacy::PrivacyIssuerIdV1::new([0; 32]),
                    iroha_data_model::privacy::PrivacyPolicyIdV1::new([0x92; 32]),
                    64,
                )
                .is_err()
        );
    }
    struct EmptyRegistry;
    impl IrohaRuntimeProviderRegistryV1 for EmptyRegistry {
        fn resolve(
            &self,
            _bindings: &IrohaRuntimeProviderBindingsV1,
        ) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
            Ok(IrohaRuntimeDeps::default())
        }
    }
    struct FixedRegistry(IrohaRuntimeDeps);
    impl IrohaRuntimeProviderRegistryV1 for FixedRegistry {
        fn resolve(
            &self,
            _bindings: &IrohaRuntimeProviderBindingsV1,
        ) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
            Ok(self.0.clone())
        }
    }
    const GOVERNANCE_IPFS_HANDLE: &str = "vault://governance/ipfs-primary";
    const GOVERNANCE_HEAD_HANDLE: &str = "vault://governance/head-primary";
    const GOVERNANCE_IPFS_ENDPOINT: &str = "https://governance-ingress.invalid/ipfs/";
    const GOVERNANCE_HEAD_ENDPOINT: &str = "https://governance-ingress.invalid/head";
    const GOVERNANCE_CHECKPOINT_HANDLE: &str = "kms://governance/checkpoint-primary";
    const GOVERNANCE_SIGNER_HANDLE: &str = "software://sorafs/governance-dag/primary";
    const GOVERNANCE_PUBLISHER_PEER_ID: &str = "12D3KooWGovernanceProducerPrimary";
    const GOVERNANCE_QUALIFICATION: sorafs_node::GovernanceDagRuntimeProviderQualificationV1 =
        sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(7, [0x71; 32]);
    const EVIDENCE_CHECKPOINT_HANDLE: &str = "sealed://sorafs/evidence-viewer/checkpoint-primary";
    const EVIDENCE_CHECKPOINT_QUALIFICATION:
        sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1 =
        sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1::new(
            15, [0xA5; 32],
        );
    const EVIDENCE_ARCHIVE_HANDLE: &str = "object-lock://sorafs/evidence-viewer/archive-primary";
    const EVIDENCE_ARCHIVE_ID: [u8; 32] = [0xA7; 32];
    const EVIDENCE_ARCHIVE_QUALIFICATION:
        sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1 =
        sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1::new(
            16, [0xA8; 32],
        );
    const EVIDENCE_TRANSPARENCY_PUBLISHER_HANDLE: &str =
        "transparency://sorafs/evidence-viewer/publisher-primary";
    const EVIDENCE_TRANSPARENCY_PUBLISHER_QUALIFICATION:
        sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1 =
        sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1::new(
            17, [0xA9; 32],
        );
    const TRANSPARENCY_LEADER_LEASE_HANDLE: &str = "sealed-cas:transparency:leader-primary";
    const TRANSPARENCY_LEADER_LEASE_QUALIFICATION:
        sorafs_node::TransparencyRuntimeProviderQualificationV1 =
        sorafs_node::TransparencyRuntimeProviderQualificationV1::new(11, [0xF1; 32]);
    const FENCED_PRIVACY_HANDLE: &str = "governance-cas:transparency:privacy-primary";
    const FENCED_PRIVACY_QUALIFICATION: sorafs_node::GovernanceDagRuntimeProviderQualificationV1 =
        sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(13, [0x91; 32]);
    const REPUTATION_CHECKPOINT_HANDLE: &str =
        "sealed://sorafs/reputation/journal-checkpoint-primary";
    const REPUTATION_CHECKPOINT_QUALIFICATION:
        sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1 =
        sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1::new(
            sorafs_node::reputation::runtime::REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
            [0xA4; 32],
        );
    #[derive(Debug)]
    struct ReputationJournalCheckpointProvider {
        handle: &'static str,
        first: sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1,
        later: Option<sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1>,
        qualification_calls: AtomicUsize,
        load_error:
            Option<sorafs_node::reputation::runtime::ReputationJournalCheckpointExternalErrorV1>,
    }
    impl ReputationJournalCheckpointProvider {
        fn exact() -> Self {
            Self {
                handle: REPUTATION_CHECKPOINT_HANDLE,
                first: REPUTATION_CHECKPOINT_QUALIFICATION,
                later: None,
                qualification_calls: AtomicUsize::new(0),
                load_error: None,
            }
        }
    }
    impl sorafs_node::reputation::runtime::ReputationRuntimeProviderV1
        for ReputationJournalCheckpointProvider
    {
        fn handle(&self) -> &str {
            self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1,
            sorafs_node::reputation::runtime::ReputationExternalFailureV1,
        > {
            let call = self.qualification_calls.fetch_add(1, Ordering::Relaxed);
            Ok(if call == 0 {
                self.first
            } else {
                self.later.unwrap_or(self.first)
            })
        }
    }
    impl sorafs_node::reputation::runtime::ReputationJournalCheckpointRuntimeV1
        for ReputationJournalCheckpointProvider
    {
        fn load_latest(
            &self,
        ) -> Result<
            Option<sorafs_node::reputation::runtime::ReputationJournalSealedCheckpointRecordV1>,
            sorafs_node::reputation::runtime::ReputationJournalCheckpointExternalErrorV1,
        > {
            self.load_error.map_or(Ok(None), Err)
        }
        fn compare_and_swap_latest(
            &self,
            _expected_revision: Option<[u8; 32]>,
            _next: &sorafs_node::reputation::runtime::ReputationJournalSealedCheckpointRecordV1,
        ) -> Result<(), sorafs_node::reputation::runtime::ReputationJournalCheckpointExternalErrorV1>
        {
            Err(
                sorafs_node::reputation::runtime::
                    ReputationJournalCheckpointExternalErrorV1::Rejected,
            )
        }
    }
    fn evidence_archive_public_key() -> [u8; 32] {
        let key_pair = KeyPair::try_from_seed(vec![0x63; 32], Algorithm::Ed25519)
            .expect("evidence-viewer archive signer key");
        let public_key = key_pair.public_key().to_bytes().1;
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(public_key);
        bytes
    }
    fn governance_signer_keypair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("Governance DAG signer key")
    }
    fn governance_signer_public_key(seed: u8) -> [u8; 32] {
        governance_signer_keypair(seed)
            .public_key()
            .to_bytes()
            .1
            .try_into()
            .expect("Ed25519 public key has 32 bytes")
    }
    fn por_archive_binding(seed: u8) -> sorafs_node::PorFinalizedReplayArchiveBindingV1 {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("test Ed25519 keypair");
        let public_key = key_pair.public_key().to_bytes().1;
        let mut signing_public_key = [0_u8; 32];
        signing_public_key.copy_from_slice(public_key);
        sorafs_node::PorFinalizedReplayArchiveBindingV1::try_new(
            [0xB1; 32],
            17,
            [0xB2; 32],
            signing_public_key,
        )
        .expect("valid test replay-archive binding")
    }
    fn por_archive_config(
        binding: sorafs_node::PorFinalizedReplayArchiveBindingV1,
    ) -> iroha_config::parameters::actual::SorafsPorReplayArchive {
        iroha_config::parameters::actual::SorafsPorReplayArchive {
            handle: "object-lock://sorafs/por-replay-archive/primary".to_owned(),
            archive_id: binding.archive_id,
            revision: binding.revision,
            policy_digest: binding.policy_digest,
            signing_public_key: binding.signing_public_key,
            poll_interval: Duration::from_secs(1),
            max_records_per_tick: 64,
            max_successor_receipts: 1_024,
            max_successor_proof_bytes: 1_048_576,
        }
    }
    fn por_archive_request(
        binding: sorafs_node::PorFinalizedReplayArchiveBindingV1,
    ) -> IrohaRuntimeProviderBindingsV1 {
        let archive = por_archive_config(binding);
        IrohaRuntimeProviderBindingsV1 {
            chain_id: "por-replay-test-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: vec![
                IrohaRuntimeProviderBindingV1::try_new_por_replay_archive(&archive)
                    .expect("valid archive request"),
            ],
        }
    }
    #[derive(Debug)]
    struct PorReplayArchive {
        handle: &'static str,
        first_binding: sorafs_node::PorFinalizedReplayArchiveBindingV1,
        later_binding: Option<sorafs_node::PorFinalizedReplayArchiveBindingV1>,
        binding_calls: AtomicUsize,
        readiness_error: Option<sorafs_node::PorFinalizedReplayArchiveExternalErrorV1>,
    }
    impl PorReplayArchive {
        fn exact(binding: sorafs_node::PorFinalizedReplayArchiveBindingV1) -> Self {
            Self {
                handle: "object-lock://sorafs/por-replay-archive/primary",
                first_binding: binding,
                later_binding: None,
                binding_calls: AtomicUsize::new(0),
                readiness_error: None,
            }
        }
    }
    impl sorafs_node::PorFinalizedReplayArchiveV1 for PorReplayArchive {
        fn runtime_handle(&self) -> &str {
            self.handle
        }
        fn binding(
            &self,
        ) -> Result<
            sorafs_node::PorFinalizedReplayArchiveBindingV1,
            sorafs_node::PorFinalizedReplayArchiveExternalErrorV1,
        > {
            let call = self.binding_calls.fetch_add(1, Ordering::Relaxed);
            Ok(if call == 0 {
                self.first_binding
            } else {
                self.later_binding.unwrap_or(self.first_binding)
            })
        }
        fn check_readiness(
            &self,
        ) -> Result<(), sorafs_node::PorFinalizedReplayArchiveExternalErrorV1> {
            self.readiness_error.map_or(Ok(()), Err)
        }
        fn current_head(
            &self,
        ) -> Result<
            Option<sorafs_node::PorFinalizedReplayArchiveReceiptV1>,
            sorafs_node::PorFinalizedReplayArchiveExternalErrorV1,
        > {
            Ok(None)
        }
        fn append(
            &self,
            _record: &sorafs_node::PorFinalizedReplayArchiveRecordV1,
            _expected_previous_head: Option<[u8; 32]>,
        ) -> Result<
            sorafs_node::PorFinalizedReplayArchiveReceiptV1,
            sorafs_node::PorFinalizedReplayArchiveExternalErrorV1,
        > {
            Err(sorafs_node::PorFinalizedReplayArchiveExternalErrorV1::Rejected)
        }
        fn lookup(
            &self,
            _challenge_id: [u8; 32],
            _expected_checkpoint_head: sorafs_node::PorFinalizedReplayArchiveReceiptV1,
            _proof_bounds: sorafs_node::PorFinalizedReplayArchiveProofBoundsV1,
        ) -> Result<
            sorafs_node::PorFinalizedReplayArchiveLookupV1,
            sorafs_node::PorFinalizedReplayArchiveExternalErrorV1,
        > {
            Err(sorafs_node::PorFinalizedReplayArchiveExternalErrorV1::Rejected)
        }
    }
    #[test]
    fn runtime_provider_slot_wire_ids_are_stable_and_ordered() {
        let mut seen = [false; 61];
        for (expected, slot) in (1_u16..=60)
            .filter(|id| *id != 53)
            .zip(IrohaRuntimeProviderSlotV1::ALL)
        {
            let wire_id = slot.wire_id();
            assert_eq!(
                wire_id, expected,
                "V1 broker role identifiers must retain their exact assigned IDs"
            );
            assert_eq!(
                IrohaRuntimeProviderSlotV1::from_wire_id(wire_id),
                Some(slot),
                "every advertised wire ID must have an exact inverse"
            );
            assert!(
                !std::mem::replace(&mut seen[usize::from(wire_id)], true),
                "wire ID {wire_id} must not be duplicated"
            );
        }
        assert!(
            seen[1..]
                .iter()
                .enumerate()
                .all(|(index, present)| *present == (index + 1 != 53)),
            "the V1 slot inventory must contain exactly the registered wire IDs"
        );
        for unknown in [0, 53, 61, u16::MAX] {
            assert_eq!(
                IrohaRuntimeProviderSlotV1::from_wire_id(unknown),
                None,
                "unknown wire ID {unknown} must fail closed"
            );
        }
    }
    #[test]
    fn runtime_provider_catalog_capacity_is_derived_from_configured_multiplicities() {
        let derived = IrohaRuntimeProviderSlotV1::ALL
            .into_iter()
            .map(IrohaRuntimeProviderSlotV1::max_configured_multiplicity)
            .sum::<usize>();
        assert_eq!(derived, RUNTIME_PROVIDER_CATALOG_MAX_ENTRIES_V1);
        assert_eq!(
            RUNTIME_PROVIDER_CATALOG_MAX_ENTRIES_V1,
            IrohaRuntimeProviderSlotV1::ALL.len() - 1
                + iroha_config::parameters::SORAFS_APPEAL_FINANCE_MAX_SUBMITTER_SIGNERS_V1
        );
        assert_eq!(
            IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner
                .max_configured_multiplicity(),
            iroha_config::parameters::SORAFS_APPEAL_FINANCE_MAX_SUBMITTER_SIGNERS_V1
        );
        assert!(
            IrohaRuntimeProviderSlotV1::ALL.into_iter().all(|slot| slot
                == IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner
                || slot.max_configured_multiplicity() == 1),
            "every non-appeal role is singular in the V1 configuration projection"
        );
    }
    #[test]
    fn soracloud_runtime_signer_projects_only_exact_public_metadata() {
        let key_pair =
            KeyPair::try_from_seed(vec![0xD1; 32], Algorithm::Ed25519).expect("test key");
        let configured = iroha_config::parameters::actual::SoracloudRuntimeMutationSignerBinding {
            handle: "software://sorafs/ai/runtime-primary".to_owned(),
            authority: iroha_data_model::account::AccountId::new(key_pair.public_key().clone()),
            algorithm: Algorithm::Ed25519,
            public_key: key_pair.public_key().clone(),
            revision: 11,
            policy_digest: [0xD2; 32],
        };
        let projected =
            IrohaRuntimeProviderBindingV1::try_new_soracloud_runtime_signer(&configured)
                .expect("valid public signer binding");
        assert_eq!(
            projected.slot(),
            IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner
        );
        assert_eq!(projected.handle(), configured.handle);
        assert_eq!(projected.revision(), Some(configured.revision));
        assert_eq!(projected.policy_digest(), Some(configured.policy_digest));
        let exact = projected
            .soracloud_runtime_signer_binding()
            .expect("exact signer metadata");
        assert_eq!(exact.authority(), &configured.authority);
        assert_eq!(exact.public_key(), &configured.public_key);
        assert!(exact.qualification().active());
        assert!(!exact.qualification().test_only());
        let mut test_marked = configured;
        test_marked.handle = "software://sorafs/ai/test".to_owned();
        assert_eq!(
            IrohaRuntimeProviderBindingV1::try_new_soracloud_runtime_signer(&test_marked),
            Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner,
            ))
        );
    }
    fn pop_registry_config() -> iroha_config::parameters::actual::SorafsPopCredentialService {
        let issuer = KeyPair::try_from_seed(vec![0x91; 32], Algorithm::Ed25519)
            .expect("derive PoP issuer test key");
        let issuer_public_key = issuer
            .public_key()
            .to_bytes()
            .1
            .try_into()
            .expect("Ed25519 public key width");
        iroha_config::parameters::actual::SorafsPopCredentialService {
            issuer_state_dir: std::path::PathBuf::from("/runtime/pop/issuer"),
            wallet_state_dir: std::path::PathBuf::from("/runtime/pop/wallet"),
            issuer_policy_digest: [0x92; 32],
            issuer_id: "pop-issuer-production-primary".to_owned(),
            issuer_signer_handle: "software://sorafs/pop-credentials/primary".to_owned(),
            issuer_public_key,
            enrollment_recipient_key_id: "kms:pop/enrollment:primary".to_owned(),
            enrollment_recipient_public_key_digest: [0x94; 32],
            wallet_recipient_key_id: "kms:pop/wallet-recipient:primary".to_owned(),
            wallet_recipient_public_key_digest: [0x95; 32],
            wallet_wrapping_key_id: "kms:pop/wallet:primary".to_owned(),
            runtime_provider_registry_handle: "runtime://sorafs/pop/provider-registry-primary"
                .to_owned(),
            runtime_provider_registry_revision: 7,
            runtime_provider_registry_policy_digest: [0x93; 32],
            approval_quorum: 2,
            approval_signers: Vec::new(),
            max_pending_enrollments: 16,
            max_outbox_entries: 16,
            max_dead_letters: 16,
            max_seen_nullifiers: 16,
            max_submission_attempts: 3,
            worker_interval: Duration::from_secs(1),
            max_finalized_time_skew: Duration::from_secs(30),
        }
    }
    #[test]
    fn pop_registry_binding_projects_only_exact_non_secret_public_metadata() {
        let config = pop_registry_config();
        let binding = IrohaRuntimeProviderBindingV1::try_new_pop_credential_registry(&config)
            .expect("canonical PoP registry binding");
        assert_eq!(
            binding.slot(),
            IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry
        );
        assert_eq!(
            binding.handle(),
            "runtime://sorafs/pop/provider-registry-primary"
        );
        assert_eq!(binding.revision(), Some(7));
        assert_eq!(binding.policy_digest(), Some([0x93; 32]));
        let exact = binding
            .pop_credential_runtime_binding()
            .expect("exact PoP public metadata");
        assert_eq!(exact.issuer_policy_digest, [0x92; 32]);
        assert_eq!(exact.issuer_id, "pop-issuer-production-primary");
        assert_eq!(exact.issuer_signer_handle, config.issuer_signer_handle);
        assert_eq!(exact.issuer_public_key, config.issuer_public_key);
        assert_eq!(
            exact.enrollment_recipient_key_id,
            "kms:pop/enrollment:primary"
        );
        assert_eq!(exact.enrollment_recipient_public_key_digest, [0x94; 32]);
        assert_eq!(
            exact.wallet_recipient_key_id,
            "kms:pop/wallet-recipient:primary"
        );
        assert_eq!(exact.wallet_recipient_public_key_digest, [0x95; 32]);
        assert_eq!(exact.wallet_wrapping_key_id, "kms:pop/wallet:primary");
        for invalid in [
            {
                let mut value = config.clone();
                value.issuer_policy_digest = [0; 32];
                value
            },
            {
                let mut value = config.clone();
                value.issuer_id.push('\n');
                value
            },
            {
                let mut value = config.clone();
                value.issuer_signer_handle = "software://sorafs/pop-credentials/test".into();
                value
            },
            {
                let mut value = config.clone();
                value.enrollment_recipient_key_id = "kms://pop/mock/enrollment".to_owned();
                value
            },
            {
                let mut value = config.clone();
                value.enrollment_recipient_public_key_digest = [0; 32];
                value
            },
            {
                let mut value = config.clone();
                value.wallet_recipient_key_id = "kms://pop/mock/wallet-recipient".to_owned();
                value
            },
            {
                let mut value = config.clone();
                value.wallet_recipient_public_key_digest = [0; 32];
                value
            },
            {
                let mut value = config.clone();
                value.wallet_wrapping_key_id = "kms://pop/fake/wallet".to_owned();
                value
            },
            {
                let mut value = config.clone();
                value.issuer_public_key = [0; 32];
                value
            },
        ] {
            assert_eq!(
                IrohaRuntimeProviderBindingV1::try_new_pop_credential_registry(&invalid),
                Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry,
                ))
            );
        }
    }
    fn resolve_por_archive(
        requested: &IrohaRuntimeProviderBindingsV1,
        archive: PorReplayArchive,
    ) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
        let archive: Arc<dyn sorafs_node::PorFinalizedReplayArchiveV1> = Arc::new(archive);
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default().with_sorafs_por_finalized_replay_archive(archive),
        );
        resolve_runtime_deps_from_bindings(requested, Some(&registry))
    }
    #[test]
    fn por_replay_archive_slot_projects_and_qualifies_the_exact_public_binding() {
        let binding = por_archive_binding(0xB3);
        let requested = por_archive_request(binding);
        let projected = requested
            .iter()
            .find(|candidate| {
                candidate.slot() == IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive
            })
            .expect("archive request");
        assert_eq!(
            IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive.wire_id(),
            46
        );
        assert_eq!(
            projected.handle(),
            "object-lock://sorafs/por-replay-archive/primary"
        );
        assert_eq!(projected.revision(), Some(binding.revision));
        assert_eq!(projected.policy_digest(), Some(binding.policy_digest));
        assert_eq!(projected.por_replay_archive_binding(), Some(binding));
        assert_eq!(
            projected.por_replay_archive_proof_limits(),
            Some(PorReplayArchiveProofLimitsV1 {
                max_successor_receipts: 1_024,
                max_successor_proof_bytes: 1_048_576,
            })
        );
        assert!(resolve_por_archive(&requested, PorReplayArchive::exact(binding)).is_ok());
        let mut config = default_runtime_config();
        config.torii.sorafs_storage.por_replay_archive = Some(por_archive_config(binding));
        let from_config = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .expect("project archive through the sanitized config collector");
        assert!(from_config.iter().any(|candidate| {
            candidate.slot() == IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive
                && candidate.por_replay_archive_binding() == Some(binding)
                && candidate.por_replay_archive_proof_limits()
                    == Some(PorReplayArchiveProofLimitsV1 {
                        max_successor_receipts: 1_024,
                        max_successor_proof_bytes: 1_048_576,
                    })
        }));
    }
    #[test]
    fn por_replay_archive_projection_rejects_zero_and_excessive_proof_limits() {
        let binding = por_archive_binding(0xB7);
        let mut zero_receipts = por_archive_config(binding);
        zero_receipts.max_successor_receipts = 0;
        let mut zero_bytes = por_archive_config(binding);
        zero_bytes.max_successor_proof_bytes = 0;
        let mut excessive_receipts = por_archive_config(binding);
        excessive_receipts.max_successor_receipts =
            iroha_config::parameters::defaults::sorafs::storage::por_replay_archive::
                MAX_SUCCESSOR_RECEIPTS_LIMIT
                + 1;
        let mut excessive_bytes = por_archive_config(binding);
        excessive_bytes.max_successor_proof_bytes =
            iroha_config::parameters::defaults::sorafs::storage::por_replay_archive::
                MAX_SUCCESSOR_PROOF_BYTES_LIMIT
                + 1;
        for invalid in [
            zero_receipts,
            zero_bytes,
            excessive_receipts,
            excessive_bytes,
        ] {
            assert_eq!(
                IrohaRuntimeProviderBindingV1::try_new_por_replay_archive(&invalid),
                Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive,
                ))
            );
        }
    }
    #[test]
    fn por_replay_archive_resolution_rejects_missing_and_unrequested_dependencies() {
        let binding = por_archive_binding(0xB4);
        let requested = por_archive_request(binding);
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&EmptyRegistry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
        ));
        let empty = IrohaRuntimeProviderBindingsV1 {
            chain_id: "por-replay-test-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: Vec::new(),
        };
        assert!(matches!(
            resolve_por_archive(&empty, PorReplayArchive::exact(binding)),
            Err(IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders)
        ));
    }
    #[test]
    fn por_replay_archive_resolution_rejects_substitution_staleness_and_drift() {
        let binding = por_archive_binding(0xB5);
        let requested = por_archive_request(binding);
        let mut substituted = PorReplayArchive::exact(binding);
        substituted.first_binding = sorafs_node::PorFinalizedReplayArchiveBindingV1::try_new(
            [0xB6; 32],
            binding.revision,
            binding.policy_digest,
            binding.signing_public_key,
        )
        .expect("valid substituted binding");
        assert!(matches!(
            resolve_por_archive(&requested, substituted),
            Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
        ));
        let mut test_marked = PorReplayArchive::exact(binding);
        test_marked.handle = "object-lock://sorafs/por-replay-archive/test-provider";
        assert!(matches!(
            resolve_por_archive(&requested, test_marked),
            Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected)
        ));
        let mut stale = PorReplayArchive::exact(binding);
        stale.readiness_error =
            Some(sorafs_node::PorFinalizedReplayArchiveExternalErrorV1::Rejected);
        assert!(matches!(
            resolve_por_archive(&requested, stale),
            Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)
        ));
        let mut drifted = PorReplayArchive::exact(binding);
        drifted.later_binding = Some(
            sorafs_node::PorFinalizedReplayArchiveBindingV1::try_new(
                binding.archive_id,
                binding.revision + 1,
                binding.policy_digest,
                binding.signing_public_key,
            )
            .expect("valid later binding"),
        );
        assert!(matches!(
            resolve_por_archive(&requested, drifted),
            Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)
        ));
    }
    #[derive(Debug)]
    struct FencedPrivacyRuntime {
        handle: &'static str,
        qualification: Option<sorafs_node::GovernanceDagRuntimeProviderQualificationV1>,
    }
    impl FencedPrivacyRuntime {
        const fn exact() -> Self {
            Self {
                handle: FENCED_PRIVACY_HANDLE,
                qualification: Some(FENCED_PRIVACY_QUALIFICATION),
            }
        }
    }
    impl sorafs_node::FencedTransparencyPublisherV1 for FencedPrivacyRuntime {
        fn handle(&self) -> &str {
            self.handle
        }
        fn qualification(
            &self,
        ) -> Result<sorafs_node::GovernanceDagRuntimeProviderQualificationV1, String> {
            self.qualification
                .ok_or_else(|| "redacted test qualification failure".to_owned())
        }
        fn compare_and_append_privacy(
            &self,
            _request: &sorafs_node::FencedPrivacyPublicationRequestV1,
        ) -> Result<
            sorafs_node::FencedPrivacyPublicationReceiptV1,
            sorafs_node::FencedTransparencyPublishErrorV1,
        > {
            Err(sorafs_node::FencedTransparencyPublishErrorV1::Rejected)
        }
    }
    impl sorafs_node::FencedTransparencyAuthoritativeHeadReaderV1 for FencedPrivacyRuntime {
        fn handle(&self) -> &str {
            self.handle
        }
        fn qualification(
            &self,
        ) -> Result<sorafs_node::GovernanceDagRuntimeProviderQualificationV1, String> {
            self.qualification
                .ok_or_else(|| "redacted test qualification failure".to_owned())
        }
        fn read_authoritative_head_with_ancestry(
            &self,
            required_ancestors: &[sorafs_node::FencedTransparencyTargetHeadV1],
            required_publications: &[sorafs_node::FencedTransparencyPublicationInclusionV1],
        ) -> Result<sorafs_node::FencedTransparencyHeadAncestryProofV1, String> {
            if !required_ancestors.is_empty() || !required_publications.is_empty() {
                return Err(
                    "fresh fused privacy registry target cannot prove retained ancestry or publication inclusion"
                        .to_owned(),
                );
            }
            sorafs_node::FencedTransparencyHeadAncestryProofV1::try_new(
                None,
                Vec::new(),
                Vec::new(),
                [0xFA; 32],
            )
            .map_err(|_| {
                "fresh fused privacy registry target returned a malformed genesis proof".to_owned()
            })
        }
    }
    fn fenced_privacy_dependencies(
        writer: Option<Arc<FencedPrivacyRuntime>>,
        reader: Option<Arc<FencedPrivacyRuntime>>,
    ) -> IrohaRuntimeDeps {
        let mut dependencies = IrohaRuntimeDeps::default();
        if let Some(writer) = writer {
            let writer: Arc<dyn sorafs_node::FencedTransparencyPublisherV1> = writer;
            dependencies = dependencies.with_sorafs_fenced_transparency_publisher(writer);
        }
        if let Some(reader) = reader {
            let reader: Arc<dyn sorafs_node::FencedTransparencyAuthoritativeHeadReaderV1> = reader;
            dependencies = dependencies.with_sorafs_fenced_transparency_head_reader(reader);
        }
        dependencies
    }
    fn configure_fenced_privacy_runtime(config: &mut Config) {
        config
            .torii
            .sorafs_storage
            .privacy_aggregates
            .fenced_privacy_publisher = Some(
            iroha_config::parameters::actual::SorafsTransparencyRuntimeProviderBinding {
                handle: FENCED_PRIVACY_HANDLE.to_owned(),
                revision: FENCED_PRIVACY_QUALIFICATION.revision,
                policy_digest: FENCED_PRIVACY_QUALIFICATION.policy_digest,
            },
        );
    }
    struct TransparencyLeaderLeaseProvider;
    impl sorafs_node::ProductionTransparencyRuntimeProviderV1 for TransparencyLeaderLeaseProvider {
        fn handle(&self) -> &str {
            TRANSPARENCY_LEADER_LEASE_HANDLE
        }
        fn qualification(
            &self,
        ) -> Result<sorafs_node::TransparencyRuntimeProviderQualificationV1, String> {
            Ok(TRANSPARENCY_LEADER_LEASE_QUALIFICATION)
        }
    }
    impl sorafs_node::TransparencyLeaderLeaseProviderV1 for TransparencyLeaderLeaseProvider {
        fn acquire(
            &self,
            _request: &sorafs_node::TransparencyLeaderLeaseAcquireRequestV1,
        ) -> Result<
            sorafs_node::TransparencyLeaderLeaseGrantV1,
            sorafs_node::TransparencyLeaderLeaseProviderErrorV1,
        > {
            Err(sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Unavailable)
        }
        fn renew(
            &self,
            _request: &sorafs_node::TransparencyLeaderLeaseRenewRequestV1,
        ) -> Result<
            sorafs_node::TransparencyLeaderLeaseGrantV1,
            sorafs_node::TransparencyLeaderLeaseProviderErrorV1,
        > {
            Err(sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Unavailable)
        }
        fn release(
            &self,
            _request: &sorafs_node::TransparencyLeaderLeaseReleaseRequestV1,
        ) -> Result<
            sorafs_node::TransparencyLeaderLeaseReleaseReceiptV1,
            sorafs_node::TransparencyLeaderLeaseProviderErrorV1,
        > {
            Err(sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Unavailable)
        }
    }
    #[derive(Debug)]
    struct GovernanceAuthenticator {
        handle: &'static str,
        key_handle: &'static str,
        ingress_binding: sorafs_node::GovernanceDagRequestIngressBindingV1,
        nonce: AtomicU64,
    }
    impl GovernanceAuthenticator {
        fn new(
            handle: &'static str,
            ingress_binding: sorafs_node::GovernanceDagRequestIngressBindingV1,
        ) -> Self {
            Self {
                handle,
                key_handle: handle,
                ingress_binding,
                nonce: AtomicU64::new(0),
            }
        }
        fn with_key_from(mut self, handle: &'static str) -> Self {
            self.key_handle = handle;
            self.ingress_binding = sorafs_node::GovernanceDagRequestIngressBindingV1::try_new(
                self.ingress_binding.scope(),
                self.ingress_binding.endpoint_binding(),
                governance_auth_public_key(handle),
                self.ingress_binding.max_body_bytes(),
                self.ingress_binding.max_envelope_lifetime_secs(),
                self.ingress_binding.max_future_skew_secs(),
            )
            .expect("substituted test key remains canonical Ed25519");
            self
        }
    }
    #[derive(Debug)]
    struct GovernanceSigner {
        handle: &'static str,
        later_handle: Option<&'static str>,
        handle_calls: AtomicUsize,
        publisher_peer_id: Vec<u8>,
        later_publisher_peer_id: Option<Vec<u8>>,
        publisher_peer_id_calls: AtomicUsize,
        key_pair: KeyPair,
        signing_key_pair: Option<KeyPair>,
        sign_error: bool,
        first_qualification: sorafs_node::GovernanceDagRuntimeProviderQualificationV1,
        later_qualification: Option<sorafs_node::GovernanceDagRuntimeProviderQualificationV1>,
        qualification_calls: AtomicUsize,
        later_public_key: Option<[u8; 32]>,
        public_key_calls: AtomicUsize,
    }
    impl GovernanceSigner {
        fn exact() -> Self {
            Self {
                handle: GOVERNANCE_SIGNER_HANDLE,
                later_handle: None,
                handle_calls: AtomicUsize::new(0),
                publisher_peer_id: GOVERNANCE_PUBLISHER_PEER_ID.as_bytes().to_vec(),
                later_publisher_peer_id: None,
                publisher_peer_id_calls: AtomicUsize::new(0),
                key_pair: governance_signer_keypair(0x73),
                signing_key_pair: None,
                sign_error: false,
                first_qualification: GOVERNANCE_QUALIFICATION,
                later_qualification: None,
                qualification_calls: AtomicUsize::new(0),
                later_public_key: None,
                public_key_calls: AtomicUsize::new(0),
            }
        }
    }
    include!("runtime_provider_registry/governance_signer_test_impl.rs");
    fn governance_auth_keypair(handle: &str) -> KeyPair {
        let seed = if handle == GOVERNANCE_IPFS_HANDLE {
            0x71
        } else {
            0x72
        };
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("Governance DAG request-auth test key")
    }
    fn governance_auth_public_key(handle: &str) -> [u8; 32] {
        let keypair = governance_auth_keypair(handle);
        let public_key = keypair.public_key().to_bytes().1;
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(public_key);
        bytes
    }
    impl sorafs_node::GovernanceDagRequestAuthenticator for GovernanceAuthenticator {
        fn handle(&self) -> &str {
            self.handle
        }
        fn ingress_qualification(
            &self,
        ) -> Result<sorafs_node::GovernanceDagRequestIngressQualificationV1, String> {
            sorafs_node::GovernanceDagRequestIngressQualificationV1::try_new(
                GOVERNANCE_QUALIFICATION,
                self.ingress_binding,
                [0x91; 32],
                [0x92; 32],
                [0x93; 32],
            )
            .map_err(|error| error.to_string())
        }
        fn authenticate(
            &self,
            request: &sorafs_node::GovernanceDagCanonicalRequestV1,
        ) -> Result<sorafs_node::GovernanceDagRequestAuthenticationEnvelopeV1, String> {
            let issued_at_unix_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "redacted request-auth clock failure".to_owned())?
                .as_secs();
            let expires_at_unix_secs = issued_at_unix_secs
                .checked_add(30)
                .ok_or_else(|| "redacted request-auth clock failure".to_owned())?;
            let sequence = self
                .nonce
                .fetch_add(1, Ordering::Relaxed)
                .checked_add(1)
                .ok_or_else(|| "redacted request-auth nonce exhaustion".to_owned())?;
            let mut nonce = request.request_digest();
            nonce[..8].copy_from_slice(&sequence.to_be_bytes());
            let public_key = governance_auth_public_key(self.key_handle);
            let payload =
                sorafs_node::GovernanceDagRequestAuthenticationEnvelopeV1::signing_payload(
                    request,
                    issued_at_unix_secs,
                    expires_at_unix_secs,
                    nonce,
                    public_key,
                );
            let signature = iroha_crypto::Signature::try_new(
                governance_auth_keypair(self.key_handle).private_key(),
                &payload,
            )
            .map_err(|_| "redacted request-auth signing failure".to_owned())?;
            let mut signature_bytes = [0_u8; 64];
            signature_bytes.copy_from_slice(signature.payload());
            sorafs_node::GovernanceDagRequestAuthenticationEnvelopeV1::try_new(
                request,
                issued_at_unix_secs,
                expires_at_unix_secs,
                nonce,
                public_key,
                signature_bytes,
            )
            .map_err(str::to_owned)
        }
    }
    #[derive(Debug, Default)]
    struct GovernanceCheckpointStoreState {
        checkpoint: Option<sorafs_node::GovernanceDagSealedStateRecord>,
        publish_intent: Option<sorafs_node::GovernanceDagSealedStateRecord>,
        producer_checkpoint: Option<sorafs_node::GovernanceDagSealedStateRecord>,
        producer_publish_intent: Option<sorafs_node::GovernanceDagSealedStateRecord>,
        ipfs_request_replay: Option<sorafs_node::GovernanceDagSealedStateRecord>,
        signed_head_request_replay: Option<sorafs_node::GovernanceDagSealedStateRecord>,
        checkpoint_generation_floor: u64,
        publish_intent_generation_floor: u64,
        producer_checkpoint_generation_floor: u64,
        producer_publish_intent_generation_floor: u64,
        ipfs_request_replay_generation_floor: u64,
        signed_head_request_replay_generation_floor: u64,
    }
    impl GovernanceCheckpointStoreState {
        fn slot(
            &self,
            slot: sorafs_node::GovernanceDagSealedStateSlot,
        ) -> Option<&sorafs_node::GovernanceDagSealedStateRecord> {
            match slot {
                sorafs_node::GovernanceDagSealedStateSlot::Checkpoint => self.checkpoint.as_ref(),
                sorafs_node::GovernanceDagSealedStateSlot::PublishIntent => {
                    self.publish_intent.as_ref()
                }
                sorafs_node::GovernanceDagSealedStateSlot::ProducerCheckpoint => {
                    self.producer_checkpoint.as_ref()
                }
                sorafs_node::GovernanceDagSealedStateSlot::ProducerPublishIntent => {
                    self.producer_publish_intent.as_ref()
                }
                sorafs_node::GovernanceDagSealedStateSlot::IpfsRequestReplay => {
                    self.ipfs_request_replay.as_ref()
                }
                sorafs_node::GovernanceDagSealedStateSlot::SignedHeadRequestReplay => {
                    self.signed_head_request_replay.as_ref()
                }
            }
        }
        fn slot_mut(
            &mut self,
            slot: sorafs_node::GovernanceDagSealedStateSlot,
        ) -> &mut Option<sorafs_node::GovernanceDagSealedStateRecord> {
            match slot {
                sorafs_node::GovernanceDagSealedStateSlot::Checkpoint => &mut self.checkpoint,
                sorafs_node::GovernanceDagSealedStateSlot::PublishIntent => {
                    &mut self.publish_intent
                }
                sorafs_node::GovernanceDagSealedStateSlot::ProducerCheckpoint => {
                    &mut self.producer_checkpoint
                }
                sorafs_node::GovernanceDagSealedStateSlot::ProducerPublishIntent => {
                    &mut self.producer_publish_intent
                }
                sorafs_node::GovernanceDagSealedStateSlot::IpfsRequestReplay => {
                    &mut self.ipfs_request_replay
                }
                sorafs_node::GovernanceDagSealedStateSlot::SignedHeadRequestReplay => {
                    &mut self.signed_head_request_replay
                }
            }
        }
        const fn generation_floor(&self, slot: sorafs_node::GovernanceDagSealedStateSlot) -> u64 {
            match slot {
                sorafs_node::GovernanceDagSealedStateSlot::Checkpoint => {
                    self.checkpoint_generation_floor
                }
                sorafs_node::GovernanceDagSealedStateSlot::PublishIntent => {
                    self.publish_intent_generation_floor
                }
                sorafs_node::GovernanceDagSealedStateSlot::ProducerCheckpoint => {
                    self.producer_checkpoint_generation_floor
                }
                sorafs_node::GovernanceDagSealedStateSlot::ProducerPublishIntent => {
                    self.producer_publish_intent_generation_floor
                }
                sorafs_node::GovernanceDagSealedStateSlot::IpfsRequestReplay => {
                    self.ipfs_request_replay_generation_floor
                }
                sorafs_node::GovernanceDagSealedStateSlot::SignedHeadRequestReplay => {
                    self.signed_head_request_replay_generation_floor
                }
            }
        }
        fn set_generation_floor(
            &mut self,
            slot: sorafs_node::GovernanceDagSealedStateSlot,
            generation: u64,
        ) {
            match slot {
                sorafs_node::GovernanceDagSealedStateSlot::Checkpoint => {
                    self.checkpoint_generation_floor = generation;
                }
                sorafs_node::GovernanceDagSealedStateSlot::PublishIntent => {
                    self.publish_intent_generation_floor = generation;
                }
                sorafs_node::GovernanceDagSealedStateSlot::ProducerCheckpoint => {
                    self.producer_checkpoint_generation_floor = generation;
                }
                sorafs_node::GovernanceDagSealedStateSlot::ProducerPublishIntent => {
                    self.producer_publish_intent_generation_floor = generation;
                }
                sorafs_node::GovernanceDagSealedStateSlot::IpfsRequestReplay => {
                    self.ipfs_request_replay_generation_floor = generation;
                }
                sorafs_node::GovernanceDagSealedStateSlot::SignedHeadRequestReplay => {
                    self.signed_head_request_replay_generation_floor = generation;
                }
            }
        }
    }
    #[derive(Debug, Default)]
    struct GovernanceCheckpointStore {
        state: Mutex<GovernanceCheckpointStoreState>,
    }
    impl sorafs_node::GovernanceDagSealedCheckpointStore for GovernanceCheckpointStore {
        fn handle(&self) -> &str {
            GOVERNANCE_CHECKPOINT_HANDLE
        }
        fn qualification(
            &self,
        ) -> Result<sorafs_node::GovernanceDagRuntimeProviderQualificationV1, String> {
            Ok(GOVERNANCE_QUALIFICATION)
        }
        fn load(
            &self,
            slot: sorafs_node::GovernanceDagSealedStateSlot,
        ) -> Result<Option<sorafs_node::GovernanceDagSealedStateRecord>, String> {
            let state = self
                .state
                .lock()
                .map_err(|_| "governance checkpoint store lock poisoned".to_owned())?;
            Ok(state.slot(slot).cloned())
        }
        fn compare_and_swap(
            &self,
            slot: sorafs_node::GovernanceDagSealedStateSlot,
            expected_revision: Option<[u8; 32]>,
            next: sorafs_node::GovernanceDagSealedStateRecord,
        ) -> Result<(), String> {
            if next.generation == 0 || !next.has_valid_revision(slot) {
                return Err("invalid governance sealed-state record".to_owned());
            }
            let mut state = self
                .state
                .lock()
                .map_err(|_| "governance checkpoint store lock poisoned".to_owned())?;
            let current = state.slot(slot);
            if current.map(|record| record.revision) != expected_revision {
                return Err("governance checkpoint compare-and-swap conflict".to_owned());
            }
            let floor = state.generation_floor(slot);
            let generation_is_valid = match slot {
                sorafs_node::GovernanceDagSealedStateSlot::PublishIntent
                | sorafs_node::GovernanceDagSealedStateSlot::ProducerPublishIntent
                    if current.is_some() =>
                {
                    next.generation >= floor
                }
                sorafs_node::GovernanceDagSealedStateSlot::Checkpoint
                | sorafs_node::GovernanceDagSealedStateSlot::ProducerCheckpoint
                | sorafs_node::GovernanceDagSealedStateSlot::IpfsRequestReplay
                | sorafs_node::GovernanceDagSealedStateSlot::SignedHeadRequestReplay
                | sorafs_node::GovernanceDagSealedStateSlot::PublishIntent
                | sorafs_node::GovernanceDagSealedStateSlot::ProducerPublishIntent => {
                    next.generation > floor
                }
            };
            if !generation_is_valid {
                return Err("governance checkpoint generation rollback".to_owned());
            }
            state.set_generation_floor(slot, next.generation);
            *state.slot_mut(slot) = Some(next);
            Ok(())
        }
        fn delete(
            &self,
            slot: sorafs_node::GovernanceDagSealedStateSlot,
            expected_revision: [u8; 32],
        ) -> Result<(), String> {
            if matches!(
                slot,
                sorafs_node::GovernanceDagSealedStateSlot::Checkpoint
                    | sorafs_node::GovernanceDagSealedStateSlot::ProducerCheckpoint
                    | sorafs_node::GovernanceDagSealedStateSlot::IpfsRequestReplay
                    | sorafs_node::GovernanceDagSealedStateSlot::SignedHeadRequestReplay
            ) {
                return Err("governance checkpoint record is not transient".to_owned());
            }
            let mut state = self
                .state
                .lock()
                .map_err(|_| "governance checkpoint store lock poisoned".to_owned())?;
            if state.slot(slot).map(|record| record.revision) != Some(expected_revision) {
                return Err("governance checkpoint compare-and-swap conflict".to_owned());
            }
            *state.slot_mut(slot) = None;
            Ok(())
        }
    }
    #[test]
    fn governance_checkpoint_store_keeps_sealed_state_slots_isolated_and_monotonic() {
        use sorafs_node::{
            GovernanceDagSealedCheckpointStore as _, GovernanceDagSealedStateRecord,
            GovernanceDagSealedStateSlot as Slot,
        };
        let store = GovernanceCheckpointStore::default();
        let records = [
            (
                Slot::Checkpoint,
                GovernanceDagSealedStateRecord::new(Slot::Checkpoint, 1, vec![0x11]),
            ),
            (
                Slot::PublishIntent,
                GovernanceDagSealedStateRecord::new(Slot::PublishIntent, 1, vec![0x22]),
            ),
            (
                Slot::ProducerCheckpoint,
                GovernanceDagSealedStateRecord::new(Slot::ProducerCheckpoint, 1, vec![0x33]),
            ),
            (
                Slot::ProducerPublishIntent,
                GovernanceDagSealedStateRecord::new(Slot::ProducerPublishIntent, 1, vec![0x44]),
            ),
        ];
        for (slot, record) in &records {
            store
                .compare_and_swap(*slot, None, record.clone())
                .expect("install independent sealed-state record");
        }
        for (slot, record) in &records {
            assert_eq!(
                store.load(*slot).expect("load sealed-state slot"),
                Some(record.clone())
            );
        }
        for slot in [Slot::Checkpoint, Slot::ProducerCheckpoint] {
            let current = store
                .load(slot)
                .expect("load checkpoint")
                .expect("checkpoint exists");
            let replacement = GovernanceDagSealedStateRecord::new(slot, 1, vec![0x55]);
            assert!(
                store
                    .compare_and_swap(slot, Some(current.revision), replacement)
                    .is_err(),
                "checkpoint generations must strictly advance"
            );
            assert!(
                store.delete(slot, current.revision).is_err(),
                "durable checkpoints are not transient"
            );
        }
        for slot in [Slot::PublishIntent, Slot::ProducerPublishIntent] {
            let current = store
                .load(slot)
                .expect("load publish intent")
                .expect("publish intent exists");
            let replacement = GovernanceDagSealedStateRecord::new(slot, 1, vec![0x66]);
            store
                .compare_and_swap(slot, Some(current.revision), replacement.clone())
                .expect("an active intent may advance at the same generation");
            store
                .delete(slot, replacement.revision)
                .expect("delete exact transient intent revision");
            assert!(
                store
                    .compare_and_swap(
                        slot,
                        None,
                        GovernanceDagSealedStateRecord::new(slot, 1, vec![0x77]),
                    )
                    .is_err(),
                "deleting an intent must retain its monotonic generation floor"
            );
            store
                .compare_and_swap(
                    slot,
                    None,
                    GovernanceDagSealedStateRecord::new(slot, 2, vec![0x88]),
                )
                .expect("a later intent generation may follow deletion");
        }
    }
    #[derive(Debug)]
    struct EvidenceViewerCheckpointStore;
    impl sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderV1
        for EvidenceViewerCheckpointStore
    {
        fn handle(&self) -> &str {
            EVIDENCE_CHECKPOINT_HANDLE
        }
        fn qualification(
            &self,
        ) -> Result<
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1,
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1,
        > {
            Ok(EVIDENCE_CHECKPOINT_QUALIFICATION)
        }
    }
    impl sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreV1
        for EvidenceViewerCheckpointStore
    {
        fn load_latest(
            &self,
        ) -> Result<
            Option<sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreRecordV1>,
            sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreExternalErrorV1,
        > {
            Ok(None)
        }
        fn compare_and_swap_latest(
            &self,
            _expected_revision: Option<[u8; 32]>,
            _next: &sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreRecordV1,
        ) -> Result<(), sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreExternalErrorV1>
        {
            Ok(())
        }
    }
    #[derive(Debug)]
    struct EvidenceViewerCompactionArchive {
        handle: &'static str,
        archive_id: [u8; 32],
        public_key: [u8; 32],
        first_qualification:
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1,
        later_qualification:
            Option<sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1>,
        qualification_error:
            Option<sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1>,
        qualification_calls: AtomicUsize,
    }
    impl EvidenceViewerCompactionArchive {
        fn exact() -> Self {
            Self {
                handle: EVIDENCE_ARCHIVE_HANDLE,
                archive_id: EVIDENCE_ARCHIVE_ID,
                public_key: evidence_archive_public_key(),
                first_qualification: EVIDENCE_ARCHIVE_QUALIFICATION,
                later_qualification: None,
                qualification_error: None,
                qualification_calls: AtomicUsize::new(0),
            }
        }
    }
    impl sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderV1
        for EvidenceViewerCompactionArchive
    {
        fn handle(&self) -> &str {
            self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1,
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1,
        > {
            if let Some(error) = self.qualification_error {
                return Err(error);
            }
            let call = self.qualification_calls.fetch_add(1, Ordering::Relaxed);
            Ok(if call == 0 {
                self.first_qualification
            } else {
                self.later_qualification.unwrap_or(self.first_qualification)
            })
        }
    }
    impl sorafs_node::evidence_viewer::EvidenceViewerCompactionArchiveV1
        for EvidenceViewerCompactionArchive
    {
        fn archive_id(&self) -> [u8; 32] {
            self.archive_id
        }
        fn signing_public_key(&self) -> [u8; 32] {
            self.public_key
        }
        fn install(
            &self,
            _operation_id: [u8; 32],
            _receipt_message: [u8; 32],
            _canonical_artifact: &[u8],
        ) -> Result<[u8; 64], sorafs_node::evidence_viewer::EvidenceViewerExternalErrorV1> {
            Err(sorafs_node::evidence_viewer::EvidenceViewerExternalErrorV1::Rejected)
        }
        fn read(
            &self,
            _operation_id: [u8; 32],
        ) -> Result<
            Option<sorafs_node::evidence_viewer::EvidenceViewerCompactionArchiveReadbackV1>,
            sorafs_node::evidence_viewer::EvidenceViewerExternalErrorV1,
        > {
            Err(sorafs_node::evidence_viewer::EvidenceViewerExternalErrorV1::Rejected)
        }
    }
    #[derive(Debug)]
    struct EvidenceViewerTransparencyPublisher {
        handle: &'static str,
        public_key: [u8; 32],
        qualification: sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1,
        qualification_error:
            Option<sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1>,
    }
    impl EvidenceViewerTransparencyPublisher {
        fn exact() -> Self {
            Self {
                handle: EVIDENCE_TRANSPARENCY_PUBLISHER_HANDLE,
                public_key: evidence_archive_public_key(),
                qualification: EVIDENCE_TRANSPARENCY_PUBLISHER_QUALIFICATION,
                qualification_error: None,
            }
        }
    }
    impl sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderV1
        for EvidenceViewerTransparencyPublisher
    {
        fn handle(&self) -> &str {
            self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1,
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1,
        > {
            self.qualification_error.map_or(Ok(self.qualification), Err)
        }
    }
    impl sorafs_node::evidence_viewer::transparency_producer::EvidenceViewerTransparencyPublisherV1
        for EvidenceViewerTransparencyPublisher
    {
        fn public_key(&self) -> [u8; 32] {
            self.public_key
        }
        fn load_head(
            &self,
        ) -> Result<
            Option<
                sorafs_node::evidence_viewer::transparency_producer::
                    EvidenceViewerSignedTransparencyHeadV1,
            >,
            sorafs_node::evidence_viewer::transparency_producer::
                EvidenceViewerTransparencyPublisherExternalErrorV1,
        >{
            Ok(None)
        }
        fn compare_and_publish(
            &self,
            _body: &sorafs_node::evidence_viewer::transparency_producer::
                EvidenceViewerTransparencyHeadBodyV1,
        ) -> Result<
            (),
            sorafs_node::evidence_viewer::transparency_producer::
                EvidenceViewerTransparencyPublisherExternalErrorV1,
        >{
            Ok(())
        }
    }
    fn configure_governance_producer(config: &mut Config) {
        let storage = &mut config.torii.sorafs_storage;
        storage.enabled = true;
        storage.governance_dag_dir = Some("/var/lib/iroha/governance-producer".into());
        storage.governance_dag_publisher_peer_id = Some(GOVERNANCE_PUBLISHER_PEER_ID.to_owned());
        storage.governance_dag_signer_handle = Some(GOVERNANCE_SIGNER_HANDLE.to_owned());
        storage.governance_dag_signer_revision = Some(GOVERNANCE_QUALIFICATION.revision);
        storage.governance_dag_signer_policy_digest = Some(GOVERNANCE_QUALIFICATION.policy_digest);
        storage.governance_dag_publisher_public_key_hex =
            Some(hex::encode(governance_signer_public_key(0x73)));
        let service = &mut storage.governance_dag_service;
        service.enabled = false;
        service.checkpoint_store_handle = Some(GOVERNANCE_CHECKPOINT_HANDLE.to_owned());
        service.checkpoint_store_revision = Some(GOVERNANCE_QUALIFICATION.revision);
        service.checkpoint_store_policy_digest = Some(GOVERNANCE_QUALIFICATION.policy_digest);
    }
    macro_rules! define_explicit_test_signer {
        ($name:ident, $role:ident, $handle:literal, $seed:literal, $signer_trait:ident, $error:ident) => {
            struct $name {
                public_key: iroha_crypto::PublicKey,
            }
            impl $name {
                fn new() -> Self {
                    let keypair = iroha_crypto::KeyPair::try_from_seed(
                        vec![$seed; 32],
                        iroha_crypto::Algorithm::Ed25519,
                    )
                    .expect("derive explicit runtime-signer fixture");
                    Self {
                        public_key: keypair.public_key().clone(),
                    }
                }
                fn expected_binding(&self) -> iroha_torii::SorafsNativeTransactionSignerBindingV1 {
                    iroha_torii::SorafsNativeTransactionSignerBindingV1::try_new(
                        iroha_torii::SorafsNativeTransactionSignerRoleV1::$role,
                        $handle,
                        iroha_data_model::account::AccountId::new(self.public_key.clone()),
                        self.public_key.clone(),
                        iroha_torii::SorafsNativeTransactionSignerQualificationV1::new(
                            1,
                            [$seed; 32],
                        ),
                    )
                    .expect("valid explicit runtime-signer binding")
                }
            }
            impl iroha_torii::SorafsNativeTransactionSignerProviderV1 for $name {
                fn role(&self) -> iroha_torii::SorafsNativeTransactionSignerRoleV1 {
                    iroha_torii::SorafsNativeTransactionSignerRoleV1::$role
                }
                fn handle(&self) -> &str {
                    $handle
                }
                fn authority(&self) -> iroha_data_model::account::AccountId {
                    iroha_data_model::account::AccountId::new(self.public_key.clone())
                }
                fn public_key(
                    &self,
                ) -> Result<
                    iroha_crypto::PublicKey,
                    iroha_torii::SorafsNativeTransactionSignerProbeErrorV1,
                > {
                    Ok(self.public_key.clone())
                }
                fn qualification(
                    &self,
                ) -> Result<
                    iroha_torii::SorafsNativeTransactionSignerQualificationV1,
                    iroha_torii::SorafsNativeTransactionSignerProbeErrorV1,
                > {
                    Ok(
                        iroha_torii::SorafsNativeTransactionSignerQualificationV1::new(
                            1,
                            [$seed; 32],
                        ),
                    )
                }
            }
            impl iroha_torii::$signer_trait for $name {
                fn sign(
                    &self,
                    _payload: iroha_data_model::transaction::TransactionPayload,
                ) -> Result<iroha_data_model::transaction::SignedTransaction, iroha_torii::$error>
                {
                    Err(iroha_torii::$error::Refused)
                }
            }
        };
    }
    define_explicit_test_signer!(
        ProofOutcomeTestSigner,
        ProofOutcome,
        "software://sorafs/proof-outcome/primary",
        0x31,
        SoraFsProofOutcomeTransactionSigner,
        SoraFsProofOutcomeSigningError
    );
    define_explicit_test_signer!(
        RepairTestSigner,
        Repair,
        "software://sorafs/repair/primary",
        0x32,
        SoraFsRepairTransactionSigner,
        SoraFsRepairTransactionSigningError
    );
    define_explicit_test_signer!(
        ReserveTestSigner,
        Reserve,
        "software://sorafs/reserve/primary",
        0x33,
        SoraFsReserveTransactionSigner,
        SoraFsReserveTransactionSigningError
    );
    define_explicit_test_signer!(
        OrderbookTestSigner,
        Orderbook,
        "software://sorafs/orderbook/primary",
        0x34,
        SoraFsOrderbookTransactionSigner,
        SoraFsOrderbookTransactionSigningError
    );
    struct RoleConfusedProofOutcomeSigner(ProofOutcomeTestSigner);
    impl iroha_torii::SorafsNativeTransactionSignerProviderV1 for RoleConfusedProofOutcomeSigner {
        fn role(&self) -> iroha_torii::SorafsNativeTransactionSignerRoleV1 {
            iroha_torii::SorafsNativeTransactionSignerRoleV1::Repair
        }
        fn handle(&self) -> &str {
            iroha_torii::SorafsNativeTransactionSignerProviderV1::handle(&self.0)
        }
        fn authority(&self) -> iroha_data_model::account::AccountId {
            iroha_torii::SorafsNativeTransactionSignerProviderV1::authority(&self.0)
        }
        fn public_key(
            &self,
        ) -> Result<iroha_crypto::PublicKey, iroha_torii::SorafsNativeTransactionSignerProbeErrorV1>
        {
            iroha_torii::SorafsNativeTransactionSignerProviderV1::public_key(&self.0)
        }
        fn qualification(
            &self,
        ) -> Result<
            iroha_torii::SorafsNativeTransactionSignerQualificationV1,
            iroha_torii::SorafsNativeTransactionSignerProbeErrorV1,
        > {
            iroha_torii::SorafsNativeTransactionSignerProviderV1::qualification(&self.0)
        }
    }
    impl iroha_torii::SoraFsProofOutcomeTransactionSigner for RoleConfusedProofOutcomeSigner {
        fn sign(
            &self,
            _payload: iroha_data_model::transaction::TransactionPayload,
        ) -> Result<
            iroha_data_model::transaction::SignedTransaction,
            iroha_torii::SoraFsProofOutcomeSigningError,
        > {
            Err(iroha_torii::SoraFsProofOutcomeSigningError::Refused)
        }
    }
    fn default_runtime_config() -> Config {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../defaults/kagami/iroha3-dev/peer0.toml");
        let source = std::fs::read_to_string(path).expect("read checked-in default daemon config");
        let mut table: toml::Table = toml::from_str(&source).expect("parse default daemon config");
        let genesis = table
            .get_mut("genesis")
            .and_then(toml::Value::as_table_mut)
            .expect("default daemon genesis config");
        assert_eq!(
            genesis.remove("expected_hash_file"),
            Some(toml::Value::String("genesis.expected_hash".to_owned()))
        );
        // Supply a canonical, explicit test trust root instead of opening the
        // operator-provisioned identity file while inspecting provider bindings.
        let expected_hash = HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
            Hash::new(b"runtime-provider non-runtime profile inspection"),
        );
        let network_id = NetworkId::from_genesis_hash(expected_hash);
        assert!(
            genesis
                .insert(
                    "expected_hash".to_owned(),
                    toml::Value::String(network_id.to_string()),
                )
                .is_none(),
            "checked-in profile must use the single file-backed identity source"
        );
        let config = Config::from_toml_source(TomlSource::inline(table))
            .expect("resolve checked-in default daemon config for inspection");
        assert_eq!(config.genesis.expected_hash, expected_hash);
        config
    }
    fn assert_canonical_config_catalog_roundtrip(
        family: &str,
        config: &Config,
        required_slots: &[IrohaRuntimeProviderSlotV1],
    ) {
        let projected = IrohaRuntimeProviderBindingsV1::try_from_config(config)
            .unwrap_or_else(|error| panic!("project {family} runtime-provider catalog: {error}"));
        for slot in required_slots {
            assert!(
                projected.iter().any(|binding| binding.slot() == *slot),
                "{family} projection omitted specialized slot {slot:?}"
            );
        }
        let first = projected
            .export_canonical_v1()
            .unwrap_or_else(|error| panic!("export {family} runtime-provider catalog: {error}"));
        let second = projected.export_canonical_v1().unwrap_or_else(|error| {
            panic!("repeat export of {family} runtime-provider catalog: {error}")
        });
        assert_eq!(first, second, "{family} export must be deterministic");
        let loaded = IrohaRuntimeProviderBindingsV1::load_canonical_v1(&first)
            .unwrap_or_else(|error| panic!("load {family} runtime-provider catalog: {error}"));
        assert_eq!(
            loaded, projected,
            "{family} handoff must retain every exact public binding field"
        );
        assert_eq!(
            loaded.export_canonical_v1().unwrap_or_else(|error| {
                panic!("re-export loaded {family} runtime-provider catalog: {error}")
            }),
            first,
            "{family} load/re-export must be byte-identical"
        );
    }
    fn configure_stream_token_runtime(config: &mut Config) {
        config.torii.sorafs_storage.enabled = true;
        config.torii.sorafs_storage.provider_id =
            Some(iroha_data_model::sorafs::capacity::ProviderId([0x72; 32]));
        let signer = KeyPair::try_from_seed(vec![0x81; 32], Algorithm::Ed25519)
            .expect("stream-token signer key");
        let signer_public_key = signer
            .public_key()
            .to_bytes()
            .1
            .try_into()
            .expect("Ed25519 public key width");
        let tokens = &mut config.torii.sorafs_storage.stream_tokens;
        tokens.enabled = true;
        tokens.signer = Some(super::stream_token_signer_binding::tests::hardware_config(
            signer_public_key,
        ));
        let compliance_key = evidence_archive_public_key();
        config.torii.sorafs_gateway.compliance =
            Some(iroha_config::parameters::actual::SorafsGatewayCompliance {
                checkpoint_path: Path::new(
                    "/var/lib/iroha/sorafs/gateway-compliance/checkpoint.to",
                )
                .to_path_buf(),
                feed_transport_provider:
                    iroha_config::parameters::actual::SorafsGatewayRuntimeProviderBinding {
                        provider_handle: "network://sorafs/gateway/compliance-feed-primary"
                            .to_owned(),
                        revision: 5,
                        policy_digest: [0x84; 32],
                    },
                policy_id: [0x85; 32],
                region_id: "primary-region".to_owned(),
                gateway_id: "primary-gateway".to_owned(),
                catalog_threshold: 1,
                catalog_signers: vec![
                    iroha_config::parameters::actual::SorafsGatewayComplianceSigner {
                        signer_id: "catalog-primary".to_owned(),
                        public_key: compliance_key,
                    },
                ],
                revoked_catalog_signer_ids: Vec::new(),
                gateway_ack_threshold: 1,
                gateway_signers: vec![
                    iroha_config::parameters::actual::SorafsGatewayComplianceSigner {
                        signer_id: "primary-gateway".to_owned(),
                        public_key: signer_public_key,
                    },
                ],
                revoked_gateway_signer_ids: Vec::new(),
                feeds: vec![
                    iroha_config::parameters::actual::SorafsGatewayComplianceFeed {
                        feed_id: "governed-primary".to_owned(),
                        url: "https://compliance.example/catalog".to_owned(),
                        required: true,
                        hosts: vec![
                            iroha_config::parameters::actual::SorafsGatewayComplianceFeedHost {
                                hostname: "compliance.example".to_owned(),
                                accepted_spki_sha256: vec![[0x86; 32]],
                            },
                        ],
                    },
                ],
                max_encoded_bytes: Bytes(4 * 1024 * 1024),
                max_decoded_bytes: Bytes(8 * 1024 * 1024),
                max_redirects: 2,
                max_dns_addresses: 8,
                connect_timeout: Duration::from_secs(5),
                total_timeout: Duration::from_secs(20),
                max_clock_skew: Duration::from_secs(300),
                max_feed_age: Duration::from_secs(3_600),
                max_catalog_validity: Duration::from_secs(7_200),
                max_history_entries: 64,
            });
    }
    fn configure_appeal_finance_runtime(config: &mut Config) {
        use iroha_config::parameters::actual::{
            SorafsAppealFinanceCheckpointBinding, SorafsAppealFinanceSignerBinding,
        };
        let active = KeyPair::try_from_seed(vec![0xA1; 32], Algorithm::Ed25519)
            .expect("active appeal-finance signer key");
        let rotated = KeyPair::try_from_seed(vec![0xA2; 32], Algorithm::Ed25519)
            .expect("rotated appeal-finance signer key");
        let checkpoint = KeyPair::try_from_seed(vec![0xA3; 32], Algorithm::Ed25519)
            .expect("appeal-finance checkpoint key");
        let appeal = &mut config.torii.sorafs_appeal_finance_settlement;
        appeal.submitter_signers = vec![
            SorafsAppealFinanceSignerBinding {
                handle: "software://sorafs/appeal-finance/signer-a".to_owned(),
                authority: iroha_data_model::account::AccountId::new(active.public_key().clone()),
                public_key: active.public_key().clone(),
                revision: 7,
                policy_digest: [0xA7; 32],
                valid_from_block_height: 1,
                revoked_at_block_height: Some(10),
            },
            SorafsAppealFinanceSignerBinding {
                handle: "software://sorafs/appeal-finance/signer-b".to_owned(),
                authority: iroha_data_model::account::AccountId::new(rotated.public_key().clone()),
                public_key: rotated.public_key().clone(),
                revision: 8,
                policy_digest: [0xA8; 32],
                valid_from_block_height: 10,
                revoked_at_block_height: None,
            },
        ];
        appeal.checkpoint_provider = Some(SorafsAppealFinanceCheckpointBinding {
            handle: "kms://sorafs/appeal-finance/checkpoint-primary".to_owned(),
            public_key: checkpoint.public_key().clone(),
            revision: 3,
            policy_digest: [0xA3; 32],
        });
    }
    fn configure_pop_potr_runtime(config: &mut Config) {
        config.torii.sorafs_storage.pop_credentials = Some(pop_registry_config());
        let gateway = KeyPair::try_from_seed(vec![0x71; 32], Algorithm::Ed25519)
            .expect("PoTR gateway signer key");
        let gateway_public_key = gateway
            .public_key()
            .to_bytes()
            .1
            .try_into()
            .expect("Ed25519 public key width");
        config.torii.sorafs_por.potr_runtime =
            Some(iroha_config::parameters::actual::SorafsPotrRuntimeBinding {
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
                gateway_public_key,
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
            });
    }
    fn configure_moderation_runtime(config: &mut Config) {
        let maintenance_key = KeyPair::try_from_seed(vec![0xC1; 32], Algorithm::Ed25519)
            .expect("moderation maintenance key");
        let strict_qualification = iroha_torii::sorafs::moderation_runtime::
            torii_moderation_strict_ingress_qualification_v1();
        config.torii.sorafs_storage.moderation_orchestrator = Some(
            iroha_config::parameters::actual::SorafsModerationOrchestrator {
                checkpoint_path: Path::new("/var/lib/iroha/sorafs/moderation.to").to_path_buf(),
                checkpoint_store_handle: "sealed://sorafs/moderation/checkpoint-primary".to_owned(),
                checkpoint_store_revision: 7,
                checkpoint_store_policy_digest: [0xC7; 32],
                checkpoint_store_attestation_public_key: [
                    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7,
                    0x4d, 0x1b, 0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
                    0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
                ],
                maintenance_authority: iroha_data_model::account::AccountId::new(
                    maintenance_key.public_key().clone(),
                ),
                transaction_signer_handle: "software://sorafs/moderation/primary".to_owned(),
                transaction_signer_revision: 8,
                transaction_signer_policy_digest: [0xC8; 32],
                strict_ingress_handle: iroha_torii::sorafs::moderation_runtime::
                    TORII_MODERATION_STRICT_INGRESS_HANDLE_V1.to_owned(),
                strict_ingress_revision: strict_qualification.revision(),
                strict_ingress_policy_digest: strict_qualification.policy_digest(),
                settlement_handoff_handle: "queue://sorafs/moderation/settlement-primary".to_owned(),
                settlement_handoff_revision: 9,
                settlement_handoff_policy_digest: [0xC9; 32],
                publication_handoff_handle: "dag://sorafs/moderation/publication-primary".to_owned(),
                publication_handoff_revision: 10,
                publication_handoff_policy_digest: [0xCA; 32],
                panel_notification_handle: "queue://sorafs/moderation/notification-primary".to_owned(),
                panel_notification_revision: 11,
                panel_notification_policy_digest: [0xCB; 32],
                panel_notification_archive_handle:
                    "object-lock://sorafs/moderation/notification-receipts-primary".to_owned(),
                panel_notification_archive_revision: 12,
                panel_notification_archive_policy_digest: [0xCC; 32],
                panel_notification_archive_id: [0xCD; 32],
                panel_notification_archive_bootstrap_public_key: [
                    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3,
                    0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
                    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
                ],
                panel_notification_archive_public_key: [
                    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3,
                    0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
                    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
                ],
                panel_notification_archive_predecessor_revocation_generation: None,
                panel_notification_archive_predecessor_authorization_signature: None,
                panel_notification_archive_new_key_possession_signature: None,
                max_cases: 128,
                max_events: 512,
                max_outbox_entries: 128,
                max_idempotency_records: 512,
                max_handoffs: 128,
                max_submit_attempts: 4,
                checkpoint_max_bytes: Bytes(4 * 1024 * 1024),
                panel_notification_archive_max_bytes: Bytes(5 * 1024 * 1024),
                worker_interval: Duration::from_secs(1),
                maintenance_batch_limit: 64,
            },
        );
    }
    #[test]
    fn moderation_strict_ingress_is_qualified_during_catalog_projection() {
        let mut config = default_runtime_config();
        configure_moderation_runtime(&mut config);
        let bindings = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .expect("qualify Torii strict ingress before broker projection");
        assert!(bindings.iter().all(|binding| {
            binding.handle()
                != iroha_torii::sorafs::moderation_runtime::
                    TORII_MODERATION_STRICT_INGRESS_HANDLE_V1
        }));
        let checkpoint = bindings
            .iter()
            .find(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::ModerationCheckpointStore)
            .expect("project moderation checkpoint binding");
        assert_eq!(
            checkpoint.moderation_checkpoint_max_bytes(),
            Some(4 * 1024 * 1024)
        );
        assert_eq!(
            checkpoint.moderation_checkpoint_attestation_public_key(),
            Some([
                0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
                0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
                0x2a, 0xf4, 0x66, 0x0c,
            ])
        );
        let archive = bindings
            .iter()
            .find(|binding| {
                binding.slot() == IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive
            })
            .expect("project moderation archive binding");
        assert_eq!(
            archive.moderation_panel_notification_archive_id(),
            Some([0xCD; 32])
        );
        assert_eq!(
            archive.moderation_panel_notification_archive_bootstrap_public_key(),
            archive.moderation_panel_notification_archive_public_key()
        );
        assert_eq!(
            archive.moderation_panel_notification_archive_max_bytes(),
            Some(5 * 1024 * 1024)
        );
        assert_eq!(
            archive.moderation_panel_notification_archive_max_records(),
            Some(128)
        );
    }
    #[test]
    fn moderation_archive_projection_rejects_missing_source_and_archive_identities() {
        for mutation in 0..5 {
            let mut config = default_runtime_config();
            configure_moderation_runtime(&mut config);
            let moderation = config
                .torii
                .sorafs_storage
                .moderation_orchestrator
                .as_mut()
                .expect("configured moderation runtime");
            match mutation {
                0 => moderation.checkpoint_store_attestation_public_key = [0; 32],
                1 => moderation.panel_notification_archive_id = [0; 32],
                2 => moderation.panel_notification_archive_bootstrap_public_key = [0; 32],
                3 => moderation.panel_notification_archive_public_key = [0; 32],
                4 => moderation.max_handoffs = 0,
                _ => unreachable!(),
            }
            assert!(matches!(
                IrohaRuntimeProviderBindingsV1::try_from_config(&config),
                Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    IrohaRuntimeProviderSlotV1::ModerationCheckpointStore
                        | IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive
                ))
            ));
        }
    }
    #[test]
    fn moderation_archive_projection_rejects_checkpoint_role_collisions() {
        let archive_slot = IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive;
        for mutation in 0..3 {
            let mut config = default_runtime_config();
            configure_moderation_runtime(&mut config);
            let moderation = config
                .torii
                .sorafs_storage
                .moderation_orchestrator
                .as_mut()
                .expect("configured moderation runtime");
            match mutation {
                0 => {
                    moderation.panel_notification_archive_handle =
                        moderation.checkpoint_store_handle.clone();
                }
                1 => {
                    moderation.checkpoint_store_attestation_public_key =
                        moderation.panel_notification_archive_bootstrap_public_key;
                }
                2 => {
                    moderation.panel_notification_archive_public_key =
                        moderation.checkpoint_store_attestation_public_key;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                IrohaRuntimeProviderBindingsV1::try_from_config(&config),
                Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    archive_slot
                ))
            );
        }
    }
    #[test]
    fn moderation_strict_ingress_preflight_rejects_missing_substituted_stale_and_test_bindings() {
        for (mutation, expected) in [
            (0, IrohaRuntimeProviderRegistryErrorV1::BindingMismatch),
            (1, IrohaRuntimeProviderRegistryErrorV1::BindingMismatch),
            (2, IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked),
            (3, IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked),
            (4, IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected),
        ] {
            let mut config = default_runtime_config();
            configure_moderation_runtime(&mut config);
            let moderation = config
                .torii
                .sorafs_storage
                .moderation_orchestrator
                .as_mut()
                .expect("configured moderation runtime");
            match mutation {
                0 => moderation.strict_ingress_handle.clear(),
                1 => {
                    moderation.strict_ingress_handle =
                        "torii.sorafs.moderation-strict-ingress.secondary".to_owned();
                }
                2 => moderation.strict_ingress_revision += 1,
                3 => moderation.strict_ingress_policy_digest = [0xD1; 32],
                4 => {
                    moderation.strict_ingress_handle =
                        "torii.sorafs.moderation-test-ingress.v1".to_owned();
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                resolve_runtime_deps(&config, Some(&EmptyRegistry)),
                Err(error) if error == expected
            ));
        }
    }
    fn configure_provider_ingest_runtime(config: &mut Config) {
        let completion_signer =
            iroha_crypto::KeyPair::try_from_seed(vec![0x61; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("provider-ingest completion signer key");
        config.torii.sorafs_storage.provider_ingest_runtime = Some(
            iroha_config::parameters::actual::SorafsProviderIngestRuntime {
                native_source_origins: std::collections::BTreeMap::default(),
                native_completion_credential: None,
                authenticated_source_fetch_handle:
                    "network://sorafs/provider-ingest/source-primary".to_owned(),
                authenticated_source_fetch_revision: 5,
                authenticated_source_fetch_policy_digest: [0xB1; 32],
                completion_signer_resolver_handle: "resolver://sorafs/provider-ingest/primary"
                    .to_owned(),
                completion_signer_resolver_revision: 6,
                completion_signer_resolver_policy_digest: [0xB2; 32],
                completion_signer_handle: "software://sorafs/provider-ingest/signer-primary"
                    .to_owned(),
                completion_signer_adapter_revision: 3,
                completion_signer_policy: sorafs_node::ProviderIngestCompletionSignerPolicyV1 {
                    policy_id: [0xA1; 32],
                    revision: 1,
                    predecessor_digest: None,
                    policy_digest: [0xA2; 32],
                },
                completion_signer_algorithm: iroha_crypto::Algorithm::Ed25519,
                completion_signer_public_key: completion_signer.public_key().clone(),
                checkpoint_store_handle: "sealed://sorafs/provider-ingest/checkpoint-primary"
                    .to_owned(),
                checkpoint_store_revision: 7,
                checkpoint_store_policy_digest: [0xA7; 32],
                scan_interval_ms: 1_000,
                max_page_rows: 64,
                max_pages_per_tick: 4,
                max_source_jobs_per_tick: 32,
                max_source_providers: 1_024,
                source_operation_timeout_ms: 30_000,
                source_lease_renew_interval_ms: 5_000,
                signer_timeout_ms: 10_000,
                ingress_timeout_ms: 10_000,
                completion_transaction_ttl_ms: 30_000,
                finalized_archive:
                    iroha_config::parameters::actual::SorafsProviderIngestFinalizedArchive {
                        relative_root: "provider-ingest-finalized-archive-v1".into(),
                        max_record_bytes: 128 * 1024 * 1024,
                        max_archive_entries: 1_000_000,
                        max_total_bytes: 64 * 1024 * 1024 * 1024,
                        max_providers_per_anchor: 1_024,
                        max_orders_per_provider: 256,
                        max_total_orders_per_anchor: 256,
                        max_page_rows: 64,
                        max_kura_tip_lag_blocks: 2,
                        retention_authority: None,
                    },
                outbox: iroha_config::parameters::actual::SorafsProviderIngestOutbox {
                    max_active_entries: 32,
                    max_terminal_entries: 4_096,
                    max_attempts: 8,
                    checkpoint_max_bytes: Bytes(192 * 1024 * 1024),
                    checkpoint_operation_timeout_ms: 30_000,
                    source_lease_ttl_ms: 30_000,
                    retry_base_delay_ms: 1_000,
                    retry_max_delay_ms: 60_000,
                    terminal_retention_blocks: 100_000,
                    max_signed_transaction_bytes: Bytes(1024 * 1024),
                    max_status_page_size: 256,
                },
                provider_attestation_journal: None,
            },
        );
    }
    fn configure_reputation_runtime(config: &mut Config) {
        config.torii.sorafs_storage.reputation_runtime = Some(
            iroha_config::parameters::actual::SorafsReputationRuntime {
                state_dir: Path::new("/var/lib/iroha/sorafs/reputation").to_path_buf(),
                finalized_archive_root: Path::new(
                    "/var/lib/iroha/sorafs/reputation-finalized-archive",
                )
                .to_path_buf(),
                finalized_archive_max_record_bytes: 4 * 1024 * 1024,
                finalized_archive_max_entries: 4_096,
                finalized_archive_max_total_bytes: 256 * 1024 * 1024,
                finalized_archive_max_kura_tip_lag_blocks: 2,
                finalized_archive_retention_authority: Some(
                    iroha_config::parameters::actual::
                        SorafsReputationFinalizedArchiveRetentionAuthority {
                            handle: "sealed://sorafs/reputation/retention-primary".to_owned(),
                            revision: 9,
                            policy_digest: [0xC9; 32],
                        },
                ),
                window_start_height: 1,
                window_end_height: 10,
                finalized_query_handle: "ledger://sorafs/reputation/finalized-primary".to_owned(),
                journal_checkpoint_provider_handle:
                    "sealed://sorafs/reputation/journal-primary".to_owned(),
                journal_checkpoint_provider_revision: 1,
                journal_checkpoint_provider_policy_digest: [0x60; 32],
                journal_transaction_submitter_handle:
                    "queue://sorafs/reputation/journal-primary".to_owned(),
                journal_transaction_submitter_revision: 11,
                journal_transaction_submitter_policy_digest: [0x61; 32],
                threshold_signer_handle: "software://sorafs/reputation/primary".to_owned(),
                threshold_signer_revision: 12,
                threshold_signer_policy_digest: [0x62; 32],
                governance_dag_handle: "dag://sorafs/reputation/publisher-primary".to_owned(),
                governance_dag_revision: 13,
                governance_dag_policy_digest: [0x63; 32],
                governance_publisher_peer_id: b"12D3KooWProductionPublisher".to_vec(),
                governance_publisher_public_key: [0x73; 32],
                poll_interval: Duration::from_secs(1),
                page_items: 64,
                max_pages_per_batch: 4_096,
                max_providers: 65_536,
                max_pending_events: 65_536,
                max_replay_receipts: 262_144,
                max_material_delivery_failures: 64,
                ingest_checkpoint_max_bytes: Bytes(64 * 1024 * 1024),
                publication_checkpoint_max_bytes: Bytes(32 * 1024 * 1024),
                por_success_bps: 2_200,
                pdp_success_bps: 2_000,
                potr_success_bps: 1_800,
                latency_bps: 1_500,
                dispute_bps: 1_000,
                token_violation_bps: 500,
                repair_breach_bps: 1_000,
            },
        );
    }
    fn configure_evidence_viewer(config: &mut Config) {
        config.torii.sorafs_storage.evidence_viewer =
            Some(iroha_config::parameters::actual::SorafsEvidenceViewer {
                checkpoint_path: Path::new("/var/lib/iroha/sorafs/evidence-viewer.to")
                    .to_path_buf(),
                checkpoint_max_bytes: Bytes(64 * 1024 * 1024),
                checkpoint_store_handle: EVIDENCE_CHECKPOINT_HANDLE.to_owned(),
                checkpoint_store_revision: EVIDENCE_CHECKPOINT_QUALIFICATION.revision(),
                checkpoint_store_policy_digest: EVIDENCE_CHECKPOINT_QUALIFICATION.policy_digest(),
                session_ttl: Duration::from_secs(15 * 60),
                grant_ttl: Duration::from_secs(5 * 60),
                challenge_ttl: Duration::from_secs(60),
                max_range_bytes: Bytes(64 * 1024 * 1024),
                max_challenges: 1_024,
                max_sessions: 1_024,
                max_receipts: 4_096,
                max_idempotency_records: 4_096,
                retention_after_expiry: Duration::from_secs(24 * 60 * 60),
                webauthn_rp_id: "review.example".to_owned(),
                webauthn_allowed_origins: vec!["https://review.example".to_owned()],
                webauthn_handle: "webauthn://sorafs/evidence-viewer/primary".to_owned(),
                webauthn_revision: 11,
                webauthn_policy_digest: [0xA1; 32],
                grant_handle: "kms://sorafs/evidence-viewer/grants-primary".to_owned(),
                grant_revision: 12,
                grant_policy_digest: [0xA2; 32],
                erasure_handle: "kms://sorafs/evidence-viewer/erasure-primary".to_owned(),
                erasure_revision: 13,
                erasure_policy_digest: [0xA3; 32],
                compaction_archive_handle: EVIDENCE_ARCHIVE_HANDLE.to_owned(),
                compaction_archive_id: EVIDENCE_ARCHIVE_ID,
                compaction_archive_revision: EVIDENCE_ARCHIVE_QUALIFICATION.revision(),
                compaction_archive_policy_digest: EVIDENCE_ARCHIVE_QUALIFICATION.policy_digest(),
                compaction_archive_public_key: evidence_archive_public_key(),
                compaction_interval: Duration::from_secs(60),
                compaction_max_records: 256,
                receipt_signer_handle: "software://sorafs/evidence-viewer/primary".to_owned(),
                receipt_signer_revision: 14,
                receipt_signer_policy_digest: [0xA4; 32],
                receipt_signer_public_key: evidence_archive_public_key(),
                transparency_publisher_handle: EVIDENCE_TRANSPARENCY_PUBLISHER_HANDLE.to_owned(),
                transparency_publisher_revision: EVIDENCE_TRANSPARENCY_PUBLISHER_QUALIFICATION
                    .revision(),
                transparency_publisher_policy_digest: EVIDENCE_TRANSPARENCY_PUBLISHER_QUALIFICATION
                    .policy_digest(),
                transparency_publisher_public_key: evidence_archive_public_key(),
            });
    }
    #[test]
    fn canonical_catalog_roundtrips_every_specialized_config_projection_family() {
        let mut governance = default_runtime_config();
        configure_governance_producer(&mut governance);
        configure_governance_service(&mut governance);
        assert_canonical_config_catalog_roundtrip(
            "Governance DAG",
            &governance,
            &[
                IrohaRuntimeProviderSlotV1::GovernanceDagSigner,
                IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator,
                IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator,
                IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore,
            ],
        );
        let mut stream_tokens = default_runtime_config();
        configure_stream_token_runtime(&mut stream_tokens);
        assert_canonical_config_catalog_roundtrip(
            "stream token",
            &stream_tokens,
            &[IrohaRuntimeProviderSlotV1::StreamTokenSigner],
        );
        let mut appeal_finance = default_runtime_config();
        configure_appeal_finance_runtime(&mut appeal_finance);
        assert_canonical_config_catalog_roundtrip(
            "appeal finance",
            &appeal_finance,
            &[
                IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner,
                IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint,
            ],
        );
        let proof = ProofOutcomeTestSigner::new();
        let repair = RepairTestSigner::new();
        let reserve = ReserveTestSigner::new();
        let orderbook = OrderbookTestSigner::new();
        let mut native_archive_cloud = default_runtime_config();
        let native = &mut native_archive_cloud
            .torii
            .sorafs_storage
            .native_transaction_signers;
        native.proof_outcome = Some(actual_native_signer_binding(&proof.expected_binding()));
        native.repair = Some(actual_native_signer_binding(&repair.expected_binding()));
        native.reserve = Some(actual_native_signer_binding(&reserve.expected_binding()));
        native.orderbook = Some(actual_native_signer_binding(&orderbook.expected_binding()));
        native_archive_cloud.torii.sorafs_storage.por_replay_archive =
            Some(por_archive_config(por_archive_binding(0xB3)));
        let cloud_signer = KeyPair::try_from_seed(vec![0xD1; 32], Algorithm::Ed25519)
            .expect("Soracloud runtime signer key");
        native_archive_cloud.soracloud_runtime.submission.signer = Some(
            iroha_config::parameters::actual::SoracloudRuntimeMutationSignerBinding {
                handle: "software://sorafs/ai/runtime-primary".to_owned(),
                authority: iroha_data_model::account::AccountId::new(
                    cloud_signer.public_key().clone(),
                ),
                algorithm: Algorithm::Ed25519,
                public_key: cloud_signer.public_key().clone(),
                revision: 11,
                policy_digest: [0xD2; 32],
            },
        );
        assert_canonical_config_catalog_roundtrip(
            "native signer, PoR archive, and Soracloud",
            &native_archive_cloud,
            &[
                IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner,
                IrohaRuntimeProviderSlotV1::RepairTransactionSigner,
                IrohaRuntimeProviderSlotV1::ReserveTransactionSigner,
                IrohaRuntimeProviderSlotV1::OrderbookTransactionSigner,
                IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive,
                IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner,
            ],
        );
        let mut moderation_evidence = default_runtime_config();
        configure_moderation_runtime(&mut moderation_evidence);
        configure_evidence_viewer(&mut moderation_evidence);
        assert_canonical_config_catalog_roundtrip(
            "moderation and evidence viewer",
            &moderation_evidence,
            &[
                IrohaRuntimeProviderSlotV1::ModerationTransactionSigner,
                IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff,
                IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff,
                IrohaRuntimeProviderSlotV1::ModerationPanelNotification,
                IrohaRuntimeProviderSlotV1::ModerationCheckpointStore,
                IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
                IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn,
                IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority,
                IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner,
                IrohaRuntimeProviderSlotV1::EvidenceViewerErasure,
                IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore,
                IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive,
                IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher,
            ],
        );
        let mut pop_potr = default_runtime_config();
        configure_pop_potr_runtime(&mut pop_potr);
        assert_canonical_config_catalog_roundtrip(
            "PoP and PoTR",
            &pop_potr,
            &[
                IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry,
                IrohaRuntimeProviderSlotV1::PotrGatewaySigner,
                IrohaRuntimeProviderSlotV1::PotrProviderSigner,
            ],
        );
        let mut provider_ingest = default_runtime_config();
        configure_provider_ingest_runtime(&mut provider_ingest);
        provider_ingest
            .torii
            .sorafs_storage
            .provider_ingest_runtime
            .as_mut()
            .expect("configured provider ingest")
            .finalized_archive
            .retention_authority = Some(
            iroha_config::parameters::actual::
                SorafsProviderIngestFinalizedArchiveRetentionAuthority {
                    handle: "sealed://sorafs/provider-ingest/retention-primary".to_owned(),
                    revision: 8,
                    policy_digest: [0xA8; 32],
                },
        );
        assert_canonical_config_catalog_roundtrip(
            "provider ingest",
            &provider_ingest,
            &[
                IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource,
                IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver,
                IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner,
                IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore,
                IrohaRuntimeProviderSlotV1::ProviderIngestRetentionAuthority,
            ],
        );
        let mut reputation = default_runtime_config();
        configure_reputation_runtime(&mut reputation);
        assert_canonical_config_catalog_roundtrip(
            "reputation",
            &reputation,
            &[IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint],
        );
    }
    fn evidence_archive_request() -> IrohaRuntimeProviderBindingsV1 {
        let mut config = default_runtime_config();
        configure_evidence_viewer(&mut config);
        let viewer = config
            .torii
            .sorafs_storage
            .evidence_viewer
            .as_ref()
            .expect("configured evidence viewer");
        IrohaRuntimeProviderBindingsV1 {
            chain_id: "evidence-viewer-archive-test-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: vec![
                IrohaRuntimeProviderBindingV1::try_new_evidence_viewer_archive(viewer)
                    .expect("valid evidence-viewer archive request"),
            ],
        }
    }
    fn evidence_transparency_publisher_request() -> IrohaRuntimeProviderBindingsV1 {
        let mut config = default_runtime_config();
        configure_evidence_viewer(&mut config);
        let viewer = config
            .torii
            .sorafs_storage
            .evidence_viewer
            .as_ref()
            .expect("configured evidence viewer");
        IrohaRuntimeProviderBindingsV1 {
            chain_id: "evidence-viewer-transparency-test-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: vec![
                IrohaRuntimeProviderBindingV1::try_new_evidence_viewer_transparency_publisher(
                    viewer,
                )
                .expect("valid evidence-viewer transparency publisher request"),
            ],
        }
    }
    fn actual_native_signer_binding(
        binding: &iroha_torii::SorafsNativeTransactionSignerBindingV1,
    ) -> iroha_config::parameters::actual::SorafsNativeTransactionSignerBinding {
        iroha_config::parameters::actual::SorafsNativeTransactionSignerBinding {
            software_credential: None,
            handle: binding.handle().to_owned(),
            authority: binding.authority().clone(),
            algorithm: binding
                .public_key()
                .try_algorithm()
                .expect("fixture key algorithm"),
            public_key: binding.public_key().clone(),
            revision: binding.qualification().revision(),
            policy_digest: binding.qualification().policy_digest(),
        }
    }
    fn observed_native_signer_binding(
        provider: &(impl iroha_torii::SorafsNativeTransactionSignerProviderV1 + ?Sized),
    ) -> iroha_torii::SorafsNativeTransactionSignerBindingV1 {
        iroha_torii::SorafsNativeTransactionSignerBindingV1::try_new(
            provider.role(),
            provider.handle(),
            provider.authority(),
            provider
                .public_key()
                .expect("qualified provider public key"),
            provider
                .qualification()
                .expect("qualified provider qualification"),
        )
        .expect("qualified provider exposes a valid immutable binding")
    }
    fn native_signer_catalog(
        entries: impl IntoIterator<
            Item = (
                IrohaRuntimeProviderSlotV1,
                iroha_torii::SorafsNativeTransactionSignerBindingV1,
            ),
        >,
    ) -> IrohaRuntimeProviderBindingsV1 {
        let mut bindings = entries
            .into_iter()
            .map(|(slot, binding)| {
                IrohaRuntimeProviderBindingV1::try_new_native_signer(slot, binding)
                    .expect("valid native signer catalog entry")
            })
            .collect::<Vec<_>>();
        bindings.sort_unstable_by_key(IrohaRuntimeProviderBindingV1::slot);
        IrohaRuntimeProviderBindingsV1 {
            chain_id: "production-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings,
        }
    }
    fn one_binding_catalog() -> IrohaRuntimeProviderBindingsV1 {
        IrohaRuntimeProviderBindingsV1 {
            chain_id: "production-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: vec![
                IrohaRuntimeProviderBindingV1::try_new(
                    IrohaRuntimeProviderSlotV1::BillingStatementSigner,
                    "kms://billing/statement-primary",
                    Some(1),
                    Some([0x51; 32]),
                )
                .expect("valid production binding"),
            ],
        }
    }
    #[test]
    fn production_handle_filter_rejects_test_markers_and_noncanonical_text() {
        for rejected in [
            "",
            "kms://cluster/test/signer",
            "mock.signer",
            "provider placeholder",
            "provider\nprimary",
            "https://operator:secret@host",
            "https://host/source?token=secret",
            "https://host/source#fragment",
            "https://host/%73ource",
        ] {
            assert!(!is_production_runtime_handle(rejected), "{rejected:?}");
        }
        assert!(is_production_runtime_handle(
            "provider://cluster-a/sorafs-primary"
        ));
    }
    #[test]
    fn binding_rejects_partial_or_zero_qualification() {
        let slot = IrohaRuntimeProviderSlotV1::BillingStatementSigner;
        for (revision, digest) in [
            (Some(0), Some([1; 32])),
            (Some(1), Some([0; 32])),
            (Some(1), None),
            (None, Some([1; 32])),
        ] {
            assert_eq!(
                IrohaRuntimeProviderBindingV1::try_new(
                    slot,
                    "kms://billing/statement-primary",
                    revision,
                    digest,
                ),
                Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))
            );
        }
    }
    #[test]
    fn registry_errors_do_not_echo_handles_or_provider_diagnostics() {
        for error in [
            IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                IrohaRuntimeProviderSlotV1::GatewayAcmeClient,
            ),
            IrohaRuntimeProviderRegistryErrorV1::MissingRegistry,
            IrohaRuntimeProviderRegistryErrorV1::Unavailable,
            IrohaRuntimeProviderRegistryErrorV1::BindingMismatch,
            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked,
            IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected,
            IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution,
            IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains("pkcs11"));
            assert!(!rendered.contains("credential"));
            assert!(!rendered.contains("private"));
        }
    }
    #[test]
    fn configured_catalog_projects_exact_genesis_derived_network_id() {
        let config = default_runtime_config();
        let expected = NetworkId::from_genesis_hash(config.genesis.expected_hash);
        let catalog = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .expect("project configured runtime-provider catalog");
        assert_eq!(catalog.network_id(), &expected);
    }
    #[test]
    fn disabled_services_need_no_registry() {
        let bindings = IrohaRuntimeProviderBindingsV1 {
            chain_id: "default-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: Vec::new(),
        };
        let dependencies =
            resolve_runtime_deps_from_bindings(&bindings, None).expect("empty default resolution");
        assert!(dependencies.is_empty());
    }
    #[test]
    fn configured_provider_binding_requires_registry() {
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&one_binding_catalog(), None),
            Err(IrohaRuntimeProviderRegistryErrorV1::MissingRegistry)
        ));
    }
    #[test]
    fn configured_provider_binding_rejects_empty_resolution() {
        let registry: Arc<dyn IrohaRuntimeProviderRegistryV1> = Arc::new(EmptyRegistry);
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&one_binding_catalog(), Some(registry.as_ref())),
            Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
        ));
    }
    #[test]
    fn evidence_viewer_catalog_rejects_noncanonical_webauthn_policy() {
        let webauthn_slot = IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn;
        for rp_id in ["Review.example", "localhost", "127.0.0.1"] {
            let mut config = default_runtime_config();
            configure_evidence_viewer(&mut config);
            config
                .torii
                .sorafs_storage
                .evidence_viewer
                .as_mut()
                .expect("evidence-viewer config")
                .webauthn_rp_id = rp_id.to_owned();
            assert_eq!(
                IrohaRuntimeProviderBindingsV1::try_from_config(&config),
                Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    webauthn_slot
                )),
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
            let mut config = default_runtime_config();
            configure_evidence_viewer(&mut config);
            config
                .torii
                .sorafs_storage
                .evidence_viewer
                .as_mut()
                .expect("evidence-viewer config")
                .webauthn_allowed_origins = vec![origin.to_owned()];
            assert_eq!(
                IrohaRuntimeProviderBindingsV1::try_from_config(&config),
                Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    webauthn_slot
                )),
                "{origin:?} must fail closed"
            );
        }
        let mut canonical = default_runtime_config();
        configure_evidence_viewer(&mut canonical);
        canonical
            .torii
            .sorafs_storage
            .evidence_viewer
            .as_mut()
            .expect("evidence-viewer config")
            .webauthn_allowed_origins = vec!["https://login.review.example:8443".to_owned()];
        IrohaRuntimeProviderBindingsV1::try_from_config(&canonical)
            .expect("canonical non-default origin port");
    }
    #[test]
    fn evidence_viewer_catalog_projects_exact_checkpoint_store_qualification() {
        let mut config = default_runtime_config();
        configure_evidence_viewer(&mut config);
        let bindings = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .expect("project evidence-viewer provider bindings");
        assert_eq!(
            bindings
                .iter()
                .filter(|binding| matches!(
                    binding.slot(),
                    IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn
                        | IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority
                        | IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner
                        | IrohaRuntimeProviderSlotV1::EvidenceViewerErasure
                        | IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore
                        | IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive
                        | IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher
                ))
                .count(),
            7
        );
        let webauthn = bindings
            .iter()
            .find(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn)
            .expect("WebAuthn binding");
        assert_eq!(
            webauthn.evidence_viewer_webauthn_binding(),
            Some(&EvidenceViewerWebAuthnBindingV1 {
                rp_id: "review.example".to_owned(),
                allowed_origins: vec!["https://review.example".to_owned()],
                challenge_ttl_ms: 60_000,
            })
        );
        let grants = bindings
            .iter()
            .find(|binding| {
                binding.slot() == IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority
            })
            .expect("grant binding");
        assert_eq!(grants.evidence_viewer_grant_ttl_ms(), Some(300_000));
        let receipt_signer = bindings
            .iter()
            .find(|binding| {
                binding.slot() == IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner
            })
            .expect("receipt-signer binding");
        assert_eq!(
            receipt_signer.evidence_viewer_receipt_signer_public_key(),
            Some(evidence_archive_public_key())
        );
        let checkpoint_store = bindings
            .iter()
            .find(|binding| {
                binding.slot() == IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore
            })
            .expect("checkpoint-store binding");
        assert_eq!(checkpoint_store.handle(), EVIDENCE_CHECKPOINT_HANDLE);
        assert_eq!(
            checkpoint_store.revision(),
            Some(EVIDENCE_CHECKPOINT_QUALIFICATION.revision())
        );
        assert_eq!(
            checkpoint_store.policy_digest(),
            Some(EVIDENCE_CHECKPOINT_QUALIFICATION.policy_digest())
        );
        assert_eq!(
            checkpoint_store.evidence_viewer_checkpoint_max_bytes(),
            Some(64 * 1024 * 1024)
        );
        let archive = bindings
            .iter()
            .find(|binding| {
                binding.slot() == IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive
            })
            .expect("compaction-archive binding");
        assert_eq!(archive.handle(), EVIDENCE_ARCHIVE_HANDLE);
        assert_eq!(
            archive.revision(),
            Some(EVIDENCE_ARCHIVE_QUALIFICATION.revision())
        );
        assert_eq!(
            archive.policy_digest(),
            Some(EVIDENCE_ARCHIVE_QUALIFICATION.policy_digest())
        );
        assert_eq!(
            archive.evidence_viewer_archive_id(),
            Some(EVIDENCE_ARCHIVE_ID)
        );
        assert_eq!(
            archive.evidence_viewer_archive_public_key(),
            Some(evidence_archive_public_key())
        );
        assert_eq!(
            archive.evidence_viewer_archive_max_bytes(),
            Some(64 * 1024 * 1024 + 16 * 1024)
        );
        let transparency_publisher = bindings
            .iter()
            .find(|binding| {
                binding.slot() == IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher
            })
            .expect("transparency-publisher binding");
        assert_eq!(
            transparency_publisher.handle(),
            EVIDENCE_TRANSPARENCY_PUBLISHER_HANDLE
        );
        assert_eq!(
            transparency_publisher.revision(),
            Some(EVIDENCE_TRANSPARENCY_PUBLISHER_QUALIFICATION.revision())
        );
        assert_eq!(
            transparency_publisher.policy_digest(),
            Some(EVIDENCE_TRANSPARENCY_PUBLISHER_QUALIFICATION.policy_digest())
        );
        assert_eq!(
            transparency_publisher.evidence_viewer_transparency_publisher_public_key(),
            Some(evidence_archive_public_key())
        );
    }
    #[test]
    fn evidence_viewer_catalog_rejects_test_marked_checkpoint_store() {
        let mut config = default_runtime_config();
        configure_evidence_viewer(&mut config);
        config
            .torii
            .sorafs_storage
            .evidence_viewer
            .as_mut()
            .expect("configured evidence viewer")
            .checkpoint_store_handle = "sealed://sorafs/evidence-viewer/test".to_owned();
        assert!(matches!(
            IrohaRuntimeProviderBindingsV1::try_from_config(&config),
            Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore
            ))
        ));
    }
    #[test]
    fn evidence_viewer_checkpoint_store_resolution_is_exactly_scoped() {
        let binding = IrohaRuntimeProviderBindingV1::try_new(
            IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore,
            EVIDENCE_CHECKPOINT_HANDLE,
            Some(EVIDENCE_CHECKPOINT_QUALIFICATION.revision()),
            Some(EVIDENCE_CHECKPOINT_QUALIFICATION.policy_digest()),
        )
        .expect("valid evidence-viewer checkpoint-store binding");
        let requested = IrohaRuntimeProviderBindingsV1 {
            chain_id: "production-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: vec![binding],
        };
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&EmptyRegistry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
        ));
        let checkpoint_store = Arc::new(EvidenceViewerCheckpointStore);
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default()
                .with_sorafs_evidence_viewer_checkpoint_store(checkpoint_store.clone()),
        );
        let resolved = resolve_runtime_deps_from_bindings(&requested, Some(&registry))
            .expect("resolve the requested checkpoint-store dependency");
        assert!(resolved.sorafs_evidence_viewer_checkpoint_store.is_some());
        let unrequested = IrohaRuntimeProviderBindingsV1 {
            chain_id: "production-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: Vec::new(),
        };
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default()
                .with_sorafs_evidence_viewer_checkpoint_store(checkpoint_store),
        );
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&unrequested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders)
        ));
    }
    #[test]
    fn evidence_viewer_archive_resolution_is_exactly_scoped_and_qualified() {
        let requested = evidence_archive_request();
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&EmptyRegistry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
        ));
        let archive = Arc::new(EvidenceViewerCompactionArchive::exact());
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default()
                .with_sorafs_evidence_viewer_compaction_archive(archive.clone()),
        );
        let resolved = resolve_runtime_deps_from_bindings(&requested, Some(&registry))
            .expect("resolve exact evidence-viewer compaction archive");
        assert!(resolved.sorafs_evidence_viewer_compaction_archive.is_some());
        let unrequested = IrohaRuntimeProviderBindingsV1 {
            chain_id: "production-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: Vec::new(),
        };
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default().with_sorafs_evidence_viewer_compaction_archive(archive),
        );
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&unrequested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders)
        ));
    }
    #[test]
    fn evidence_viewer_archive_resolution_rejects_substitution_staleness_and_drift() {
        let requested = evidence_archive_request();
        let mut substituted = EvidenceViewerCompactionArchive::exact();
        substituted.archive_id = [0xF1; 32];
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default()
                .with_sorafs_evidence_viewer_compaction_archive(Arc::new(substituted)),
        );
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
        ));
        let mut stale = EvidenceViewerCompactionArchive::exact();
        stale.qualification_error = Some(
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1::Rejected,
        );
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default()
                .with_sorafs_evidence_viewer_compaction_archive(Arc::new(stale)),
        );
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)
        ));
        let mut drifting = EvidenceViewerCompactionArchive::exact();
        drifting.later_qualification = Some(
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1::new(
                EVIDENCE_ARCHIVE_QUALIFICATION.revision() + 1,
                EVIDENCE_ARCHIVE_QUALIFICATION.policy_digest(),
            ),
        );
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default()
                .with_sorafs_evidence_viewer_compaction_archive(Arc::new(drifting)),
        );
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch
                | IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)
        ));
    }
    #[test]
    fn evidence_viewer_transparency_publisher_resolution_is_exact_and_fail_closed() {
        let requested = evidence_transparency_publisher_request();
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&EmptyRegistry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
        ));
        let publisher = Arc::new(EvidenceViewerTransparencyPublisher::exact());
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default()
                .with_sorafs_evidence_viewer_transparency_publisher(publisher.clone()),
        );
        let resolved = resolve_runtime_deps_from_bindings(&requested, Some(&registry))
            .expect("resolve exact evidence-viewer transparency publisher");
        assert!(
            resolved
                .sorafs_evidence_viewer_transparency_publisher
                .is_some()
        );
        let unrequested = IrohaRuntimeProviderBindingsV1 {
            chain_id: "production-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: Vec::new(),
        };
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default()
                .with_sorafs_evidence_viewer_transparency_publisher(publisher),
        );
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&unrequested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders)
        ));
        let mut substituted = EvidenceViewerTransparencyPublisher::exact();
        substituted.public_key = [0xF1; 32];
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default()
                .with_sorafs_evidence_viewer_transparency_publisher(Arc::new(substituted)),
        );
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
        ));
        let mut stale = EvidenceViewerTransparencyPublisher::exact();
        stale.qualification_error = Some(
            sorafs_node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1::Rejected,
        );
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default()
                .with_sorafs_evidence_viewer_transparency_publisher(Arc::new(stale)),
        );
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)
        ));
    }
    #[test]
    fn transparency_leader_lease_catalog_and_resolution_are_exactly_scoped() {
        let mut config = default_runtime_config();
        config
            .torii
            .sorafs_storage
            .privacy_aggregates
            .leader_lease_provider = Some(
            iroha_config::parameters::actual::SorafsTransparencyRuntimeProviderBinding {
                handle: TRANSPARENCY_LEADER_LEASE_HANDLE.to_owned(),
                revision: TRANSPARENCY_LEADER_LEASE_QUALIFICATION.revision(),
                policy_digest: TRANSPARENCY_LEADER_LEASE_QUALIFICATION.policy_digest(),
            },
        );
        let projected = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .expect("project transparency leader-lease binding");
        let binding = projected
            .iter()
            .find(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::TransparencyLeaderLease)
            .expect("transparency leader-lease binding");
        assert_eq!(binding.handle(), TRANSPARENCY_LEADER_LEASE_HANDLE);
        assert_eq!(
            binding.revision(),
            Some(TRANSPARENCY_LEADER_LEASE_QUALIFICATION.revision())
        );
        assert_eq!(
            binding.policy_digest(),
            Some(TRANSPARENCY_LEADER_LEASE_QUALIFICATION.policy_digest())
        );
        let requested = IrohaRuntimeProviderBindingsV1 {
            chain_id: "production-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: vec![binding.clone()],
        };
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&EmptyRegistry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
        ));
        let provider: Arc<dyn sorafs_node::ProductionTransparencyLeaderLeaseProviderV1> =
            Arc::new(TransparencyLeaderLeaseProvider);
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default()
                .with_transparency_leader_lease_provider(Arc::clone(&provider)),
        );
        let resolved = resolve_runtime_deps_from_bindings(&requested, Some(&registry))
            .expect("resolve requested transparency leader-lease dependency");
        assert!(resolved.transparency_leader_lease_provider.is_some());
        let unrequested = IrohaRuntimeProviderBindingsV1 {
            chain_id: "production-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: Vec::new(),
        };
        let registry = FixedRegistry(
            IrohaRuntimeDeps::default().with_transparency_leader_lease_provider(provider),
        );
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&unrequested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders)
        ));
    }
    #[test]
    fn fenced_privacy_catalog_projects_two_exact_roles_from_one_binding() {
        let mut config = default_runtime_config();
        configure_fenced_privacy_runtime(&mut config);
        let projected = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .expect("project fused privacy runtime bindings");
        let fenced = projected
            .iter()
            .filter(|binding| {
                matches!(
                    binding.slot(),
                    IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher
                        | IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(fenced.len(), 2);
        assert_eq!(
            fenced
                .iter()
                .map(|binding| binding.slot())
                .collect::<Vec<_>>(),
            vec![
                IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher,
                IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader,
            ]
        );
        for binding in fenced {
            assert_eq!(binding.handle(), FENCED_PRIVACY_HANDLE);
            assert_eq!(
                binding.revision(),
                Some(FENCED_PRIVACY_QUALIFICATION.revision)
            );
            assert_eq!(
                binding.policy_digest(),
                Some(FENCED_PRIVACY_QUALIFICATION.policy_digest)
            );
        }
        let mut test_marked = config;
        test_marked
            .torii
            .sorafs_storage
            .privacy_aggregates
            .fenced_privacy_publisher
            .as_mut()
            .expect("configured fused runtime")
            .handle = "governance-cas:transparency:privacy-test".to_owned();
        assert!(matches!(
            IrohaRuntimeProviderBindingsV1::try_from_config(&test_marked),
            Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher
            ))
        ));
    }
    #[test]
    fn fenced_privacy_resolution_requires_the_complete_role_pair() {
        let mut config = default_runtime_config();
        configure_fenced_privacy_runtime(&mut config);
        let mut requested = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .expect("project fused privacy runtime bindings");
        requested.bindings.retain(|binding| {
            matches!(
                binding.slot(),
                IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher
                    | IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader
            )
        });
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, None),
            Err(IrohaRuntimeProviderRegistryErrorV1::MissingRegistry)
        ));
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&EmptyRegistry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
        ));
        for (writer, reader) in [(true, false), (false, true)] {
            let runtime = Arc::new(FencedPrivacyRuntime::exact());
            let registry = FixedRegistry(fenced_privacy_dependencies(
                writer.then(|| Arc::clone(&runtime)),
                reader.then(|| Arc::clone(&runtime)),
            ));
            assert!(matches!(
                resolve_runtime_deps_from_bindings(&requested, Some(&registry)),
                Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
            ));
        }
        let runtime = Arc::new(FencedPrivacyRuntime::exact());
        let registry = FixedRegistry(fenced_privacy_dependencies(
            Some(Arc::clone(&runtime)),
            Some(runtime),
        ));
        let resolved = resolve_runtime_deps_from_bindings(&requested, Some(&registry))
            .expect("resolve both exact fused privacy roles");
        assert!(resolved.sorafs_fenced_transparency_publisher.is_some());
        assert!(resolved.sorafs_fenced_transparency_head_reader.is_some());
        assert!(!resolved.is_empty());
        let mut incomplete_catalog = requested.clone();
        incomplete_catalog
            .bindings
            .retain(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher);
        let runtime = Arc::new(FencedPrivacyRuntime::exact());
        let registry = FixedRegistry(fenced_privacy_dependencies(Some(runtime), None));
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&incomplete_catalog, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
        ));
        let mut conflicting_catalog = requested.clone();
        conflicting_catalog
            .bindings
            .iter_mut()
            .find(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader)
            .expect("authenticated head-reader binding")
            .policy_digest = Some([0x92; 32]);
        let runtime = Arc::new(FencedPrivacyRuntime::exact());
        let registry = FixedRegistry(fenced_privacy_dependencies(
            Some(Arc::clone(&runtime)),
            Some(runtime),
        ));
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&conflicting_catalog, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
        ));
        let unrequested = IrohaRuntimeProviderBindingsV1 {
            chain_id: "production-chain".to_owned(),
            network_id: test_network_id(0xA5),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings: Vec::new(),
        };
        let runtime = Arc::new(FencedPrivacyRuntime::exact());
        let registry = FixedRegistry(fenced_privacy_dependencies(
            Some(Arc::clone(&runtime)),
            Some(runtime),
        ));
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&unrequested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders)
        ));
    }
    #[test]
    fn fenced_privacy_resolution_rejects_substituted_stale_and_test_marked_roles() {
        let mut config = default_runtime_config();
        configure_fenced_privacy_runtime(&mut config);
        let mut requested = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .expect("project fused privacy runtime bindings");
        requested.bindings.retain(|binding| {
            matches!(
                binding.slot(),
                IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher
                    | IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader
            )
        });
        let exact = Arc::new(FencedPrivacyRuntime::exact());
        let substituted = Arc::new(FencedPrivacyRuntime {
            handle: "governance-cas:transparency:privacy-secondary",
            qualification: Some(FENCED_PRIVACY_QUALIFICATION),
        });
        let registry = FixedRegistry(fenced_privacy_dependencies(
            Some(substituted),
            Some(Arc::clone(&exact)),
        ));
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
        ));
        let stale = Arc::new(FencedPrivacyRuntime {
            handle: FENCED_PRIVACY_HANDLE,
            qualification: Some(
                sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                    FENCED_PRIVACY_QUALIFICATION.revision + 1,
                    FENCED_PRIVACY_QUALIFICATION.policy_digest,
                ),
            ),
        });
        let registry = FixedRegistry(fenced_privacy_dependencies(
            Some(Arc::clone(&exact)),
            Some(stale),
        ));
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)
        ));
        let test_marked = Arc::new(FencedPrivacyRuntime {
            handle: "governance-cas:transparency:privacy-test",
            qualification: Some(FENCED_PRIVACY_QUALIFICATION),
        });
        let registry = FixedRegistry(fenced_privacy_dependencies(
            Some(test_marked),
            Some(Arc::clone(&exact)),
        ));
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected)
        ));
        let unavailable = Arc::new(FencedPrivacyRuntime {
            handle: FENCED_PRIVACY_HANDLE,
            qualification: None,
        });
        let registry = FixedRegistry(fenced_privacy_dependencies(
            Some(Arc::clone(&exact)),
            Some(unavailable),
        ));
        assert!(matches!(
            resolve_runtime_deps_from_bindings(&requested, Some(&registry)),
            Err(IrohaRuntimeProviderRegistryErrorV1::Unavailable)
        ));
    }
    include!("runtime_provider_registry/provider_ingest_binding_tests.rs");
    include!("runtime_provider_registry/registry_tail_tests.rs");
}
