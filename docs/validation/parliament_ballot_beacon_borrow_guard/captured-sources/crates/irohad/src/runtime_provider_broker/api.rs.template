//! Launcher-facing lifecycle, registry, backend-injection, and server boundary.
//!
//! This module owns only public provider bindings and injected runtime adapters;
//! it never loads credentials or private keys.
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::protocol;
use crate::{
    IrohaRuntimeDeps,
    runtime_provider_registry::{
        IrohaRuntimeProviderBindingsV1, IrohaRuntimeProviderRegistryErrorV1,
        IrohaRuntimeProviderRegistryV1, IrohaRuntimeProviderSlotV1,
        resolve_runtime_deps_from_bindings,
    },
    sorafs_provider_ingest_runtime::https_source_pool::{
        ProviderIngestHttpsCompositionErrorV1, ProviderIngestHttpsSourceRegistrationV1,
        compose_provider_ingest_https_pool_v1,
    },
};
use iroha_config::parameters::actual::RuntimeProviderBrokerEndpointPath;
use std::{fmt, sync::Arc};
const BROKER_LIFECYCLE_STARTING_V1: u8 = 0;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BROKER_LIFECYCLE_READY_V1: u8 = 1;
const BROKER_LIFECYCLE_STOPPING_V1: u8 = 2;

/// Public, credential-free qualification for a consensus signing provider.
///
/// `test_marked` is carried by the live provider rather than configuration so
/// a test implementation cannot masquerade as a production backend merely by
/// copying an expected handle and revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusSignerProviderQualificationV1 {
    /// Monotonic deployment-owned provider revision.
    pub revision: u64,
    /// Public policy commitment expected by the daemon catalog.
    pub policy_digest: [u8; 32],
    /// Whether this backend is intentionally test-only.
    pub test_marked: bool,
}

impl ConsensusSignerProviderQualificationV1 {
    /// Construct one live public provider qualification.
    #[must_use]
    pub const fn new(revision: u64, policy_digest: [u8; 32], test_marked: bool) -> Self {
        Self {
            revision,
            policy_digest,
            test_marked,
        }
    }
}

/// Payload-free global-beacon broker backend failure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalBeaconPartialSignerBrokerBackendErrorV1 {
    /// The provider transport is temporarily unavailable and a non-mutating
    /// request may be retried after reconnecting.
    Unavailable,
    /// The provider deterministically refused or could not satisfy the exact
    /// authenticated request; automatic replay is forbidden.
    Rejected,
}

/// Payload-free Parliament TLE broker backend failure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParliamentTlePartialReleaseSignerBrokerBackendErrorV1 {
    /// The provider transport is temporarily unavailable and a non-mutating
    /// request may be retried after reconnecting.
    Unavailable,
    /// The provider deterministically refused or could not satisfy the exact
    /// authenticated request; automatic replay is forbidden.
    Rejected,
}

/// Authenticated broker-server backend for global beacon partial signatures.
///
/// The broker validates the complete public DKG transcript and either a canonical pulse
/// slot or the exact prepared-seat readiness challenge, then independently verifies the returned
/// proof. Provider diagnostics and private share material never cross the wire.
pub trait GlobalBeaconPartialSignerBrokerBackendV1: Send + Sync {
    /// Return the production runtime handle.
    fn handle(&self) -> &str;
    /// Return the live public qualification.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is unavailable or rejects the qualification request.
    fn qualification(
        &self,
    ) -> Result<ConsensusSignerProviderQualificationV1, GlobalBeaconPartialSignerBrokerBackendErrorV1>;
    /// Attest live custody for one exact validated public session and seat.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is unavailable or rejects the validated request.
    fn attest_partial_signing_capability(
        &self,
        session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        expected_signer_index: u16,
    ) -> Result<
        iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1,
        GlobalBeaconPartialSignerBrokerBackendErrorV1,
    >;
    /// Sign one exact broker-validated pulse or separately domain-bound readiness challenge.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is unavailable or rejects the validated request.
    fn sign_partial(
        &self,
        session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        payload: &[u8],
    ) -> Result<
        iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1,
        GlobalBeaconPartialSignerBrokerBackendErrorV1,
    >;
}

/// Authenticated broker-server backend for Parliament TLE partial releases.
///
/// The server reconstructs and validates the complete public release
/// projection before calling this trait, then independently verifies the
/// returned proof-carrying share. Provider diagnostics never cross the wire.
pub trait ParliamentTlePartialReleaseSignerBrokerBackendV1: Send + Sync {
    /// Return the production runtime handle.
    fn handle(&self) -> &str;
    /// Return the live public qualification.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is unavailable or rejects the qualification request.
    fn qualification(
        &self,
    ) -> Result<
        ConsensusSignerProviderQualificationV1,
        ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,
    >;
    /// Attest live custody for one exact validated public session and seat.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is unavailable or rejects the validated request.
    fn attest_partial_release_capability(
        &self,
        session: &iroha_core_timed_ovn::tle::ValidatedTleKeySessionV1,
        expected_participant_index: u16,
    ) -> Result<
        iroha_core::tle_release::TlePartialReleaseCapabilityAttestationV1,
        ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,
    >;
    /// Sign one exact broker-validated public release projection.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is unavailable or rejects the validated request.
    fn sign_projected_partial_release(
        &self,
        projection: &iroha_core_timed_ovn::tle::ValidatedTleReleaseProjectionV1,
    ) -> Result<
        iroha_core_timed_ovn::tle::TlePartialReleaseShareV1,
        ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,
    >;
}

/// One-shot lifecycle control shared by a broker launcher and serving thread.
///
/// Readiness publication and shutdown are linearized through a bounded
/// callback gate plus one atomic state. A shutdown request that wins while the
/// server is starting prevents the readiness callback and short-circuits
/// startup before backend qualification when it is already present at entry.
#[derive(Debug)]
pub struct RuntimeProviderBrokerLifecycleV1 {
    state: std::sync::atomic::AtomicU8,
    readiness_publication_gate: std::sync::Mutex<()>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    active_provider_calls: std::sync::atomic::AtomicUsize,
}
impl RuntimeProviderBrokerLifecycleV1 {
    /// Construct a fresh one-shot lifecycle in the starting state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: std::sync::atomic::AtomicU8::new(BROKER_LIFECYCLE_STARTING_V1),
            readiness_publication_gate: std::sync::Mutex::new(()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            active_provider_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    /// Request orderly shutdown without waiting for in-flight provider calls.
    ///
    /// The serving call closes accepted local transports and joins every session before it returns.
    /// A provider qualification already in progress or an operation already admitted when this
    /// method linearizes is allowed to finish because the synchronous V1 provider traits do not
    /// expose cancellation. Operation admission is the final atomic check immediately before
    /// dispatch; it can precede the actual trait-method call by a small in-process interval.
    ///
    /// This call waits for a readiness callback that already owns the bounded publication gate. The
    /// callback must therefore be bounded and must not call `request_shutdown` reentrantly.
    pub fn request_shutdown(&self) {
        let _publication = self
            .readiness_publication_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.state.store(
            BROKER_LIFECYCLE_STOPPING_V1,
            std::sync::atomic::Ordering::SeqCst,
        );
    }
    /// Return whether orderly shutdown has been requested or begun.
    #[must_use]
    pub fn shutdown_requested(&self) -> bool {
        self.state.load(std::sync::atomic::Ordering::SeqCst) == BROKER_LIFECYCLE_STOPPING_V1
    }
    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(super) fn publish_ready<R>(&self, on_ready: R) -> bool
    where
        R: FnOnce(),
    {
        match self.publish_ready_fallible(|| {
            on_ready();
            Ok::<(), std::convert::Infallible>(())
        }) {
            Ok(published) => published,
            Err(never) => match never {},
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn publish_ready_fallible<R, E>(&self, on_ready: R) -> Result<bool, E>
    where
        R: FnOnce() -> Result<(), E>,
    {
        let _publication = self
            .readiness_publication_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.state.load(std::sync::atomic::Ordering::SeqCst) != BROKER_LIFECYCLE_STARTING_V1 {
            return Ok(false);
        }
        if let Err(error) = on_ready() {
            self.state.store(
                BROKER_LIFECYCLE_STOPPING_V1,
                std::sync::atomic::Ordering::SeqCst,
            );
            return Err(error);
        }
        self.state.store(
            BROKER_LIFECYCLE_READY_V1,
            std::sync::atomic::Ordering::SeqCst,
        );
        Ok(true)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn try_begin_qualification(
        self: &Arc<Self>,
    ) -> Option<RuntimeProviderBrokerCallPermitV1> {
        if self.state.load(std::sync::atomic::Ordering::SeqCst) == BROKER_LIFECYCLE_STOPPING_V1 {
            return None;
        }
        self.active_provider_calls
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        if self.state.load(std::sync::atomic::Ordering::SeqCst) == BROKER_LIFECYCLE_STOPPING_V1 {
            self.active_provider_calls
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            return None;
        }
        Some(RuntimeProviderBrokerCallPermitV1 {
            lifecycle: Arc::clone(self),
        })
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn try_begin_operation(
        self: &Arc<Self>,
    ) -> Option<RuntimeProviderBrokerCallPermitV1> {
        if self.state.load(std::sync::atomic::Ordering::SeqCst) != BROKER_LIFECYCLE_READY_V1 {
            return None;
        }
        self.active_provider_calls
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        if self.state.load(std::sync::atomic::Ordering::SeqCst) != BROKER_LIFECYCLE_READY_V1 {
            self.active_provider_calls
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            return None;
        }
        Some(RuntimeProviderBrokerCallPermitV1 {
            lifecycle: Arc::clone(self),
        })
    }
    #[cfg(all(any(target_os = "linux", target_os = "macos"), test))]
    pub(super) fn active_provider_call_count(&self) -> usize {
        self.active_provider_calls
            .load(std::sync::atomic::Ordering::Acquire)
    }
}
impl Default for RuntimeProviderBrokerLifecycleV1 {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) struct RuntimeProviderBrokerCallPermitV1 {
    lifecycle: Arc<RuntimeProviderBrokerLifecycleV1>,
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for RuntimeProviderBrokerCallPermitV1 {
    fn drop(&mut self) {
        self.lifecycle
            .active_provider_calls
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}
/// Stock authenticated local runtime-provider registry used by `main_entry`.
///
/// Construction performs no I/O. The registry connects to the configured local
/// endpoint only when the validated public binding catalog is non-empty.
#[derive(Clone, Debug)]
pub struct StockRuntimeProviderBrokerRegistryV1 {
    endpoint_path: RuntimeProviderBrokerEndpointPath,
}
impl StockRuntimeProviderBrokerRegistryV1 {
    /// Construct the stock registry for one validated public endpoint.
    #[must_use]
    pub(crate) const fn new(endpoint_path: RuntimeProviderBrokerEndpointPath) -> Self {
        Self { endpoint_path }
    }
}
const fn stock_runtime_provider_slot_is_supported(slot: IrohaRuntimeProviderSlotV1) -> bool {
    let wire_id = slot.wire_id();
    (wire_id >= IrohaRuntimeProviderSlotV1::ModerationQuarantineKeyWrapper.wire_id()
        && wire_id <= IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry.wire_id())
        || matches!(
            slot,
            IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner
                | IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner
        )
}
impl IrohaRuntimeProviderRegistryV1 for StockRuntimeProviderBrokerRegistryV1 {
    fn resolve(
        &self,
        bindings: &IrohaRuntimeProviderBindingsV1,
    ) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
        if bindings.is_empty() {
            return Ok(IrohaRuntimeDeps::default());
        }
        // The frozen V1 wire ids are a contiguous, exhaustively tested
        // whitelist. A future role outside that closed interval fails until
        // this registry and its bounded protocol surface are extended.
        if bindings
            .iter()
            .any(|binding| !stock_runtime_provider_slot_is_supported(binding.slot()))
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            protocol::resolve(bindings, &self.endpoint_path)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = bindings;
            Err(IrohaRuntimeProviderRegistryErrorV1::Unavailable)
        }
    }
}
#[cfg(test)]
mod stock_registry_tests {
    use super::*;
    fn endpoint() -> RuntimeProviderBrokerEndpointPath {
        RuntimeProviderBrokerEndpointPath::try_new(
            iroha_config::parameters::defaults::runtime_provider_broker::endpoint_path(),
        )
        .expect("validated default broker endpoint")
    }
    #[test]
    fn standalone_registry_retains_exact_network_identity() {
        let chain_id = iroha_model_base::chain::ChainId::from("standalone-governance-test");
        let network_id = crate::runtime_provider_registry::runtime_provider_test_network_id();
        let registry = StockGovernanceDagServiceRuntimeProviderRegistryV1::new(
            chain_id.clone(),
            network_id,
            endpoint(),
        );
        assert_eq!(registry.chain_id, chain_id);
        assert_eq!(registry.network_id, network_id);
        assert_eq!(registry.endpoint_path, endpoint());
    }
    #[test]
    fn reserved_musubi_attestation_slots_fail_before_broker_connection() {
        let registry = StockRuntimeProviderBrokerRegistryV1::new(endpoint());
        for (slot, handle) in [
            (
                IrohaRuntimeProviderSlotV1::MusubiProviderAttestationClockSeal,
                "sealed://musubi/provider-attestation/clock",
            ),
            (
                IrohaRuntimeProviderSlotV1::MusubiProviderAttestationApprovalSigner,
                "provider://musubi/provider-attestation/approval",
            ),
            (
                IrohaRuntimeProviderSlotV1::MusubiProviderAttestationAuthenticatedInventory,
                "inventory://musubi/provider-attestation/coordinator",
            ),
        ] {
            let bindings = IrohaRuntimeProviderBindingsV1::qualified_for_test(
                "stock-broker-musubi-test-chain",
                slot,
                handle,
                1,
                [0xA5; 32],
            );
            assert!(matches!(
                registry.resolve(&bindings),
                Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
            ));
        }
    }
}
/// Stock broker-backed registry for the packaged Governance DAG service.
///
/// The display chain and exact genesis-derived network identity participate in
/// the broker handshake. Construction performs no I/O and stores no secret.
#[derive(Clone, Debug)]
pub struct StockGovernanceDagServiceRuntimeProviderRegistryV1 {
    chain_id: iroha_model_base::chain::ChainId,
    network_id: iroha_data_model::NetworkId,
    endpoint_path: RuntimeProviderBrokerEndpointPath,
}
impl StockGovernanceDagServiceRuntimeProviderRegistryV1 {
    /// Construct a standalone-service registry for one exact network.
    #[must_use]
    pub const fn new(
        chain_id: iroha_model_base::chain::ChainId,
        network_id: iroha_data_model::NetworkId,
        endpoint_path: RuntimeProviderBrokerEndpointPath,
    ) -> Self {
        Self {
            chain_id,
            network_id,
            endpoint_path,
        }
    }
}
impl sorafs_node::GovernanceDagServiceRuntimeProviderRegistryV1
    for StockGovernanceDagServiceRuntimeProviderRegistryV1
{
    fn resolve(
        &self,
        service: &sorafs_node::GovernanceDagServiceRuntimeProviderBindingsV1,
    ) -> Result<
        sorafs_node::GovernanceDagServiceRuntimeProviders,
        sorafs_node::GovernanceDagServiceRuntimeProviderRegistryErrorV1,
    > {
        let bindings = IrohaRuntimeProviderBindingsV1::try_from_governance_dag_service(
            &self.chain_id,
            self.network_id,
            service,
        )
        .map_err(map_governance_service_registry_error)?;
        let dependencies = resolve_runtime_deps_from_bindings(
            &bindings,
            Some(&StockRuntimeProviderBrokerRegistryV1::new(
                self.endpoint_path.clone(),
            )),
        )
        .map_err(map_governance_service_registry_error)?;
        let ipfs_authenticator = dependencies
            .sorafs_governance_dag_ipfs_authenticator
            .ok_or(
                sorafs_node::GovernanceDagServiceRuntimeProviderRegistryErrorV1::RejectedBindings,
            )?;
        let checkpoint_store = dependencies.sorafs_governance_dag_checkpoint_store.ok_or(
            sorafs_node::GovernanceDagServiceRuntimeProviderRegistryErrorV1::RejectedBindings,
        )?;
        let mut providers = sorafs_node::GovernanceDagServiceRuntimeProviders::default()
            .with_ipfs_authenticator(ipfs_authenticator)
            .with_checkpoint_store(checkpoint_store);
        if let Some(head_authenticator) = dependencies.sorafs_governance_dag_head_authenticator {
            providers = providers.with_head_authenticator(head_authenticator);
        }
        Ok(providers)
    }
}
fn map_governance_service_registry_error(
    error: IrohaRuntimeProviderRegistryErrorV1,
) -> sorafs_node::GovernanceDagServiceRuntimeProviderRegistryErrorV1 {
    use sorafs_node::GovernanceDagServiceRuntimeProviderRegistryErrorV1 as ServiceError;
    match error {
        IrohaRuntimeProviderRegistryErrorV1::Unavailable
        | IrohaRuntimeProviderRegistryErrorV1::MissingRegistry => ServiceError::Unavailable,
        IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked => ServiceError::StaleOrRevoked,
        IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(_)
        | IrohaRuntimeProviderRegistryErrorV1::BindingMismatch
        | IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected
        | IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution
        | IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders => {
            ServiceError::RejectedBindings
        }
    }
}
#[cfg(test)]
mod governance_service_registry_tests {
    use super::*;
    use sorafs_node::GovernanceDagServiceRuntimeProviderRegistryErrorV1 as ServiceError;
    #[test]
    fn stock_registry_whitelists_every_frozen_v1_slot() {
        use IrohaRuntimeProviderSlotV1 as Slot;
        let slots = [
            Slot::ModerationQuarantineKeyWrapper,
            Slot::PrivacyCyclePrfProvider,
            Slot::PrivacyReleaseAnchor,
            Slot::TransparencyLeaderLease,
            Slot::FencedPrivacyPublisher,
            Slot::FencedPrivacyHeadReader,
            Slot::GovernanceDagSigner,
            Slot::GovernanceDagIpfsAuthenticator,
            Slot::GovernanceDagHeadAuthenticator,
            Slot::GovernanceDagCheckpointStore,
            Slot::StreamTokenSigner,
            Slot::AppealFinanceTransactionSigner,
            Slot::AppealFinanceCheckpoint,
            Slot::ProofOutcomeTransactionSigner,
            Slot::RepairTransactionSigner,
            Slot::ReserveTransactionSigner,
            Slot::OrderbookTransactionSigner,
            Slot::ModerationTransactionSigner,
            Slot::ModerationSettlementHandoff,
            Slot::ModerationPublicationHandoff,
            Slot::ModerationPanelNotification,
            Slot::EvidenceViewerWebAuthn,
            Slot::EvidenceViewerGrantAuthority,
            Slot::EvidenceViewerReceiptSigner,
            Slot::EvidenceViewerErasure,
            Slot::EvidenceViewerCheckpointStore,
            Slot::PopCredentialProviderRegistry,
            Slot::PotrGatewaySigner,
            Slot::PotrProviderSigner,
            Slot::GatewayAcmeClient,
            Slot::GatewayComplianceFeedTransport,
            Slot::ReputationJournalTransactionSubmitter,
            Slot::ReputationThresholdSigner,
            Slot::ReputationGovernanceDag,
            Slot::BillingFinalizedQuery,
            Slot::BillingJournalVerifier,
            Slot::BillingStatementSigner,
            Slot::BillingStatementPublisher,
            Slot::BillingAcknowledgementAuthority,
            Slot::BillingEpochWitnessStore,
            Slot::ProviderIngestAuthenticatedSource,
            Slot::ProviderIngestCompletionSignerResolver,
            Slot::ProviderIngestCompletionSigner,
            Slot::ProviderIngestCheckpointStore,
            Slot::ProviderIngestRetentionAuthority,
            Slot::PorFinalizedReplayArchive,
            Slot::EvidenceViewerCompactionArchive,
            Slot::ReputationFinalizedArchiveRetentionAuthority,
            Slot::SoracloudRuntimeMutationSigner,
            Slot::ReputationJournalCheckpoint,
            Slot::ModerationCheckpointStore,
            Slot::EvidenceViewerTransparencyPublisher,
            Slot::ModerationPanelNotificationArchive,
        ];
        assert_eq!(slots.len(), 53);
        for (expected, slot) in (1_u16..=54).filter(|id| *id != 53).zip(slots) {
            assert_eq!(slot.wire_id(), expected);
            assert!(stock_runtime_provider_slot_is_supported(slot));
        }
    }
    #[test]
    fn registry_errors_map_to_payload_free_service_categories() {
        for error in [
            IrohaRuntimeProviderRegistryErrorV1::Unavailable,
            IrohaRuntimeProviderRegistryErrorV1::MissingRegistry,
        ] {
            assert_eq!(
                map_governance_service_registry_error(error),
                ServiceError::Unavailable
            );
        }
        assert_eq!(
            map_governance_service_registry_error(
                IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
            ),
            ServiceError::StaleOrRevoked
        );
        for error in [
            IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator,
            ),
            IrohaRuntimeProviderRegistryErrorV1::BindingMismatch,
            IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected,
            IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution,
            IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders,
        ] {
            assert_eq!(
                map_governance_service_registry_error(error),
                ServiceError::RejectedBindings
            );
        }
    }
}
/// Stable redacted failure from the private Bootle/Lantern issuer boundary.
///
/// The broker deliberately exposes no backend-specific diagnostics, key
/// identifiers, or randomness details to its same-UID client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootleLanternIssuanceBrokerBackendErrorV1 {
    /// The canonical request or one of its public bindings was invalid.
    InvalidRequest,
    /// The injected issuer key does not match the governed active policy.
    PolicyMismatch,
    /// The issuer key service or cryptographic randomness was unavailable.
    Unavailable,
}
/// Deployment-owned pure cryptographic boundary for brokered Bootle/Lantern issuance.
///
/// Implementations hold the issuer trapdoor (or its protected runtime boundary) and opaque
/// authenticator. They must not hold or mutate an issuance replay store. Torii remains the sole
/// authority for authorization registration, preflight, claim, completion, and terminal failure.
pub trait BootleLanternIssuanceBrokerBackendV1: Send + Sync {
    /// Exact stable production handle served by this backend.
    fn handle(&self) -> &str;
    /// Return the current independently administered public qualification.
    ///
    /// # Errors
    ///
    /// Returns a stable registry error when the backend cannot prove its current qualification.
    fn qualification(
        &self,
    ) -> Result<
        iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderQualificationV1,
        iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
    >;
    /// Return the exact current public issuer, policy, and lifetime bindings.
    ///
    /// # Errors
    ///
    /// Returns a stable registry error when the current bindings cannot be read or validated.
    fn bindings(
        &self,
    ) -> Result<
        iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderBindingsV1,
        iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
    >;
    /// Authenticate opaque bearer bytes for one exact action/body/height binding.
    ///
    /// # Errors
    ///
    /// Returns an authentication error when the credential or its request binding is invalid.
    fn authenticate(
        &self,
        opaque_credential: &[u8],
        action: iroha_torii::privacy_issuance_api::BootleLanternIssuanceActionV1,
        request_binding: [u8; 32],
        committed_height: u64,
    ) -> Result<
        iroha_torii::privacy_issuance_api::BootleLanternIssuanceAuthenticatedPrincipalV1,
        iroha_torii::privacy_issuance_api::BootleLanternIssuanceAuthenticationErrorV1,
    >;
    /// Prepare one native canonical `ILA1` candidate without replay-state mutation.
    ///
    /// # Errors
    ///
    /// Returns a redacted backend error when validation or authorization preparation fails.
    fn prepare_authorization(
        &self,
        context: &iroha_data_model::privacy::PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &iroha_data_model::privacy::BootleLanternIssuerPolicyV1,
        requester_authorization_digest: [u8; 32],
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> Result<
        iroha_core_privacy::privacy_engines::bootle_lantern::issuer::BootleLanternIssuanceAuthorizationV1,
        BootleLanternIssuanceBrokerBackendErrorV1,
    >;
    /// Verify one canonical `ILQ1` against the injected issuer key without randomness or state mutation.
    ///
    /// Native implementations use core's
    /// `issuer_validate_blind_issuance_request_for_issuer_encoded_v1`; a public-only validation is
    /// not sufficient private-key/provider-bound readiness check for this operation.
    ///
    /// # Errors
    ///
    /// Returns a redacted backend error when the request is invalid or provider validation fails.
    fn validate_request(
        &self,
        context: &iroha_data_model::privacy::PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &iroha_data_model::privacy::BootleLanternIssuerPolicyV1,
        authorization: &iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
            BootleLanternIssuanceAuthorizationV1,
        request_bytes: &[u8],
        current_height: u64,
    ) -> Result<[u8; 32], BootleLanternIssuanceBrokerBackendErrorV1>;
    /// Repeat validation and issue one canonical response after Torii's exact claim.
    ///
    /// # Errors
    ///
    /// Returns a redacted backend error when validation or issuance fails.
    fn issue_validated(
        &self,
        context: &iroha_data_model::privacy::PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &iroha_data_model::privacy::BootleLanternIssuerPolicyV1,
        authorization: &iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
            BootleLanternIssuanceAuthorizationV1,
        request_bytes: &[u8],
        current_height: u64,
    ) -> Result<
        iroha_core_privacy::privacy_engines::bootle_lantern::issuer::BootleLanternBlindIssuanceResponseV1,
        BootleLanternIssuanceBrokerBackendErrorV1,
    >;
}
// The backend set has one frozen typed inventory. Its generated container,
// redacted presence-only Debug, const-empty constructor, and documented
// injection methods cannot drift independently when a stock role is added.
macro_rules! runtime_provider_backend_collection_v1 {
    (optional, $backend:ty) => {
        Option<$backend>
    };
    (repeated, $backend:ty) => {
        Vec<$backend>
    };
}
macro_rules! runtime_provider_backend_initial_value_v1 {
    (optional) => {
        None
    };
    (repeated) => {
        Vec::new()
    };
}
macro_rules! append_runtime_provider_backend_debug_field_v1 {
    ($debug:ident, $value:ident, optional $field:ident) => {
        $debug.field(stringify!($field), &$value.$field.is_some());
    };
    ($debug:ident, $value:ident, repeated $field:ident, $label:literal) => {
        $debug.field($label, &$value.$field.len());
    };
}
macro_rules! define_runtime_provider_backend_setter_v1 {
    (
        $(#[$attribute:meta])*
        optional $field:ident: $backend:ty => pub fn $method:ident($argument:ident)
    ) => {
        $(#[$attribute])*
        #[must_use]
        pub fn $method(mut self, $argument: $backend) -> Self {
            self.$field = Some($argument);
            self
        }
    };
    (
        $(#[$attribute:meta])*
        repeated $field:ident: $backend:ty => pub fn $method:ident($argument:ident)
    ) => {
        $(#[$attribute])*
        #[must_use]
        pub fn $method(mut self, $argument: $backend) -> Self {
            self.$field.push($argument);
            self
        }
    };
}
macro_rules! define_runtime_provider_backends_v1 {
    (
        $(#[$struct_attribute:meta])*
        $visibility:vis struct $name:ident {
            $(
                $(#[$setter_attribute:meta])*
                $kind:ident $field:ident: $backend:ty
                    => pub fn $method:ident($argument:ident) $(, $debug_label:literal)?;
            )+
        }
    ) => {
        $(#[$struct_attribute])*
        $visibility struct $name {
            $(pub(super) $field: runtime_provider_backend_collection_v1!($kind, $backend),)+
        }
        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut debug = formatter.debug_struct(stringify!($name));
                $(append_runtime_provider_backend_debug_field_v1!(
                    debug, self, $kind $field $(, $debug_label)?
                );)+
                debug.finish()
            }
        }
        impl $name {
            /// Construct an empty injection set.
            ///
            /// The server accepts this only for an empty catalog. Every requested
            /// production role must be attached explicitly before serving.
            #[must_use]
            pub const fn new() -> Self {
                Self {
                    $($field: runtime_provider_backend_initial_value_v1!($kind),)+
                }
            }
            $(define_runtime_provider_backend_setter_v1! {
                $(#[$setter_attribute])*
                $kind $field: $backend => pub fn $method($argument)
            })+
        }
    };
}
define_runtime_provider_backends_v1! {
    /// Runtime-only backends injected into the stock local broker server.
    ///
    /// The value contains no credential loader, key material, endpoint discovery,
    /// or built-in implementation. A deployment-owned launcher must inject each
    /// backend requested by its public binding catalog. Startup rejects missing,
    /// extra, substituted, stale, revoked, and test-marked bindings.
    #[derive(Clone, Default)]
    pub struct RuntimeProviderBrokerBackendsV1 {
        /// Attach the deployment-owned native Bootle/Lantern issuer and authenticator.
        optional bootle_lantern_issuance: Arc<dyn BootleLanternIssuanceBrokerBackendV1> => pub fn with_bootle_lantern_issuance(backend);
        /// Attach the deployment-owned authenticated quarantine-DEK wrapper.
        optional moderation_quarantine_key_wrapper: Arc<dyn sorafs_node::ModerationQuarantineKeyWrapper> => pub fn with_moderation_quarantine_key_wrapper(key_wrapper);
        /// Attach the deployment-owned threshold-PRF provider used for privacy cycles.
        optional privacy_cycle_prf_provider: Arc<dyn sorafs_node::ProductionPrivacyCyclePrfProviderV1> => pub fn with_privacy_cycle_prf_provider(provider);
        /// Attach the independently administered finalized privacy-release anchor.
        optional privacy_release_anchor: Arc<dyn sorafs_node::ProductionPrivacyReleaseAnchorV1> => pub fn with_privacy_release_anchor(anchor);
        /// Attach the external sealed-CAS transparency leader-lease provider.
        optional transparency_leader_lease_provider: Arc<dyn sorafs_node::ProductionTransparencyLeaderLeaseProviderV1> => pub fn with_transparency_leader_lease_provider(provider);
        /// Attach the deployment-owned fused privacy Governance target writer.
        optional fenced_privacy_publisher: Arc<dyn sorafs_node::FencedTransparencyPublisherV1> => pub fn with_fenced_privacy_publisher(publisher);
        /// Attach the authenticated fused-privacy authoritative-head reader.
        optional fenced_privacy_head_reader: Arc<dyn sorafs_node::FencedTransparencyAuthoritativeHeadReaderV1> => pub fn with_fenced_privacy_head_reader(reader);
        /// Attach the deployment-owned authenticated external Governance DAG signer.
        optional governance_dag_signer: Arc<dyn sorafs_node::GovernanceDagRuntimeSigner> => pub fn with_governance_dag_signer(signer);
        /// Attach the deployment-owned Governance DAG IPFS request authenticator.
        optional governance_dag_ipfs_authenticator: Arc<dyn sorafs_node::GovernanceDagRequestAuthenticator> => pub fn with_governance_dag_ipfs_authenticator(authenticator);
        /// Attach the independently administered signed-head request authenticator.
        optional governance_dag_head_authenticator: Arc<dyn sorafs_node::GovernanceDagRequestAuthenticator> => pub fn with_governance_dag_head_authenticator(authenticator);
        /// Attach the deployment-owned Governance DAG sealed checkpoint store.
        optional governance_dag_checkpoint_store: Arc<dyn sorafs_node::GovernanceDagSealedCheckpointStore> => pub fn with_governance_dag_checkpoint_store(store);
        /// Attach the deployment-owned opaque signer operation client, never a trust anchor.
        optional stream_token_signer_client: Arc<dyn iroha_torii::sorafs::StreamTokenSignerClientV1> => pub fn with_stream_token_signer_client(client);
        /// Attach the separately routed, independently authenticated finalized-state observer.
        optional stream_token_state_observer: Arc<dyn iroha_torii::sorafs::StreamTokenStateObserverClientV1> => pub fn with_stream_token_state_observer(observer);
        /// Attach one independently administered appeal-finance transaction signer.
        ///
        /// Call this once for every configured signer handle. Server startup
        /// rejects duplicates, missing providers, and extras.
        repeated appeal_finance_transaction_signers: Arc<dyn iroha_torii::SoraFsAppealFinanceTransactionSigner> => pub fn with_appeal_finance_transaction_signer(signer), "appeal_finance_transaction_signer_count";
        /// Attach the appeal-finance external signer and sealed monotonic checkpoint store.
        optional appeal_finance_checkpoint: Arc< dyn sorafs_node::appeal_finance_transaction_forwarder:: AppealFinanceCheckpointRuntime, > => pub fn with_appeal_finance_checkpoint(checkpoint);
        /// Attach the independently administered proof-outcome transaction signer.
        optional proof_outcome_transaction_signer: Arc<dyn iroha_torii::SoraFsProofOutcomeTransactionSigner> => pub fn with_proof_outcome_transaction_signer(signer);
        /// Attach the independently administered native repair transaction signer.
        optional repair_transaction_signer: Arc<dyn iroha_torii::SoraFsRepairTransactionSigner> => pub fn with_repair_transaction_signer(signer);
        /// Attach the independently administered reserve/rent transaction signer.
        optional reserve_transaction_signer: Arc<dyn iroha_torii::SoraFsReserveTransactionSigner> => pub fn with_reserve_transaction_signer(signer);
        /// Attach the independently administered orderbook transaction signer.
        optional orderbook_transaction_signer: Arc<dyn iroha_torii::SoraFsOrderbookTransactionSigner> => pub fn with_orderbook_transaction_signer(signer);
        /// Attach the independently administered moderation transaction signer.
        optional moderation_transaction_signer: Arc< dyn iroha_torii::sorafs::moderation_runtime::ModerationSignedTransactionSignerV1, > => pub fn with_moderation_transaction_signer(signer);
        /// Attach the durable exactly-once moderation settlement boundary.
        optional moderation_settlement_handoff: Arc<dyn iroha_torii::sorafs::moderation_runtime::ModerationDurableHandoffBoundaryV1> => pub fn with_moderation_settlement_handoff(boundary);
        /// Attach the durable exactly-once moderation publication boundary.
        optional moderation_publication_handoff: Arc<dyn iroha_torii::sorafs::moderation_runtime::ModerationDurableHandoffBoundaryV1> => pub fn with_moderation_publication_handoff(boundary);
        /// Attach the durable payload-free moderation panel notification boundary.
        optional moderation_panel_notification: Arc< dyn iroha_torii::sorafs::moderation_runtime:: ModerationDurablePanelNotificationBoundaryV1, > => pub fn with_moderation_panel_notification(boundary);
        /// Attach the deployment-owned sealed monotonic moderation checkpoint store.
        optional moderation_checkpoint_store: Arc<dyn sorafs_node::moderation_orchestrator::ModerationCheckpointStoreV1> => pub fn with_moderation_checkpoint_store(store);
        /// Attach the deployment-owned immutable moderation notification archive.
        optional moderation_panel_notification_archive: Arc< dyn sorafs_node::moderation_orchestrator:: ModerationPanelNotificationArchiveV1, > => pub fn with_moderation_panel_notification_archive(archive);
        /// Attach the authenticated governed provider-ingest source pool.
        optional provider_ingest_authenticated_source: Arc< dyn crate::sorafs_provider_ingest_runtime:: ProviderIngestAuthenticatedSourceRuntimeV1, > => pub fn with_provider_ingest_authenticated_source(source);
        /// Attach the governed provider-ingest completion-signer resolver.
        optional provider_ingest_signer_resolver: Arc< dyn crate::sorafs_provider_ingest_runtime:: ProviderIngestGovernedSignerResolverRuntimeV1, > => pub fn with_provider_ingest_signer_resolver(resolver);
        /// Attach the provider-ingest sealed monotonic checkpoint store.
        optional provider_ingest_checkpoint_store: Arc<dyn sorafs_node::ProviderIngestCheckpointRuntimeV1> => pub fn with_provider_ingest_checkpoint_store(store);
        /// Attach the provider-ingest finalized-archive retention authority.
        optional provider_ingest_retention_authority: Arc< dyn iroha_core::query::provider_ingest_finalized:: ProviderIngestFinalizedArchiveRetentionAuthorityV1, > => pub fn with_provider_ingest_retention_authority(authority);
        /// Attach the reputation finalized-archive sealed retention authority.
        optional reputation_finalized_archive_retention_authority: Arc< dyn iroha_core::query::reputation_finalized:: ReputationFinalizedArchiveRetentionAuthorityV1, > => pub fn with_reputation_finalized_archive_retention_authority(authority);
        /// Attach the runtime-only native reputation-journal transaction submitter.
        optional reputation_journal_transaction_submitter: Arc<dyn sorafs_node::reputation::runtime::ReputationJournalTransactionSubmitterV1> => pub fn with_reputation_journal_transaction_submitter(submitter);
        /// Attach the externally sealed monotonic reputation-journal checkpoint provider.
        optional reputation_journal_checkpoint: Arc<dyn sorafs_node::reputation::runtime::ReputationJournalCheckpointRuntimeV1> => pub fn with_reputation_journal_checkpoint(checkpoint);
        /// Attach the independently administered reputation threshold signer.
        optional reputation_threshold_signer: Arc<dyn sorafs_node::reputation::runtime::ReputationThresholdSignerClientV1> => pub fn with_reputation_threshold_signer(signer);
        /// Attach the authenticated reputation Governance DAG publication/readback provider.
        optional reputation_governance_dag: Arc<dyn sorafs_node::reputation::runtime::ReputationGovernanceDagClientV1> => pub fn with_reputation_governance_dag(governance_dag);
        /// Attach the immutable finalized-ledger billing query.
        optional billing_finalized_query: Arc<dyn sorafs_node::hedging_billing_service::HedgingBillingFinalizedQuery> => pub fn with_billing_finalized_query(query);
        /// Attach the consensus billing-journal proof verifier.
        optional billing_journal_verifier: Arc<dyn sorafs_node::hedging_billing_service::HedgingBillingJournalVerifier> => pub fn with_billing_journal_verifier(verifier);
        /// Attach the independently administered external billing statement signer.
        optional billing_statement_signer: Arc<dyn sorafs_node::hedging_billing_service::BillingStatementRuntimeSigner> => pub fn with_billing_statement_signer(signer);
        /// Attach the immutable billing statement publication/readback provider.
        optional billing_statement_publisher: Arc<dyn sorafs_node::hedging_billing_service::BillingStatementPublisher> => pub fn with_billing_statement_publisher(publisher);
        /// Attach the authenticated acknowledgement/reconciliation authority.
        optional billing_acknowledgement_authority: Arc< dyn sorafs_node::hedging_billing_service:: BillingStatementAcknowledgementAuthority, > => pub fn with_billing_acknowledgement_authority(authority);
        /// Attach the sealed monotonic billing epoch-witness store.
        optional billing_epoch_witness_store: Arc<dyn sorafs_node::hedging_billing_service::HedgingBillingEpochWitnessStore> => pub fn with_billing_epoch_witness_store(store);
        /// Attach the deployment-owned `PoP` private-runtime provider registry.
        optional pop_credential_provider_registry: Arc< dyn iroha_torii::sorafs::pop_api::PopCredentialRuntimeProviderRegistryV1, > => pub fn with_pop_credential_provider_registry(registry);
        /// Attach the independently administered `PoTR` gateway Ed25519 signer.
        optional potr_gateway_signer: Arc<dyn iroha_torii::sorafs::PotrGatewaySignerV1> => pub fn with_potr_gateway_signer(signer);
        /// Attach the independently administered `PoTR` provider ML-DSA-65 signer.
        optional potr_provider_signer: Arc<dyn iroha_torii::sorafs::PotrProviderSignerV1> => pub fn with_potr_provider_signer(signer);
        /// Attach the deployment-owned authenticated ACME client.
        optional gateway_acme_client: Arc<dyn iroha_torii::sorafs::gateway::AcmeClient> => pub fn with_gateway_acme_client(client);
        /// Attach the deployment-owned pinned DNS/HTTPS compliance-feed transport.
        optional gateway_compliance_feed_transport: Arc< dyn iroha_torii::sorafs::gateway:: GatewayComplianceFeedTransport, > => pub fn with_gateway_compliance_feed_transport(transport);
        /// Attach the deployment-owned authenticated finalized-PoR replay archive.
        optional por_finalized_replay_archive: Arc<dyn sorafs_node::PorFinalizedReplayArchiveV1> => pub fn with_por_finalized_replay_archive(archive);
        /// Attach the deployment-owned evidence-viewer `WebAuthn` boundary.
        optional evidence_viewer_webauthn: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerWebAuthnBoundaryV1> => pub fn with_evidence_viewer_webauthn(boundary);
        /// Attach the deployment-owned evidence-viewer rotating-grant authority.
        optional evidence_viewer_grants: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerGrantBoundaryV1> => pub fn with_evidence_viewer_grants(boundary);
        /// Attach the deployment-owned evidence-viewer receipt signer.
        optional evidence_viewer_receipt_signer: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerReceiptSignerV1> => pub fn with_evidence_viewer_receipt_signer(signer);
        /// Attach the deployment-owned evidence-viewer erasure boundary.
        optional evidence_viewer_erasure: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerErasureBoundaryV1> => pub fn with_evidence_viewer_erasure(boundary);
        /// Attach the deployment-owned evidence-viewer authoritative checkpoint store.
        optional evidence_viewer_checkpoint_store: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreV1> => pub fn with_evidence_viewer_checkpoint_store(store);
        /// Attach the deployment-owned evidence-viewer immutable compaction archive.
        optional evidence_viewer_compaction_archive: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerCompactionArchiveV1> => pub fn with_evidence_viewer_compaction_archive(archive);
        /// Attach the deployment-owned signed monotonic evidence transparency publisher.
        optional evidence_viewer_transparency_publisher: Arc< dyn sorafs_node::evidence_viewer::transparency_producer:: EvidenceViewerTransparencyPublisherV1, > => pub fn with_evidence_viewer_transparency_publisher(publisher);
        /// Attach the deployment-owned Soracloud transaction and provenance signer.
        optional soracloud_runtime_mutation_signer: Arc<dyn crate::soracloud_runtime_signer::SoracloudRuntimeMutationSignerV1> => pub fn with_soracloud_runtime_mutation_signer(signer);
        /// Attach the exact-qualified global threshold-beacon partial signer.
        optional global_beacon_partial_signer: Arc<dyn GlobalBeaconPartialSignerBrokerBackendV1> => pub fn with_global_beacon_partial_signer(signer);
        /// Attach the exact-qualified Parliament TLE partial-release signer.
        optional parliament_tle_partial_release_signer: Arc<dyn ParliamentTlePartialReleaseSignerBrokerBackendV1> => pub fn with_parliament_tle_partial_release_signer(signer);
    }
}

impl RuntimeProviderBrokerBackendsV1 {
    /// Compose catalog-bound native HTTPS sources in a deployment-owned backend registry.
    ///
    /// Call this from `RuntimeProviderBrokerBackendRegistryV1::resolve` with the exact catalog
    /// passed by `RuntimeProviderBrokerDeploymentV1::try_new`. Governance/grant resolvers remain
    /// mandatory injected authorities. Successful composition does not assert readiness; the
    /// stock broker still independently qualifies the complete backend set before serving.
    ///
    /// # Errors
    ///
    /// Returns a payload-free failure for an already installed source backend or any catalog,
    /// policy, identity or live qualification mismatch. Other backend roles remain unchanged.
    pub fn with_provider_ingest_https_sources(
        self,
        catalog: &IrohaRuntimeProviderBindingsV1,
        sources: Vec<ProviderIngestHttpsSourceRegistrationV1>,
    ) -> Result<Self, ProviderIngestHttpsCompositionErrorV1> {
        if self.provider_ingest_authenticated_source.is_some() {
            return Err(ProviderIngestHttpsCompositionErrorV1::AlreadyInstalled);
        }
        let pool = compose_provider_ingest_https_pool_v1(catalog, sources)?;
        Ok(self.with_provider_ingest_authenticated_source(Arc::new(pool)))
    }

    pub(crate) fn contains_external_software_signer_v1(&self) -> bool {
        self.governance_dag_signer.is_some()
            || self.proof_outcome_transaction_signer.is_some()
            || self.repair_transaction_signer.is_some()
            || self.reserve_transaction_signer.is_some()
            || self.orderbook_transaction_signer.is_some()
            || self.billing_statement_signer.is_some()
            || self.pop_credential_provider_registry.is_some()
            || self.potr_gateway_signer.is_some()
            || self.potr_provider_signer.is_some()
            || self.evidence_viewer_receipt_signer.is_some()
    }
}
/// Payload-free stock broker-server startup or transport failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeProviderBrokerServerErrorV1 {
    /// The catalog requests a role the bounded V1 server does not implement.
    UnsupportedRole,
    /// A requested backend is absent or an unrequested backend was injected.
    BackendSetMismatch,
    /// A backend's live public identity or qualification is not exact.
    BindingMismatch,
    /// The configured service-UID-owned local endpoint could not be secured.
    EndpointUnavailable,
    /// The broker could not prove and remove its bound endpoint entry without
    /// risking a path-substitution unlink.
    EndpointCleanupFailed,
    /// A canonical protocol or authenticated peer invariant failed.
    Protocol,
    /// The supervisor readiness publication boundary rejected the transition.
    ReadinessUnavailable,
    /// This platform lacks the authenticated V1 local transport.
    UnsupportedPlatform,
}
impl fmt::Display for RuntimeProviderBrokerServerErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedRole => "runtime-provider broker role is unsupported",
            Self::BackendSetMismatch => "runtime-provider broker backend set is incomplete",
            Self::BindingMismatch => "runtime-provider broker binding is not qualified",
            Self::EndpointUnavailable => "runtime-provider broker endpoint is unavailable",
            Self::EndpointCleanupFailed => {
                "runtime-provider broker endpoint cleanup could not be completed safely"
            }
            Self::Protocol => "runtime-provider broker protocol failed",
            Self::ReadinessUnavailable => {
                "runtime-provider broker readiness publication is unavailable"
            }
            Self::UnsupportedPlatform => {
                "runtime-provider broker transport is unsupported on this platform"
            }
        })
    }
}
impl std::error::Error for RuntimeProviderBrokerServerErrorV1 {}
/// Fixed failure returned by a supervisor readiness callback.
///
/// The callback retains transport-specific diagnostics inside the deployment
/// boundary. The broker accepts only this payload-free marker and maps it to
/// [`RuntimeProviderBrokerServerErrorV1::ReadinessUnavailable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeProviderBrokerReadinessErrorV1;
impl fmt::Display for RuntimeProviderBrokerReadinessErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime-provider broker readiness publication failed")
    }
}
impl std::error::Error for RuntimeProviderBrokerReadinessErrorV1 {}
/// Serve the exact qualified catalog on a validated service-UID-owned endpoint.
///
/// This is the packaged launcher boundary for deployment-owned broker executables. It blocks in the
/// authenticated accept loop and never loads credentials, private keys, environment overrides, or
/// test backends. Each client authenticates a canonical non-empty subset of this catalog and is
/// confined to that exact subset for the lifetime of its session. This lets the stock daemon and
/// packaged standalone services share one supervised broker without weakening binding or operation
/// isolation.
///
/// The complete file-configured `policy` supplies the endpoint and the admitted
/// observer-operation allowance. That original absolute deadline begins before
/// provider dispatch and spans completed-reply encoding and publication; it never
/// renews on local continuation. A synchronous provider already running cannot
/// be cancelled, and a reply returned after expiry cannot be published.
///
/// # Errors
///
/// Fails before accepting clients if the catalog/backend set is incomplete or any live public
/// binding is missing, substituted, stale, revoked, or test-marked. It also fails when the fixed
/// endpoint cannot be created with the required ownership and mode.
pub fn serve_runtime_provider_broker_v1(
    bindings: &IrohaRuntimeProviderBindingsV1,
    policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    backends: RuntimeProviderBrokerBackendsV1,
) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        protocol::serve(bindings, policy, backends)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (bindings, policy, backends);
        Err(RuntimeProviderBrokerServerErrorV1::UnsupportedPlatform)
    }
}
/// Serve the exact catalog until the caller requests an orderly shutdown.
///
/// The caller retains a clone of `lifecycle` and requests shutdown through
/// [`RuntimeProviderBrokerLifecycleV1::request_shutdown`]. `on_ready` runs exactly once, on the
/// serving thread, after all requested backends have passed live qualification, the configured endpoint
/// has been securely bound, and the complete backend catalog has passed an immediate second
/// qualification. A bounded gate linearizes the complete callback against shutdown: a shutdown that
/// wins suppresses the callback, while a shutdown that loses waits for the callback to finish
/// before returning.
///
/// The callback must be bounded and must not call
/// [`RuntimeProviderBrokerLifecycleV1::request_shutdown`] reentrantly. The lifecycle remains in its
/// starting state while the callback runs and becomes ready only after it returns `Ok(())`. A
/// payload-free callback failure moves the lifecycle to stopping, removes the endpoint, and returns
/// before the accept loop is entered.
///
/// After shutdown, the server closes every accepted transport and joins every session before
/// returning. Synchronous deployment-owned provider methods do not expose cancellation or a uniform
/// deadline, so a qualification call already in progress or an operation already admitted can delay
/// this return; deployments must enforce their advertised bounds inside each provider adapter.
/// Admission is the final atomic check immediately before dispatch and can precede entry into the
/// trait method by a small in-process interval. No operation is admitted after the shutdown
/// transition.
///
/// Startup acquires a mode-`0600`, single-link instance file with an exclusive nonblocking lock
/// that remains held for the complete serving lifetime. A conforming active broker therefore
/// prevents a second process from touching its endpoint, while a crash releases the lock. After
/// acquiring it, startup recovers a socket only when the validated lock marker pre-dates this
/// process; a newly created marker plus an existing endpoint is rejected and the new marker is
/// removed. Recovery accepts only the exact service UID, mode, single-link count, and stable
/// device/inode identity. It then binds an unpredictable staging name in the pinned parent
/// directory and atomically promotes it to the canonical name without replacement. Stale recovery
/// and orderly cleanup atomically move the candidate to an OS-random quarantine name with no
/// replacement, verify the moved identity, and unlink only that quarantine entry. A mismatch is
/// preserved or restored and fails closed. The service-owned runtime directory must still exclude
/// untrusted same-UID pathname mutators.
///
/// # Errors
///
/// Fails before readiness if the catalog/backend set is incomplete, any live public binding is
/// missing, substituted, stale, revoked, or test-marked, the configured endpoint cannot be created with
/// the required ownership and mode, or the readiness callback returns
/// [`RuntimeProviderBrokerReadinessErrorV1`].
pub fn serve_runtime_provider_broker_with_fallible_readiness_v1<R>(
    bindings: &IrohaRuntimeProviderBindingsV1,
    policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    backends: RuntimeProviderBrokerBackendsV1,
    lifecycle: Arc<RuntimeProviderBrokerLifecycleV1>,
    on_ready: R,
) -> Result<(), RuntimeProviderBrokerServerErrorV1>
where
    R: FnOnce() -> Result<(), RuntimeProviderBrokerReadinessErrorV1>,
{
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        protocol::serve_with_fallible_readiness(bindings, policy, backends, lifecycle, on_ready)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        lifecycle.request_shutdown();
        let _ = (bindings, policy, backends, on_ready);
        Err(RuntimeProviderBrokerServerErrorV1::UnsupportedPlatform)
    }
}
/// Serve the exact catalog with an infallible caller-owned readiness callback.
///
/// This preserves the original callback contract as a wrapper around
/// [`serve_runtime_provider_broker_with_fallible_readiness_v1`]. Use the fallible variant for
/// supervisor transports such as systemd where readiness publication itself can fail.
///
/// # Errors
///
/// Preserves every fail-closed server error from the fallible variant.
pub fn serve_runtime_provider_broker_with_lifecycle_v1<R>(
    bindings: &IrohaRuntimeProviderBindingsV1,
    policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    backends: RuntimeProviderBrokerBackendsV1,
    lifecycle: Arc<RuntimeProviderBrokerLifecycleV1>,
    on_ready: R,
) -> Result<(), RuntimeProviderBrokerServerErrorV1>
where
    R: FnOnce(),
{
    serve_runtime_provider_broker_with_fallible_readiness_v1(
        bindings,
        policy,
        backends,
        lifecycle,
        || {
            on_ready();
            Ok(())
        },
    )
}
