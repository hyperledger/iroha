use mv::storage::StorageReadOnly as _;

/// Runtime-only daemon dependencies supplied by the deployment launcher.
///
/// Implementations of the moderation wrapper, privacy-cycle PRF provider, stream-token and native
/// proof/repair/reserve/orderbook/moderation signers, moderation durable handoffs, evidence-viewer
/// checkpoint authority, appeal-finance transaction signers, role-separated `PoTR` signers,
/// exact-view billing queries, external or threshold signers, immutable publication, acknowledgement,
/// sealed witness storage, authenticated Governance DAG publication/readback/head updates, sealed
/// monotonic Governance DAG checkpoints, externally sealed reputation journal checkpoints, the
/// Soracloud mutation/provenance signer, plus the reserved Musubi provider-attestation clock,
/// approval signer, and authenticated inventory, are the reference-node boundaries for ledger
/// access and deployment-owned signing or custody services. Provider implementation details are
/// outside Iroha and are not product modes. Provider credentials, unwrapped keys, PRF shares,
/// seeds, and outputs must stay inside those implementations and must never be sourced from
/// `iroha_config`.
#[derive(Clone, Default)]
pub struct IrohaRuntimeDeps {
    /// The operator's one-shot `--sumeragi-assert-fresh-key` boot flag (§7.4): the node's
    /// consensus keys never signed for this chain. Never a configuration key.
    sumeragi_assert_fresh_key: bool,
    sumeragi_global_beacon_partial_signer:
        Option<Arc<dyn iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1>>,
    bootle_lantern_issuance_provider_registry: Option<
        Arc<
            dyn iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderRegistryV1,
        >,
    >,
    moderation_quarantine_key_wrapper: Option<Arc<dyn sorafs_node::ModerationQuarantineKeyWrapper>>,
    privacy_cycle_prf_provider:
        Option<Arc<dyn sorafs_node::ProductionPrivacyCyclePrfProviderV1>>,
    privacy_release_anchor: Option<Arc<dyn sorafs_node::ProductionPrivacyReleaseAnchorV1>>,
    transparency_leader_lease_provider:
        Option<Arc<dyn sorafs_node::ProductionTransparencyLeaderLeaseProviderV1>>,
    sorafs_fenced_transparency_publisher:
        Option<Arc<dyn sorafs_node::FencedTransparencyPublisherV1>>,
    sorafs_fenced_transparency_head_reader:
        Option<Arc<dyn sorafs_node::FencedTransparencyAuthoritativeHeadReaderV1>>,
    sorafs_governance_dag_signer: Option<Arc<dyn sorafs_node::GovernanceDagRuntimeSigner>>,
    sorafs_governance_dag_ipfs_authenticator:
        Option<Arc<dyn sorafs_node::GovernanceDagRequestAuthenticator>>,
    sorafs_governance_dag_head_authenticator:
        Option<Arc<dyn sorafs_node::GovernanceDagRequestAuthenticator>>,
    sorafs_governance_dag_checkpoint_store:
        Option<Arc<dyn sorafs_node::GovernanceDagSealedCheckpointStore>>,
    sorafs_stream_token_signer_client: Option<Arc<dyn iroha_torii::sorafs::StreamTokenSignerClientV1>>,
    sorafs_stream_token_state_observer: Option<Arc<dyn iroha_torii::sorafs::StreamTokenStateObserverClientV1>>,
    sorafs_stream_token_approved_anchor: Option<iroha_torii::sorafs::StreamTokenApprovedCustodyAnchorV1>,
    sorafs_stream_token_gateway_admission:
        Option<Arc<dyn iroha_torii::sorafs::StreamTokenGatewayAdmissionProviderV1>>,
    sorafs_appeal_finance_runtime_signers:
        Option<Arc<iroha_torii::SoraFsAppealFinanceRuntimeSignersV1>>,
    sorafs_appeal_finance_checkpoint_runtime: Option<
        Arc<dyn sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceCheckpointRuntime>,
    >,
    sorafs_proof_outcome_signer: Option<Arc<dyn iroha_torii::SoraFsProofOutcomeTransactionSigner>>,
    sorafs_repair_transaction_signer: Option<Arc<dyn iroha_torii::SoraFsRepairTransactionSigner>>,
    sorafs_reserve_transaction_signer: Option<Arc<dyn iroha_torii::SoraFsReserveTransactionSigner>>,
    sorafs_orderbook_transaction_signer:
        Option<Arc<dyn iroha_torii::SoraFsOrderbookTransactionSigner>>,
    sorafs_moderation_transaction_signer: Option<
        Arc<dyn iroha_torii::sorafs::moderation_runtime::ModerationSignedTransactionSignerV1>,
    >,
    sorafs_moderation_settlement_handoff: Option<
        Arc<dyn iroha_torii::sorafs::moderation_runtime::ModerationDurableHandoffBoundaryV1>,
    >,
    sorafs_moderation_publication_handoff: Option<
        Arc<dyn iroha_torii::sorafs::moderation_runtime::ModerationDurableHandoffBoundaryV1>,
    >,
    sorafs_moderation_panel_notification: Option<
        Arc<
            dyn iroha_torii::sorafs::moderation_runtime::ModerationDurablePanelNotificationBoundaryV1,
        >,
    >,
    sorafs_moderation_panel_notification_archive: Option<
        Arc<
            dyn sorafs_node::moderation_orchestrator::ModerationPanelNotificationArchiveV1,
        >,
    >,
    sorafs_moderation_checkpoint_store:
        Option<Arc<dyn sorafs_node::moderation_orchestrator::ModerationCheckpointStoreV1>>,
    sorafs_evidence_viewer_webauthn:
        Option<Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerWebAuthnBoundaryV1>>,
    sorafs_evidence_viewer_grants:
        Option<Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerGrantBoundaryV1>>,
    sorafs_evidence_viewer_receipt_signer:
        Option<Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerReceiptSignerV1>>,
    sorafs_evidence_viewer_erasure:
        Option<Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerErasureBoundaryV1>>,
    sorafs_evidence_viewer_checkpoint_store:
        Option<Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreV1>>,
    sorafs_evidence_viewer_compaction_archive:
        Option<Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerCompactionArchiveV1>>,
    sorafs_evidence_viewer_transparency_publisher: Option<
        Arc<
            dyn sorafs_node::evidence_viewer::transparency_producer::
                EvidenceViewerTransparencyPublisherV1,
        >,
    >,
    sorafs_pop_credential_provider_registry:
        Option<Arc<dyn iroha_torii::sorafs::pop_api::PopCredentialRuntimeProviderRegistryV1>>,
    sorafs_potr_runtime_signer_roles: Option<Arc<iroha_torii::sorafs::PotrRuntimeSignerRolesV1>>,
    sorafs_gateway_acme_client: Option<Arc<dyn iroha_torii::sorafs::gateway::AcmeClient>>,
    sorafs_gateway_compliance_feed_transport:
        Option<Arc<dyn iroha_torii::sorafs::gateway::GatewayComplianceFeedTransport>>,
    sorafs_reputation_journal_checkpoint_provider: Option<
        Arc<dyn sorafs_node::reputation::runtime::ReputationJournalCheckpointRuntimeV1>,
    >,
    sorafs_reputation_journal_transaction_submitter:
        Option<Arc<dyn sorafs_node::reputation::runtime::ReputationJournalTransactionSubmitterV1>>,
    sorafs_reputation_threshold_signer:
        Option<Arc<dyn sorafs_node::reputation::runtime::ReputationThresholdSignerClientV1>>,
    sorafs_reputation_governance_dag:
        Option<Arc<dyn sorafs_node::reputation::runtime::ReputationGovernanceDagClientV1>>,
    sorafs_reputation_retention_authority: Option<
        Arc<
            dyn iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionAuthorityV1,
        >,
    >,
    sorafs_hedging_billing_finalized_query:
        Option<Arc<dyn sorafs_node::hedging_billing_service::HedgingBillingFinalizedQuery>>,
    sorafs_hedging_billing_journal_verifier:
        Option<Arc<dyn sorafs_node::hedging_billing_service::HedgingBillingJournalVerifier>>,
    sorafs_billing_statement_signer:
        Option<Arc<dyn sorafs_node::hedging_billing_service::BillingStatementRuntimeSigner>>,
    sorafs_billing_statement_publisher:
        Option<Arc<dyn sorafs_node::hedging_billing_service::BillingStatementPublisher>>,
    sorafs_billing_acknowledgement_authority: Option<
        Arc<dyn sorafs_node::hedging_billing_service::BillingStatementAcknowledgementAuthority>,
    >,
    sorafs_hedging_billing_epoch_witness_store:
        Option<Arc<dyn sorafs_node::hedging_billing_service::HedgingBillingEpochWitnessStore>>,
    sorafs_provider_ingest_authenticated_source:
        Option<Arc<dyn sorafs_provider_ingest_runtime::ProviderIngestAuthenticatedSourceRuntimeV1>>,
    sorafs_provider_ingest_signer_resolver: Option<
        Arc<dyn sorafs_provider_ingest_runtime::ProviderIngestGovernedSignerResolverRuntimeV1>,
    >,
    sorafs_provider_ingest_checkpoint_runtime:
        Option<Arc<dyn sorafs_node::ProviderIngestCheckpointRuntimeV1>>,
    sorafs_provider_ingest_retention_authority: Option<
        Arc<
            dyn iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveRetentionAuthorityV1,
        >,
    >,
    sorafs_por_finalized_replay_archive:
        Option<Arc<dyn sorafs_node::PorFinalizedReplayArchiveV1>>,
    soracloud_runtime_mutation_signer:
        Option<Arc<dyn soracloud_runtime_signer::SoracloudRuntimeMutationSignerV1>>,
    sorafs_musubi_provider_attestation_clock_seal:
        Option<Arc<dyn sorafs_node::MusubiProviderAttestationClockSealV1>>,
    sorafs_musubi_provider_attestation_approval_signer:
        Option<Arc<dyn sorafs_node::MusubiProviderAttestationSignerV1>>,
    sorafs_musubi_provider_attestation_inventory:
        Option<Arc<dyn sorafs_node::MusubiProviderAttestationInventoryRuntimeV1>>,
}

fn require_global_beacon_signer_for_local_seat_v1(
    local_has_committee_seat: bool,
    signer_is_resolved: bool,
) -> Result<(), &'static str> {
    if local_has_committee_seat && !signer_is_resolved {
        return Err("local global-beacon committee seat has no resolved partial signer");
    }
    Ok(())
}

fn require_global_beacon_capability_for_local_seat_v1(
    local_signer_index: Option<u16>,
    signer: Option<&dyn iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1>,
    session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
) -> Result<(), &'static str> {
    require_global_beacon_signer_for_local_seat_v1(local_signer_index.is_some(), signer.is_some())?;
    let (Some(signer_index), Some(signer)) = (local_signer_index, signer) else {
        return Ok(());
    };
    let attestation = signer
        .attest_partial_signing_capability(session, signer_index)
        .map_err(
            |_| "local global-beacon committee seat has no exact runtime custody attestation",
        )?;
    if !attestation.matches(session, signer_index) {
        return Err(
            "local global-beacon committee seat returned a mismatched runtime custody attestation",
        );
    }
    Ok(())
}

/// Await the synchronous global-beacon custody inspection on a blocking worker before consensus
/// starts. The exact State and runtime provider handles stay owned until the check finishes.
///
/// Parliament state never gates startup: no Parliament state is read here.
async fn preflight_threshold_signer_startup_readiness_v1(
    state: Arc<iroha_core::state::State>,
    local_peer: PeerId,
    runtime_deps: IrohaRuntimeDeps,
) -> Result<(), &'static str> {
    tokio::task::spawn_blocking(move || {
        validate_threshold_signer_startup_readiness_v1(&state, &local_peer, &runtime_deps)
    })
    .await
    .map_err(|_| "threshold-signer startup worker failed")?
}

/// Validate runtime custody of the active global-beacon key session when the startup topology
/// seats the local peer in it.
///
/// A local seat is operational only after an exact live capability lookup in
/// the provider that owns its session and signer index. Presence of a provider
/// alone does not establish custody after committee or key rotation.
///
/// This check is consensus-native only. Parliament state never gates startup: it is
/// neither read nor queried.
fn validate_threshold_signer_startup_readiness_v1(
    state: &iroha_core::state::State,
    local_peer: &PeerId,
    runtime_deps: &IrohaRuntimeDeps,
) -> Result<(), &'static str> {
    use iroha_core::state::WorldReadOnly as _;

    let world = state.world_view();
    let topology = state.commit_topology_snapshot();
    let topology_roster_hash =
        iroha_core::beacon::global_threshold_beacon_roster_hash_v1(&topology);
    let committed_height = u64::try_from(state.committed_height()).unwrap_or(u64::MAX);
    let active_session_id =
        iroha_core::beacon::active_global_threshold_beacon_session_id_v1(&world)
            .map_err(|_| "active global-beacon key-session storage is noncanonical")?;
    if let Some(active_session_id) = active_session_id {
        let record = world
            .global_beacon_key_sessions()
            .get(&active_session_id)
            .ok_or("active global-beacon key session is absent")?;
        record
            .validate()
            .map_err(|_| "active global-beacon key session is invalid")?;
        if record.session.network_id != *state.network_id_ref()
            || record.session.roster_hash != topology_roster_hash
            || usize::from(record.session.committee_size) != topology.len()
            || !record.is_active_at(committed_height.saturating_add(1))
        {
            return Err("active global-beacon key session is not bound to the startup roster");
        }
        let session = &record.session;
        session
            .check_binding(&iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1 {
                network_id: *state.network_id_ref(),
                session_id: active_session_id,
                roster_hash: topology_roster_hash,
                transcript_hash: session.transcript_hash,
            })
            .map_err(|_| "active global-beacon key session is invalid")?;
        let local_signer_index = topology
            .iter()
            .position(|peer| peer == local_peer)
            .map(|index| {
                u16::try_from(index + 1)
                    .map_err(|_| "global-beacon key-session signer index exceeds u16")
            })
            .transpose()?;
        require_global_beacon_capability_for_local_seat_v1(
            local_signer_index,
            runtime_deps
                .sumeragi_global_beacon_partial_signer
                .as_deref(),
            session,
        )?;
    }

    Ok(())
}
macro_rules! define_runtime_dep_setters_v1 {
    (
        $(
            $(#[$attribute:meta])*
            $name:ident($argument:ident: $dependency:ty $(,)?) => $field:ident;
        )+
    ) => {
        $(
            $(#[$attribute])*
            #[must_use]
            pub fn $name(mut self, $argument: $dependency) -> Self {
                self.$field = Some($argument);
                self
            }
        )+
    };
}

impl IrohaRuntimeDeps {
    /// Return whether no deployment-owned runtime dependency is attached.
    ///
    /// The standard launcher uses this to reject a registry that returns
    /// process-local authority when configuration requested no provider.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sumeragi_global_beacon_partial_signer.is_none()
            && self.bootle_lantern_issuance_provider_registry.is_none()
            && self.moderation_quarantine_key_wrapper.is_none()
            && self.privacy_cycle_prf_provider.is_none()
            && self.privacy_release_anchor.is_none()
            && self.transparency_leader_lease_provider.is_none()
            && self.sorafs_fenced_transparency_publisher.is_none()
            && self.sorafs_fenced_transparency_head_reader.is_none()
            && self.sorafs_governance_dag_signer.is_none()
            && self.sorafs_governance_dag_ipfs_authenticator.is_none()
            && self.sorafs_governance_dag_head_authenticator.is_none()
            && self.sorafs_governance_dag_checkpoint_store.is_none()
            && self.sorafs_stream_token_signer_client.is_none()
            && self.sorafs_stream_token_state_observer.is_none()
            && self.sorafs_stream_token_approved_anchor.is_none()
            && self.sorafs_stream_token_gateway_admission.is_none()
            && self.sorafs_appeal_finance_runtime_signers.is_none()
            && self.sorafs_appeal_finance_checkpoint_runtime.is_none()
            && self.sorafs_proof_outcome_signer.is_none()
            && self.sorafs_repair_transaction_signer.is_none()
            && self.sorafs_reserve_transaction_signer.is_none()
            && self.sorafs_orderbook_transaction_signer.is_none()
            && self.sorafs_moderation_transaction_signer.is_none()
            && self.sorafs_moderation_settlement_handoff.is_none()
            && self.sorafs_moderation_publication_handoff.is_none()
            && self.sorafs_moderation_panel_notification.is_none()
            && self.sorafs_moderation_panel_notification_archive.is_none()
            && self.sorafs_moderation_checkpoint_store.is_none()
            && self.sorafs_evidence_viewer_webauthn.is_none()
            && self.sorafs_evidence_viewer_grants.is_none()
            && self.sorafs_evidence_viewer_receipt_signer.is_none()
            && self.sorafs_evidence_viewer_erasure.is_none()
            && self.sorafs_evidence_viewer_checkpoint_store.is_none()
            && self.sorafs_evidence_viewer_compaction_archive.is_none()
            && self.sorafs_evidence_viewer_transparency_publisher.is_none()
            && self.sorafs_pop_credential_provider_registry.is_none()
            && self.sorafs_potr_runtime_signer_roles.is_none()
            && self.sorafs_gateway_acme_client.is_none()
            && self.sorafs_gateway_compliance_feed_transport.is_none()
            && self.sorafs_reputation_journal_checkpoint_provider.is_none()
            && self
                .sorafs_reputation_journal_transaction_submitter
                .is_none()
            && self.sorafs_reputation_threshold_signer.is_none()
            && self.sorafs_reputation_governance_dag.is_none()
            && self.sorafs_reputation_retention_authority.is_none()
            && self.sorafs_hedging_billing_finalized_query.is_none()
            && self.sorafs_hedging_billing_journal_verifier.is_none()
            && self.sorafs_billing_statement_signer.is_none()
            && self.sorafs_billing_statement_publisher.is_none()
            && self.sorafs_billing_acknowledgement_authority.is_none()
            && self.sorafs_hedging_billing_epoch_witness_store.is_none()
            && self.sorafs_provider_ingest_authenticated_source.is_none()
            && self.sorafs_provider_ingest_signer_resolver.is_none()
            && self.sorafs_provider_ingest_checkpoint_runtime.is_none()
            && self.sorafs_provider_ingest_retention_authority.is_none()
            && self.sorafs_por_finalized_replay_archive.is_none()
            && self.soracloud_runtime_mutation_signer.is_none()
            && self.sorafs_musubi_provider_attestation_clock_seal.is_none()
            && self
                .sorafs_musubi_provider_attestation_approval_signer
                .is_none()
            && self.sorafs_musubi_provider_attestation_inventory.is_none()
    }

    define_runtime_dep_setters_v1! {
        /// Attach the runtime-only adaptive threshold-beacon signing-share owner.
        with_sumeragi_global_beacon_partial_signer(
            signer: Arc<dyn iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1>,
        ) => sumeragi_global_beacon_partial_signer;
        /// Attach the deployment-owned Bootle/Lantern issuer and authentication registry.
        with_bootle_lantern_issuance_provider_registry(
            registry: Arc<
                dyn iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderRegistryV1,
            >,
        ) => bootle_lantern_issuance_provider_registry;
        /// Attach the deployment-owned wrapper for moderation quarantine object data keys.
        with_moderation_quarantine_key_wrapper(
            key_wrapper: Arc<dyn sorafs_node::ModerationQuarantineKeyWrapper>,
        ) => moderation_quarantine_key_wrapper;
        /// Attach the production threshold-PRF provider for differential-privacy publication cycles.
        with_privacy_cycle_prf_provider(
            provider: Arc<dyn sorafs_node::ProductionPrivacyCyclePrfProviderV1>,
        ) => privacy_cycle_prf_provider;
        /// Attach the independently administered finalized privacy-release head.
        with_privacy_release_anchor(
            anchor: Arc<dyn sorafs_node::ProductionPrivacyReleaseAnchorV1>,
        ) => privacy_release_anchor;
        /// Attach the production external sealed-CAS transparency leader lease.
        with_transparency_leader_lease_provider(
            provider: Arc<dyn sorafs_node::ProductionTransparencyLeaderLeaseProviderV1>,
        ) => transparency_leader_lease_provider;
        /// Attach the deployment-owned fused privacy Governance target writer.
        ///
        /// Enabled privacy publication requires this writer and an authenticated
        /// head reader. Both roles must expose the exact configured handle,
        /// revision, and policy digest; partial or mismatched pairs fail startup.
        with_sorafs_fenced_transparency_publisher(
            publisher: Arc<dyn sorafs_node::FencedTransparencyPublisherV1>,
        ) => sorafs_fenced_transparency_publisher;
        /// Attach the authenticated authoritative-head reader paired with the
        /// fused privacy target writer.
        ///
        /// Enabled privacy publication requires both roles to expose the exact configured handle,
        /// revision, and policy digest; partial or mismatched pairs fail startup.
        with_sorafs_fenced_transparency_head_reader(
            reader: Arc<dyn sorafs_node::FencedTransparencyAuthoritativeHeadReaderV1>,
        ) => sorafs_fenced_transparency_head_reader;
        /// Attach the production external signer for the embedded `SoraFS` Governance DAG publisher.
        with_sorafs_governance_dag_signer(
            signer: Arc<dyn sorafs_node::GovernanceDagRuntimeSigner>,
        ) => sorafs_governance_dag_signer;
        /// Attach the production Kubo/IPFS/IPNS request authenticator for the
        /// supervised Governance DAG service.
        with_sorafs_governance_dag_ipfs_authenticator(
            authenticator: Arc<dyn sorafs_node::GovernanceDagRequestAuthenticator>,
        ) => sorafs_governance_dag_ipfs_authenticator;
        /// Attach the production signed-head compare-and-swap authenticator for
        /// the supervised Governance DAG service.
        with_sorafs_governance_dag_head_authenticator(
            authenticator: Arc<dyn sorafs_node::GovernanceDagRequestAuthenticator>,
        ) => sorafs_governance_dag_head_authenticator;
        /// Attach the sealed monotonic checkpoint and publish-intent store for the
        /// supervised Governance DAG service.
        with_sorafs_governance_dag_checkpoint_store(
            checkpoint_store: Arc<dyn sorafs_node::GovernanceDagSealedCheckpointStore>,
        ) => sorafs_governance_dag_checkpoint_store;
        /// Attach the opaque signer client for exact prepared stream-token operations.
        /// Raw replies require independent challenged evidence before token release.
        with_sorafs_stream_token_signer_client(
            client: Arc<dyn iroha_torii::sorafs::StreamTokenSignerClientV1>,
        ) => sorafs_stream_token_signer_client;
        /// Attach the separately routed state observer; its replies confer no authority alone.
        with_sorafs_stream_token_state_observer(
            observer: Arc<dyn iroha_torii::sorafs::StreamTokenStateObserverClientV1>,
        ) => sorafs_stream_token_state_observer;
        /// Attach an independently approved custody floor bound to the complete public pins.
        /// The deployment obtains this separately from both untrusted transport clients.
        /// Torii requires and validates it against its own finalized history at startup.
        with_sorafs_stream_token_approved_anchor(
            anchor: iroha_torii::sorafs::StreamTokenApprovedCustodyAnchorV1,
        ) => sorafs_stream_token_approved_anchor;
        /// Attach the deployment-owned atomic stream-token quota, sealed sequence,
        /// and ordered callback-outbox provider.
        with_sorafs_stream_token_gateway_admission(
            provider: Arc<dyn iroha_torii::sorafs::StreamTokenGatewayAdmissionProviderV1>,
        ) => sorafs_stream_token_gateway_admission;
        /// Attach runtime-only external signers for appeal-finance lock,
        /// disbursement, and refund transactions.
        with_sorafs_appeal_finance_runtime_signers(
            signers: Arc<iroha_torii::SoraFsAppealFinanceRuntimeSignersV1>,
        ) => sorafs_appeal_finance_runtime_signers;
        /// Attach the signer-authenticated monotonic checkpoint boundary for the
        /// appeal-finance transaction forwarder.
        with_sorafs_appeal_finance_checkpoint_runtime(
            runtime: Arc<
                dyn sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceCheckpointRuntime,
            >,
        ) => sorafs_appeal_finance_checkpoint_runtime;
        /// Attach a raw runtime-only signer for authoritative proof-outcome transactions.
        ///
        /// The deployment registry resolver replaces this provider with an immutable facade qualified
        /// against the exact configured role, authority, algorithm, key, revision, and policy digest.
        with_sorafs_proof_outcome_signer(
            signer: Arc<dyn iroha_torii::SoraFsProofOutcomeTransactionSigner>,
        ) => sorafs_proof_outcome_signer;
        /// Attach a raw runtime-only signer for native repair transactions.
        ///
        /// The deployment registry resolver replaces this provider with an immutable facade qualified
        /// against the exact configured role, authority, algorithm, key, revision, and policy digest.
        with_sorafs_repair_transaction_signer(
            signer: Arc<dyn iroha_torii::SoraFsRepairTransactionSigner>,
        ) => sorafs_repair_transaction_signer;
        /// Attach a raw runtime-only signer for native reserve/rent transactions.
        ///
        /// The deployment registry resolver replaces this provider with an immutable facade qualified
        /// against the exact configured role, authority, algorithm, key, revision, and policy digest.
        with_sorafs_reserve_transaction_signer(
            signer: Arc<dyn iroha_torii::SoraFsReserveTransactionSigner>,
        ) => sorafs_reserve_transaction_signer;
        /// Attach a raw runtime-only signer for native orderbook transactions.
        ///
        /// The deployment registry resolver replaces this provider with an immutable facade qualified
        /// against the exact configured role, authority, algorithm, key, revision, and policy digest.
        with_sorafs_orderbook_transaction_signer(
            signer: Arc<dyn iroha_torii::SoraFsOrderbookTransactionSigner>,
        ) => sorafs_orderbook_transaction_signer;
        /// Attach the raw deployment-owned Soracloud transaction and provenance signer.
        ///
        /// The runtime-provider registry replaces this provider with an immutable
        /// facade qualified against the exact configured handle, authority, key,
        /// revision, policy digest, active posture, and non-test posture.
        with_soracloud_runtime_mutation_signer(
            signer: Arc<dyn soracloud_runtime_signer::SoracloudRuntimeMutationSignerV1>,
        ) => soracloud_runtime_mutation_signer;
        /// Attach the runtime-only external signer for exact moderation native transaction envelopes.
        with_sorafs_moderation_transaction_signer(
            signer: Arc<
                dyn iroha_torii::sorafs::moderation_runtime::ModerationSignedTransactionSignerV1,
            >,
        ) => sorafs_moderation_transaction_signer;
        /// Attach the durable appeal-finance boundary for finalized moderation settlement handoffs.
        with_sorafs_moderation_settlement_handoff(
            boundary: Arc<
                dyn iroha_torii::sorafs::moderation_runtime::ModerationDurableHandoffBoundaryV1,
            >,
        ) => sorafs_moderation_settlement_handoff;
        /// Attach the durable governance/transparency boundary for finalized
        /// moderation publication handoffs.
        with_sorafs_moderation_publication_handoff(
            boundary: Arc<
                dyn iroha_torii::sorafs::moderation_runtime::ModerationDurableHandoffBoundaryV1,
            >,
        ) => sorafs_moderation_publication_handoff;
        /// Attach the durable payload-free juror-notification boundary.
        with_sorafs_moderation_panel_notification(
            boundary: Arc<
                dyn iroha_torii::sorafs::moderation_runtime::ModerationDurablePanelNotificationBoundaryV1,
            >,
        ) => sorafs_moderation_panel_notification;
        /// Attach the immutable authenticated moderation notification-receipt archive.
        with_sorafs_moderation_panel_notification_archive(
            archive: Arc<
                dyn sorafs_node::moderation_orchestrator::ModerationPanelNotificationArchiveV1,
            >,
        ) => sorafs_moderation_panel_notification_archive;
        /// Attach the deployment-owned sealed monotonic moderation checkpoint authority.
        with_sorafs_moderation_checkpoint_store(
            checkpoint_store: Arc<
                dyn sorafs_node::moderation_orchestrator::ModerationCheckpointStoreV1,
            >,
        ) => sorafs_moderation_checkpoint_store;
        /// Attach the production `WebAuthn` verifier for evidence-viewer sessions.
        with_sorafs_evidence_viewer_webauthn(
            boundary: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerWebAuthnBoundaryV1>,
        ) => sorafs_evidence_viewer_webauthn;
        /// Attach the finalized assignment/role grant authority for evidence viewing.
        with_sorafs_evidence_viewer_grants(
            boundary: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerGrantBoundaryV1>,
        ) => sorafs_evidence_viewer_grants;
        /// Attach the external signer for hash-chained evidence access receipts.
        with_sorafs_evidence_viewer_receipt_signer(
            signer: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerReceiptSignerV1>,
        ) => sorafs_evidence_viewer_receipt_signer;
        /// Attach the authenticated evidence erasure boundary. Its implementation
        /// owns provider/storage credentials and must honor stable operation IDs.
        with_sorafs_evidence_viewer_erasure(
            boundary: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerErasureBoundaryV1>,
        ) => sorafs_evidence_viewer_erasure;
        /// Attach the deployment-owned linearizable evidence-viewer checkpoint authority. Its
        /// implementation owns all CAS credentials and sealed persistence state.
        with_sorafs_evidence_viewer_checkpoint_store(
            checkpoint_store: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreV1>,
        ) => sorafs_evidence_viewer_checkpoint_store;
        /// Attach the authenticated immutable evidence-viewer compaction archive.
        ///
        /// Archive credentials and its Ed25519 private signing key remain inside
        /// the deployment-owned implementation.
        with_sorafs_evidence_viewer_compaction_archive(
            archive: Arc<dyn sorafs_node::evidence_viewer::EvidenceViewerCompactionArchiveV1>,
        ) => sorafs_evidence_viewer_compaction_archive;
        /// Attach the deployment-owned signed monotonic evidence transparency publisher.
        ///
        /// Publisher credentials and the Ed25519 private signing key remain inside
        /// the deployment-owned implementation.
        with_sorafs_evidence_viewer_transparency_publisher(
            publisher: Arc<
                dyn sorafs_node::evidence_viewer::transparency_producer::
                    EvidenceViewerTransparencyPublisherV1,
            >,
        ) => sorafs_evidence_viewer_transparency_publisher;
        /// Attach the deployment-owned registry for all runtime-only `PoP` enrollment, issuer,
        /// finalized-query, wallet, and authentication providers.
        with_sorafs_pop_credential_provider_registry(
            provider_registry: Arc<
                dyn iroha_torii::sorafs::pop_api::PopCredentialRuntimeProviderRegistryV1,
            >,
        ) => sorafs_pop_credential_provider_registry;
        /// Attach independently administered runtime signing services for the `SoraFS`
        /// `PoTR` gateway Ed25519 and provider ML-DSA-65 receipt roles.
        ///
        /// Torii binds these roles to its own authoritative finalized state after
        /// state and the council-verified admission registry are available.
        with_sorafs_potr_runtime_signer_roles(
            roles: Arc<iroha_torii::sorafs::PotrRuntimeSignerRolesV1>,
        ) => sorafs_potr_runtime_signer_roles;
        /// Attach the runtime-owned ACME client used by the `SoraFS` regional gateway.
        ///
        /// Account and DNS-provider credentials remain inside the implementation
        /// and never enter resolved configuration or Torii state.
        with_sorafs_gateway_acme_client(
            client: Arc<dyn iroha_torii::sorafs::gateway::AcmeClient>,
        ) => sorafs_gateway_acme_client;
        /// Attach the authenticated, address-pinned `SoraFS` compliance feed transport.
        ///
        /// Bearer tokens, client identities, DNS credentials, and TLS key material
        /// remain owned by the deployment adapter.
        with_sorafs_gateway_compliance_feed_transport(
            transport: Arc<dyn iroha_torii::sorafs::gateway::GatewayComplianceFeedTransport>,
        ) => sorafs_gateway_compliance_feed_transport;
        /// Attach a runtime-only identity-matching signer and normal-queue
        /// submitter for native `PoR` and stream-token reputation journal entries.
        with_sorafs_reputation_journal_transaction_submitter(
            submitter: Arc<
                dyn sorafs_node::reputation::runtime::ReputationJournalTransactionSubmitterV1,
            >,
        ) => sorafs_reputation_journal_transaction_submitter;
        /// Attach the externally sealed monotonic checkpoint provider for the
        /// native reputation journal outbox.
        with_sorafs_reputation_journal_checkpoint_provider(
            provider: Arc<dyn sorafs_node::reputation::runtime::ReputationJournalCheckpointRuntimeV1>,
        ) => sorafs_reputation_journal_checkpoint_provider;
        /// Attach the external threshold-signing service for exact committed reputation material.
        with_sorafs_reputation_threshold_signer(
            signer: Arc<dyn sorafs_node::reputation::runtime::ReputationThresholdSignerClientV1>,
        ) => sorafs_reputation_threshold_signer;
        /// Attach the authenticated Governance DAG publication/readback service for
        /// committed reputation snapshots.
        with_sorafs_reputation_governance_dag(
            governance_dag: Arc<dyn sorafs_node::reputation::runtime::ReputationGovernanceDagClientV1>,
        ) => sorafs_reputation_governance_dag;
        /// Attach the separate sealed monotonic finalized-reputation archive retention authority.
        with_sorafs_reputation_retention_authority(
            authority: Arc<
                dyn iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionAuthorityV1,
            >,
        ) => sorafs_reputation_retention_authority;
        /// Attach the identity-pinned finalized billing query, including typed
        /// consensus-authenticated period-close records.
        with_sorafs_hedging_billing_finalized_query(
            query: Arc<dyn sorafs_node::hedging_billing_service::HedgingBillingFinalizedQuery>,
        ) => sorafs_hedging_billing_finalized_query;
        /// Attach the consensus billing-journal inclusion/finality verifier.
        with_sorafs_hedging_billing_journal_verifier(
            verifier: Arc<dyn sorafs_node::hedging_billing_service::HedgingBillingJournalVerifier>,
        ) => sorafs_hedging_billing_journal_verifier;
        /// Attach the runtime-only billing statement signer.
        with_sorafs_billing_statement_signer(
            signer: Arc<dyn sorafs_node::hedging_billing_service::BillingStatementRuntimeSigner>,
        ) => sorafs_billing_statement_signer;
        /// Attach the authenticated immutable billing statement publisher.
        with_sorafs_billing_statement_publisher(
            publisher: Arc<dyn sorafs_node::hedging_billing_service::BillingStatementPublisher>,
        ) => sorafs_billing_statement_publisher;
        /// Attach the authoritative billing statement acknowledgement service.
        with_sorafs_billing_acknowledgement_authority(
            authority: Arc<
                dyn sorafs_node::hedging_billing_service::BillingStatementAcknowledgementAuthority,
            >,
        ) => sorafs_billing_acknowledgement_authority;
        /// Attach the authenticated monotonic sealed billing epoch witness store.
        with_sorafs_hedging_billing_epoch_witness_store(
            store: Arc<dyn sorafs_node::hedging_billing_service::HedgingBillingEpochWitnessStore>,
        ) => sorafs_hedging_billing_epoch_witness_store;
        /// Attach the authenticated governed source-fetch boundary used by local
        /// finalized replication ingest.
        with_sorafs_provider_ingest_authenticated_source(
            source: Arc<dyn sorafs_provider_ingest_runtime::ProviderIngestAuthenticatedSourceRuntimeV1>,
        ) => sorafs_provider_ingest_authenticated_source;
        /// Attach the governance-aware runtime completion-signer resolver.
        with_sorafs_provider_ingest_signer_resolver(
            resolver: Arc<
                dyn sorafs_provider_ingest_runtime::ProviderIngestGovernedSignerResolverRuntimeV1,
            >,
        ) => sorafs_provider_ingest_signer_resolver;
        /// Attach the sealed monotonic provider-ingest checkpoint authority.
        with_sorafs_provider_ingest_checkpoint_runtime(
            runtime: Arc<dyn sorafs_node::ProviderIngestCheckpointRuntimeV1>,
        ) => sorafs_provider_ingest_checkpoint_runtime;
        /// Attach the separate sealed monotonic finalized-archive retention authority.
        with_sorafs_provider_ingest_retention_authority(
            authority: Arc<
                dyn iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveRetentionAuthorityV1,
            >,
        ) => sorafs_provider_ingest_retention_authority;
        /// Attach the authenticated immutable finalized-PoR replay archive.
        ///
        /// Archive credentials and the Ed25519 private signing key remain inside
        /// the deployment-owned implementation.
        with_sorafs_por_finalized_replay_archive(
            archive: Arc<dyn sorafs_node::PorFinalizedReplayArchiveV1>,
        ) => sorafs_por_finalized_replay_archive;
        /// Attach the rollback-resistant monotonic clock seal reserved for the
        /// supervised Musubi provider-attestation journal.
        with_sorafs_musubi_provider_attestation_clock_seal(
            seal: Arc<dyn sorafs_node::MusubiProviderAttestationClockSealV1>,
        ) => sorafs_musubi_provider_attestation_clock_seal;
        /// Attach the approval-only external or threshold signer reserved for the
        /// supervised Musubi provider-attestation journal.
        with_sorafs_musubi_provider_attestation_approval_signer(
            signer: Arc<dyn sorafs_node::MusubiProviderAttestationSignerV1>,
        ) => sorafs_musubi_provider_attestation_approval_signer;
        /// Attach the authenticated coordinator inventory reserved for the
        /// supervised Musubi provider-attestation journal.
        with_sorafs_musubi_provider_attestation_inventory(
            inventory: Arc<dyn sorafs_node::MusubiProviderAttestationInventoryRuntimeV1>,
        ) => sorafs_musubi_provider_attestation_inventory;
    }
}

#[cfg(test)]
mod threshold_signer_startup_tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::block::BlockHeader;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone, Copy)]
    enum CapabilityMode {
        Exact,
        BlockingRuntime,
        MismatchedSeat,
        Rejected,
    }

    struct BeaconCapabilityProbeSigner {
        mode: CapabilityMode,
        attestation_calls: Mutex<Vec<([u8; 32], u16)>>,
        sign_calls: AtomicUsize,
    }

    impl BeaconCapabilityProbeSigner {
        fn new(mode: CapabilityMode) -> Self {
            Self {
                mode,
                attestation_calls: Mutex::new(Vec::new()),
                sign_calls: AtomicUsize::new(0),
            }
        }

        fn attestation_calls(&self) -> Vec<([u8; 32], u16)> {
            self.attestation_calls
                .lock()
                .expect("beacon capability call journal lock")
                .clone()
        }
    }

    impl iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1 for BeaconCapabilityProbeSigner {
        fn attest_partial_signing_capability(
            &self,
            session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
            expected_signer_index: u16,
        ) -> Result<
            iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1,
            iroha_core::beacon::GlobalThresholdBeaconCapabilityErrorV1,
        > {
            self.attestation_calls
                .lock()
                .expect("beacon capability call journal lock")
                .push((session.record().session_id, expected_signer_index));
            let signer_index = match self.mode {
                CapabilityMode::Exact => expected_signer_index,
                CapabilityMode::BlockingRuntime => {
                    // A broker reconnect owns this same synchronous runtime boundary.
                    // Running it on an async executor must reproduce Tokio's nested-runtime panic.
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("provider runtime");
                    runtime.block_on(std::future::ready(()));
                    expected_signer_index
                }
                CapabilityMode::MismatchedSeat => {
                    if expected_signer_index == 1 {
                        2
                    } else {
                        1
                    }
                }
                CapabilityMode::Rejected => {
                    return Err(
                        iroha_core::beacon::GlobalThresholdBeaconCapabilityErrorV1::NotOwned,
                    );
                }
            };
            iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1::for_validated_session(
                session,
                signer_index,
            )
        }

        fn sign_partial(
            &self,
            _session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
            _payload: &[u8],
        ) -> Result<iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1, String>
        {
            self.sign_calls.fetch_add(1, Ordering::AcqRel);
            Err("the readiness path must never invoke signing".to_owned())
        }
    }

    /// Committed startup state: an active global-beacon key session bound to the startup
    /// topology. The local peer holds a seat in it.
    struct ThresholdSignerReadinessFixture {
        state: State,
        local_peer: PeerId,
        observer_peer: PeerId,
        beacon_session_id: [u8; 32],
        beacon_signer_index: u16,
    }

    fn threshold_signer_readiness_fixture_v1(
        committed_height: u64,
    ) -> ThresholdSignerReadinessFixture {
        // The exact committee of `signed_persisted_pulse_fixture_for_world`: four BLS validators
        // from seeds 1..=4 in canonical public-key order. It is the startup topology.
        let mut validator_keys = (1_u8..=4)
            .map(|seed| {
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                    .expect("derive deterministic validator key")
            })
            .collect::<Vec<_>>();
        validator_keys.sort_by(|left, right| left.public_key().cmp(right.public_key()));
        let startup_topology = validator_keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        let local_peer = startup_topology[1].clone();
        let observer_peer = PeerId::new(
            KeyPair::try_from_seed(vec![0x51; 32], Algorithm::BlsNormal)
                .expect("derive deterministic observer key")
                .public_key()
                .clone(),
        );
        assert!(!startup_topology.contains(&observer_peer));
        let beacon_signer_index = 2;
        assert_eq!(
            startup_topology[usize::from(beacon_signer_index - 1)],
            local_peer
        );

        let network_id = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x31; Hash::LENGTH])),
        );
        let state = State::new_with_chain_and_network_id_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            "threshold-readiness-test"
                .parse()
                .expect("fixture chain id"),
            network_id,
        );
        let header = BlockHeader::new(
            NonZeroU64::new(1).expect("non-zero fixture height"),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        // A proof-valid consensus-native key session, active from its DKG finalization height.
        let (beacon_key_record, beacon_pulse) =
            iroha_core::beacon::signed_persisted_pulse_fixture_for_world(
                network_id,
                5,
                &state.ivm_execution_budget(),
            );
        let beacon_session_id = beacon_key_record.session.record().session_id;
        assert_eq!(
            beacon_key_record.session.record().roster_hash,
            iroha_core::beacon::global_threshold_beacon_roster_hash_v1(&startup_topology),
            "the beacon fixture committee is the startup topology"
        );
        block
            .world
            .install_global_beacon_fixture_for_testing(
                beacon_key_record,
                beacon_pulse,
                &iroha_core::beacon::pulse_context_fixture_v1(),
            )
            .expect("install active global-beacon key session fixture");
        block
            .commit_world_overlay_for_testing()
            .expect("commit startup-readiness fixture");

        {
            let mut topology = state.commit_topology.block();
            *topology.get_mut() = startup_topology.clone();
            topology.commit();
        }

        let mut block_hashes = state.block_hashes.block();
        while u64::try_from(block_hashes.len()).unwrap_or(u64::MAX) < committed_height {
            let marker = u8::try_from(block_hashes.len() + 1).expect("small fixture height");
            block_hashes.push_for_tests(HashOf::<BlockHeader>::from_untyped_unchecked(
                Hash::prehashed([marker; Hash::LENGTH]),
            ));
        }
        block_hashes.commit_for_tests();

        assert_eq!(
            state.commit_topology_snapshot(),
            startup_topology,
            "startup topology must be the active global-beacon committee in this fixture",
        );

        ThresholdSignerReadinessFixture {
            state,
            local_peer,
            observer_peer,
            beacon_session_id,
            beacon_signer_index,
        }
    }

    #[test]
    fn local_global_beacon_committee_seat_fails_closed_without_runtime_signer() {
        assert_eq!(
            require_global_beacon_signer_for_local_seat_v1(true, false),
            Err("local global-beacon committee seat has no resolved partial signer")
        );
        assert_eq!(
            require_global_beacon_signer_for_local_seat_v1(true, true),
            Ok(())
        );
        assert_eq!(
            require_global_beacon_signer_for_local_seat_v1(false, false),
            Ok(())
        );
    }

    #[cfg(unix)]
    #[test]
    fn global_beacon_startup_requires_exact_non_signing_custody_attestation() {
        let fixture =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let session = fixture.session;
        for (mode, expected) in [
            (CapabilityMode::Exact, Ok(())),
            (
                CapabilityMode::MismatchedSeat,
                Err(
                    "local global-beacon committee seat returned a mismatched runtime custody attestation",
                ),
            ),
            (
                CapabilityMode::Rejected,
                Err("local global-beacon committee seat has no exact runtime custody attestation"),
            ),
        ] {
            let signer = BeaconCapabilityProbeSigner::new(mode);
            assert_eq!(
                require_global_beacon_capability_for_local_seat_v1(
                    Some(3),
                    Some(&signer),
                    &session
                ),
                expected,
            );
            assert_eq!(
                *signer.attestation_calls.lock().expect("capability journal"),
                vec![(session.record().session_id, 3)],
            );
            assert_eq!(signer.sign_calls.load(Ordering::Acquire), 0);
            assert_eq!(
                require_global_beacon_capability_for_local_seat_v1(None, Some(&signer), &session),
                Ok(()),
                "observers do not query another validator's custody",
            );
            assert_eq!(
                signer
                    .attestation_calls
                    .lock()
                    .expect("capability journal")
                    .len(),
                1
            );
        }
        assert_eq!(
            require_global_beacon_capability_for_local_seat_v1(Some(1), None, &session),
            Err("local global-beacon committee seat has no resolved partial signer"),
        );
        assert_eq!(
            require_global_beacon_capability_for_local_seat_v1(None, None, &session),
            Ok(()),
        );
    }

    #[test]
    fn threshold_signer_startup_readiness_requires_global_beacon_custody_for_local_seat() {
        let fixture = threshold_signer_readiness_fixture_v1(13);

        assert_eq!(
            validate_threshold_signer_startup_readiness_v1(
                &fixture.state,
                &fixture.local_peer,
                &IrohaRuntimeDeps::default(),
            ),
            Err("local global-beacon committee seat has no resolved partial signer")
        );
        for (mode, expected) in [
            (CapabilityMode::Exact, Ok(())),
            (
                CapabilityMode::Rejected,
                Err("local global-beacon committee seat has no exact runtime custody attestation"),
            ),
            (
                CapabilityMode::MismatchedSeat,
                Err(
                    "local global-beacon committee seat returned a mismatched runtime custody attestation",
                ),
            ),
        ] {
            let signer = Arc::new(BeaconCapabilityProbeSigner::new(mode));
            let runtime_deps = IrohaRuntimeDeps::default()
                .with_sumeragi_global_beacon_partial_signer(signer.clone());
            assert_eq!(
                validate_threshold_signer_startup_readiness_v1(
                    &fixture.state,
                    &fixture.local_peer,
                    &runtime_deps,
                ),
                expected
            );
            assert_eq!(
                signer.attestation_calls(),
                vec![(fixture.beacon_session_id, fixture.beacon_signer_index)]
            );
            assert_eq!(signer.sign_calls.load(Ordering::Acquire), 0);
        }

        // An observer owns no seat: it starts without a signer and never queries one.
        assert_eq!(
            validate_threshold_signer_startup_readiness_v1(
                &fixture.state,
                &fixture.observer_peer,
                &IrohaRuntimeDeps::default(),
            ),
            Ok(())
        );
        let observer_signer = Arc::new(BeaconCapabilityProbeSigner::new(CapabilityMode::Rejected));
        assert_eq!(
            validate_threshold_signer_startup_readiness_v1(
                &fixture.state,
                &fixture.observer_peer,
                &IrohaRuntimeDeps::default()
                    .with_sumeragi_global_beacon_partial_signer(observer_signer.clone()),
            ),
            Ok(())
        );
        assert!(observer_signer.attestation_calls().is_empty());

        // The active session must be bound to the exact startup roster.
        {
            let mut topology = fixture.state.commit_topology.block();
            topology.get_mut().reverse();
            topology.commit();
        }
        let exact_signer = Arc::new(BeaconCapabilityProbeSigner::new(CapabilityMode::Exact));
        assert_eq!(
            validate_threshold_signer_startup_readiness_v1(
                &fixture.state,
                &fixture.local_peer,
                &IrohaRuntimeDeps::default()
                    .with_sumeragi_global_beacon_partial_signer(exact_signer.clone()),
            ),
            Err("active global-beacon key session is not bound to the startup roster")
        );
        assert!(exact_signer.attestation_calls().is_empty());
    }

    #[tokio::test]
    async fn threshold_signer_startup_preflight_runs_synchronous_provider_on_blocking_worker() {
        let fixture = threshold_signer_readiness_fixture_v1(13);
        let signer = Arc::new(BeaconCapabilityProbeSigner::new(
            CapabilityMode::BlockingRuntime,
        ));
        let runtime_deps =
            IrohaRuntimeDeps::default().with_sumeragi_global_beacon_partial_signer(signer.clone());
        let state = Arc::new(fixture.state);
        preflight_threshold_signer_startup_readiness_v1(
            Arc::clone(&state),
            fixture.local_peer,
            runtime_deps,
        )
        .await
        .expect("global-beacon custody completes outside the async runtime");
        assert_eq!(
            signer.attestation_calls(),
            vec![(fixture.beacon_session_id, fixture.beacon_signer_index)]
        );
        assert_eq!(signer.sign_calls.load(Ordering::Acquire), 0);
        assert_eq!(
            Arc::strong_count(&state),
            1,
            "completed worker releases the exact State owner"
        );
    }

    #[tokio::test]
    async fn threshold_signer_startup_preflight_preserves_worker_custody_refusal() {
        let fixture = threshold_signer_readiness_fixture_v1(14);
        let signer = Arc::new(BeaconCapabilityProbeSigner::new(
            CapabilityMode::MismatchedSeat,
        ));
        let runtime_deps =
            IrohaRuntimeDeps::default().with_sumeragi_global_beacon_partial_signer(signer.clone());
        assert_eq!(
            preflight_threshold_signer_startup_readiness_v1(
                Arc::new(fixture.state),
                fixture.local_peer,
                runtime_deps,
            )
            .await,
            Err(
                "local global-beacon committee seat returned a mismatched runtime custody attestation"
            )
        );
        assert_eq!(
            signer.attestation_calls(),
            vec![(fixture.beacon_session_id, fixture.beacon_signer_index)]
        );
        assert_eq!(signer.sign_calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn threshold_signer_preflight_rejects_before_consensus_startup() {
        let startup = include_str!("../main.rs")
            .split_once("let sumeragi = match prepared_sumeragi")
            .expect("consensus startup branch")
            .1
            .split_once("let tx_gossiper = if emergency_fast")
            .expect("consensus startup boundary")
            .0;
        let preflight = startup
            .find("preflight_threshold_signer_startup_readiness_v1")
            .expect("threshold-signer startup preflight");
        let consensus_start = startup.find("start_on_network").expect("Sumeragi startup");
        let guarded_preflight: String = startup[preflight..consensus_start]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        assert!(preflight < consensus_start);
        assert!(
            guarded_preflight
                .contains(".map_err(|message|Report::new(StartError::StartP2p).attach(message))?;")
        );
        // Startup custody is consensus-native: the branch names no Parliament state.
        let startup_lowercase = startup.to_lowercase();
        assert!(
            !startup_lowercase.contains("parliament"),
            "consensus startup must not mention Parliament state"
        );
    }
}

impl IrohaRuntimeDeps {
    /// Carry the operator's one-shot fresh-key assertion (`--sumeragi-assert-fresh-key`).
    #[must_use]
    pub fn with_sumeragi_fresh_key_assertion(mut self, asserted: bool) -> Self {
        self.sumeragi_assert_fresh_key = asserted;
        self
    }

    /// Whether the operator asserted fresh consensus keys at this boot.
    pub(crate) fn sumeragi_assert_fresh_key(&self) -> bool {
        self.sumeragi_assert_fresh_key
    }
}
