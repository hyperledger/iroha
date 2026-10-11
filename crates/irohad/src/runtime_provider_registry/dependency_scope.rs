//! Exact scope checks for deployment-resolved runtime dependencies.
//!
//! The registry accepts only the dependency roles requested by the sanitized binding catalog.
//! Shared provider objects remain valid only when every role in their fixed V1 pair was requested.
use super::*;
/// Return whether the resolved dependency catalog contains the requested role.
pub(super) fn dependency_is_present(
    dependencies: &IrohaRuntimeDeps,
    slot: IrohaRuntimeProviderSlotV1,
) -> bool {
    use IrohaRuntimeProviderSlotV1 as Slot;
    let deps = dependencies;
    match slot {
        Slot::GlobalBeaconPartialSigner => deps.sumeragi_global_beacon_partial_signer.is_some(),
        Slot::ParliamentTlePartialReleaseSigner => {
            deps.parliament_tle_partial_release_signer.is_some()
        }
        Slot::BootleLanternIssuanceProviderRegistry => {
            deps.bootle_lantern_issuance_provider_registry.is_some()
        }
        Slot::ModerationQuarantineKeyWrapper => deps.moderation_quarantine_key_wrapper.is_some(),
        Slot::PrivacyCyclePrfProvider => deps.privacy_cycle_prf_provider.is_some(),
        Slot::PrivacyReleaseAnchor => deps.privacy_release_anchor.is_some(),
        Slot::TransparencyLeaderLease => deps.transparency_leader_lease_provider.is_some(),
        Slot::FencedPrivacyPublisher => deps.sorafs_fenced_transparency_publisher.is_some(),
        Slot::FencedPrivacyHeadReader => deps.sorafs_fenced_transparency_head_reader.is_some(),
        Slot::GovernanceDagSigner => deps.sorafs_governance_dag_signer.is_some(),
        Slot::GovernanceDagIpfsAuthenticator => {
            deps.sorafs_governance_dag_ipfs_authenticator.is_some()
        }
        Slot::GovernanceDagHeadAuthenticator => {
            deps.sorafs_governance_dag_head_authenticator.is_some()
        }
        Slot::GovernanceDagCheckpointStore => deps.sorafs_governance_dag_checkpoint_store.is_some(),
        // The independent approved anchor is checked by Torii after local history exists.
        Slot::StreamTokenSigner => {
            deps.sorafs_stream_token_signer_client.is_some()
                && deps.sorafs_stream_token_state_observer.is_some()
        }
        Slot::AppealFinanceTransactionSigner => {
            deps.sorafs_appeal_finance_runtime_signers.is_some()
        }
        Slot::AppealFinanceCheckpoint => deps.sorafs_appeal_finance_checkpoint_runtime.is_some(),
        Slot::ProofOutcomeTransactionSigner => deps.sorafs_proof_outcome_signer.is_some(),
        Slot::RepairTransactionSigner => deps.sorafs_repair_transaction_signer.is_some(),
        Slot::ReserveTransactionSigner => deps.sorafs_reserve_transaction_signer.is_some(),
        Slot::OrderbookTransactionSigner => deps.sorafs_orderbook_transaction_signer.is_some(),
        Slot::ModerationTransactionSigner => deps.sorafs_moderation_transaction_signer.is_some(),
        Slot::ModerationSettlementHandoff => deps.sorafs_moderation_settlement_handoff.is_some(),
        Slot::ModerationPublicationHandoff => deps.sorafs_moderation_publication_handoff.is_some(),
        Slot::ModerationPanelNotification => deps.sorafs_moderation_panel_notification.is_some(),
        Slot::ModerationPanelNotificationArchive => {
            deps.sorafs_moderation_panel_notification_archive.is_some()
        }
        Slot::ModerationCheckpointStore => deps.sorafs_moderation_checkpoint_store.is_some(),
        Slot::EvidenceViewerWebAuthn => deps.sorafs_evidence_viewer_webauthn.is_some(),
        Slot::EvidenceViewerGrantAuthority => deps.sorafs_evidence_viewer_grants.is_some(),
        Slot::EvidenceViewerReceiptSigner => deps.sorafs_evidence_viewer_receipt_signer.is_some(),
        Slot::EvidenceViewerErasure => deps.sorafs_evidence_viewer_erasure.is_some(),
        Slot::EvidenceViewerCheckpointStore => {
            deps.sorafs_evidence_viewer_checkpoint_store.is_some()
        }
        Slot::PopCredentialProviderRegistry => {
            deps.sorafs_pop_credential_provider_registry.is_some()
        }
        Slot::PotrGatewaySigner | Slot::PotrProviderSigner => {
            deps.sorafs_potr_runtime_signer_roles.is_some()
        }
        Slot::GatewayAcmeClient => deps.sorafs_gateway_acme_client.is_some(),
        Slot::GatewayComplianceFeedTransport => {
            deps.sorafs_gateway_compliance_feed_transport.is_some()
        }
        Slot::ReputationJournalTransactionSubmitter => deps
            .sorafs_reputation_journal_transaction_submitter
            .is_some(),
        Slot::ReputationJournalCheckpoint => {
            deps.sorafs_reputation_journal_checkpoint_provider.is_some()
        }
        Slot::ReputationThresholdSigner => deps.sorafs_reputation_threshold_signer.is_some(),
        Slot::ReputationGovernanceDag => deps.sorafs_reputation_governance_dag.is_some(),
        Slot::ReputationFinalizedArchiveRetentionAuthority => {
            deps.sorafs_reputation_retention_authority.is_some()
        }
        Slot::BillingFinalizedQuery => deps.sorafs_hedging_billing_finalized_query.is_some(),
        Slot::BillingJournalVerifier => deps.sorafs_hedging_billing_journal_verifier.is_some(),
        Slot::BillingStatementSigner => deps.sorafs_billing_statement_signer.is_some(),
        Slot::BillingStatementPublisher => deps.sorafs_billing_statement_publisher.is_some(),
        Slot::BillingAcknowledgementAuthority => {
            deps.sorafs_billing_acknowledgement_authority.is_some()
        }
        Slot::BillingEpochWitnessStore => deps.sorafs_hedging_billing_epoch_witness_store.is_some(),
        Slot::ProviderIngestAuthenticatedSource => {
            deps.sorafs_provider_ingest_authenticated_source.is_some()
        }
        Slot::ProviderIngestCompletionSignerResolver | Slot::ProviderIngestCompletionSigner => {
            deps.sorafs_provider_ingest_signer_resolver.is_some()
        }
        Slot::ProviderIngestCheckpointStore => {
            deps.sorafs_provider_ingest_checkpoint_runtime.is_some()
        }
        Slot::ProviderIngestRetentionAuthority => {
            deps.sorafs_provider_ingest_retention_authority.is_some()
        }
        Slot::PorFinalizedReplayArchive => deps.sorafs_por_finalized_replay_archive.is_some(),
        Slot::EvidenceViewerCompactionArchive => {
            deps.sorafs_evidence_viewer_compaction_archive.is_some()
        }
        Slot::EvidenceViewerTransparencyPublisher => {
            deps.sorafs_evidence_viewer_transparency_publisher.is_some()
        }
        Slot::SoracloudRuntimeMutationSigner => deps.soracloud_runtime_mutation_signer.is_some(),
        Slot::MusubiProviderAttestationClockSeal => {
            deps.sorafs_musubi_provider_attestation_clock_seal.is_some()
        }
        Slot::MusubiProviderAttestationApprovalSigner => deps
            .sorafs_musubi_provider_attestation_approval_signer
            .is_some(),
        Slot::MusubiProviderAttestationAuthenticatedInventory => {
            deps.sorafs_musubi_provider_attestation_inventory.is_some()
        }
    }
}
/// Reject any resolved dependency that was not requested by exact binding.
pub(super) fn has_unrequested_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> bool {
    // Gateway admission authority is constructed from local Core; no broker catalog
    // binding may install an externally asserted admission provider.
    dependencies.sorafs_stream_token_gateway_admission.is_some()
        || dependency_is_unrequested(
            bindings,
            IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
            dependencies.sumeragi_global_beacon_partial_signer.is_some(),
        )
        || dependency_is_unrequested(
            bindings,
            IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner,
            dependencies.parliament_tle_partial_release_signer.is_some(),
        )
        || dependency_is_unrequested(
            bindings,
            IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry,
            dependencies
                .bootle_lantern_issuance_provider_registry
                .is_some(),
        )
        || has_unrequested_storage_security_dependency(bindings, dependencies)
        || has_unrequested_finance_native_dependency(bindings, dependencies)
        || has_unrequested_moderation_viewer_dependency(bindings, dependencies)
        || has_unrequested_pop_potr_gateway_dependency(bindings, dependencies)
        || has_unrequested_reputation_billing_dependency(bindings, dependencies)
        || has_unrequested_provider_ingest_dependency(bindings, dependencies)
        || dependency_is_unrequested(
            bindings,
            IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner,
            dependencies.soracloud_runtime_mutation_signer.is_some(),
        )
        || has_unrequested_musubi_provider_attestation_dependency(bindings, dependencies)
}
fn dependency_is_unrequested(
    bindings: &IrohaRuntimeProviderBindingsV1,
    slot: IrohaRuntimeProviderSlotV1,
    is_present: bool,
) -> bool {
    is_present && !bindings.iter().any(|binding| binding.slot() == slot)
}
fn paired_dependency_is_unrequested(
    bindings: &IrohaRuntimeProviderBindingsV1,
    first_slot: IrohaRuntimeProviderSlotV1,
    second_slot: IrohaRuntimeProviderSlotV1,
    is_present: bool,
) -> bool {
    is_present
        && ![first_slot, second_slot]
            .into_iter()
            .all(|slot| bindings.iter().any(|binding| binding.slot() == slot))
}
fn has_unrequested_storage_security_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> bool {
    use IrohaRuntimeProviderSlotV1 as Slot;
    dependency_is_unrequested(
        bindings,
        Slot::ModerationQuarantineKeyWrapper,
        dependencies.moderation_quarantine_key_wrapper.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::PrivacyCyclePrfProvider,
        dependencies.privacy_cycle_prf_provider.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::PrivacyReleaseAnchor,
        dependencies.privacy_release_anchor.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::TransparencyLeaderLease,
        dependencies.transparency_leader_lease_provider.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::FencedPrivacyPublisher,
        dependencies.sorafs_fenced_transparency_publisher.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::FencedPrivacyHeadReader,
        dependencies
            .sorafs_fenced_transparency_head_reader
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::GovernanceDagSigner,
        dependencies.sorafs_governance_dag_signer.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::GovernanceDagIpfsAuthenticator,
        dependencies
            .sorafs_governance_dag_ipfs_authenticator
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::GovernanceDagHeadAuthenticator,
        dependencies
            .sorafs_governance_dag_head_authenticator
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::GovernanceDagCheckpointStore,
        dependencies
            .sorafs_governance_dag_checkpoint_store
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::StreamTokenSigner,
        dependencies.sorafs_stream_token_signer_client.is_some()
            || dependencies.sorafs_stream_token_state_observer.is_some()
            || dependencies.sorafs_stream_token_approved_anchor.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::PorFinalizedReplayArchive,
        dependencies.sorafs_por_finalized_replay_archive.is_some(),
    )
}
fn has_unrequested_finance_native_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> bool {
    use IrohaRuntimeProviderSlotV1 as Slot;
    dependency_is_unrequested(
        bindings,
        Slot::AppealFinanceTransactionSigner,
        dependencies.sorafs_appeal_finance_runtime_signers.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::AppealFinanceCheckpoint,
        dependencies
            .sorafs_appeal_finance_checkpoint_runtime
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ProofOutcomeTransactionSigner,
        dependencies.sorafs_proof_outcome_signer.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::RepairTransactionSigner,
        dependencies.sorafs_repair_transaction_signer.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ReserveTransactionSigner,
        dependencies.sorafs_reserve_transaction_signer.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::OrderbookTransactionSigner,
        dependencies.sorafs_orderbook_transaction_signer.is_some(),
    )
}
fn has_unrequested_moderation_viewer_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> bool {
    use IrohaRuntimeProviderSlotV1 as Slot;
    dependency_is_unrequested(
        bindings,
        Slot::ModerationTransactionSigner,
        dependencies.sorafs_moderation_transaction_signer.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ModerationSettlementHandoff,
        dependencies.sorafs_moderation_settlement_handoff.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ModerationPublicationHandoff,
        dependencies.sorafs_moderation_publication_handoff.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ModerationPanelNotification,
        dependencies.sorafs_moderation_panel_notification.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ModerationPanelNotificationArchive,
        dependencies
            .sorafs_moderation_panel_notification_archive
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ModerationCheckpointStore,
        dependencies.sorafs_moderation_checkpoint_store.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::EvidenceViewerWebAuthn,
        dependencies.sorafs_evidence_viewer_webauthn.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::EvidenceViewerGrantAuthority,
        dependencies.sorafs_evidence_viewer_grants.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::EvidenceViewerReceiptSigner,
        dependencies.sorafs_evidence_viewer_receipt_signer.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::EvidenceViewerErasure,
        dependencies.sorafs_evidence_viewer_erasure.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::EvidenceViewerCheckpointStore,
        dependencies
            .sorafs_evidence_viewer_checkpoint_store
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::EvidenceViewerCompactionArchive,
        dependencies
            .sorafs_evidence_viewer_compaction_archive
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::EvidenceViewerTransparencyPublisher,
        dependencies
            .sorafs_evidence_viewer_transparency_publisher
            .is_some(),
    )
}
fn has_unrequested_pop_potr_gateway_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> bool {
    use IrohaRuntimeProviderSlotV1 as Slot;
    dependency_is_unrequested(
        bindings,
        Slot::PopCredentialProviderRegistry,
        dependencies
            .sorafs_pop_credential_provider_registry
            .is_some(),
    ) || paired_dependency_is_unrequested(
        bindings,
        Slot::PotrGatewaySigner,
        Slot::PotrProviderSigner,
        dependencies.sorafs_potr_runtime_signer_roles.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::GatewayAcmeClient,
        dependencies.sorafs_gateway_acme_client.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::GatewayComplianceFeedTransport,
        dependencies
            .sorafs_gateway_compliance_feed_transport
            .is_some(),
    )
}
fn has_unrequested_reputation_billing_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> bool {
    use IrohaRuntimeProviderSlotV1 as Slot;
    dependency_is_unrequested(
        bindings,
        Slot::ReputationJournalCheckpoint,
        dependencies
            .sorafs_reputation_journal_checkpoint_provider
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ReputationJournalTransactionSubmitter,
        dependencies
            .sorafs_reputation_journal_transaction_submitter
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ReputationThresholdSigner,
        dependencies.sorafs_reputation_threshold_signer.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ReputationGovernanceDag,
        dependencies.sorafs_reputation_governance_dag.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ReputationFinalizedArchiveRetentionAuthority,
        dependencies.sorafs_reputation_retention_authority.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::BillingFinalizedQuery,
        dependencies
            .sorafs_hedging_billing_finalized_query
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::BillingJournalVerifier,
        dependencies
            .sorafs_hedging_billing_journal_verifier
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::BillingStatementSigner,
        dependencies.sorafs_billing_statement_signer.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::BillingStatementPublisher,
        dependencies.sorafs_billing_statement_publisher.is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::BillingAcknowledgementAuthority,
        dependencies
            .sorafs_billing_acknowledgement_authority
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::BillingEpochWitnessStore,
        dependencies
            .sorafs_hedging_billing_epoch_witness_store
            .is_some(),
    )
}
fn has_unrequested_provider_ingest_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> bool {
    use IrohaRuntimeProviderSlotV1 as Slot;
    dependency_is_unrequested(
        bindings,
        Slot::ProviderIngestAuthenticatedSource,
        dependencies
            .sorafs_provider_ingest_authenticated_source
            .is_some(),
    ) || paired_dependency_is_unrequested(
        bindings,
        Slot::ProviderIngestCompletionSignerResolver,
        Slot::ProviderIngestCompletionSigner,
        dependencies
            .sorafs_provider_ingest_signer_resolver
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ProviderIngestCheckpointStore,
        dependencies
            .sorafs_provider_ingest_checkpoint_runtime
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::ProviderIngestRetentionAuthority,
        dependencies
            .sorafs_provider_ingest_retention_authority
            .is_some(),
    )
}
fn has_unrequested_musubi_provider_attestation_dependency(
    bindings: &IrohaRuntimeProviderBindingsV1,
    dependencies: &IrohaRuntimeDeps,
) -> bool {
    use IrohaRuntimeProviderSlotV1 as Slot;
    dependency_is_unrequested(
        bindings,
        Slot::MusubiProviderAttestationClockSeal,
        dependencies
            .sorafs_musubi_provider_attestation_clock_seal
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::MusubiProviderAttestationApprovalSigner,
        dependencies
            .sorafs_musubi_provider_attestation_approval_signer
            .is_some(),
    ) || dependency_is_unrequested(
        bindings,
        Slot::MusubiProviderAttestationAuthenticatedInventory,
        dependencies
            .sorafs_musubi_provider_attestation_inventory
            .is_some(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    const MUSUBI_PROVIDER_ATTESTATION_SLOTS: [IrohaRuntimeProviderSlotV1; 3] = [
        IrohaRuntimeProviderSlotV1::MusubiProviderAttestationClockSeal,
        IrohaRuntimeProviderSlotV1::MusubiProviderAttestationApprovalSigner,
        IrohaRuntimeProviderSlotV1::MusubiProviderAttestationAuthenticatedInventory,
    ];
    #[derive(Clone, Debug)]
    struct AttestationProviderMetadata {
        handle: String,
        handle_after_first: Option<String>,
        handle_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        revision: u64,
        policy_digest: [u8; 32],
        qualification_after_first: bool,
        qualification_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        unavailable: bool,
    }
    impl AttestationProviderMetadata {
        fn from_binding(binding: &IrohaRuntimeProviderBindingV1) -> Self {
            Self {
                handle: binding.handle().to_owned(),
                handle_after_first: None,
                handle_calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                revision: binding.revision().expect("qualified fixture revision"),
                policy_digest: binding
                    .policy_digest()
                    .expect("qualified fixture policy digest"),
                qualification_after_first: false,
                qualification_calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                unavailable: false,
            }
        }
        fn with_drift(mut self, drift: AttestationProviderDrift) -> Self {
            match drift {
                AttestationProviderDrift::Handle => {
                    self.handle = "provider://sorafs/provider-attestation/substituted".to_owned();
                }
                AttestationProviderDrift::HandleAfterSnapshot => {
                    self.handle_after_first =
                        Some("provider://sorafs/provider-attestation/substituted".to_owned());
                }
                AttestationProviderDrift::Revision => {
                    self.revision = self.revision.saturating_add(1);
                }
                AttestationProviderDrift::PolicyDigest => {
                    self.policy_digest[0] ^= 0xFF;
                }
                AttestationProviderDrift::QualificationAfterSnapshot => {
                    self.qualification_after_first = true;
                }
                AttestationProviderDrift::Unavailable => self.unavailable = true,
            }
            self
        }
        fn observed_handle(&self) -> &str {
            let call = self
                .handle_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call > 0 {
                self.handle_after_first.as_deref().unwrap_or(&self.handle)
            } else {
                &self.handle
            }
        }
        fn observed_qualification(&self) -> (u64, [u8; 32]) {
            let call = self
                .qualification_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let revision = if self.qualification_after_first && call > 0 {
                self.revision.saturating_add(1)
            } else {
                self.revision
            };
            (revision, self.policy_digest)
        }
    }
    #[derive(Clone, Copy)]
    enum AttestationProviderDrift {
        Handle,
        HandleAfterSnapshot,
        Revision,
        PolicyDigest,
        QualificationAfterSnapshot,
        Unavailable,
    }
    #[derive(Debug)]
    struct ClockSeal(AttestationProviderMetadata);
    impl sorafs_node::MusubiProviderAttestationClockSealV1 for ClockSeal {
        fn runtime_handle(&self) -> &str {
            self.0.observed_handle()
        }
        fn qualification(
            &self,
        ) -> Result<
            sorafs_node::MusubiProviderAttestationClockSealQualificationV1,
            sorafs_node::MusubiProviderAttestationClockSealErrorV1,
        > {
            if self.0.unavailable {
                Err(sorafs_node::MusubiProviderAttestationClockSealErrorV1::Unavailable)
            } else {
                let (revision, policy_digest) = self.0.observed_qualification();
                Ok(
                    sorafs_node::MusubiProviderAttestationClockSealQualificationV1::new(
                        revision,
                        policy_digest,
                    ),
                )
            }
        }
        fn load_latest(
            &self,
            _scope_digest: [u8; 32],
        ) -> sorafs_node::ProviderIngestFutureV1<
            '_,
            Result<
                Option<sorafs_node::MusubiProviderAttestationClockSealRecordV1>,
                sorafs_node::MusubiProviderAttestationClockSealErrorV1,
            >,
        > {
            Box::pin(async {
                Err(sorafs_node::MusubiProviderAttestationClockSealErrorV1::Unavailable)
            })
        }
        fn compare_and_swap<'a>(
            &'a self,
            _scope_digest: [u8; 32],
            _expected: Option<[u8; 32]>,
            _next: &'a sorafs_node::MusubiProviderAttestationClockSealRecordV1,
        ) -> sorafs_node::ProviderIngestFutureV1<
            'a,
            Result<(), sorafs_node::MusubiProviderAttestationClockSealErrorV1>,
        > {
            Box::pin(async {
                Err(sorafs_node::MusubiProviderAttestationClockSealErrorV1::Unavailable)
            })
        }
    }
    struct ApprovalSigner {
        metadata: AttestationProviderMetadata,
        authority: iroha_data_model::account::AccountId,
        policy: iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1,
        malformed_qualification: bool,
    }
    impl ApprovalSigner {
        fn new(metadata: AttestationProviderMetadata) -> Self {
            let key_pair = iroha_crypto::KeyPair::try_from_seed(
                vec![0x91; 32],
                iroha_crypto::Algorithm::Ed25519,
            )
            .expect("derive provider-attestation signer fixture key");
            Self {
                metadata,
                authority: iroha_data_model::account::AccountId::new(key_pair.public_key().clone()),
                policy:
                    iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1 {
                        policy_id: [0x92; 32],
                        revision: 1,
                        predecessor_digest: None,
                        policy_digest: [0x93; 32],
                    },
                malformed_qualification: false,
            }
        }
    }
    impl sorafs_node::MusubiProviderAttestationSignerV1 for ApprovalSigner {
        fn runtime_handle(&self) -> &str {
            self.metadata.observed_handle()
        }
        fn authority(&self) -> &iroha_data_model::account::AccountId {
            &self.authority
        }
        fn qualification(
            &self,
        ) -> Result<
            sorafs_node::MusubiProviderAttestationSignerQualificationV1,
            sorafs_node::MusubiProviderAttestationSignerErrorV1,
        > {
            if self.metadata.unavailable {
                Err(sorafs_node::MusubiProviderAttestationSignerErrorV1::Unavailable)
            } else {
                let (revision, policy_digest) = self.metadata.observed_qualification();
                let mut qualification =
                    sorafs_node::MusubiProviderAttestationSignerQualificationV1::new(
                        revision,
                        policy_digest,
                        self.policy,
                        self.authority.clone(),
                        [0x94; 32],
                    );
                if self.malformed_qualification {
                    qualification.version = qualification.version.saturating_add(1);
                }
                Ok(qualification)
            }
        }
        fn signer_policy(
            &self,
        ) -> iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1
        {
            self.policy
        }
        fn current_eligibility(
            &self,
        ) -> Result<
            iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1,
            sorafs_node::MusubiProviderAttestationSignerErrorV1,
        > {
            Ok(self.policy)
        }
        fn approve<'a>(
            &'a self,
            _request: &'a sorafs_node::ProviderIngestMusubiAttestationApprovalRequestV1,
        ) -> sorafs_node::ProviderIngestFutureV1<
            'a,
            Result<
                iroha_data_model::musubi::MusubiProviderBundleVerificationAttestationV1,
                sorafs_node::MusubiProviderAttestationSignerErrorV1,
            >,
        > {
            Box::pin(async {
                Err(sorafs_node::MusubiProviderAttestationSignerErrorV1::Unavailable)
            })
        }
    }
    struct Inventory(AttestationProviderMetadata);
    impl sorafs_node::MusubiProviderAttestationInventorySinkV1 for Inventory {
        fn put(
            &self,
            _item: sorafs_node::MusubiProviderAttestationInventoryItemV1,
        ) -> sorafs_node::ProviderIngestFutureV1<
            '_,
            Result<u64, sorafs_node::MusubiProviderAttestationInventoryErrorV1>,
        > {
            Box::pin(async {
                Err(sorafs_node::MusubiProviderAttestationInventoryErrorV1::Unavailable)
            })
        }
    }
    impl sorafs_node::MusubiProviderAttestationInventoryReaderV1 for Inventory {
        fn get<'a>(
            &'a self,
            _scope: &'a sorafs_node::MusubiProviderAttestationInventoryScopeV1,
            _key: iroha_data_model::musubi::MusubiProviderBundleAttestationKeyV1,
        ) -> sorafs_node::ProviderIngestFutureV1<
            'a,
            Result<
                Option<sorafs_node::MusubiProviderAttestationInventoryReadbackV1>,
                sorafs_node::MusubiProviderAttestationInventoryErrorV1,
            >,
        > {
            Box::pin(async {
                Err(sorafs_node::MusubiProviderAttestationInventoryErrorV1::Unavailable)
            })
        }
        fn inventory<'a>(
            &'a self,
            _scope: &'a sorafs_node::MusubiProviderAttestationInventoryScopeV1,
        ) -> sorafs_node::ProviderIngestFutureV1<
            'a,
            Result<
                Option<sorafs_node::MusubiProviderAttestationInventoryV1>,
                sorafs_node::MusubiProviderAttestationInventoryErrorV1,
            >,
        > {
            Box::pin(async {
                Err(sorafs_node::MusubiProviderAttestationInventoryErrorV1::Unavailable)
            })
        }
    }
    impl sorafs_node::MusubiProviderAttestationInventoryRuntimeV1 for Inventory {
        fn runtime_handle(&self) -> &str {
            self.0.observed_handle()
        }
        fn qualification(
            &self,
        ) -> Result<
            sorafs_node::MusubiProviderAttestationInventoryQualificationV1,
            sorafs_node::MusubiProviderAttestationInventoryRuntimeErrorV1,
        > {
            if self.0.unavailable {
                Err(sorafs_node::MusubiProviderAttestationInventoryRuntimeErrorV1::Unavailable)
            } else {
                let (revision, policy_digest) = self.0.observed_qualification();
                Ok(
                    sorafs_node::MusubiProviderAttestationInventoryQualificationV1::new(
                        revision,
                        policy_digest,
                    ),
                )
            }
        }
        fn check_readiness(
            &self,
        ) -> sorafs_node::ProviderIngestFutureV1<
            '_,
            Result<(), sorafs_node::MusubiProviderAttestationInventoryRuntimeErrorV1>,
        > {
            Box::pin(async {
                Err(sorafs_node::MusubiProviderAttestationInventoryRuntimeErrorV1::Unavailable)
            })
        }
    }
    fn attestation_metadata(
        bindings: &IrohaRuntimeProviderBindingsV1,
        slot: IrohaRuntimeProviderSlotV1,
        drift: Option<(IrohaRuntimeProviderSlotV1, AttestationProviderDrift)>,
    ) -> AttestationProviderMetadata {
        let binding = bindings
            .iter()
            .find(|binding| binding.slot() == slot)
            .expect("fixture binding must exist");
        let metadata = AttestationProviderMetadata::from_binding(binding);
        match drift {
            Some((drift_slot, drift)) if drift_slot == slot => metadata.with_drift(drift),
            Some(_) | None => metadata,
        }
    }
    fn musubi_provider_attestation_dependencies_with_drift(
        bindings: &IrohaRuntimeProviderBindingsV1,
        mask: u8,
        drift: Option<(IrohaRuntimeProviderSlotV1, AttestationProviderDrift)>,
    ) -> IrohaRuntimeDeps {
        use IrohaRuntimeProviderSlotV1 as Slot;
        let mut dependencies = IrohaRuntimeDeps::default();
        if mask & 0b001 != 0 {
            dependencies = dependencies.with_sorafs_musubi_provider_attestation_clock_seal(
                std::sync::Arc::new(ClockSeal(attestation_metadata(
                    bindings,
                    Slot::MusubiProviderAttestationClockSeal,
                    drift,
                ))),
            );
        }
        if mask & 0b010 != 0 {
            dependencies = dependencies.with_sorafs_musubi_provider_attestation_approval_signer(
                std::sync::Arc::new(ApprovalSigner::new(attestation_metadata(
                    bindings,
                    Slot::MusubiProviderAttestationApprovalSigner,
                    drift,
                ))),
            );
        }
        if mask & 0b100 != 0 {
            dependencies = dependencies.with_sorafs_musubi_provider_attestation_inventory(
                std::sync::Arc::new(Inventory(attestation_metadata(
                    bindings,
                    Slot::MusubiProviderAttestationAuthenticatedInventory,
                    drift,
                ))),
            );
        }
        dependencies
    }
    fn musubi_provider_attestation_dependencies(
        bindings: &IrohaRuntimeProviderBindingsV1,
        mask: u8,
    ) -> IrohaRuntimeDeps {
        musubi_provider_attestation_dependencies_with_drift(bindings, mask, None)
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
    fn bindings_for(slots: &[IrohaRuntimeProviderSlotV1]) -> IrohaRuntimeProviderBindingsV1 {
        let bindings = slots
            .iter()
            .copied()
            .enumerate()
            .map(|(index, slot)| {
                IrohaRuntimeProviderBindingV1::try_new(
                    slot,
                    format!("runtime://sorafs/runtime-scope-{index}"),
                    Some(1),
                    Some([u8::try_from(index + 1).expect("small fixture index"); 32]),
                )
                .expect("scope fixture binding must be production-shaped")
            })
            .collect();
        IrohaRuntimeProviderBindingsV1 {
            chain_id: "runtime-scope-chain".to_owned(),
            network_id: crate::runtime_provider_registry::runtime_provider_test_network_id(),
            credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
            bindings,
        }
    }
    #[test]
    fn single_dependency_scope_requires_the_exact_requested_slot() {
        use IrohaRuntimeProviderSlotV1 as Slot;
        let bindings = bindings_for(&[Slot::GatewayAcmeClient]);
        assert!(!dependency_is_unrequested(
            &bindings,
            Slot::GatewayAcmeClient,
            true,
        ));
        assert!(dependency_is_unrequested(
            &bindings,
            Slot::GatewayComplianceFeedTransport,
            true,
        ));
        assert!(!dependency_is_unrequested(
            &bindings,
            Slot::GatewayComplianceFeedTransport,
            false,
        ));
    }
    #[test]
    fn shared_dependency_scope_requires_the_complete_role_pair() {
        use IrohaRuntimeProviderSlotV1 as Slot;
        let gateway_only = bindings_for(&[Slot::PotrGatewaySigner]);
        assert!(paired_dependency_is_unrequested(
            &gateway_only,
            Slot::PotrGatewaySigner,
            Slot::PotrProviderSigner,
            true,
        ));
        let complete = bindings_for(&[Slot::PotrGatewaySigner, Slot::PotrProviderSigner]);
        assert!(!paired_dependency_is_unrequested(
            &complete,
            Slot::PotrGatewaySigner,
            Slot::PotrProviderSigner,
            true,
        ));
        assert!(!paired_dependency_is_unrequested(
            &gateway_only,
            Slot::PotrGatewaySigner,
            Slot::PotrProviderSigner,
            false,
        ));
    }
    #[test]
    fn enabled_musubi_provider_attestation_rejects_every_missing_effect_combination() {
        let bindings = bindings_for(&MUSUBI_PROVIDER_ATTESTATION_SLOTS);
        for mask in 0_u8..0b111 {
            let dependencies = musubi_provider_attestation_dependencies(&bindings, mask);
            assert!(
                bindings
                    .iter()
                    .any(|binding| !dependency_is_present(&dependencies, binding.slot())),
                "effect mask {mask:03b} must be incomplete"
            );
            assert!(
                !has_unrequested_dependency(&bindings, &dependencies),
                "every attached effect in mask {mask:03b} was requested"
            );
            assert_eq!(dependencies.is_empty(), mask == 0);
            assert!(matches!(
                resolve_runtime_deps_from_bindings(&bindings, Some(&FixedRegistry(dependencies))),
                Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
            ));
        }
        let complete = musubi_provider_attestation_dependencies(&bindings, 0b111);
        assert!(
            bindings
                .iter()
                .all(|binding| dependency_is_present(&complete, binding.slot()))
        );
        assert!(!has_unrequested_dependency(&bindings, &complete));
        assert!(!complete.is_empty());
    }
    #[test]
    fn disabled_musubi_provider_attestation_rejects_every_extra_effect_combination() {
        let bindings = bindings_for(&[]);
        for mask in 1_u8..=0b111 {
            let configured = bindings_for(&MUSUBI_PROVIDER_ATTESTATION_SLOTS);
            let dependencies = musubi_provider_attestation_dependencies(&configured, mask);
            assert!(
                has_unrequested_dependency(&bindings, &dependencies),
                "disabled journal must reject extra effect mask {mask:03b}"
            );
            assert!(matches!(
                resolve_runtime_deps_from_bindings(&bindings, Some(&FixedRegistry(dependencies))),
                Err(IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders)
            ));
        }
    }
    #[test]
    fn musubi_provider_attestation_qualification_requires_exact_deployment_metadata() {
        let bindings = bindings_for(&MUSUBI_PROVIDER_ATTESTATION_SLOTS);
        let exact = musubi_provider_attestation_dependencies(&bindings, 0b111);
        assert!(resolve_runtime_deps_from_bindings(&bindings, Some(&FixedRegistry(exact))).is_ok());
        for slot in MUSUBI_PROVIDER_ATTESTATION_SLOTS {
            for drift in [
                AttestationProviderDrift::Revision,
                AttestationProviderDrift::PolicyDigest,
            ] {
                let dependencies = musubi_provider_attestation_dependencies_with_drift(
                    &bindings,
                    0b111,
                    Some((slot, drift)),
                );
                assert!(matches!(
                    resolve_runtime_deps_from_bindings(
                        &bindings,
                        Some(&FixedRegistry(dependencies))
                    ),
                    Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)
                ));
            }
            let substituted = musubi_provider_attestation_dependencies_with_drift(
                &bindings,
                0b111,
                Some((slot, AttestationProviderDrift::Handle)),
            );
            assert!(matches!(
                resolve_runtime_deps_from_bindings(&bindings, Some(&FixedRegistry(substituted))),
                Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
            ));
            let unavailable = musubi_provider_attestation_dependencies_with_drift(
                &bindings,
                0b111,
                Some((slot, AttestationProviderDrift::Unavailable)),
            );
            assert!(matches!(
                resolve_runtime_deps_from_bindings(&bindings, Some(&FixedRegistry(unavailable))),
                Err(IrohaRuntimeProviderRegistryErrorV1::Unavailable)
            ));
            let handle_drift = musubi_provider_attestation_dependencies_with_drift(
                &bindings,
                0b111,
                Some((slot, AttestationProviderDrift::HandleAfterSnapshot)),
            );
            assert!(matches!(
                resolve_runtime_deps_from_bindings(&bindings, Some(&FixedRegistry(handle_drift))),
                Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
            ));
            let qualification_drift = musubi_provider_attestation_dependencies_with_drift(
                &bindings,
                0b111,
                Some((slot, AttestationProviderDrift::QualificationAfterSnapshot)),
            );
            assert!(matches!(
                resolve_runtime_deps_from_bindings(
                    &bindings,
                    Some(&FixedRegistry(qualification_drift))
                ),
                Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)
            ));
        }
        let mut malformed_dependencies = musubi_provider_attestation_dependencies(&bindings, 0b111);
        let signer_metadata = attestation_metadata(
            &bindings,
            IrohaRuntimeProviderSlotV1::MusubiProviderAttestationApprovalSigner,
            None,
        );
        let mut malformed_signer = ApprovalSigner::new(signer_metadata);
        malformed_signer.malformed_qualification = true;
        malformed_dependencies.sorafs_musubi_provider_attestation_approval_signer =
            Some(std::sync::Arc::new(malformed_signer));
        assert!(matches!(
            resolve_runtime_deps_from_bindings(
                &bindings,
                Some(&FixedRegistry(malformed_dependencies))
            ),
            Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)
        ));
    }
    #[test]
    fn musubi_provider_attestation_binding_catalog_is_all_or_none() {
        assert!(validate_musubi_provider_attestation_binding_set(&bindings_for(&[])).is_ok());
        assert!(
            validate_musubi_provider_attestation_binding_set(&bindings_for(
                &MUSUBI_PROVIDER_ATTESTATION_SLOTS
            ))
            .is_ok()
        );
        for mask in 1_u8..0b111 {
            let slots = MUSUBI_PROVIDER_ATTESTATION_SLOTS
                .into_iter()
                .enumerate()
                .filter_map(|(index, slot)| (mask & (1 << index) != 0).then_some(slot))
                .collect::<Vec<_>>();
            assert!(matches!(
                validate_musubi_provider_attestation_binding_set(&bindings_for(&slots)),
                Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
            ));
        }
    }
}
