// Each operation owns its local values. Keeping capability bodies out of the
// exhaustive router avoids reserving every branch's debug stack slots at entry.
#[path = "protocol/platform/operation_dispatch/appeal_finance.rs"]
mod appeal_finance_operations;
#[path = "protocol/platform/operation_dispatch/billing.rs"]
mod billing_operations;
#[path = "protocol/platform/operation_dispatch/bootle_lantern.rs"]
mod bootle_lantern_operations;
#[path = "protocol/platform/operation_dispatch/consensus.rs"]
mod consensus_operations;
#[path = "protocol/platform/operation_dispatch/evidence_viewer.rs"]
mod evidence_viewer_operations;
#[path = "protocol/platform/operation_dispatch/gateway.rs"]
mod gateway_operations;
#[path = "protocol/platform/operation_dispatch/governance.rs"]
mod governance_operations;
#[path = "protocol/platform/operation_dispatch/moderation.rs"]
mod moderation_operations;
#[path = "protocol/platform/operation_dispatch/pop.rs"]
mod pop_operations;
#[path = "protocol/platform/operation_dispatch/por_archive.rs"]
mod por_archive_operations;
#[path = "protocol/platform/operation_dispatch/potr.rs"]
mod potr_operations;
#[path = "protocol/platform/operation_dispatch/privacy.rs"]
mod privacy_operations;
#[path = "protocol/platform/operation_dispatch/provider_ingest.rs"]
mod provider_ingest_operations;
#[path = "protocol/platform/operation_dispatch/reputation.rs"]
mod reputation_operations;
#[path = "protocol/platform/operation_dispatch/stream_token.rs"]
mod stream_token_operations;
#[path = "protocol/platform/operation_dispatch/transaction_signing.rs"]
mod transaction_signing_operations;

fn dispatch_server_operation_with_session(
    state: &BrokerServerStateV1,
    pop_session: &mut PopBrokerServerSessionV1,
    request: &OperationRequestV1,
) -> Result<ScrubbedBytes, BrokerError> {
    let requalify =
        || qualify_server_binding(state, &request.binding, request.provider_metadata_digest);
    requalify()?;
    let moderation_quarantine_slot =
        IrohaRuntimeProviderSlotV1::ModerationQuarantineKeyWrapper.wire_id();
    let moderation_transaction_signer_slot =
        IrohaRuntimeProviderSlotV1::ModerationTransactionSigner.wire_id();
    let moderation_settlement_handoff_slot =
        IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff.wire_id();
    let moderation_publication_handoff_slot =
        IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id();
    let moderation_panel_notification_slot =
        IrohaRuntimeProviderSlotV1::ModerationPanelNotification.wire_id();
    let privacy_cycle_prf_slot = IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider.wire_id();
    let privacy_release_anchor_slot = IrohaRuntimeProviderSlotV1::PrivacyReleaseAnchor.wire_id();
    let transparency_leader_lease_slot =
        IrohaRuntimeProviderSlotV1::TransparencyLeaderLease.wire_id();
    let fenced_privacy_publisher_slot =
        IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher.wire_id();
    let fenced_privacy_head_reader_slot =
        IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader.wire_id();
    let governance_signer_slot = IrohaRuntimeProviderSlotV1::GovernanceDagSigner.wire_id();
    let governance_ipfs_auth_slot =
        IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator.wire_id();
    let governance_head_auth_slot =
        IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator.wire_id();
    let governance_checkpoint_slot =
        IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore.wire_id();
    let stream_token_slot = IrohaRuntimeProviderSlotV1::StreamTokenSigner.wire_id();
    let appeal_signer_slot = IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner.wire_id();
    let appeal_checkpoint_slot = IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint.wire_id();
    let potr_gateway_slot = IrohaRuntimeProviderSlotV1::PotrGatewaySigner.wire_id();
    let potr_provider_slot = IrohaRuntimeProviderSlotV1::PotrProviderSigner.wire_id();
    let gateway_acme_slot = IrohaRuntimeProviderSlotV1::GatewayAcmeClient.wire_id();
    let gateway_compliance_slot =
        IrohaRuntimeProviderSlotV1::GatewayComplianceFeedTransport.wire_id();
    let pop_registry_slot = IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry.wire_id();
    let por_replay_archive_slot = IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive.wire_id();
    let provider_resolver_slot =
        IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver.wire_id();
    let provider_source_slot =
        IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource.wire_id();
    let provider_signer_slot = IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner.wire_id();
    let provider_checkpoint_slot =
        IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore.wire_id();
    let provider_retention_slot =
        IrohaRuntimeProviderSlotV1::ProviderIngestRetentionAuthority.wire_id();
    let reputation_retention_slot =
        IrohaRuntimeProviderSlotV1::ReputationFinalizedArchiveRetentionAuthority.wire_id();
    let reputation_journal_slot =
        IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter.wire_id();
    let reputation_threshold_slot = IrohaRuntimeProviderSlotV1::ReputationThresholdSigner.wire_id();
    let reputation_governance_slot = IrohaRuntimeProviderSlotV1::ReputationGovernanceDag.wire_id();
    let reputation_checkpoint_slot =
        IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint.wire_id();
    let billing_finalized_query_slot = IrohaRuntimeProviderSlotV1::BillingFinalizedQuery.wire_id();
    let billing_journal_verifier_slot =
        IrohaRuntimeProviderSlotV1::BillingJournalVerifier.wire_id();
    let billing_statement_signer_slot =
        IrohaRuntimeProviderSlotV1::BillingStatementSigner.wire_id();
    let billing_statement_publisher_slot =
        IrohaRuntimeProviderSlotV1::BillingStatementPublisher.wire_id();
    let billing_acknowledgement_authority_slot =
        IrohaRuntimeProviderSlotV1::BillingAcknowledgementAuthority.wire_id();
    let billing_epoch_witness_store_slot =
        IrohaRuntimeProviderSlotV1::BillingEpochWitnessStore.wire_id();
    let evidence_webauthn_slot = IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn.wire_id();
    let evidence_grants_slot = IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority.wire_id();
    let evidence_receipt_signer_slot =
        IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner.wire_id();
    let evidence_erasure_slot = IrohaRuntimeProviderSlotV1::EvidenceViewerErasure.wire_id();
    let evidence_checkpoint_slot =
        IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore.wire_id();
    let moderation_checkpoint_slot =
        IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id();
    let moderation_panel_notification_archive_slot =
        IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id();
    let evidence_archive_slot =
        IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive.wire_id();
    let evidence_transparency_publisher_slot =
        IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher.wire_id();
    let soracloud_runtime_signer_slot =
        IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner.wire_id();
    let bootle_lantern_issuance_slot =
        IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry.wire_id();
    let global_beacon_partial_signer_slot =
        IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id();
    let parliament_tle_partial_release_signer_slot =
        IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id();
    let result = match (request.binding.slot, request.operation) {
        (slot, OPERATION_QUALIFY_V1)
            if slot == global_beacon_partial_signer_slot
                || slot == parliament_tle_partial_release_signer_slot =>
        {
            consensus_operations::qualify_consensus_signer(state, request)
        }
        (slot, OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1)
            if slot == global_beacon_partial_signer_slot =>
        {
            consensus_operations::global_beacon_partial_sign(state, request)
        }
        (slot, OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1)
            if slot == global_beacon_partial_signer_slot =>
        {
            consensus_operations::global_beacon_seat_readiness(state, request)
        }
        (slot, OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1)
            if slot == parliament_tle_partial_release_signer_slot =>
        {
            consensus_operations::parliament_tle_partial_release_sign(state, request)
        }
        (slot, OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1)
            if slot == parliament_tle_partial_release_signer_slot =>
        {
            consensus_operations::parliament_tle_capability_attest(state, request)
        }
        (slot, OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1)
            if slot == global_beacon_partial_signer_slot =>
        {
            consensus_operations::global_beacon_capability_attest(state, request)
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_QUALIFY_V1)
            if slot == moderation_panel_notification_archive_slot =>
        {
            moderation_operations::moderation_panel_notification_archive_qualify(state, request)
        }
        (slot, OPERATION_QUALIFY_V1) if slot == bootle_lantern_issuance_slot => {
            bootle_lantern_operations::qualify_bootle_lantern(state)
        }
        (slot, OPERATION_BOOTLE_LANTERN_ISSUANCE_AUTHENTICATE_V1)
            if slot == bootle_lantern_issuance_slot =>
        {
            bootle_lantern_operations::bootle_lantern_issuance_authenticate(state, request)
        }
        (slot, OPERATION_BOOTLE_LANTERN_ISSUANCE_PREPARE_AUTHORIZATION_V1)
            if slot == bootle_lantern_issuance_slot =>
        {
            bootle_lantern_operations::bootle_lantern_issuance_prepare_authorization(state, request)
        }
        (slot, OPERATION_BOOTLE_LANTERN_ISSUANCE_VALIDATE_REQUEST_V1)
            if slot == bootle_lantern_issuance_slot =>
        {
            bootle_lantern_operations::bootle_lantern_issuance_validate_request(state, request)
        }
        (slot, OPERATION_BOOTLE_LANTERN_ISSUANCE_ISSUE_VALIDATED_V1)
            if slot == bootle_lantern_issuance_slot =>
        {
            bootle_lantern_operations::bootle_lantern_issuance_issue_validated(state, request)
        }
        (slot, OPERATION_QUALIFY_V1) if slot == moderation_quarantine_slot => {
            moderation_operations::qualify_quarantine_wrapper(state)
        }
        (slot, OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1)
            if slot == moderation_quarantine_slot =>
        {
            moderation_operations::moderation_quarantine_wrap_dek(state, request)
        }
        (slot, OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1)
            if slot == moderation_quarantine_slot =>
        {
            moderation_operations::moderation_quarantine_unwrap_dek(state, request)
        }
        (slot, OPERATION_QUALIFY_V1) if slot == provider_source_slot => {
            provider_ingest_operations::qualify_source(state)
        }
        (slot, OPERATION_PROVIDER_INGEST_SOURCE_READINESS_V1) if slot == provider_source_slot => {
            provider_ingest_operations::provider_ingest_source_readiness(state)
        }
        (slot, OPERATION_QUALIFY_V1) if slot == provider_resolver_slot => {
            provider_ingest_operations::qualify_resolver(state)
        }
        (slot, OPERATION_QUALIFY_V1) if slot == soracloud_runtime_signer_slot => {
            transaction_signing_operations::qualify_soracloud_signer(state, request)
        }
        (slot, OPERATION_QUALIFY_V1)
            if slot == governance_ipfs_auth_slot || slot == governance_head_auth_slot =>
        {
            governance_operations::qualify_governance_authenticator(state, request)
        }
        (slot, OPERATION_QUALIFY_V1) if slot == stream_token_slot => {
            requalify()?;
            encode_canonical(
                required_binding_ref!(&request.binding, stream_token_signer_binding),
                MAX_QUALIFICATION_FRAME_BYTES_V1,
            )
        }
        (slot, OPERATION_QUALIFY_V1)
            if slot == governance_signer_slot
                || slot == privacy_cycle_prf_slot
                || slot == privacy_release_anchor_slot
                || slot == transparency_leader_lease_slot
                || slot == fenced_privacy_publisher_slot
                || slot == fenced_privacy_head_reader_slot
                || slot == governance_checkpoint_slot
                || slot == appeal_signer_slot
                || slot == appeal_checkpoint_slot
                || slot == potr_gateway_slot
                || slot == potr_provider_slot
                || slot == gateway_acme_slot
                || slot == gateway_compliance_slot
                || slot == pop_registry_slot
                || slot == por_replay_archive_slot
                || slot == moderation_transaction_signer_slot
                || slot == moderation_settlement_handoff_slot
                || slot == moderation_publication_handoff_slot
                || slot == moderation_panel_notification_slot
                || native_transaction_signer_role_for_slot(slot).is_some()
                || slot == provider_checkpoint_slot
                || slot == provider_retention_slot
                || slot == reputation_retention_slot
                || slot == reputation_journal_slot
                || slot == reputation_threshold_slot
                || slot == reputation_governance_slot
                || slot == reputation_checkpoint_slot
                || slot == billing_finalized_query_slot
                || slot == billing_journal_verifier_slot
                || slot == billing_statement_signer_slot
                || slot == billing_statement_publisher_slot
                || slot == billing_acknowledgement_authority_slot
                || slot == billing_epoch_witness_store_slot
                || slot == evidence_webauthn_slot
                || slot == evidence_grants_slot
                || slot == evidence_receipt_signer_slot
                || slot == evidence_erasure_slot
                || slot == evidence_checkpoint_slot
                || slot == moderation_checkpoint_slot
                || slot == evidence_archive_slot
                || slot == evidence_transparency_publisher_slot =>
        {
            let qualification = qualification_from_binding(&request.binding)?;
            encode_canonical(
                &QualificationResultWireV1 {
                    revision: qualification.revision,
                    policy_digest: qualification.policy_digest,
                },
                MAX_OPERATION_FRAME_BYTES_V1,
            )
        }
        (slot, OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1)
            if slot == reputation_journal_slot =>
        {
            reputation_operations::reputation_journal_supports_authority(state, request)
        }
        (slot, OPERATION_REPUTATION_JOURNAL_SUBMIT_V1) if slot == reputation_journal_slot => {
            reputation_operations::reputation_journal_submit(state, request)
        }
        (slot, OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1)
            if slot == reputation_threshold_slot =>
        {
            reputation_operations::reputation_threshold_reconcile(state, request)
        }
        (slot, OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1)
            if slot == reputation_governance_slot =>
        {
            reputation_operations::reputation_governance_reconcile(state, request)
        }
        (slot, OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1)
            if slot == reputation_checkpoint_slot =>
        {
            reputation_operations::reputation_journal_checkpoint_load(state, request)
        }
        (slot, OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1)
            if slot == reputation_checkpoint_slot =>
        {
            reputation_operations::reputation_journal_checkpoint_compare_and_swap(state, request)
        }
        (slot, OPERATION_BILLING_IDENTITY_V1) if slot == billing_finalized_query_slot => {
            billing_operations::billing_query_identity(state, request)
        }
        (slot, OPERATION_BILLING_IDENTITY_V1) if slot == billing_journal_verifier_slot => {
            billing_operations::billing_verifier_identity(state, request)
        }
        (slot, OPERATION_BILLING_IDENTITY_V1) if slot == billing_statement_signer_slot => {
            billing_operations::billing_signer_identity(state, request)
        }
        (slot, OPERATION_BILLING_IDENTITY_V1) if slot == billing_statement_publisher_slot => {
            billing_operations::billing_publisher_identity(state, request)
        }
        (slot, OPERATION_BILLING_IDENTITY_V1) if slot == billing_acknowledgement_authority_slot => {
            billing_operations::billing_acknowledgement_identity(state, request)
        }
        (slot, OPERATION_BILLING_READINESS_V1) if slot == billing_finalized_query_slot => {
            billing_operations::billing_query_readiness(state, request)
        }
        (slot, OPERATION_BILLING_READINESS_V1) if slot == billing_journal_verifier_slot => {
            billing_operations::billing_verifier_readiness(state, request)
        }
        (slot, OPERATION_BILLING_READINESS_V1) if slot == billing_statement_signer_slot => {
            billing_operations::billing_signer_readiness(state, request)
        }
        (slot, OPERATION_BILLING_READINESS_V1) if slot == billing_statement_publisher_slot => {
            billing_operations::billing_publisher_readiness(state, request)
        }
        (slot, OPERATION_BILLING_READINESS_V1)
            if slot == billing_acknowledgement_authority_slot =>
        {
            billing_operations::billing_acknowledgement_readiness(state, request)
        }
        (slot, OPERATION_BILLING_READINESS_V1) if slot == billing_epoch_witness_store_slot => {
            billing_operations::billing_epoch_store_readiness(state, request)
        }
        (slot, OPERATION_BILLING_QUERY_CAPABILITIES_V1) if slot == billing_finalized_query_slot => {
            billing_operations::billing_query_capabilities(state, request)
        }
        (slot, OPERATION_BILLING_FINALIZED_HEAD_V1) if slot == billing_finalized_query_slot => {
            billing_operations::billing_finalized_head(state, request)
        }
        (slot, OPERATION_BILLING_QUERY_PAGE_V1) if slot == billing_finalized_query_slot => {
            billing_operations::billing_query_page(state, request)
        }
        (slot, OPERATION_BILLING_QUERY_PERIOD_CLOSE_V1) if slot == billing_finalized_query_slot => {
            billing_operations::billing_query_period_close(state, request)
        }
        (slot, OPERATION_BILLING_VERIFY_PAGE_V1) if slot == billing_journal_verifier_slot => {
            billing_operations::billing_verify_page(state, request)
        }
        (slot, OPERATION_BILLING_VERIFY_PERIOD_CLOSE_V1)
            if slot == billing_journal_verifier_slot =>
        {
            billing_operations::billing_verify_period_close(state, request)
        }
        (slot, OPERATION_BILLING_VERIFY_EPOCH_TRANSITION_V1)
            if slot == billing_journal_verifier_slot =>
        {
            billing_operations::billing_verify_epoch_transition(state, request)
        }
        (slot, OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1)
            if slot == billing_statement_signer_slot =>
        {
            billing_operations::billing_sign_statement_digest(state, request)
        }
        (slot, OPERATION_BILLING_PUBLISH_STATEMENT_V1)
            if slot == billing_statement_publisher_slot =>
        {
            billing_operations::billing_publish_statement(state, request)
        }
        (slot, OPERATION_BILLING_LOOKUP_PUBLICATION_V1)
            if slot == billing_statement_publisher_slot =>
        {
            billing_operations::billing_lookup_publication(state, request)
        }
        (slot, OPERATION_BILLING_VERIFY_ACKNOWLEDGEMENT_V1)
            if slot == billing_acknowledgement_authority_slot =>
        {
            billing_operations::billing_verify_acknowledgement(state, request)
        }
        (slot, OPERATION_BILLING_RECORD_ACKNOWLEDGEMENT_V1)
            if slot == billing_acknowledgement_authority_slot =>
        {
            billing_operations::billing_record_acknowledgement(state, request)
        }
        (slot, OPERATION_BILLING_LOOKUP_ACKNOWLEDGEMENT_V1)
            if slot == billing_acknowledgement_authority_slot =>
        {
            billing_operations::billing_lookup_acknowledgement(state, request)
        }
        (slot, OPERATION_BILLING_LOAD_LATEST_EPOCH_V1)
            if slot == billing_epoch_witness_store_slot =>
        {
            billing_operations::billing_load_latest_epoch(state, request)
        }
        (slot, OPERATION_BILLING_LOAD_EPOCH_V1) if slot == billing_epoch_witness_store_slot => {
            billing_operations::billing_load_epoch(state, request)
        }
        (slot, OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1)
            if slot == billing_epoch_witness_store_slot =>
        {
            billing_operations::billing_compare_and_swap_epoch(state, request)
        }
        (slot, OPERATION_PRIVACY_CYCLE_PRF_DERIVE_V1) if slot == privacy_cycle_prf_slot => {
            privacy_operations::privacy_cycle_prf_derive(state, request)
        }
        (slot, OPERATION_PRIVACY_RELEASE_ANCHOR_FINALIZED_HEAD_V1)
            if slot == privacy_release_anchor_slot =>
        {
            privacy_operations::privacy_release_anchor_finalized_head(state, request)
        }
        (slot, OPERATION_PRIVACY_RELEASE_ANCHOR_COMPARE_AND_SET_V1)
            if slot == privacy_release_anchor_slot =>
        {
            privacy_operations::privacy_release_anchor_compare_and_set(state, request)
        }
        (slot, OPERATION_TRANSPARENCY_LEADER_LEASE_ACQUIRE_V1)
            if slot == transparency_leader_lease_slot =>
        {
            privacy_operations::transparency_leader_lease_acquire(state, request)
        }
        (slot, OPERATION_TRANSPARENCY_LEADER_LEASE_RENEW_V1)
            if slot == transparency_leader_lease_slot =>
        {
            privacy_operations::transparency_leader_lease_renew(state, request)
        }
        (slot, OPERATION_TRANSPARENCY_LEADER_LEASE_RELEASE_V1)
            if slot == transparency_leader_lease_slot =>
        {
            privacy_operations::transparency_leader_lease_release(state, request)
        }
        (slot, OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1)
            if slot == fenced_privacy_publisher_slot =>
        {
            privacy_operations::fenced_privacy_compare_and_append(state, request)
        }
        (slot, OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1)
            if slot == fenced_privacy_head_reader_slot =>
        {
            privacy_operations::fenced_privacy_read_head_with_ancestry(state, request)
        }
        (slot, OPERATION_STREAM_TOKEN_SIGN_V1 | OPERATION_STREAM_TOKEN_RECOVER_V1)
            if slot == stream_token_slot =>
        {
            stream_token_operations::stream_token_sign_or_recover(state, request)
        }
        (slot, OPERATION_STREAM_TOKEN_CHECK_V1) if slot == stream_token_slot => {
            stream_token_operations::stream_token_check(state, request)
        }
        (slot, OPERATION_APPEAL_FINANCE_TRANSACTION_SIGN_V1) if slot == appeal_signer_slot => {
            appeal_finance_operations::appeal_finance_transaction_sign(state, request)
        }
        (slot, OPERATION_APPEAL_FINANCE_CHECKPOINT_SIGN_V1) if slot == appeal_checkpoint_slot => {
            appeal_finance_operations::appeal_finance_checkpoint_sign(state, request)
        }
        (slot, OPERATION_APPEAL_FINANCE_CHECKPOINT_LOAD_V1) if slot == appeal_checkpoint_slot => {
            appeal_finance_operations::appeal_finance_checkpoint_load(state, request)
        }
        (slot, OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1)
            if slot == appeal_checkpoint_slot =>
        {
            appeal_finance_operations::appeal_finance_checkpoint_compare_and_swap(state, request)
        }
        (slot, OPERATION_POTR_SIGN_V1)
            if slot == potr_gateway_slot || slot == potr_provider_slot =>
        {
            potr_operations::potr_sign(state, request)
        }
        (slot, OPERATION_GATEWAY_ACME_ORDER_CERTIFICATE_V1) if slot == gateway_acme_slot => {
            gateway_operations::gateway_acme_order_certificate(state, request)
        }
        (slot, OPERATION_GATEWAY_COMPLIANCE_RESOLVE_V1) if slot == gateway_compliance_slot => {
            gateway_operations::gateway_compliance_resolve(state, request)
        }
        (slot, OPERATION_GATEWAY_COMPLIANCE_FETCH_V1) if slot == gateway_compliance_slot => {
            gateway_operations::gateway_compliance_fetch(state, request)
        }
        (slot, OPERATION_POP_RUNTIME_OPEN_V1) if slot == pop_registry_slot => {
            pop_operations::pop_runtime_open(state, pop_session, request)
        }
        (
            slot,
            operation @ (OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1
            | OPERATION_POP_WALLET_RECIPIENT_OPEN_V1),
        ) if slot == pop_registry_slot => {
            pop_operations::pop_recipient_open(state, pop_session, request, operation)
        }
        (slot, OPERATION_POP_ISSUER_SIGN_V1) if slot == pop_registry_slot => {
            pop_operations::pop_issuer_sign(state, pop_session, request)
        }
        (slot, OPERATION_POP_AUTHENTICATE_V1) if slot == pop_registry_slot => {
            pop_operations::pop_authenticate(state, pop_session, request)
        }
        (slot, OPERATION_POP_REGISTRY_SUBMIT_V1) if slot == pop_registry_slot => {
            pop_operations::pop_registry_submit(state, pop_session, request)
        }
        (slot, OPERATION_POP_REGISTRY_NEXT_V1) if slot == pop_registry_slot => {
            pop_operations::pop_registry_next(state, pop_session, request)
        }
        (slot, OPERATION_POP_ISSUANCE_DRAFT_V1) if slot == pop_registry_slot => {
            pop_operations::pop_issuance_draft(state, pop_session, request)
        }
        (slot, OPERATION_POP_WALLET_WRAP_DEK_V1) if slot == pop_registry_slot => {
            pop_operations::pop_wallet_wrap_dek(state, pop_session, request)
        }
        (slot, OPERATION_POP_WALLET_UNWRAP_DEK_V1) if slot == pop_registry_slot => {
            pop_operations::pop_wallet_unwrap_dek(state, pop_session, request)
        }
        (slot, OPERATION_POP_WALLET_WITNESS_V1) if slot == pop_registry_slot => {
            pop_operations::pop_wallet_witness(state, pop_session, request)
        }
        (slot, OPERATION_POP_FINALIZED_TIME_V1) if slot == pop_registry_slot => {
            pop_operations::pop_finalized_time(state, pop_session, request)
        }
        (slot, OPERATION_POR_REPLAY_ARCHIVE_READINESS_V1) if slot == por_replay_archive_slot => {
            por_archive_operations::por_replay_archive_readiness(state, request)
        }
        (slot, OPERATION_POR_REPLAY_ARCHIVE_CURRENT_HEAD_V1) if slot == por_replay_archive_slot => {
            por_archive_operations::por_replay_archive_current_head(state, request)
        }
        (slot, OPERATION_POR_REPLAY_ARCHIVE_APPEND_V1) if slot == por_replay_archive_slot => {
            por_archive_operations::por_replay_archive_append(state, request)
        }
        (slot, OPERATION_POR_REPLAY_ARCHIVE_LOOKUP_V1) if slot == por_replay_archive_slot => {
            por_archive_operations::por_replay_archive_lookup(state, request)
        }
        (slot, OPERATION_NATIVE_TRANSACTION_SIGN_V1)
            if slot == moderation_transaction_signer_slot =>
        {
            transaction_signing_operations::moderation_transaction_sign(state, request)
        }
        (slot, OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1)
            if slot == moderation_settlement_handoff_slot
                || slot == moderation_publication_handoff_slot =>
        {
            moderation_operations::moderation_handoff_deliver_once(state, request)
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1)
            if slot == moderation_publication_handoff_slot =>
        {
            moderation_operations::moderation_panel_notification_archive_head_publish(
                state, request,
            )
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1)
            if slot == moderation_publication_handoff_slot =>
        {
            moderation_operations::moderation_panel_notification_archive_head_read(state, request)
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1)
            if slot == moderation_panel_notification_slot =>
        {
            moderation_operations::moderation_panel_notification_deliver_once(state, request)
        }
        (slot, OPERATION_NATIVE_TRANSACTION_SIGN_V1)
            if native_transaction_signer_role_for_slot(slot).is_some() =>
        {
            transaction_signing_operations::native_transaction_sign(state, request)
        }
        (slot, OPERATION_NATIVE_TRANSACTION_SIGN_V1) if slot == soracloud_runtime_signer_slot => {
            transaction_signing_operations::soracloud_transaction_sign(state, request)
        }
        (slot, OPERATION_SORACLOUD_PROVENANCE_SIGN_V1) if slot == soracloud_runtime_signer_slot => {
            transaction_signing_operations::soracloud_provenance_sign(state, request)
        }
        (slot, OPERATION_SIGN_V1) if slot == governance_signer_slot => {
            governance_operations::sign(state, request)
        }
        (slot, OPERATION_GOVERNANCE_REQUEST_AUTHENTICATE_V1)
            if slot == governance_ipfs_auth_slot || slot == governance_head_auth_slot =>
        {
            governance_operations::governance_request_authenticate(state, request)
        }
        (slot, OPERATION_SEALED_LOAD_V1) if slot == governance_checkpoint_slot => {
            governance_operations::sealed_load(state, request)
        }
        (slot, OPERATION_SEALED_COMPARE_AND_SWAP_V1) if slot == governance_checkpoint_slot => {
            governance_operations::sealed_compare_and_swap(state, request)
        }
        (slot, OPERATION_SEALED_DELETE_V1) if slot == governance_checkpoint_slot => {
            governance_operations::sealed_delete(state, request)
        }
        (slot, OPERATION_PROVIDER_INGEST_RESOLVER_READINESS_V1)
            if slot == provider_resolver_slot =>
        {
            provider_ingest_operations::provider_ingest_resolver_readiness(state, request)
        }
        (slot, OPERATION_PROVIDER_INGEST_RESOLVE_SIGNER_V1) if slot == provider_resolver_slot => {
            provider_ingest_operations::provider_ingest_resolve_signer(state, request)
        }
        (slot, OPERATION_PROVIDER_INGEST_SIGN_V1) if slot == provider_signer_slot => {
            provider_ingest_operations::provider_ingest_sign(state, request)
        }
        (slot, OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1)
            if slot == provider_checkpoint_slot =>
        {
            provider_ingest_operations::provider_ingest_checkpoint_load(state, request)
        }
        (slot, OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1)
            if slot == provider_checkpoint_slot =>
        {
            provider_ingest_operations::provider_ingest_checkpoint_compare_and_swap(state, request)
        }
        (slot, OPERATION_PROVIDER_INGEST_RETENTION_LOAD_V1) if slot == provider_retention_slot => {
            provider_ingest_operations::provider_ingest_retention_load(state, request)
        }
        (slot, OPERATION_PROVIDER_INGEST_RETENTION_COMPARE_AND_SWAP_V1)
            if slot == provider_retention_slot =>
        {
            provider_ingest_operations::provider_ingest_retention_compare_and_swap(state, request)
        }
        (slot, OPERATION_REPUTATION_RETENTION_LOAD_V1) if slot == reputation_retention_slot => {
            reputation_operations::reputation_retention_load(state, request)
        }
        (slot, OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1)
            if slot == reputation_retention_slot =>
        {
            reputation_operations::reputation_retention_compare_and_swap(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_ISSUE_CHALLENGE_V1) if slot == evidence_webauthn_slot => {
            evidence_viewer_operations::evidence_viewer_issue_challenge(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_VERIFY_AND_CONSUME_V1)
            if slot == evidence_webauthn_slot =>
        {
            evidence_viewer_operations::evidence_viewer_verify_and_consume(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_GRANT_ISSUE_V1) if slot == evidence_grants_slot => {
            evidence_viewer_operations::evidence_viewer_grant_issue(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_GRANT_VERIFY_V1) if slot == evidence_grants_slot => {
            evidence_viewer_operations::evidence_viewer_grant_verify(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_GRANT_REVOKE_V1) if slot == evidence_grants_slot => {
            evidence_viewer_operations::evidence_viewer_grant_revoke(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_RECEIPT_SIGN_V1)
            if slot == evidence_receipt_signer_slot =>
        {
            evidence_viewer_operations::evidence_viewer_receipt_sign(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_ERASE_V1) if slot == evidence_erasure_slot => {
            evidence_viewer_operations::evidence_viewer_erase(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_CHECKPOINT_LOAD_V1)
            if slot == evidence_checkpoint_slot =>
        {
            evidence_viewer_operations::evidence_viewer_checkpoint_load(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1)
            if slot == evidence_checkpoint_slot =>
        {
            evidence_viewer_operations::evidence_viewer_checkpoint_compare_and_swap(state, request)
        }
        (slot, OPERATION_MODERATION_CHECKPOINT_LOAD_V1) if slot == moderation_checkpoint_slot => {
            moderation_operations::moderation_checkpoint_load(state, request)
        }
        (slot, OPERATION_MODERATION_CHECKPOINT_COMPARE_AND_SWAP_V1)
            if slot == moderation_checkpoint_slot =>
        {
            moderation_operations::moderation_checkpoint_compare_and_swap(state, request)
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_SOURCE_ATTEST_V1)
            if slot == moderation_checkpoint_slot =>
        {
            moderation_operations::moderation_panel_notification_source_attest(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1) if slot == evidence_archive_slot => {
            evidence_viewer_operations::evidence_viewer_archive_install(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_ARCHIVE_READ_V1) if slot == evidence_archive_slot => {
            evidence_viewer_operations::evidence_viewer_archive_read(state, request)
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1)
            if slot == moderation_panel_notification_archive_slot =>
        {
            moderation_operations::moderation_panel_notification_archive_install(state, request)
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1)
            if slot == moderation_panel_notification_archive_slot =>
        {
            moderation_operations::moderation_panel_notification_archive_read(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1)
            if slot == evidence_transparency_publisher_slot =>
        {
            evidence_viewer_operations::evidence_viewer_transparency_load(state, request)
        }
        (slot, OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1)
            if slot == evidence_transparency_publisher_slot =>
        {
            evidence_viewer_operations::evidence_viewer_transparency_compare_and_publish(
                state, request,
            )
        }
        _ => Err(BrokerError::BindingMismatch),
    };
    result.map(ScrubbedBytes::new)
}

#[cfg(test)]
fn dispatch_server_operation(
    state: &BrokerServerStateV1,
    request: &OperationRequestV1,
) -> Result<ScrubbedBytes, BrokerError> {
    // An explicit fixture scope models the full ingress/dispatch/response
    // lifetime and must not be replaced. Standalone dispatch fixtures own one
    // operation from their simulated broker process.
    let admission = match current_decode_resource_admission() {
        Some(admission) => admission,
        None => DecodeResourceAdmissionV1::acquire_operation_from(
            Arc::clone(&state.decode_pool),
            request.operation,
        )?,
    };
    let _scope = admission.enter();
    if request.operation == OPERATION_STREAM_TOKEN_OBSERVE_V1 {
        return server_observation::dispatch_fixture(state, request, admission);
    }
    let mut result = dispatch_server_operation_with_session(
        state,
        &mut PopBrokerServerSessionV1::default(),
        request,
    )?;
    result.decode_admission = Some(admission);
    Ok(result)
}
