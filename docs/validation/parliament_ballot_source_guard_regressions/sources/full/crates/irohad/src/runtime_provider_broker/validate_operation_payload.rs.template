fn validate_operation_payload(
    request: &OperationRequestV1,
    session_chain_id: Option<&str>,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
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
    let signer_slot = IrohaRuntimeProviderSlotV1::GovernanceDagSigner.wire_id();
    let ipfs_auth_slot = IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator.wire_id();
    let head_auth_slot = IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator.wire_id();
    let checkpoint_slot = IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore.wire_id();
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
    let provider_ingest_resolver_slot =
        IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver.wire_id();
    let provider_ingest_source_slot =
        IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource.wire_id();
    let provider_ingest_signer_slot =
        IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner.wire_id();
    let provider_ingest_checkpoint_slot =
        IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore.wire_id();
    let provider_ingest_retention_slot =
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
    match (request.binding.slot, request.operation) {
        (slot, OPERATION_QUALIFY_V1)
            if slot == moderation_quarantine_slot
                || slot == privacy_cycle_prf_slot
                || slot == privacy_release_anchor_slot
                || slot == transparency_leader_lease_slot
                || slot == fenced_privacy_publisher_slot
                || slot == fenced_privacy_head_reader_slot
                || slot == signer_slot
                || slot == ipfs_auth_slot
                || slot == head_auth_slot
                || slot == checkpoint_slot
                || slot == stream_token_slot
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
                || slot == soracloud_runtime_signer_slot
                || slot == bootle_lantern_issuance_slot
                || slot == global_beacon_partial_signer_slot
                || slot == parliament_tle_partial_release_signer_slot
                || native_transaction_signer_role_for_slot(slot).is_some() =>
        {
            decode_canonical::<()>(&request.payload, MAX_OPERATION_FRAME_BYTES_V1)?;
        }
        (slot, OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1)
            if slot == global_beacon_partial_signer_slot =>
        {
            let _ =
                decode_global_beacon_partial_sign_request(&request.payload, session_network_id)?;
        }
        (slot, OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1)
            if slot == global_beacon_partial_signer_slot =>
        {
            let _ =
                decode_global_beacon_seat_readiness_request(&request.payload, session_network_id)?;
        }
        (slot, OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1)
            if slot == parliament_tle_partial_release_signer_slot =>
        {
            let _ = decode_parliament_tle_partial_release_sign_request(
                &request.payload,
                session_network_id,
            )?;
        }
        (slot, OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1)
            if slot == parliament_tle_partial_release_signer_slot =>
        {
            let _ = decode_parliament_tle_capability_attest_request(
                &request.payload,
                session_network_id,
            )?;
        }
        (slot, OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1)
            if slot == global_beacon_partial_signer_slot =>
        {
            let _ = decode_global_beacon_capability_attest_request(
                &request.payload,
                session_network_id,
            )?;
        }
        (slot, OPERATION_BOOTLE_LANTERN_ISSUANCE_AUTHENTICATE_V1)
            if slot == bootle_lantern_issuance_slot =>
        {
            let authenticate = decode_canonical::<BootleLanternAuthenticateRequestWireV1>(
                &request.payload,
                MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
            )?;
            if authenticate.opaque_credential.is_empty()
                || authenticate.opaque_credential.len()
                    > MAX_BOOTLE_LANTERN_AUTH_CREDENTIAL_BYTES_V1
                || authenticate.request_binding == [0; 32]
                || authenticate.committed_height == 0
            {
                return Err(BrokerError::Rejected);
            }
            bootle_lantern_action_from_wire(authenticate.action)?;
        }
        (slot, OPERATION_BOOTLE_LANTERN_ISSUANCE_PREPARE_AUTHORIZATION_V1)
            if slot == bootle_lantern_issuance_slot =>
        {
            let prepare = decode_canonical::<BootleLanternPrepareAuthorizationRequestWireV1>(
                &request.payload,
                MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
            )?;
            validate_bootle_lantern_prepare_request(
                &prepare,
                &request.binding,
                session_network_id,
            )?;
        }
        (slot, OPERATION_BOOTLE_LANTERN_ISSUANCE_VALIDATE_REQUEST_V1)
            if slot == bootle_lantern_issuance_slot =>
        {
            decode_bootle_lantern_issue_request(
                &request.payload,
                &request.binding,
                session_network_id,
            )?;
        }
        (slot, OPERATION_BOOTLE_LANTERN_ISSUANCE_ISSUE_VALIDATED_V1)
            if slot == bootle_lantern_issuance_slot =>
        {
            decode_bootle_lantern_issue_request(
                &request.payload,
                &request.binding,
                session_network_id,
            )?;
        }
        (slot, OPERATION_PRIVACY_CYCLE_PRF_DERIVE_V1) if slot == privacy_cycle_prf_slot => {
            decode_canonical::<PrivacyCyclePrfRequestWireV1>(
                &request.payload,
                MAX_TRANSPARENCY_PRF_FRAME_BYTES_V1,
            )?
            .to_request()?;
        }
        (slot, OPERATION_PRIVACY_RELEASE_ANCHOR_FINALIZED_HEAD_V1)
            if slot == privacy_release_anchor_slot =>
        {
            let finalized = decode_canonical::<PrivacyReleaseAnchorFinalizedHeadRequestWireV1>(
                &request.payload,
                MAX_PRIVACY_RELEASE_ANCHOR_FRAME_BYTES_V1,
            )?;
            validate_privacy_release_anchor_query(finalized)?;
        }
        (slot, OPERATION_PRIVACY_RELEASE_ANCHOR_COMPARE_AND_SET_V1)
            if slot == privacy_release_anchor_slot =>
        {
            let compare = decode_canonical::<PrivacyReleaseAnchorCompareAndSetRequestWireV1>(
                &request.payload,
                MAX_PRIVACY_RELEASE_ANCHOR_FRAME_BYTES_V1,
            )?;
            validate_privacy_release_anchor_compare_and_set(&compare)?;
        }
        (slot, OPERATION_TRANSPARENCY_LEADER_LEASE_ACQUIRE_V1)
            if slot == transparency_leader_lease_slot =>
        {
            let configured = transparency_runtime_binding_from_wire(&request.binding)?;
            let acquire = decode_canonical::<TransparencyLeaderLeaseAcquireRequestWireV1>(
                &request.payload,
                MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
            )?;
            validate_transparency_leader_lease_acquire(&acquire, &configured)?;
        }
        (slot, OPERATION_TRANSPARENCY_LEADER_LEASE_RENEW_V1)
            if slot == transparency_leader_lease_slot =>
        {
            let configured = transparency_runtime_binding_from_wire(&request.binding)?;
            let renew = decode_canonical::<TransparencyLeaderLeaseRenewRequestWireV1>(
                &request.payload,
                MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
            )?;
            validate_transparency_leader_lease_renew(&renew, &configured)?;
        }
        (slot, OPERATION_TRANSPARENCY_LEADER_LEASE_RELEASE_V1)
            if slot == transparency_leader_lease_slot =>
        {
            let configured = transparency_runtime_binding_from_wire(&request.binding)?;
            let release = decode_canonical::<TransparencyLeaderLeaseReleaseRequestWireV1>(
                &request.payload,
                MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
            )?;
            validate_transparency_leader_lease_release(&release, &configured)?;
        }
        (slot, OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1)
            if slot == fenced_privacy_publisher_slot =>
        {
            decode_canonical::<FencedPrivacyPublicationRequestWireV1>(
                &request.payload,
                MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1,
            )?
            .to_request()?;
        }
        (slot, OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1)
            if slot == fenced_privacy_head_reader_slot =>
        {
            decode_canonical::<FencedPrivacyHeadReadRequestWireV1>(
                &request.payload,
                MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1,
            )?
            .to_required_evidence()?;
        }
        (slot, OPERATION_NATIVE_TRANSACTION_SIGN_V1)
            if slot == moderation_transaction_signer_slot =>
        {
            let payload = decode_native_transaction_payload(&request.payload)?;
            if session_chain_id.is_some() {
                ensure_transaction_session_network(&payload, session_network_id)?;
            }
        }
        (slot, OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1)
            if slot == moderation_settlement_handoff_slot
                || slot == moderation_publication_handoff_slot =>
        {
            let handoff = decode_canonical::<ModerationDurableHandoffRequestWireV1>(
                &request.payload,
                MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
            )?;
            validate_moderation_handoff_request(&handoff, slot, Some(session_network_id))?;
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1)
            if slot == moderation_publication_handoff_slot =>
        {
            let publish = decode_canonical::<
                ModerationPanelNotificationArchiveHeadPublishRequestWireV1,
            >(&request.payload, MAX_MODERATION_HANDOFF_FRAME_BYTES_V1)?;
            validate_moderation_panel_notification_archive_head_publish_request(
                &publish,
                session_network_id,
            )?;
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1)
            if slot == moderation_publication_handoff_slot =>
        {
            decode_canonical::<()>(&request.payload, MAX_MODERATION_HANDOFF_FRAME_BYTES_V1)?;
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1)
            if slot == moderation_panel_notification_slot =>
        {
            let notification = decode_canonical::<ModerationDurablePanelNotificationRequestWireV1>(
                &request.payload,
                MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1,
            )?;
            validate_moderation_panel_notification_request(
                &notification,
                Some(session_network_id),
            )?;
        }
        (slot, OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1)
            if slot == reputation_journal_slot =>
        {
            decode_canonical::<ReputationJournalSupportsAuthorityRequestWireV1>(
                &request.payload,
                MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
            )?;
        }
        (slot, OPERATION_REPUTATION_JOURNAL_SUBMIT_V1) if slot == reputation_journal_slot => {
            let wire = decode_canonical::<ReputationJournalTransactionRequestWireV1>(
                &request.payload,
                MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
            )?;
            reputation_journal_request_from_wire(wire)?;
        }
        (slot, OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1)
            if slot == reputation_threshold_slot =>
        {
            let wire = decode_canonical::<ReputationThresholdSigningRequestWireV1>(
                &request.payload,
                MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
            )?;
            reputation_threshold_request_from_wire(wire)?;
        }
        (slot, OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1)
            if slot == reputation_governance_slot =>
        {
            let wire = decode_canonical::<ReputationGovernanceDagPublicationRequestWireV1>(
                &request.payload,
                MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
            )?;
            reputation_governance_request_from_wire(wire)?;
        }
        (slot, OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1)
            if slot == reputation_checkpoint_slot =>
        {
            let version = decode_canonical::<u8>(
                &request.payload,
                MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1,
            )?;
            if version != CHECKPOINT_LOAD_REQUEST_VERSION_V1 {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1)
            if slot == reputation_checkpoint_slot =>
        {
            let compare = decode_canonical::<ReputationJournalCheckpointCompareAndSwapRequestWireV1>(
                &request.payload,
                MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1,
            )?;
            if compare.expected_revision == Some([0; 32]) {
                return Err(BrokerError::Rejected);
            }
            reserve_external_canonical_decode(
                compare.next_record.len(),
                MAX_REPUTATION_JOURNAL_CHECKPOINT_RECORD_BYTES_V1,
            )?;
            sorafs_node::reputation::runtime::ReputationJournalSealedCheckpointRecordV1::
                    from_canonical_bytes(
                        &compare.next_record,
                        sorafs_node::reputation::runtime::
                            REPUTATION_JOURNAL_PRODUCER_MAX_CHECKPOINT_BYTES_V1,
                    )
                    .map_err(|_| BrokerError::Rejected)?;
        }
        (slot, OPERATION_BILLING_IDENTITY_V1)
            if slot == billing_finalized_query_slot
                || slot == billing_journal_verifier_slot
                || slot == billing_statement_signer_slot
                || slot == billing_statement_publisher_slot
                || slot == billing_acknowledgement_authority_slot =>
        {
            decode_canonical::<()>(&request.payload, MAX_BILLING_CONTROL_FRAME_BYTES_V1)?;
        }
        (slot, OPERATION_BILLING_READINESS_V1)
            if slot == billing_finalized_query_slot
                || slot == billing_journal_verifier_slot
                || slot == billing_statement_signer_slot
                || slot == billing_statement_publisher_slot
                || slot == billing_acknowledgement_authority_slot
                || slot == billing_epoch_witness_store_slot =>
        {
            decode_canonical::<()>(&request.payload, MAX_BILLING_CONTROL_FRAME_BYTES_V1)?;
        }
        (slot, OPERATION_BILLING_QUERY_CAPABILITIES_V1 | OPERATION_BILLING_FINALIZED_HEAD_V1)
            if slot == billing_finalized_query_slot =>
        {
            decode_canonical::<()>(&request.payload, MAX_BILLING_CONTROL_FRAME_BYTES_V1)?;
        }
        (slot, OPERATION_BILLING_QUERY_PAGE_V1) if slot == billing_finalized_query_slot => {
            let query = decode_canonical::<BillingQueryPageRequestWireV1>(
                &request.payload,
                MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
            )?;
            validate_billing_query_position(query.position, *session_network_id)?;
            if query.max_events == 0
                || query.max_events
                    > sorafs_node::hedging_billing_service::HEDGING_BILLING_MAX_EVENTS_PER_PAGE_V1
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_BILLING_QUERY_PERIOD_CLOSE_V1) if slot == billing_finalized_query_slot => {
            let query = decode_canonical::<BillingQueryPeriodCloseRequestWireV1>(
                &request.payload,
                MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
            )?;
            validate_billing_query_position(query.position, *session_network_id)?;
            if query.period_end_unix == 0 {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_BILLING_VERIFY_PAGE_V1) if slot == billing_journal_verifier_slot => {
            let verify = decode_canonical::<BillingVerifyPageRequestWireV1>(
                &request.payload,
                MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
            )?;
            validate_billing_page_shape(&verify.page, None)?;
            if verify.network_id != *session_network_id
                || verify.page.network_id != verify.network_id
            {
                return Err(BrokerError::Rejected);
            }
            if let Some(previous) = verify.previous {
                validate_billing_journal_commitment(previous, verify.network_id)?;
            }
        }
        (slot, OPERATION_BILLING_VERIFY_PERIOD_CLOSE_V1)
            if slot == billing_journal_verifier_slot =>
        {
            let verify = decode_canonical::<BillingVerifyPeriodCloseRequestWireV1>(
                &request.payload,
                MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
            )?;
            validate_billing_period_close_shape(&verify.close, None)?;
            if verify.network_id != *session_network_id
                || verify.close.network_id != verify.network_id
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_BILLING_VERIFY_EPOCH_TRANSITION_V1)
            if slot == billing_journal_verifier_slot =>
        {
            let verify = decode_canonical::<BillingVerifyEpochTransitionRequestWireV1>(
                &request.payload,
                MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
            )?;
            verify
                .transition
                .verify()
                .map_err(|_| BrokerError::Rejected)?;
            if verify.network_id != *session_network_id
                || verify.transition.previous_service_policy.network_id != verify.network_id
                || verify.transition.next_service_policy.network_id != verify.network_id
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1)
            if slot == billing_statement_signer_slot =>
        {
            let sign = decode_canonical::<BillingSignDigestRequestWireV1>(
                &request.payload,
                MAX_BILLING_CONTROL_FRAME_BYTES_V1,
            )?;
            if sign.digest == [0; 32] {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_BILLING_PUBLISH_STATEMENT_V1)
            if slot == billing_statement_publisher_slot =>
        {
            let publish = decode_canonical::<BillingPublishStatementRequestWireV1>(
                &request.payload,
                MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
            )?;
            validate_billing_publish_request(&publish, *session_network_id)?;
        }
        (slot, OPERATION_BILLING_LOOKUP_PUBLICATION_V1)
            if slot == billing_statement_publisher_slot =>
        {
            let lookup = decode_canonical::<BillingLookupRequestWireV1>(
                &request.payload,
                MAX_BILLING_CONTROL_FRAME_BYTES_V1,
            )?;
            validate_billing_record_id(lookup.record_id)?;
        }
        (
            slot,
            OPERATION_BILLING_VERIFY_ACKNOWLEDGEMENT_V1
            | OPERATION_BILLING_RECORD_ACKNOWLEDGEMENT_V1,
        ) if slot == billing_acknowledgement_authority_slot => {
            let acknowledgement = decode_canonical::<BillingAcknowledgementRequestWireV1>(
                &request.payload,
                MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
            )?;
            validate_billing_acknowledgement_request(&acknowledgement, *session_network_id)?;
        }
        (slot, OPERATION_BILLING_LOOKUP_ACKNOWLEDGEMENT_V1)
            if slot == billing_acknowledgement_authority_slot =>
        {
            let lookup = decode_canonical::<BillingLookupRequestWireV1>(
                &request.payload,
                MAX_BILLING_CONTROL_FRAME_BYTES_V1,
            )?;
            validate_billing_record_id(lookup.record_id)?;
        }
        (slot, OPERATION_BILLING_LOAD_LATEST_EPOCH_V1)
            if slot == billing_epoch_witness_store_slot =>
        {
            decode_canonical::<()>(&request.payload, MAX_BILLING_CONTROL_FRAME_BYTES_V1)?;
        }
        (slot, OPERATION_BILLING_LOAD_EPOCH_V1) if slot == billing_epoch_witness_store_slot => {
            let load = decode_canonical::<BillingLoadEpochRequestWireV1>(
                &request.payload,
                MAX_BILLING_CONTROL_FRAME_BYTES_V1,
            )?;
            if load.epoch_sequence == 0 {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1)
            if slot == billing_epoch_witness_store_slot =>
        {
            let compare = decode_canonical::<BillingCompareAndSwapEpochRequestWireV1>(
                &request.payload,
                MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
            )?;
            if compare.expected_revision == Some([0; 32]) {
                return Err(BrokerError::Rejected);
            }
            compare
                .next
                .validate(
                    sorafs_node::hedging_billing_service::HEDGING_BILLING_MAX_CHECKPOINT_BYTES_V1,
                )
                .map_err(|_| BrokerError::Rejected)?;
        }
        (slot, OPERATION_NATIVE_TRANSACTION_SIGN_V1)
            if native_transaction_signer_role_for_slot(slot).is_some() =>
        {
            let expected = native_transaction_signer_binding_from_wire(&request.binding)?;
            let payload = decode_native_transaction_payload(&request.payload)?;
            if session_chain_id.is_some() {
                ensure_transaction_session_network(&payload, session_network_id)?;
            }
            if payload.authority() != expected.authority()
                || !iroha_torii::sorafs::native_transaction_signer::sorafs_native_transaction_payload_matches_role_v1(expected.role(), &payload)
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_NATIVE_TRANSACTION_SIGN_V1) if slot == soracloud_runtime_signer_slot => {
            let expected = soracloud_runtime_signer_binding_from_wire(&request.binding)?;
            let payload = decode_native_transaction_payload(&request.payload)?;
            if session_chain_id.is_some() {
                ensure_transaction_session_network(&payload, session_network_id)?;
            }
            if payload.authority() != expected.authority() {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_SORACLOUD_PROVENANCE_SIGN_V1) if slot == soracloud_runtime_signer_slot => {
            let sign = decode_canonical::<SoracloudProvenanceSignRequestWireV1>(
                &request.payload,
                MAX_NATIVE_TRANSACTION_FRAME_BYTES_V1,
            )?;
            let purpose =
                iroha_data_model::soracloud::SoracloudRuntimeProvenancePurposeV1::try_from_wire_id(
                    sign.purpose,
                )
                .map_err(|_| BrokerError::Rejected)?;
            if sign.preimage.is_empty()
                || sign.preimage.len() > MAX_NATIVE_TRANSACTION_PAYLOAD_BYTES_V1
            {
                return Err(BrokerError::Rejected);
            }
            iroha_data_model::soracloud::validate_soracloud_runtime_provenance_preimage_v1(
                purpose,
                &sign.preimage,
            )
            .map_err(|_| BrokerError::Rejected)?;
        }
        (slot, OPERATION_STREAM_TOKEN_SIGN_V1 | OPERATION_STREAM_TOKEN_RECOVER_V1)
            if slot == stream_token_slot =>
        {
            prepare_stream_token_broker_request(&request.binding, &request.payload)?;
        }
        (slot, OPERATION_STREAM_TOKEN_OBSERVE_V1) if slot == stream_token_slot => {
            decode_stream_token_observer_request(&request.binding, &request.payload)?;
        }
        (slot, OPERATION_STREAM_TOKEN_CHECK_V1) if slot == stream_token_slot => {
            decode_stream_token_check_request(&request.binding, &request.payload)?;
        }
        (slot, OPERATION_APPEAL_FINANCE_TRANSACTION_SIGN_V1) if slot == appeal_signer_slot => {
            let exact = request
                .binding
                .appeal_finance_signer_binding
                .as_ref()
                .ok_or(BrokerError::BindingMismatch)?;
            let payload = decode_transaction_payload_bounded(
                &request.payload,
                MAX_APPEAL_FINANCE_TRANSACTION_BYTES_V1,
            )?;
            if session_chain_id.is_some() {
                ensure_transaction_session_network(&payload, session_network_id)?;
            }
            if payload.authority() != &exact.authority {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_APPEAL_FINANCE_CHECKPOINT_SIGN_V1) if slot == appeal_checkpoint_slot => {
            let digest =
                decode_canonical::<[u8; 32]>(&request.payload, MAX_STREAM_TOKEN_FRAME_BYTES_V1)?;
            if digest == [0; 32] {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_APPEAL_FINANCE_CHECKPOINT_LOAD_V1) if slot == appeal_checkpoint_slot => {
            decode_canonical::<()>(&request.payload, MAX_STREAM_TOKEN_FRAME_BYTES_V1)?;
        }
        (slot, OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1)
            if slot == appeal_checkpoint_slot =>
        {
            let compare = decode_canonical::<AppealFinanceCheckpointCompareAndSwapWireV1>(
                &request.payload,
                MAX_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1,
            )?;
            if compare.expected_revision == Some([0; 32]) {
                return Err(BrokerError::Rejected);
            }
            let checkpoint_max = request
                .binding
                .appeal_finance_checkpoint_max_bytes
                .ok_or(BrokerError::BindingMismatch)?;
            compare
                .next
                .validate(checkpoint_max)
                .map_err(|_| BrokerError::Rejected)?;
        }
        (slot, OPERATION_POTR_SIGN_V1)
            if slot == potr_gateway_slot || slot == potr_provider_slot =>
        {
            let signing = decode_canonical::<PotrSignRequestWireV1>(
                &request.payload,
                MAX_POTR_FRAME_BYTES_V1,
            )?;
            if signing.payload.is_empty()
                || signing.payload.len() > MAX_POTR_SIGNING_PAYLOAD_BYTES_V1
                || signing.expected_public_key.is_empty()
                || signing.expected_public_key.len() > MAX_POTR_PUBLIC_KEY_BYTES_V1
            {
                return Err(BrokerError::Rejected);
            }
            let runtime = request
                .binding
                .potr_runtime_binding
                .as_ref()
                .ok_or(BrokerError::BindingMismatch)?;
            validate_potr_signing_payload(
                &signing.payload,
                runtime.baseline_admission_policy.provider_id,
            )?;
            if slot == potr_gateway_slot {
                if signing.expected_public_key.as_slice() != runtime.gateway_public_key.as_slice() {
                    return Err(BrokerError::BindingMismatch);
                }
            } else if iroha_crypto::PublicKey::from_bytes(
                iroha_crypto::Algorithm::MlDsa,
                &signing.expected_public_key,
            )
            .is_err()
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_GATEWAY_ACME_ORDER_CERTIFICATE_V1) if slot == gateway_acme_slot => {
            let order = decode_canonical::<GatewayAcmeOrderRequestWireV1>(
                &request.payload,
                MAX_GATEWAY_ACME_FRAME_BYTES_V1,
            )?;
            validate_gateway_acme_order(&order)?;
        }
        (slot, OPERATION_GATEWAY_COMPLIANCE_RESOLVE_V1) if slot == gateway_compliance_slot => {
            let resolve = decode_canonical::<GatewayComplianceResolveRequestWireV1>(
                &request.payload,
                128 * 1024,
            )?;
            validate_gateway_compliance_resolve_request(&resolve)?;
        }
        (slot, OPERATION_GATEWAY_COMPLIANCE_FETCH_V1) if slot == gateway_compliance_slot => {
            let fetch = decode_canonical::<GatewayComplianceFetchRequestWireV1>(
                &request.payload,
                MAX_GATEWAY_COMPLIANCE_FRAME_BYTES_V1,
            )?;
            validate_gateway_compliance_fetch_request(&fetch)?;
        }
        (slot, OPERATION_POP_RUNTIME_OPEN_V1) if slot == pop_registry_slot => {
            let exact = decode_canonical::<PopCredentialRuntimeBindingWireV1>(
                &request.payload,
                MAX_POP_RUNTIME_FRAME_BYTES_V1,
            )?;
            if Some(&exact) != request.binding.pop_credential_runtime_binding.as_ref() {
                return Err(BrokerError::BindingMismatch);
            }
            pop_runtime_bindings_from_wire(&request.binding)?;
        }
        (
            slot,
            OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1 | OPERATION_POP_WALLET_RECIPIENT_OPEN_V1,
        ) if slot == pop_registry_slot => {
            let open = decode_canonical::<PopRecipientOpenRequestWireV1>(
                &request.payload,
                MAX_POP_RUNTIME_FRAME_BYTES_V1,
            )?;
            validate_pop_recipient_open_request(&open, request.operation)?;
        }
        (slot, OPERATION_POP_ISSUER_SIGN_V1) if slot == pop_registry_slot => {
            let sign = decode_canonical::<PopIssuerSignRequestWireV1>(
                &request.payload,
                MAX_POP_RUNTIME_FRAME_BYTES_V1,
            )?;
            if sign.digest == [0; 32]
                || sorafs_node::pop_credentials::PopIssuerSigningPurposeV1::try_from_wire_id(
                    sign.purpose,
                )
                .is_none()
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_POP_AUTHENTICATE_V1) if slot == pop_registry_slot => {
            let authenticate = decode_canonical::<PopAuthenticateRequestWireV1>(
                &request.payload,
                MAX_POP_RUNTIME_FRAME_BYTES_V1,
            )?;
            validate_pop_authenticate_request(&authenticate)?;
        }
        (slot, OPERATION_POP_REGISTRY_SUBMIT_V1) if slot == pop_registry_slot => {
            let submit = decode_canonical::<PopRegistrySubmitRequestWireV1>(
                &request.payload,
                MAX_POP_REGISTRY_OPERATION_BYTES_V1,
            )?;
            if submit.idempotency_key == [0; 32] {
                return Err(BrokerError::Rejected);
            }
            submit
                .operation
                .validate()
                .map_err(|_| BrokerError::Rejected)?;
        }
        (slot, OPERATION_POP_REGISTRY_NEXT_V1) if slot == pop_registry_slot => {
            let next = decode_canonical::<PopRegistryNextRequestWireV1>(
                &request.payload,
                MAX_POP_RUNTIME_FRAME_BYTES_V1,
            )?;
            if let Some(cursor) = next.cursor {
                validate_pop_cursor(cursor)?;
            }
        }
        (slot, OPERATION_POP_ISSUANCE_DRAFT_V1) if slot == pop_registry_slot => {
            let draft = decode_canonical::<PopIssuanceDraftRequestWireV1>(
                &request.payload,
                MAX_POP_RUNTIME_FRAME_BYTES_V1,
            )?;
            if draft.request_id == [0; 32] || draft.now_epoch == 0 {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_POP_WALLET_WRAP_DEK_V1) if slot == pop_registry_slot => {
            let wrap = decode_canonical::<PopWalletWrapDekRequestWireV1>(
                &request.payload,
                MAX_POP_RUNTIME_FRAME_BYTES_V1,
            )?;
            if wrap.context == [0; 32] || wrap.dek == [0; 32] {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_POP_WALLET_UNWRAP_DEK_V1) if slot == pop_registry_slot => {
            let unwrap = decode_canonical::<PopWalletUnwrapDekRequestWireV1>(
                &request.payload,
                MAX_POP_RUNTIME_FRAME_BYTES_V1,
            )?;
            let exact = request
                .binding
                .pop_credential_runtime_binding
                .as_ref()
                .ok_or(BrokerError::BindingMismatch)?;
            if unwrap.key_id != exact.wallet_wrapping_key_id
                || unwrap.context == [0; 32]
                || unwrap.wrapped_dek.is_empty()
                || unwrap.wrapped_dek.len() > MAX_POP_WRAPPED_DEK_BYTES_V1
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_POP_WALLET_WITNESS_V1) if slot == pop_registry_slot => {
            let witness = decode_canonical::<PopWalletWitnessRequestWireV1>(
                &request.payload,
                MAX_POP_PROJECTION_BYTES_V1,
            )?;
            if witness.credential_commitment == [0; 32] {
                return Err(BrokerError::Rejected);
            }
            let exact = request
                .binding
                .pop_credential_runtime_binding
                .as_ref()
                .ok_or(BrokerError::BindingMismatch)?;
            validate_pop_projection(&witness.projection, exact)?;
        }
        (slot, OPERATION_POP_FINALIZED_TIME_V1) if slot == pop_registry_slot => {
            decode_canonical::<()>(&request.payload, MAX_POP_RUNTIME_FRAME_BYTES_V1)?;
        }
        (
            slot,
            OPERATION_POR_REPLAY_ARCHIVE_READINESS_V1
            | OPERATION_POR_REPLAY_ARCHIVE_CURRENT_HEAD_V1,
        ) if slot == por_replay_archive_slot => {
            decode_canonical::<()>(
                &request.payload,
                MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1,
            )?;
        }
        (slot, OPERATION_POR_REPLAY_ARCHIVE_APPEND_V1) if slot == por_replay_archive_slot => {
            let append = decode_canonical::<PorReplayArchiveAppendRequestWireV1>(
                &request.payload,
                MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1,
            )?;
            validate_por_replay_archive_append_request(&append)?;
        }
        (slot, OPERATION_POR_REPLAY_ARCHIVE_LOOKUP_V1) if slot == por_replay_archive_slot => {
            let lookup = decode_canonical::<PorReplayArchiveLookupRequestWireV1>(
                &request.payload,
                MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1,
            )?;
            validate_por_replay_archive_lookup_request(&lookup, &request.binding)?;
        }
        (slot, OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1)
            if slot == moderation_quarantine_slot =>
        {
            let wrap = decode_canonical::<ModerationQuarantineWrapDekRequestWireV1>(
                &request.payload,
                MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
            )?;
            validate_moderation_quarantine_context_and_dek(wrap.context_digest, wrap.dek)?;
        }
        (slot, OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1)
            if slot == moderation_quarantine_slot =>
        {
            let unwrap = decode_nested_canonical::<ModerationQuarantineUnwrapDekRequestWireV1>(
                &request.payload,
                MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
            )?;
            validate_moderation_quarantine_key_id(&unwrap.key_id)?;
            if unwrap.context_digest == [0; 32] {
                return Err(BrokerError::Rejected);
            }
            validate_moderation_quarantine_wrapped_dek(&unwrap.wrapped_dek)?;
        }
        (slot, OPERATION_QUALIFY_V1)
            if slot == provider_ingest_resolver_slot
                || slot == provider_ingest_checkpoint_slot
                || slot == provider_ingest_source_slot
                || slot == provider_ingest_retention_slot
                || slot == reputation_retention_slot =>
        {
            decode_canonical::<()>(&request.payload, MAX_OPERATION_FRAME_BYTES_V1)?;
        }
        (slot, OPERATION_PROVIDER_INGEST_SOURCE_READINESS_V1)
            if slot == provider_ingest_source_slot =>
        {
            decode_canonical::<()>(&request.payload, MAX_OPERATION_FRAME_BYTES_V1)?;
        }
        (slot, OPERATION_PROVIDER_INGEST_SOURCE_FETCH_V1)
            if slot == provider_ingest_source_slot =>
        {
            let fetch = decode_canonical::<ProviderIngestSourceFetchRequestWireV1>(
                &request.payload,
                MAX_PROVIDER_INGEST_SOURCE_REQUEST_BYTES_V1,
            )?;
            validate_source_fetch_request(&fetch, &request.binding, None, session_network_id)?;
        }
        (slot, OPERATION_SIGN_V1) if slot == signer_slot => {
            let signing = decode_canonical::<PurposeSignRequestWireV1>(
                &request.payload,
                MAX_OPERATION_FRAME_BYTES_V1,
            )?;
            validate_governance_purpose_signing_request(&signing, &request.binding)?;
        }
        (slot, OPERATION_GOVERNANCE_REQUEST_AUTHENTICATE_V1)
            if slot == ipfs_auth_slot || slot == head_auth_slot =>
        {
            let wire = decode_canonical::<GovernanceRequestAuthRequestWireV1>(
                &request.payload,
                MAX_GOVERNANCE_REQUEST_AUTH_FRAME_BYTES_V1,
            )?;
            let ingress =
                governance_request_ingress_binding_from_provider_binding(&request.binding)?;
            let descriptor = governance_request_auth_from_wire(&wire, ingress.max_body_bytes())?;
            let expected_scope = if slot == ipfs_auth_slot {
                sorafs_node::GovernanceDagAuthenticationScope::Ipfs
            } else {
                sorafs_node::GovernanceDagAuthenticationScope::SignedHead
            };
            if descriptor.scope() != expected_scope || descriptor.scope() != ingress.scope() {
                return Err(BrokerError::BindingMismatch);
            }
        }
        (slot, OPERATION_SEALED_LOAD_V1) if slot == checkpoint_slot => {
            let load = decode_canonical::<SealedLoadRequestWireV1>(
                &request.payload,
                MAX_OPERATION_FRAME_BYTES_V1,
            )?;
            sealed_slot_from_wire(load.slot)?;
        }
        (slot, OPERATION_SEALED_COMPARE_AND_SWAP_V1) if slot == checkpoint_slot => {
            let compare_and_swap = decode_canonical::<SealedCompareAndSwapRequestWireV1>(
                &request.payload,
                MAX_OPERATION_FRAME_BYTES_V1,
            )?;
            let slot = sealed_slot_from_wire(compare_and_swap.slot)?;
            if compare_and_swap.expected_revision == Some([0; 32]) {
                return Err(BrokerError::Rejected);
            }
            validate_sealed_record_fields(
                slot,
                compare_and_swap.next.generation,
                compare_and_swap.next.revision,
                &compare_and_swap.next.payload,
            )?;
        }
        (slot, OPERATION_SEALED_DELETE_V1) if slot == checkpoint_slot => {
            let delete = decode_canonical::<SealedDeleteRequestWireV1>(
                &request.payload,
                MAX_OPERATION_FRAME_BYTES_V1,
            )?;
            validate_sealed_delete(
                sealed_slot_from_wire(delete.slot)?,
                delete.expected_revision,
            )?;
        }
        (slot, OPERATION_PROVIDER_INGEST_RESOLVER_READINESS_V1)
            if slot == provider_ingest_resolver_slot =>
        {
            decode_canonical::<()>(&request.payload, MAX_OPERATION_FRAME_BYTES_V1)?;
        }
        (slot, OPERATION_PROVIDER_INGEST_RESOLVE_SIGNER_V1)
            if slot == provider_ingest_resolver_slot =>
        {
            let resolve = decode_canonical::<ProviderIngestResolveSignerRequestWireV1>(
                &request.payload,
                MAX_OPERATION_FRAME_BYTES_V1,
            )?;
            let context = provider_ingest_signer_context_from_wire(&resolve.context)?;
            let expected = provider_ingest_expected_signer_binding(&request.binding)?;
            if !expected
                .qualification
                .matches_authority(&context.expected_authority.completion_signer)
                || expected.qualification.signer_policy != context.expected_authority.signer_policy
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        (slot, OPERATION_PROVIDER_INGEST_SIGN_V1) if slot == provider_ingest_signer_slot => {
            let (context, _expected, payload) = decode_provider_ingest_sign_operation(request)?;
            ensure_provider_ingest_completion_payload_context(&payload, &context)?;
            if session_chain_id.is_some() {
                ensure_transaction_session_network(&payload, session_network_id)?;
            }
        }
        (slot, OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1)
            if slot == provider_ingest_checkpoint_slot =>
        {
            let version = decode_canonical::<u8>(
                &request.payload,
                MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1,
            )?;
            if version != CHECKPOINT_LOAD_REQUEST_VERSION_V1 {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1)
            if slot == provider_ingest_checkpoint_slot =>
        {
            let compare = decode_canonical::<ProviderIngestCheckpointCompareAndSwapRequestWireV1>(
                &request.payload,
                MAX_OPERATION_FRAME_BYTES_V1,
            )?;
            if compare.expected_revision == Some([0; 32]) {
                return Err(BrokerError::Rejected);
            }
            let checkpoint_max = request
                .binding
                .provider_ingest_checkpoint_max_bytes
                .ok_or(BrokerError::BindingMismatch)?;
            let checkpoint_limit =
                usize::try_from(checkpoint_max).map_err(|_| BrokerError::Rejected)?;
            reserve_external_canonical_decode(compare.next_record.len(), checkpoint_limit)?;
            sorafs_node::ProviderIngestSealedCheckpointRecordV1::from_canonical_bytes(
                &compare.next_record,
                checkpoint_max,
            )
            .map_err(|_| BrokerError::Rejected)?;
        }
        (slot, OPERATION_PROVIDER_INGEST_RETENTION_LOAD_V1)
            if slot == provider_ingest_retention_slot =>
        {
            let load = decode_canonical::<ProviderIngestRetentionLoadRequestWireV1>(
                &request.payload,
                MAX_OPERATION_FRAME_BYTES_V1,
            )?;
            if session_network_id != &load.network_id {
                return Err(BrokerError::BindingMismatch);
            }
        }
        (slot, OPERATION_PROVIDER_INGEST_RETENTION_COMPARE_AND_SWAP_V1)
            if slot == provider_ingest_retention_slot =>
        {
            let compare = decode_canonical::<ProviderIngestRetentionCompareAndSwapRequestWireV1>(
                &request.payload,
                MAX_OPERATION_FRAME_BYTES_V1,
            )?;
            if session_network_id != &compare.network_id {
                return Err(BrokerError::BindingMismatch);
            }
            if compare.expected_revision == Some([0; 32]) {
                return Err(BrokerError::Rejected);
            }
            reserve_external_canonical_decode(
                compare.next_record.len(),
                MAX_PROVIDER_INGEST_RETENTION_APPROVAL_BYTES_V1,
            )?;
            let next = iroha_core::query::provider_ingest_finalized::
                    ProviderIngestFinalizedArchiveRetentionApprovalRecordV1::from_canonical_bytes(
                        &compare.next_record,
                    )
                    .map_err(|_| BrokerError::Rejected)?;
            let expected = qualification_from_binding(&request.binding)?;
            let actual = next.authority_qualification();
            if actual.revision() != expected.revision
                || actual.policy_digest() != expected.policy_digest
                || next.predecessor_revision() != compare.expected_revision
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        (slot, OPERATION_REPUTATION_RETENTION_LOAD_V1) if slot == reputation_retention_slot => {
            let load = decode_canonical::<ReputationRetentionLoadRequestWireV1>(
                &request.payload,
                MAX_REPUTATION_RETENTION_FRAME_BYTES_V1,
            )?;
            if session_network_id != &load.network_id {
                return Err(BrokerError::BindingMismatch);
            }
        }
        (slot, OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1)
            if slot == reputation_retention_slot =>
        {
            let compare = decode_canonical::<ReputationRetentionCompareAndSwapRequestWireV1>(
                &request.payload,
                MAX_REPUTATION_RETENTION_FRAME_BYTES_V1,
            )?;
            if session_network_id != &compare.network_id {
                return Err(BrokerError::BindingMismatch);
            }
            if compare.expected_revision == Some([0; 32])
                || compare.next_record.is_empty()
                || compare.next_record.len() > MAX_REPUTATION_RETENTION_APPROVAL_BYTES_V1
            {
                return Err(BrokerError::Rejected);
            }
            reserve_external_canonical_decode(
                compare.next_record.len(),
                MAX_REPUTATION_RETENTION_APPROVAL_BYTES_V1,
            )?;
            let next = iroha_core::query::reputation_finalized::
                    ReputationFinalizedArchiveRetentionApprovalRecordV1::from_canonical_bytes(
                        &compare.next_record,
                    )
                    .map_err(|_| BrokerError::Rejected)?;
            let expected = qualification_from_binding(&request.binding)?;
            let actual = next.authority_qualification();
            if actual.revision() != expected.revision
                || actual.policy_digest() != expected.policy_digest
                || next.predecessor_revision() != compare.expected_revision
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        (slot, OPERATION_QUALIFY_V1)
            if slot == evidence_webauthn_slot
                || slot == evidence_grants_slot
                || slot == evidence_receipt_signer_slot
                || slot == evidence_erasure_slot
                || slot == evidence_checkpoint_slot
                || slot == moderation_checkpoint_slot
                || slot == evidence_archive_slot
                || slot == evidence_transparency_publisher_slot =>
        {
            decode_canonical::<()>(&request.payload, MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1)?;
        }
        (slot, OPERATION_EVIDENCE_VIEWER_ISSUE_CHALLENGE_V1) if slot == evidence_webauthn_slot => {
            let issue = decode_canonical::<EvidenceViewerIssueChallengeRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )?;
            let webauthn = request
                .binding
                .evidence_viewer_webauthn_binding
                .as_ref()
                .ok_or(BrokerError::BindingMismatch)?;
            let lifetime = issue
                .expires_at_unix_ms
                .checked_sub(issue.issued_at_unix_ms)
                .ok_or(BrokerError::Rejected)?;
            if issue.binding_digest == [0; 32]
                || issue.issued_at_unix_ms == 0
                || lifetime != webauthn.challenge_ttl_ms
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_EVIDENCE_VIEWER_VERIFY_AND_CONSUME_V1)
            if slot == evidence_webauthn_slot =>
        {
            let verify = decode_canonical::<EvidenceViewerVerifyAndConsumeRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )?;
            let webauthn = request
                .binding
                .evidence_viewer_webauthn_binding
                .as_ref()
                .ok_or(BrokerError::BindingMismatch)?;
            validate_evidence_viewer_secret(&verify.challenge)?;
            if verify.assertion.is_empty()
                || verify.assertion.len()
                    > sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_WEBAUTHN_ASSERTION_BYTES_V1
                || verify.binding_digest == [0; 32]
                || verify.rp_id != webauthn.rp_id
                || verify.allowed_origins != webauthn.allowed_origins
                || verify.now_unix_ms == 0
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_EVIDENCE_VIEWER_GRANT_ISSUE_V1) if slot == evidence_grants_slot => {
            let issue = decode_canonical::<EvidenceViewerGrantIssueRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_CLAIMS_BYTES_V1,
            )?;
            validate_evidence_viewer_grant_claims(&issue.claims, &request.binding)?;
        }
        (slot, OPERATION_EVIDENCE_VIEWER_GRANT_VERIFY_V1) if slot == evidence_grants_slot => {
            let verify = decode_canonical::<EvidenceViewerGrantVerifyRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )?;
            validate_evidence_viewer_secret(&verify.token)?;
            validate_evidence_viewer_grant_claims(&verify.claims, &request.binding)?;
            if verify.now_unix_ms < verify.claims.issued_at_unix_ms
                || verify.now_unix_ms >= verify.claims.expires_at_unix_ms
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_EVIDENCE_VIEWER_GRANT_REVOKE_V1) if slot == evidence_grants_slot => {
            let revoke = decode_canonical::<EvidenceViewerGrantRevokeRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )?;
            if revoke.token_digest == [0; 32] {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_EVIDENCE_VIEWER_RECEIPT_SIGN_V1)
            if slot == evidence_receipt_signer_slot =>
        {
            let sign = decode_canonical::<PurposeSignRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )?;
            validate_evidence_purpose_signing_request(&sign, &request.binding)?;
        }
        (slot, OPERATION_EVIDENCE_VIEWER_ERASE_V1) if slot == evidence_erasure_slot => {
            let erase = decode_canonical::<EvidenceViewerEraseRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )?;
            if erase.operation_id == [0; 32]
                || erase.quarantine_id == [0; 16]
                || erase.object_id == [0; 16]
                || erase.evidence_digest == [0; 32]
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_EVIDENCE_VIEWER_CHECKPOINT_LOAD_V1)
            if slot == evidence_checkpoint_slot =>
        {
            decode_canonical::<()>(&request.payload, MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1)?;
        }
        (slot, OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1)
            if slot == evidence_checkpoint_slot =>
        {
            let compare = decode_canonical::<EvidenceViewerCheckpointCompareAndSwapRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
            )?;
            if compare.expected_revision == Some([0; 32]) {
                return Err(BrokerError::Rejected);
            }
            decode_evidence_viewer_checkpoint_record(&compare.next_record, &request.binding)?;
        }
        (slot, OPERATION_MODERATION_CHECKPOINT_LOAD_V1) if slot == moderation_checkpoint_slot => {
            decode_canonical::<()>(&request.payload, MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1)?;
        }
        (slot, OPERATION_MODERATION_CHECKPOINT_COMPARE_AND_SWAP_V1)
            if slot == moderation_checkpoint_slot =>
        {
            let compare = decode_canonical::<EvidenceViewerCheckpointCompareAndSwapRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
            )?;
            if compare.expected_revision == Some([0; 32]) {
                return Err(BrokerError::Rejected);
            }
            decode_moderation_checkpoint_record(
                &compare.next_record,
                &request.binding,
                Some(session_network_id),
            )?;
        }
        (slot, OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1) if slot == evidence_archive_slot => {
            let install = decode_canonical::<EvidenceViewerArchiveInstallRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
            )?;
            let max_bytes = usize::try_from(
                request
                    .binding
                    .evidence_viewer_archive_max_bytes
                    .ok_or(BrokerError::BindingMismatch)?,
            )
            .map_err(|_| BrokerError::Rejected)?;
            if install.operation_id == [0; 32]
                || install.receipt_message == [0; 32]
                || install.canonical_artifact.is_empty()
                || install.canonical_artifact.len() > max_bytes
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_EVIDENCE_VIEWER_ARCHIVE_READ_V1) if slot == evidence_archive_slot => {
            let read = decode_canonical::<EvidenceViewerArchiveReadRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )?;
            if read.operation_id == [0; 32] {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_QUALIFY_V1)
            if slot == moderation_panel_notification_archive_slot =>
        {
            let qualify = decode_canonical::<ModerationPanelNotificationArchiveQualifyRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )?;
            validate_moderation_panel_notification_archive_wire_scope(
                qualify.version,
                qualify.slot,
                &qualify.network_id,
                session_network_id,
            )?;
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1)
            if slot == moderation_panel_notification_archive_slot =>
        {
            let install = decode_canonical::<ModerationPanelNotificationArchiveInstallRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
            )?;
            validate_moderation_panel_notification_archive_wire_scope(
                install.version,
                install.slot,
                &install.network_id,
                session_network_id,
            )?;
            let max_bytes = usize::try_from(
                request
                    .binding
                    .moderation_panel_notification_archive_binding
                    .ok_or(BrokerError::BindingMismatch)?
                    .max_bytes,
            )
            .map_err(|_| BrokerError::Rejected)?;
            if install.operation_id == [0; 32]
                || install.receipt_message == [0; 32]
                || install.canonical_artifact.is_empty()
                || install.canonical_artifact.len() > max_bytes
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1)
            if slot == moderation_panel_notification_archive_slot =>
        {
            let read = decode_canonical::<ModerationPanelNotificationArchiveReadRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )?;
            validate_moderation_panel_notification_archive_wire_scope(
                read.version,
                read.slot,
                &read.network_id,
                session_network_id,
            )?;
            if read.operation_id == [0; 32] {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_MODERATION_PANEL_NOTIFICATION_SOURCE_ATTEST_V1)
            if slot == moderation_checkpoint_slot =>
        {
            let attest = decode_canonical::<ModerationPanelNotificationSourceAttestRequestWireV1>(
                &request.payload,
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )?;
            validate_moderation_panel_notification_source_attest_wire_scope(
                attest.version,
                attest.slot,
                &attest.network_id,
                session_network_id,
            )?;
            let statement = &attest.statement;
            if statement.version
                != sorafs_node::moderation_orchestrator::
                    MODERATION_PANEL_NOTIFICATION_ARCHIVE_VERSION_V1
                || statement.attestor_slot != slot
                || statement.network_id != attest.network_id
                || statement.checkpoint_namespace_digest == [0; 32]
                || statement.checkpoint_generation == 0
                || statement.checkpoint_revision == [0; 32]
                || statement.checkpoint_digest == [0; 32]
                || statement.terminal_set_digest == [0; 32]
                || statement.terminal_record_count == 0
                || usize::try_from(statement.terminal_record_count).map_or(true, |count| {
                    count
                        > sorafs_node::moderation_orchestrator::
                            MODERATION_PANEL_NOTIFICATION_ARCHIVE_MAX_RECORDS_V1
                })
                || statement.first_notification_id == [0; 32]
                || statement.last_notification_id == [0; 32]
                || statement.first_notification_id > statement.last_notification_id
                || statement.attestor_handle != request.binding.handle
                || Some(statement.attestor_revision) != request.binding.revision
                || Some(statement.attestor_policy_digest) != request.binding.policy_digest
                || Some(statement.attestor_public_key)
                    != request.binding.moderation_checkpoint_attestation_public_key
            {
                return Err(BrokerError::Rejected);
            }
        }
        (slot, OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1)
            if slot == evidence_transparency_publisher_slot =>
        {
            decode_canonical::<()>(&request.payload, MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1)?;
        }
        (slot, OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1)
            if slot == evidence_transparency_publisher_slot =>
        {
            let body = decode_canonical::<
                    sorafs_node::evidence_viewer::transparency_producer::
                        EvidenceViewerTransparencyHeadBodyV1,
                >(
                    &request.payload, MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1
                )?;
            validate_evidence_viewer_transparency_head_body(&body, &request.binding)?;
        }
        _ => return Err(BrokerError::BindingMismatch),
    }
    Ok(())
}
fn validate_moderation_panel_notification_archive_wire_scope(
    version: u16,
    slot: u16,
    network_id: &NetworkId,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    if version != MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1
        || slot != IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id()
        || slot != sorafs_node::moderation_orchestrator::
            MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_SLOT_V1
        || network_id != session_network_id
    {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(())
}
fn validate_moderation_panel_notification_source_attest_wire_scope(
    version: u16,
    slot: u16,
    network_id: &NetworkId,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    if version != MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1
        || slot != IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id()
        || slot
            != sorafs_node::moderation_orchestrator::
                MODERATION_PANEL_NOTIFICATION_SOURCE_ATTESTOR_BROKER_SLOT_V1
        || network_id != session_network_id
    {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(())
}
