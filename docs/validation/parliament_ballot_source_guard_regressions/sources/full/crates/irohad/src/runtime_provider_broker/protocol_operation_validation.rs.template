const fn operation_decode_policy(operation: u16) -> DecodeResourcePolicyV1 {
    match operation {
        OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1
        | OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1
        | OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1 => GLOBAL_BEACON_DECODE_POLICY_V1,
        OPERATION_STREAM_TOKEN_SIGN_V1
        | OPERATION_STREAM_TOKEN_RECOVER_V1
        | OPERATION_STREAM_TOKEN_OBSERVE_V1
        | OPERATION_STREAM_TOKEN_CHECK_V1 => STREAM_TOKEN_HARDWARE_DECODE_POLICY_V1,
        OPERATION_BILLING_IDENTITY_V1
        | OPERATION_BILLING_READINESS_V1
        | OPERATION_BILLING_QUERY_CAPABILITIES_V1
        | OPERATION_BILLING_FINALIZED_HEAD_V1
        | OPERATION_BILLING_QUERY_PAGE_V1
        | OPERATION_BILLING_QUERY_PERIOD_CLOSE_V1
        | OPERATION_BILLING_VERIFY_PAGE_V1
        | OPERATION_BILLING_VERIFY_PERIOD_CLOSE_V1
        | OPERATION_BILLING_VERIFY_EPOCH_TRANSITION_V1
        | OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1
        | OPERATION_BILLING_PUBLISH_STATEMENT_V1
        | OPERATION_BILLING_LOOKUP_PUBLICATION_V1
        | OPERATION_BILLING_VERIFY_ACKNOWLEDGEMENT_V1
        | OPERATION_BILLING_RECORD_ACKNOWLEDGEMENT_V1
        | OPERATION_BILLING_LOOKUP_ACKNOWLEDGEMENT_V1
        | OPERATION_BILLING_LOAD_LATEST_EPOCH_V1
        | OPERATION_BILLING_LOAD_EPOCH_V1
        | OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1 => BILLING_DECODE_POLICY_V1,
        OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1
        | OPERATION_REPUTATION_JOURNAL_SUBMIT_V1
        | OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1
        | OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1
        | OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1
        | OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1 => {
            REPUTATION_DECODE_POLICY_V1
        }
        OPERATION_SIGN_V1 | OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1 => {
            GOVERNANCE_BULK_DECODE_POLICY_V1
        }
        OPERATION_SEALED_LOAD_V1
        | OPERATION_SEALED_COMPARE_AND_SWAP_V1
        | OPERATION_SEALED_DELETE_V1 => GOVERNANCE_SEALED_STATE_DECODE_POLICY_V1,
        OPERATION_PROVIDER_INGEST_SOURCE_FETCH_V1 => SOURCE_PLAN_DECODE_POLICY_V1,
        OPERATION_PROVIDER_INGEST_SIGN_V1 => PROVIDER_INGEST_SIGN_DECODE_POLICY_V1,
        OPERATION_APPEAL_FINANCE_CHECKPOINT_LOAD_V1
        | OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1 => {
            APPEAL_CHECKPOINT_DECODE_POLICY_V1
        }
        OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1
        | OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1 => {
            PROVIDER_INGEST_CHECKPOINT_DECODE_POLICY_V1
        }
        OPERATION_EVIDENCE_VIEWER_CHECKPOINT_LOAD_V1
        | OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1
        | OPERATION_MODERATION_CHECKPOINT_LOAD_V1
        | OPERATION_MODERATION_CHECKPOINT_COMPARE_AND_SWAP_V1
        | OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1
        | OPERATION_EVIDENCE_VIEWER_ARCHIVE_READ_V1
        | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1
        | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1
        | OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1
        | OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1 => {
            EVIDENCE_BULK_DECODE_POLICY_V1
        }
        OPERATION_PROVIDER_INGEST_RETENTION_COMPARE_AND_SWAP_V1
        | OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1
        | OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1
        | OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1
        | OPERATION_EVIDENCE_VIEWER_VERIFY_AND_CONSUME_V1
        | OPERATION_GATEWAY_ACME_ORDER_CERTIFICATE_V1
        | OPERATION_GATEWAY_COMPLIANCE_RESOLVE_V1
        | OPERATION_GATEWAY_COMPLIANCE_FETCH_V1 => OPAQUE_BLOB_DECODE_POLICY_V1,
        _ => STANDARD_DECODE_POLICY_V1,
    }
}
const fn operation_semantic_frame_limit(operation: u16) -> usize {
    match operation {
        OPERATION_SIGN_V1 => MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1,
        OPERATION_GOVERNANCE_REQUEST_AUTHENTICATE_V1 => MAX_GOVERNANCE_REQUEST_AUTH_FRAME_BYTES_V1,
        OPERATION_NATIVE_TRANSACTION_SIGN_V1 | OPERATION_SORACLOUD_PROVENANCE_SIGN_V1 => {
            MAX_NATIVE_TRANSACTION_FRAME_BYTES_V1
        }
        OPERATION_STREAM_TOKEN_SIGN_V1
        | OPERATION_STREAM_TOKEN_RECOVER_V1
        | OPERATION_STREAM_TOKEN_OBSERVE_V1
        | OPERATION_STREAM_TOKEN_CHECK_V1 => MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
        OPERATION_APPEAL_FINANCE_CHECKPOINT_SIGN_V1 => MAX_STREAM_TOKEN_FRAME_BYTES_V1,
        OPERATION_APPEAL_FINANCE_TRANSACTION_SIGN_V1 => {
            MAX_APPEAL_FINANCE_TRANSACTION_FRAME_BYTES_V1
        }
        OPERATION_APPEAL_FINANCE_CHECKPOINT_LOAD_V1
        | OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1 => {
            MAX_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1
        }
        OPERATION_SEALED_LOAD_V1
        | OPERATION_SEALED_COMPARE_AND_SWAP_V1
        | OPERATION_SEALED_DELETE_V1 => MAX_GOVERNANCE_SEALED_STATE_FRAME_BYTES_V1,
        OPERATION_POTR_SIGN_V1 => MAX_POTR_FRAME_BYTES_V1,
        OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1 => MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1
        | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1 => {
            MAX_MODERATION_HANDOFF_FRAME_BYTES_V1
        }
        OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1 => {
            MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1
        }
        OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1
        | OPERATION_REPUTATION_JOURNAL_SUBMIT_V1
        | OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1
        | OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1 => MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
        OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1
        | OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1 => {
            MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1
        }
        OPERATION_BILLING_IDENTITY_V1
        | OPERATION_BILLING_READINESS_V1
        | OPERATION_BILLING_QUERY_CAPABILITIES_V1
        | OPERATION_BILLING_FINALIZED_HEAD_V1
        | OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1
        | OPERATION_BILLING_LOOKUP_ACKNOWLEDGEMENT_V1 => MAX_BILLING_CONTROL_FRAME_BYTES_V1,
        OPERATION_BILLING_QUERY_PAGE_V1
        | OPERATION_BILLING_QUERY_PERIOD_CLOSE_V1
        | OPERATION_BILLING_VERIFY_PAGE_V1
        | OPERATION_BILLING_VERIFY_PERIOD_CLOSE_V1
        | OPERATION_BILLING_VERIFY_EPOCH_TRANSITION_V1
        | OPERATION_BILLING_PUBLISH_STATEMENT_V1
        | OPERATION_BILLING_LOOKUP_PUBLICATION_V1
        | OPERATION_BILLING_VERIFY_ACKNOWLEDGEMENT_V1
        | OPERATION_BILLING_RECORD_ACKNOWLEDGEMENT_V1
        | OPERATION_BILLING_LOAD_LATEST_EPOCH_V1
        | OPERATION_BILLING_LOAD_EPOCH_V1
        | OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1 => MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
        OPERATION_PROVIDER_INGEST_RESOLVER_READINESS_V1
        | OPERATION_PROVIDER_INGEST_RESOLVE_SIGNER_V1
        | OPERATION_PROVIDER_INGEST_SOURCE_READINESS_V1 => {
            MAX_PROVIDER_INGEST_CONTROL_FRAME_BYTES_V1
        }
        OPERATION_PROVIDER_INGEST_SIGN_V1 => MAX_PROVIDER_INGEST_SIGNER_FRAME_BYTES_V1,
        OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1
        | OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1 => {
            MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1
        }
        OPERATION_PROVIDER_INGEST_RETENTION_LOAD_V1
        | OPERATION_PROVIDER_INGEST_RETENTION_COMPARE_AND_SWAP_V1 => {
            MAX_PROVIDER_INGEST_RETENTION_FRAME_BYTES_V1
        }
        OPERATION_PROVIDER_INGEST_SOURCE_FETCH_V1 => {
            MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1
        }
        OPERATION_QUALIFY_V1 => MAX_QUALIFICATION_FRAME_BYTES_V1,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_QUALIFY_V1
        | OPERATION_MODERATION_PANEL_NOTIFICATION_SOURCE_ATTEST_V1 => {
            MAX_BROKER_UNARY_FRAME_BYTES_V1
        }
        OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1
        | OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1 => MAX_MODERATION_QUARANTINE_FRAME_BYTES_V1,
        OPERATION_EVIDENCE_VIEWER_ISSUE_CHALLENGE_V1
        | OPERATION_EVIDENCE_VIEWER_VERIFY_AND_CONSUME_V1
        | OPERATION_EVIDENCE_VIEWER_GRANT_ISSUE_V1
        | OPERATION_EVIDENCE_VIEWER_GRANT_VERIFY_V1
        | OPERATION_EVIDENCE_VIEWER_GRANT_REVOKE_V1
        | OPERATION_EVIDENCE_VIEWER_RECEIPT_SIGN_V1
        | OPERATION_EVIDENCE_VIEWER_ERASE_V1 => MAX_EVIDENCE_VIEWER_CONTROL_FRAME_BYTES_V1,
        OPERATION_EVIDENCE_VIEWER_CHECKPOINT_LOAD_V1
        | OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1
        | OPERATION_MODERATION_CHECKPOINT_LOAD_V1
        | OPERATION_MODERATION_CHECKPOINT_COMPARE_AND_SWAP_V1
        | OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1
        | OPERATION_EVIDENCE_VIEWER_ARCHIVE_READ_V1
        | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1
        | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1
        | OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1
        | OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1 => {
            MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1
        }
        OPERATION_REPUTATION_RETENTION_LOAD_V1
        | OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1 => {
            MAX_REPUTATION_RETENTION_FRAME_BYTES_V1
        }
        OPERATION_GATEWAY_ACME_ORDER_CERTIFICATE_V1 => MAX_GATEWAY_ACME_FRAME_BYTES_V1,
        OPERATION_GATEWAY_COMPLIANCE_RESOLVE_V1 => 128 * 1024,
        OPERATION_GATEWAY_COMPLIANCE_FETCH_V1 => MAX_GATEWAY_COMPLIANCE_FRAME_BYTES_V1,
        OPERATION_POP_RUNTIME_OPEN_V1
        | OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1
        | OPERATION_POP_WALLET_RECIPIENT_OPEN_V1
        | OPERATION_POP_ISSUER_SIGN_V1
        | OPERATION_POP_AUTHENTICATE_V1
        | OPERATION_POP_REGISTRY_SUBMIT_V1
        | OPERATION_POP_REGISTRY_NEXT_V1
        | OPERATION_POP_ISSUANCE_DRAFT_V1
        | OPERATION_POP_WALLET_WRAP_DEK_V1
        | OPERATION_POP_WALLET_UNWRAP_DEK_V1
        | OPERATION_POP_WALLET_WITNESS_V1
        | OPERATION_POP_FINALIZED_TIME_V1 => MAX_POP_RUNTIME_FRAME_BYTES_V1,
        OPERATION_POR_REPLAY_ARCHIVE_READINESS_V1
        | OPERATION_POR_REPLAY_ARCHIVE_CURRENT_HEAD_V1 => {
            MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1
        }
        OPERATION_POR_REPLAY_ARCHIVE_APPEND_V1 | OPERATION_POR_REPLAY_ARCHIVE_LOOKUP_V1 => {
            MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1
        }
        OPERATION_PRIVACY_CYCLE_PRF_DERIVE_V1 => MAX_TRANSPARENCY_PRF_FRAME_BYTES_V1,
        OPERATION_PRIVACY_RELEASE_ANCHOR_FINALIZED_HEAD_V1
        | OPERATION_PRIVACY_RELEASE_ANCHOR_COMPARE_AND_SET_V1 => {
            MAX_PRIVACY_RELEASE_ANCHOR_FRAME_BYTES_V1
        }
        OPERATION_TRANSPARENCY_LEADER_LEASE_ACQUIRE_V1
        | OPERATION_TRANSPARENCY_LEADER_LEASE_RENEW_V1
        | OPERATION_TRANSPARENCY_LEADER_LEASE_RELEASE_V1 => {
            MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1
        }
        OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1 => {
            MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1
        }
        OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1 => {
            MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1
        }
        OPERATION_BOOTLE_LANTERN_ISSUANCE_AUTHENTICATE_V1
        | OPERATION_BOOTLE_LANTERN_ISSUANCE_PREPARE_AUTHORIZATION_V1
        | OPERATION_BOOTLE_LANTERN_ISSUANCE_VALIDATE_REQUEST_V1
        | OPERATION_BOOTLE_LANTERN_ISSUANCE_ISSUE_VALIDATED_V1 => {
            MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1
        }
        OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1
        | OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1
        | OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1
        | OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1
        | OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1 => MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        _ => MAX_BROKER_UNARY_FRAME_BYTES_V1,
    }
}
const fn operation_frame_limit(operation: u16) -> usize {
    let semantic_limit = operation_semantic_frame_limit(operation);
    let broker_limit = match operation {
        OPERATION_SIGN_V1 => MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1,
        OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1
        | OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1
        | OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1
        | OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1
        | OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1 => MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        OPERATION_SEALED_LOAD_V1
        | OPERATION_SEALED_COMPARE_AND_SWAP_V1
        | OPERATION_SEALED_DELETE_V1 => MAX_GOVERNANCE_SEALED_STATE_FRAME_BYTES_V1,
        OPERATION_PROVIDER_INGEST_SIGN_V1 => MAX_PROVIDER_INGEST_SIGNER_FRAME_BYTES_V1,
        OPERATION_APPEAL_FINANCE_CHECKPOINT_LOAD_V1
        | OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1 => {
            MAX_BROKER_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1
        }
        OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1
        | OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1 => {
            MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1
        }
        OPERATION_EVIDENCE_VIEWER_CHECKPOINT_LOAD_V1
        | OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1
        | OPERATION_MODERATION_CHECKPOINT_LOAD_V1
        | OPERATION_MODERATION_CHECKPOINT_COMPARE_AND_SWAP_V1
        | OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1
        | OPERATION_EVIDENCE_VIEWER_ARCHIVE_READ_V1
        | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1
        | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1
        | OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1
        | OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1 => {
            MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1
        }
        OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1
        | OPERATION_REPUTATION_JOURNAL_SUBMIT_V1
        | OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1
        | OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1 => MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
        OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1
        | OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1 => {
            MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1
        }
        OPERATION_BILLING_QUERY_PAGE_V1
        | OPERATION_BILLING_QUERY_PERIOD_CLOSE_V1
        | OPERATION_BILLING_VERIFY_PAGE_V1
        | OPERATION_BILLING_VERIFY_PERIOD_CLOSE_V1
        | OPERATION_BILLING_VERIFY_EPOCH_TRANSITION_V1
        | OPERATION_BILLING_PUBLISH_STATEMENT_V1
        | OPERATION_BILLING_LOOKUP_PUBLICATION_V1
        | OPERATION_BILLING_VERIFY_ACKNOWLEDGEMENT_V1
        | OPERATION_BILLING_RECORD_ACKNOWLEDGEMENT_V1
        | OPERATION_BILLING_LOAD_LATEST_EPOCH_V1
        | OPERATION_BILLING_LOAD_EPOCH_V1
        | OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1 => MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
        OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1 => {
            MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1
        }
        _ => MAX_BROKER_UNARY_FRAME_BYTES_V1,
    };
    if semantic_limit < broker_limit {
        semantic_limit
    } else {
        broker_limit
    }
}
const fn operation_is_known(operation: u16) -> bool {
    matches!(
        operation,
        OPERATION_QUALIFY_V1
            | OPERATION_SIGN_V1
            | OPERATION_GOVERNANCE_REQUEST_AUTHENTICATE_V1
            | OPERATION_NATIVE_TRANSACTION_SIGN_V1
            | OPERATION_SORACLOUD_PROVENANCE_SIGN_V1
            | OPERATION_STREAM_TOKEN_SIGN_V1
            | OPERATION_STREAM_TOKEN_RECOVER_V1
            | OPERATION_STREAM_TOKEN_OBSERVE_V1
            | OPERATION_STREAM_TOKEN_CHECK_V1
            | OPERATION_APPEAL_FINANCE_TRANSACTION_SIGN_V1
            | OPERATION_APPEAL_FINANCE_CHECKPOINT_SIGN_V1
            | OPERATION_APPEAL_FINANCE_CHECKPOINT_LOAD_V1
            | OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1
            | OPERATION_SEALED_LOAD_V1
            | OPERATION_SEALED_COMPARE_AND_SWAP_V1
            | OPERATION_SEALED_DELETE_V1
            | OPERATION_POTR_SIGN_V1
            | OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1
            | OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1
            | OPERATION_REPUTATION_JOURNAL_SUBMIT_V1
            | OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1
            | OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1
            | OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1
            | OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1
            | OPERATION_BILLING_IDENTITY_V1
            | OPERATION_BILLING_READINESS_V1
            | OPERATION_BILLING_QUERY_CAPABILITIES_V1
            | OPERATION_BILLING_FINALIZED_HEAD_V1
            | OPERATION_BILLING_QUERY_PAGE_V1
            | OPERATION_BILLING_QUERY_PERIOD_CLOSE_V1
            | OPERATION_BILLING_VERIFY_PAGE_V1
            | OPERATION_BILLING_VERIFY_PERIOD_CLOSE_V1
            | OPERATION_BILLING_VERIFY_EPOCH_TRANSITION_V1
            | OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1
            | OPERATION_BILLING_PUBLISH_STATEMENT_V1
            | OPERATION_BILLING_LOOKUP_PUBLICATION_V1
            | OPERATION_BILLING_VERIFY_ACKNOWLEDGEMENT_V1
            | OPERATION_BILLING_RECORD_ACKNOWLEDGEMENT_V1
            | OPERATION_BILLING_LOOKUP_ACKNOWLEDGEMENT_V1
            | OPERATION_BILLING_LOAD_LATEST_EPOCH_V1
            | OPERATION_BILLING_LOAD_EPOCH_V1
            | OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1
            | OPERATION_PROVIDER_INGEST_RESOLVER_READINESS_V1
            | OPERATION_PROVIDER_INGEST_RESOLVE_SIGNER_V1
            | OPERATION_PROVIDER_INGEST_SIGN_V1
            | OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1
            | OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1
            | OPERATION_PROVIDER_INGEST_RETENTION_LOAD_V1
            | OPERATION_PROVIDER_INGEST_RETENTION_COMPARE_AND_SWAP_V1
            | OPERATION_PROVIDER_INGEST_SOURCE_READINESS_V1
            | OPERATION_PROVIDER_INGEST_SOURCE_FETCH_V1
            | OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1
            | OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1
            | OPERATION_EVIDENCE_VIEWER_ISSUE_CHALLENGE_V1
            | OPERATION_EVIDENCE_VIEWER_VERIFY_AND_CONSUME_V1
            | OPERATION_EVIDENCE_VIEWER_GRANT_ISSUE_V1
            | OPERATION_EVIDENCE_VIEWER_GRANT_VERIFY_V1
            | OPERATION_EVIDENCE_VIEWER_GRANT_REVOKE_V1
            | OPERATION_EVIDENCE_VIEWER_RECEIPT_SIGN_V1
            | OPERATION_EVIDENCE_VIEWER_ERASE_V1
            | OPERATION_EVIDENCE_VIEWER_CHECKPOINT_LOAD_V1
            | OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1
            | OPERATION_MODERATION_CHECKPOINT_LOAD_V1
            | OPERATION_MODERATION_CHECKPOINT_COMPARE_AND_SWAP_V1
            | OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1
            | OPERATION_EVIDENCE_VIEWER_ARCHIVE_READ_V1
            | OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1
            | OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1
            | OPERATION_REPUTATION_RETENTION_LOAD_V1
            | OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1
            | OPERATION_GATEWAY_ACME_ORDER_CERTIFICATE_V1
            | OPERATION_GATEWAY_COMPLIANCE_RESOLVE_V1
            | OPERATION_GATEWAY_COMPLIANCE_FETCH_V1
            | OPERATION_POP_RUNTIME_OPEN_V1
            | OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1
            | OPERATION_POP_WALLET_RECIPIENT_OPEN_V1
            | OPERATION_POP_ISSUER_SIGN_V1
            | OPERATION_POP_AUTHENTICATE_V1
            | OPERATION_POP_REGISTRY_SUBMIT_V1
            | OPERATION_POP_REGISTRY_NEXT_V1
            | OPERATION_POP_ISSUANCE_DRAFT_V1
            | OPERATION_POP_WALLET_WRAP_DEK_V1
            | OPERATION_POP_WALLET_UNWRAP_DEK_V1
            | OPERATION_POP_WALLET_WITNESS_V1
            | OPERATION_POP_FINALIZED_TIME_V1
            | OPERATION_POR_REPLAY_ARCHIVE_READINESS_V1
            | OPERATION_POR_REPLAY_ARCHIVE_CURRENT_HEAD_V1
            | OPERATION_POR_REPLAY_ARCHIVE_APPEND_V1
            | OPERATION_POR_REPLAY_ARCHIVE_LOOKUP_V1
            | OPERATION_PRIVACY_CYCLE_PRF_DERIVE_V1
            | OPERATION_PRIVACY_RELEASE_ANCHOR_FINALIZED_HEAD_V1
            | OPERATION_PRIVACY_RELEASE_ANCHOR_COMPARE_AND_SET_V1
            | OPERATION_TRANSPARENCY_LEADER_LEASE_ACQUIRE_V1
            | OPERATION_TRANSPARENCY_LEADER_LEASE_RENEW_V1
            | OPERATION_TRANSPARENCY_LEADER_LEASE_RELEASE_V1
            | OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1
            | OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_QUALIFY_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_SOURCE_ATTEST_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1
            | OPERATION_BOOTLE_LANTERN_ISSUANCE_AUTHENTICATE_V1
            | OPERATION_BOOTLE_LANTERN_ISSUANCE_PREPARE_AUTHORIZATION_V1
            | OPERATION_BOOTLE_LANTERN_ISSUANCE_VALIDATE_REQUEST_V1
            | OPERATION_BOOTLE_LANTERN_ISSUANCE_ISSUE_VALIDATED_V1
            | OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1
            | OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1
            | OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1
            | OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1
            | OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1
    )
}
fn provider_ingest_signer_context_from_wire(
    context: &ProviderIngestSignerRequestContextWireV1,
) -> Result<sorafs_node::ProviderIngestCompletionSignerResolutionContextV1, BrokerError> {
    let authority = decode_canonical::<
        iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionAuthorityV1,
    >(
        &context.expected_authority,
        MAX_PROVIDER_INGEST_AUTHORITY_BYTES_V1,
    )?;
    for account in [&authority.provider_owner, &authority.completion_signer] {
        let canonical = encode_canonical(account, MAX_PROVIDER_INGEST_ACCOUNT_BYTES_V1)?;
        validate_provider_ingest_account_canonical_bytes(&canonical)?;
    }
    let context = sorafs_node::ProviderIngestCompletionSignerResolutionContextV1::new(
        authority,
        context.expected_assignment_revision,
        sorafs_node::ProviderIngestFinalizedCursorV1 {
            height: context.finalized_height,
            block_hash: context.finalized_block_hash,
        },
    );
    if !context.is_valid() {
        return Err(BrokerError::Rejected);
    }
    Ok(context)
}
fn validate_provider_ingest_account_canonical_bytes(
    canonical_account: &[u8],
) -> Result<(), BrokerError> {
    if canonical_account.is_empty()
        || canonical_account.len() > MAX_PROVIDER_INGEST_ACCOUNT_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn provider_ingest_signer_context_to_wire(
    context: &sorafs_node::ProviderIngestCompletionSignerResolutionContextV1,
) -> Result<ProviderIngestSignerRequestContextWireV1, BrokerError> {
    if !context.is_valid() {
        return Err(BrokerError::Rejected);
    }
    let expected_authority = encode_canonical(
        &context.expected_authority,
        MAX_PROVIDER_INGEST_AUTHORITY_BYTES_V1,
    )?;
    Ok(ProviderIngestSignerRequestContextWireV1 {
        expected_authority,
        expected_assignment_revision: context.expected_assignment_revision,
        finalized_height: context.finalized_cursor.height,
        finalized_block_hash: context.finalized_cursor.block_hash,
    })
}
fn provider_ingest_expected_signer_binding(
    binding: &ProviderBindingWireV1,
) -> Result<sorafs_node::ProviderIngestCompletionSignerBindingV1, BrokerError> {
    required_binding_ref!(binding, provider_ingest_signer_binding).to_binding()
}
fn ensure_transaction_session_network(
    payload: &iroha_data_model::transaction::TransactionPayload,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    if payload.network_id() != Some(session_network_id) {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(())
}
fn ensure_provider_ingest_completion_payload(
    payload: &iroha_data_model::transaction::TransactionPayload,
    context: &sorafs_node::ProviderIngestCompletionSignerResolutionContextV1,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    ensure_transaction_session_network(payload, session_network_id)?;
    ensure_provider_ingest_completion_payload_context(payload, context)
}
fn ensure_provider_ingest_completion_payload_context(
    payload: &iroha_data_model::transaction::TransactionPayload,
    context: &sorafs_node::ProviderIngestCompletionSignerResolutionContextV1,
) -> Result<(), BrokerError> {
    if !context.is_valid() {
        return Err(BrokerError::Rejected);
    }
    if payload.authority() != &context.expected_authority.completion_signer {
        return Err(BrokerError::BindingMismatch);
    }
    let iroha_data_model::transaction::Executable::Instructions(instructions) =
        payload.instructions()
    else {
        return Err(BrokerError::Rejected);
    };
    if instructions.len() != 1 {
        return Err(BrokerError::Rejected);
    }
    let completion = instructions[0]
        .as_any()
        .downcast_ref::<iroha_data_model::isi::sorafs::CompleteReplicationOrder>()
        .ok_or(BrokerError::Rejected)?;
    let authority = completion.expected_authority();
    let anchor = completion.finalized_anchor();
    if completion.order_id().as_bytes() == &[0; 32]
        || completion.provider_id().as_bytes() == &[0; 32]
        || *completion.completion_epoch() == 0
        || *completion.expected_assignment_revision() == 0
        || anchor.height == 0
        || anchor.block_hash == [0; 32]
        || !authority.is_valid()
    {
        return Err(BrokerError::Rejected);
    }
    if authority != &context.expected_authority
        || *completion.expected_assignment_revision() != context.expected_assignment_revision
        || anchor.height != context.finalized_cursor.height
        || anchor.block_hash != context.finalized_cursor.block_hash
    {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(())
}
fn ensure_provider_ingest_completion_transaction(
    transaction: &iroha_data_model::transaction::SignedTransaction,
    context: &sorafs_node::ProviderIngestCompletionSignerResolutionContextV1,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    ensure_provider_ingest_completion_payload(transaction.payload(), context, session_network_id)?;
    if transaction.attachments().is_some()
        || transaction.multisig_signatures().is_some()
        || transaction.verify_signature().is_err()
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn decode_provider_ingest_sign_operation(
    request: &OperationRequestV1,
) -> Result<
    (
        sorafs_node::ProviderIngestCompletionSignerResolutionContextV1,
        sorafs_node::ProviderIngestCompletionSignerBindingV1,
        iroha_data_model::transaction::TransactionPayload,
    ),
    BrokerError,
> {
    let sign = decode_canonical::<ProviderIngestSignRequestWireV1>(
        &request.payload,
        MAX_OPERATION_FRAME_BYTES_V1,
    )?;
    let context = provider_ingest_signer_context_from_wire(&sign.context)?;
    let expected = provider_ingest_expected_signer_binding(&request.binding)?;
    if !expected
        .qualification
        .matches_authority(&context.expected_authority.completion_signer)
        || expected.qualification.signer_policy != context.expected_authority.signer_policy
    {
        return Err(BrokerError::BindingMismatch);
    }
    let max_signed = usize::try_from(required_binding_value!(
        &request.binding,
        provider_ingest_max_signed_transaction_bytes
    ))
    .map_err(|_| BrokerError::Rejected)?;
    let payload = decode_canonical::<iroha_data_model::transaction::TransactionPayload>(
        &sign.transaction_payload,
        max_signed,
    )?;
    Ok((context, expected, payload))
}
fn validate_evidence_viewer_secret(secret: &[u8]) -> Result<&str, BrokerError> {
    if secret.is_empty()
        || secret.len() > sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_OPAQUE_TOKEN_BYTES_V1
        || !secret.is_ascii()
        || secret
            .iter()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(BrokerError::Rejected);
    }
    std::str::from_utf8(secret).map_err(|_| BrokerError::Rejected)
}
fn validate_evidence_viewer_grant_claims(
    claims: &sorafs_node::evidence_viewer::EvidenceViewerGrantClaimsV1,
    binding: &ProviderBindingWireV1,
) -> Result<(), BrokerError> {
    let grant_ttl_ms = required_binding_value!(binding, evidence_viewer_grant_ttl_ms);
    let lifetime = claims
        .expires_at_unix_ms
        .checked_sub(claims.issued_at_unix_ms)
        .ok_or(BrokerError::Rejected)?;
    if claims.session_id == [0; 16]
        || claims.quarantine_id == [0; 16]
        || claims.purpose_digest == [0; 32]
        || claims.issuance_nonce == [0; 32]
        || claims.generation == 0
        || claims.issued_at_unix_ms == 0
        || lifetime == 0
        || lifetime > grant_ttl_ms
        || [&claims.case_id, &claims.round_id, &claims.viewer_account]
            .into_iter()
            .any(|value| {
                value.is_empty()
                    || value.len() > MAX_PROVIDER_HANDLE_BYTES_V1
                    || value.as_bytes().contains(&0)
                    || value.chars().any(char::is_control)
            })
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_evidence_viewer_transparency_head_body(
    body: &sorafs_node::evidence_viewer::transparency_producer::
        EvidenceViewerTransparencyHeadBodyV1,
    binding: &ProviderBindingWireV1,
) -> Result<(), BrokerError> {
    let lineage_is_valid = match body.generation {
        1 => body.predecessor_head_digest.is_none(),
        2.. => body
            .predecessor_head_digest
            .is_some_and(|digest| digest != [0; 32]),
        0 => false,
    };
    if body.version
        != sorafs_node::evidence_viewer::transparency_producer::
            EVIDENCE_VIEWER_TRANSPARENCY_HEAD_VERSION_V1
        || !lineage_is_valid
        || body.operation_id == [0; 32]
        || body.source_projection_digest == [0; 32]
        || body.source_page_limit == 0
        || body.source_page_limit > 1_024
        || body.publisher_handle != binding.handle
        || Some(body.publisher_revision) != binding.revision
        || Some(body.publisher_policy_digest) != binding.policy_digest
        || Some(body.publisher_public_key)
            != binding.evidence_viewer_transparency_publisher_public_key
        || iroha_crypto::PublicKey::from_bytes(
            iroha_crypto::Algorithm::Ed25519,
            &body.publisher_public_key,
        )
        .is_err()
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn evidence_viewer_checkpoint_record_limit(
    binding: &ProviderBindingWireV1,
) -> Result<usize, BrokerError> {
    let checkpoint_max = usize::try_from(required_binding_value!(
        binding,
        evidence_viewer_checkpoint_max_bytes
    ))
    .map_err(|_| BrokerError::Rejected)?;
    checkpoint_max
        .checked_add(16 * 1024)
        .filter(|limit| *limit <= MAX_EVIDENCE_VIEWER_ARCHIVE_BYTES_V1)
        .ok_or(BrokerError::Rejected)
}
fn decode_evidence_viewer_checkpoint_record(
    bytes: &[u8],
    binding: &ProviderBindingWireV1,
) -> Result<sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreRecordV1, BrokerError> {
    let max_record = evidence_viewer_checkpoint_record_limit(binding)?;
    let record = decode_canonical::<
        sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreRecordV1,
    >(bytes, max_record)?;
    let checkpoint_max = usize::try_from(required_binding_value!(
        binding,
        evidence_viewer_checkpoint_max_bytes
    ))
    .map_err(|_| BrokerError::Rejected)?;
    let predecessor_shape_is_valid = match record.generation {
        1 => {
            record.predecessor_revision.is_none() && record.predecessor_checkpoint_digest.is_none()
        }
        2.. => {
            record
                .predecessor_revision
                .is_some_and(|revision| revision != [0; 32])
                && record
                    .predecessor_checkpoint_digest
                    .is_some_and(|digest| digest != [0; 32])
        }
        0 => false,
    };
    if record.version
        != sorafs_node::evidence_viewer::EVIDENCE_VIEWER_CHECKPOINT_STORE_RECORD_VERSION_V1
        || !predecessor_shape_is_valid
        || record.checkpoint_digest == [0; 32]
        || record.checkpoint_bytes.is_empty()
        || record.checkpoint_bytes.len() > checkpoint_max
        || record.checkpoint_store_handle != binding.handle
        || Some(record.checkpoint_store_revision) != binding.revision
        || Some(record.checkpoint_store_policy_digest) != binding.policy_digest
        || record.signer_handle.is_empty()
        || record.signer_handle.len() > MAX_PROVIDER_HANDLE_BYTES_V1
        || record.signer_handle.as_bytes().contains(&0)
        || record.signer_public_key == [0; 32]
        || iroha_crypto::PublicKey::from_bytes(
            iroha_crypto::Algorithm::Ed25519,
            &record.signer_public_key,
        )
        .is_err()
        || record.signature == [0; 64]
        || record.revision == [0; 32]
    {
        return Err(BrokerError::Rejected);
    }
    Ok(record)
}
fn validate_evidence_viewer_checkpoint_successor(
    current: Option<&sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreRecordV1>,
    expected_revision: Option<[u8; 32]>,
    next: &sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreRecordV1,
) -> Result<(), BrokerError> {
    if current.map(|record| record.revision) != expected_revision {
        return Err(BrokerError::Conflict);
    }
    let monotonic = current.map_or_else(
        || {
            next.generation == 1
                && next.predecessor_revision.is_none()
                && next.predecessor_checkpoint_digest.is_none()
        },
        |previous| {
            previous
                .generation
                .checked_add(1)
                .is_some_and(|generation| generation == next.generation)
                && next.predecessor_revision == Some(previous.revision)
                && next.predecessor_checkpoint_digest == Some(previous.checkpoint_digest)
        },
    );
    if !monotonic {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn moderation_checkpoint_record_limit(
    binding: &ProviderBindingWireV1,
) -> Result<usize, BrokerError> {
    let max_bytes = required_binding_value!(binding, moderation_checkpoint_max_bytes);
    usize::try_from(max_bytes)
        .map(|max_bytes| max_bytes.saturating_add(16 * 1024))
        .map_err(|_| BrokerError::BindingMismatch)
}
fn decode_moderation_checkpoint_record(
    bytes: &[u8],
    binding: &ProviderBindingWireV1,
    expected_network_id: Option<&NetworkId>,
) -> Result<sorafs_node::moderation_orchestrator::ModerationCheckpointStoreRecordV1, BrokerError> {
    let record = decode_canonical::<
        sorafs_node::moderation_orchestrator::ModerationCheckpointStoreRecordV1,
    >(bytes, moderation_checkpoint_record_limit(binding)?)?;
    let qualification =
        sorafs_node::moderation_orchestrator::ModerationRuntimeProviderQualificationV1::new(
            required_binding_value!(binding, revision),
            required_binding_value!(binding, policy_digest),
        );
    if expected_network_id.is_some_and(|expected| record.network_id != *expected)
        || !record.has_valid_provider_envelope(
            &binding.handle,
            qualification,
            required_binding_value!(binding, moderation_checkpoint_max_bytes),
        )
    {
        return Err(BrokerError::Rejected);
    }
    Ok(record)
}
fn validate_moderation_checkpoint_successor(
    current: Option<&sorafs_node::moderation_orchestrator::ModerationCheckpointStoreRecordV1>,
    expected_revision: Option<[u8; 32]>,
    next: &sorafs_node::moderation_orchestrator::ModerationCheckpointStoreRecordV1,
) -> Result<(), BrokerError> {
    if current.map(|record| record.revision) != expected_revision {
        return Err(BrokerError::Conflict);
    }
    let monotonic = current.map_or_else(
        || {
            next.checkpoint_generation == 0
                && next.predecessor_revision.is_none()
                && next.predecessor_checkpoint_digest.is_none()
        },
        |previous| {
            previous
                .checkpoint_generation
                .checked_add(1)
                .is_some_and(|generation| generation == next.checkpoint_generation)
                && next.namespace_digest == previous.namespace_digest
                && next.predecessor_revision == Some(previous.revision)
                && next.predecessor_checkpoint_digest == Some(previous.checkpoint_digest)
        },
    );
    if !monotonic {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn moderation_checkpoint_backend_error(
    error: sorafs_node::moderation_orchestrator::ModerationCheckpointStoreExternalErrorV1,
) -> BrokerError {
    match error {
        sorafs_node::moderation_orchestrator::ModerationCheckpointStoreExternalErrorV1::Unavailable => {
            BrokerError::Unavailable
        }
        sorafs_node::moderation_orchestrator::ModerationCheckpointStoreExternalErrorV1::Rejected => {
            BrokerError::Rejected
        }
        sorafs_node::moderation_orchestrator::ModerationCheckpointStoreExternalErrorV1::Ambiguous => {
            BrokerError::Ambiguous
        }
    }
}
fn moderation_panel_notification_archive_backend_error(
    error: sorafs_node::moderation_orchestrator::ModerationPanelNotificationArchiveExternalErrorV1,
) -> BrokerError {
    match error {
        sorafs_node::moderation_orchestrator::
            ModerationPanelNotificationArchiveExternalErrorV1::Unavailable => {
                BrokerError::Unavailable
            }
        sorafs_node::moderation_orchestrator::
            ModerationPanelNotificationArchiveExternalErrorV1::Ambiguous => {
                BrokerError::Ambiguous
            }
        sorafs_node::moderation_orchestrator::
            ModerationPanelNotificationArchiveExternalErrorV1::Rejected => {
                BrokerError::Rejected
            }
    }
}
fn validate_moderation_panel_notification_archive_artifact_at_broker_boundary(
    canonical_artifact: &[u8],
    network_id: &NetworkId,
    archive_binding: &ProviderBindingWireV1,
    catalog: &[ProviderBindingWireV1],
) -> Result<
    sorafs_node::moderation_orchestrator::ModerationPanelNotificationArchiveBrokerValidationV1,
    BrokerError,
> {
    let checkpoint_binding = catalog
        .iter()
        .find(|binding| {
            binding.slot == IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id()
        })
        .ok_or(BrokerError::BindingMismatch)?;
    let archive = archive_binding
        .moderation_panel_notification_archive_binding
        .ok_or(BrokerError::BindingMismatch)?;
    let archive_qualification =
        sorafs_node::moderation_orchestrator::ModerationRuntimeProviderQualificationV1::new(
            archive_binding
                .revision
                .ok_or(BrokerError::BindingMismatch)?,
            archive_binding
                .policy_digest
                .ok_or(BrokerError::BindingMismatch)?,
        );
    let checkpoint_qualification =
        sorafs_node::moderation_orchestrator::ModerationRuntimeProviderQualificationV1::new(
            checkpoint_binding
                .revision
                .ok_or(BrokerError::BindingMismatch)?,
            checkpoint_binding
                .policy_digest
                .ok_or(BrokerError::BindingMismatch)?,
        );
    let max_records =
        usize::try_from(archive.max_records).map_err(|_| BrokerError::BindingMismatch)?;
    let expectation = sorafs_node::moderation_orchestrator::
        ModerationPanelNotificationArchiveBrokerExpectationV1 {
            network_id,
            archive_handle: &archive_binding.handle,
            archive_qualification,
            archive_id: archive.archive_id,
            archive_bootstrap_public_key: archive.bootstrap_public_key,
            archive_public_key: archive.public_key,
            checkpoint_handle: &checkpoint_binding.handle,
            checkpoint_qualification,
            checkpoint_attestation_public_key: checkpoint_binding
                .moderation_checkpoint_attestation_public_key
                .ok_or(BrokerError::BindingMismatch)?,
            checkpoint_max_bytes: checkpoint_binding
                .moderation_checkpoint_max_bytes
                .ok_or(BrokerError::BindingMismatch)?,
            archive_max_bytes: archive.max_bytes,
            max_records,
        };
    sorafs_node::moderation_orchestrator::
        validate_moderation_panel_notification_archive_artifact_for_broker_v1(
            canonical_artifact,
            &expectation,
        )
        .map_err(|_| BrokerError::Rejected)
}
fn validate_moderation_panel_notification_archive_readback_at_broker_boundary(
    canonical_artifact: &[u8],
    network_id: &NetworkId,
    archive_binding: &ProviderBindingWireV1,
    catalog: &[ProviderBindingWireV1],
) -> Result<
    sorafs_node::moderation_orchestrator::ModerationPanelNotificationArchiveBrokerValidationV1,
    BrokerError,
> {
    let checkpoint_binding = catalog
        .iter()
        .find(|binding| {
            binding.slot == IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id()
        })
        .ok_or(BrokerError::BindingMismatch)?;
    let archive = archive_binding
        .moderation_panel_notification_archive_binding
        .ok_or(BrokerError::BindingMismatch)?;
    let archive_qualification =
        sorafs_node::moderation_orchestrator::ModerationRuntimeProviderQualificationV1::new(
            archive_binding
                .revision
                .ok_or(BrokerError::BindingMismatch)?,
            archive_binding
                .policy_digest
                .ok_or(BrokerError::BindingMismatch)?,
        );
    let checkpoint_qualification =
        sorafs_node::moderation_orchestrator::ModerationRuntimeProviderQualificationV1::new(
            checkpoint_binding
                .revision
                .ok_or(BrokerError::BindingMismatch)?,
            checkpoint_binding
                .policy_digest
                .ok_or(BrokerError::BindingMismatch)?,
        );
    let max_records =
        usize::try_from(archive.max_records).map_err(|_| BrokerError::BindingMismatch)?;
    let expectation = sorafs_node::moderation_orchestrator::
        ModerationPanelNotificationArchiveBrokerExpectationV1 {
            network_id,
            archive_handle: &archive_binding.handle,
            archive_qualification,
            archive_id: archive.archive_id,
            archive_bootstrap_public_key: archive.bootstrap_public_key,
            archive_public_key: archive.public_key,
            checkpoint_handle: &checkpoint_binding.handle,
            checkpoint_qualification,
            checkpoint_attestation_public_key: checkpoint_binding
                .moderation_checkpoint_attestation_public_key
                .ok_or(BrokerError::BindingMismatch)?,
            checkpoint_max_bytes: checkpoint_binding
                .moderation_checkpoint_max_bytes
                .ok_or(BrokerError::BindingMismatch)?,
            archive_max_bytes: archive.max_bytes,
            max_records,
        };
    sorafs_node::moderation_orchestrator::
        validate_moderation_panel_notification_archive_readback_for_broker_v1(
            canonical_artifact,
            &expectation,
        )
        .map_err(|_| BrokerError::Rejected)
}
fn validate_moderation_panel_notification_source_attestation_at_broker_boundary(
    statement: &sorafs_node::moderation_orchestrator::
        ModerationPanelNotificationSourceAttestationV1,
    network_id: &NetworkId,
    binding: &ProviderBindingWireV1,
    current_record: &sorafs_node::moderation_orchestrator::ModerationCheckpointStoreRecordV1,
) -> Result<[u8; 32], BrokerError> {
    let qualification =
        sorafs_node::moderation_orchestrator::ModerationRuntimeProviderQualificationV1::new(
            required_binding_value!(binding, revision),
            required_binding_value!(binding, policy_digest),
        );
    let canonical_record =
        encode_canonical(current_record, moderation_checkpoint_record_limit(binding)?)?;
    let validated_record =
        decode_moderation_checkpoint_record(&canonical_record, binding, Some(network_id))?;
    if &validated_record != current_record {
        return Err(BrokerError::Rejected);
    }
    sorafs_node::moderation_orchestrator::
        validate_moderation_panel_notification_source_attestation_for_broker_v1(
            statement,
            network_id,
            &binding.handle,
            qualification,
            required_binding_value!(binding, moderation_checkpoint_attestation_public_key),
            current_record,
        )
        .map_err(|_| BrokerError::Rejected)
}
fn verify_evidence_viewer_ed25519_signature(
    public_key: [u8; 32],
    signature: [u8; 64],
    message: &[u8],
) -> Result<(), BrokerError> {
    let public_key =
        iroha_crypto::PublicKey::from_bytes(iroha_crypto::Algorithm::Ed25519, &public_key)
            .map_err(|_| BrokerError::BindingMismatch)?;
    iroha_crypto::Signature::try_from_bytes(&signature)
        .map_err(|_| BrokerError::Rejected)?
        .verify(&public_key, message)
        .map_err(|_| BrokerError::Rejected)
}

fn beacon_session_error(
    error: &iroha_core::beacon::GlobalThresholdBeaconSessionError,
) -> BrokerError {
    use iroha_allocation::{
        ChargedBufferError, ChargedBufferFromChargeError, PrepaidBufferError, PrepaidSharedError,
    };
    use iroha_core::beacon::GlobalThresholdBeaconSessionError as Error;
    use iroha_crypto::{PublicKeyAllocationError, SignatureAllocationError};
    match error {
        Error::Invalid(_) => BrokerError::Rejected,
        Error::Admission(_)
        | Error::DecodeResource(_)
        | Error::Buffer(PrepaidBufferError::Allocation(
            ChargedBufferError::Admission(_) | ChargedBufferError::Allocator { .. },
        ))
        | Error::Shared(PrepaidSharedError::Allocator { .. })
        | Error::PublicKey(PublicKeyAllocationError::Allocation(
            ChargedBufferFromChargeError::Allocator { .. },
        ))
        | Error::Signature(SignatureAllocationError::Allocation(
            ChargedBufferFromChargeError::Allocator { .. },
        )) => BrokerError::Unavailable,
        // Impossible ownership/geometry differences are local protocol faults,
        // never completed user rejection or a fabricated capacity release.
        _ => BrokerError::Protocol,
    }
}

fn retain_operation_beacon_session(
    record: &iroha_data_model::consensus::GlobalThresholdBeaconKeySessionV1,
    binding: &iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1,
) -> Result<iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1, BrokerError> {
    current_decode_resource_admission()
        .ok_or(BrokerError::Unavailable)?
        .retain_beacon_session(record, binding)
}

fn global_beacon_aggregator_from_sign_request(
    request: &GlobalBeaconPartialSignRequestWireV1,
    session_network_id: &NetworkId,
) -> Result<iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1, BrokerError> {
    if request.session.network_id != *session_network_id {
        return Err(BrokerError::BindingMismatch);
    }
    let binding = iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1 {
        network_id: *session_network_id,
        session_id: request.session.session_id,
        roster_hash: request.session.roster_hash,
        transcript_hash: request.session.transcript_hash,
    };
    let session = retain_operation_beacon_session(&request.session, &binding)?;
    iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
        session,
        request.height,
        request.finalized_chain_anchor,
        request.context,
    )
    .map_err(|_| BrokerError::Rejected)
}

fn decode_global_beacon_partial_sign_request(
    payload: &[u8],
    session_network_id: &NetworkId,
) -> Result<
    (
        GlobalBeaconPartialSignRequestWireV1,
        iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1,
    ),
    BrokerError,
> {
    let request = decode_canonical_with_policy::<GlobalBeaconPartialSignRequestWireV1>(
        payload,
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        GLOBAL_BEACON_DECODE_POLICY_V1,
    )?;
    let aggregator = global_beacon_aggregator_from_sign_request(&request, session_network_id)?;
    Ok((request, aggregator))
}

fn decode_global_beacon_seat_readiness_request(
    payload: &[u8],
    session_network_id: &NetworkId,
) -> Result<
    (
        GlobalBeaconSeatReadinessRequestWireV1,
        iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
    ),
    BrokerError,
> {
    let request = decode_canonical_with_policy::<GlobalBeaconSeatReadinessRequestWireV1>(
        payload,
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        GLOBAL_BEACON_DECODE_POLICY_V1,
    )?;
    if request.session.network_id != *session_network_id {
        return Err(BrokerError::BindingMismatch);
    }
    let binding = iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1 {
        network_id: *session_network_id,
        session_id: request.session.session_id,
        roster_hash: request.session.roster_hash,
        transcript_hash: request.session.transcript_hash,
    };
    let session = retain_operation_beacon_session(&request.session, &binding)?;
    iroha_core::beacon::seat_readiness::global_threshold_beacon_seat_readiness_challenge_v1(
        &session,
        &request.authority,
        &request.context,
    )
    .map_err(|_| BrokerError::Rejected)?;
    Ok((request, session))
}

fn decode_parliament_tle_partial_release_sign_request(
    payload: &[u8],
    session_network_id: &NetworkId,
) -> Result<
    (
        ParliamentTlePartialReleaseSignRequestWireV1,
        iroha_core_timed_ovn::tle::ValidatedTleReleaseProjectionV1,
    ),
    BrokerError,
> {
    let request = decode_canonical::<ParliamentTlePartialReleaseSignRequestWireV1>(
        payload,
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )?;
    if request.projection.key_session.network_id != *session_network_id.as_bytes() {
        return Err(BrokerError::BindingMismatch);
    }
    let projection = request
        .projection
        .clone()
        .validate()
        .map_err(|_| BrokerError::Rejected)?;
    Ok((request, projection))
}

fn decode_parliament_tle_capability_attest_request(
    payload: &[u8],
    session_network_id: &NetworkId,
) -> Result<
    (
        ParliamentTleCapabilityAttestRequestWireV1,
        iroha_core_timed_ovn::tle::ValidatedTleKeySessionV1,
    ),
    BrokerError,
> {
    let request = decode_canonical::<ParliamentTleCapabilityAttestRequestWireV1>(
        payload,
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )?;
    if request.key_session.network_id != *session_network_id.as_bytes() {
        return Err(BrokerError::BindingMismatch);
    }
    let session = request
        .key_session
        .clone()
        .validate()
        .map_err(|_| BrokerError::Rejected)?;
    iroha_core::tle_release::TlePartialReleaseCapabilityAttestationV1::for_validated_session(
        &session,
        request.participant_index,
    )
    .map_err(|_| BrokerError::Rejected)?;
    Ok((request, session))
}

fn verify_parliament_tle_capability_attest_result(
    session: &iroha_core_timed_ovn::tle::ValidatedTleKeySessionV1,
    participant_index: u16,
    result: &ParliamentTleCapabilityAttestResultWireV1,
) -> Result<(), BrokerError> {
    let expected =
        iroha_core::tle_release::TlePartialReleaseCapabilityAttestationV1::for_validated_session(
            session,
            participant_index,
        )
        .map_err(|_| BrokerError::Rejected)?;
    if result.key_session_id != expected.key_session_id()
        || result.transcript_hash != expected.transcript_hash()
        || result.participant_index != expected.participant_index()
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}

fn decode_global_beacon_capability_attest_request(
    payload: &[u8],
    session_network_id: &NetworkId,
) -> Result<
    (
        GlobalBeaconCapabilityAttestRequestWireV1,
        iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
    ),
    BrokerError,
> {
    let request = decode_canonical_with_policy::<GlobalBeaconCapabilityAttestRequestWireV1>(
        payload,
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        GLOBAL_BEACON_DECODE_POLICY_V1,
    )?;
    if request.session.network_id != *session_network_id {
        return Err(BrokerError::BindingMismatch);
    }
    let binding = iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1 {
        network_id: *session_network_id,
        session_id: request.session.session_id,
        roster_hash: request.session.roster_hash,
        transcript_hash: request.session.transcript_hash,
    };
    let session = retain_operation_beacon_session(&request.session, &binding)?;
    iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1::for_validated_session(
        &session,
        request.signer_index,
    )
    .map_err(|_| BrokerError::Rejected)?;
    Ok((request, session))
}

fn verify_global_beacon_capability_attest_result(
    session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
    signer_index: u16,
    result: &GlobalBeaconCapabilityAttestResultWireV1,
) -> Result<(), BrokerError> {
    let expected =
        iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1::for_validated_session(
            session,
            signer_index,
        )
        .map_err(|_| BrokerError::Rejected)?;
    if result.session_id != expected.session_id()
        || result.transcript_hash != expected.transcript_hash()
        || result.signer_index != expected.signer_index()
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}

fn verify_parliament_tle_partial_release_result(
    projection: &iroha_core_timed_ovn::tle::ValidatedTleReleaseProjectionV1,
    partial: &iroha_core_timed_ovn::tle::TlePartialReleaseShareV1,
) -> Result<(), BrokerError> {
    projection
        .session()
        .verify_partial_release(
            projection.identity(),
            projection.finalized_height(),
            partial,
        )
        .map(|_| ())
        .map_err(|_| BrokerError::Rejected)
}
include!("governance_request_ingress.rs");
include!("validate_operation_payload.rs");
fn validate_operation_response(
    request: &OperationRequestV1,
    response: &OperationResponseV1,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    validate_operation_response_envelope(request, response)
        .map_err(|error| error.service_error())?;
    match response.status {
        STATUS_OK_V1
        | STATUS_REJECTED_V1
        | STATUS_CONFLICT_V1
        | STATUS_STALE_OR_REVOKED_V1
        | STATUS_AMBIGUOUS_V1
        | STATUS_UNAVAILABLE_V1 => validate_operation_result(
            request,
            response.status,
            &response.result,
            session_network_id,
        ),
        _ => Err(BrokerError::Protocol),
    }
}
fn validate_operation_response_for_client(
    request: &OperationRequestV1,
    response: &OperationResponseV1,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    validate_operation_response_envelope(request, response)
        .map_err(|error| error.service_error())?;
    let threshold_typed_caller = matches!(
        (request.binding.slot, request.operation),
        (slot, OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1 | OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1)
            if slot == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id()
    ) || matches!(
        (request.binding.slot, request.operation),
        (slot, OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1)
            if slot == IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id()
    ) || matches!(
        (request.binding.slot, request.operation),
        (slot, OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1)
            if slot == IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id()
    ) || matches!(
        (request.binding.slot, request.operation),
        (slot, OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1)
            if slot == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id()
    );
    if response.status == STATUS_OK_V1
        && (matches!(
            request.operation,
            OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1
                | OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1
        ) || threshold_typed_caller)
    {
        // The typed caller decodes and validates the full result exactly once
        // while the response-owned admission remains live. Repeating a large
        // sealed-record decode would multiply the composed reservation, while
        // repeating a complete threshold transcript reconstruction can exhaust
        // the daemon's ordinary thread stack. The authenticated server still
        // performs its independent semantic validation before responding.
        return Ok(());
    }
    validate_operation_result(
        request,
        response.status,
        &response.result,
        session_network_id,
    )
}
fn validate_operation_response_envelope(
    request: &OperationRequestV1,
    response: &OperationResponseV1,
) -> Result<(), CanonicalAttemptErrorV1> {
    if response.session_id != request.session_id
        || response.request_id != request.request_id
        || response.request_digest != request.request_digest
        || response.observed_binding.ne(&request.binding)
        || response.provider_metadata_digest != request.provider_metadata_digest
        || response.operation != request.operation
        || response.payload_digest != request.payload_digest
        || operation_result_digest(&response.result) != response.result_digest
    {
        return Err(BrokerError::Protocol.into());
    }
    let fields = OperationResponseFieldsV1 {
        session_id: response.session_id,
        request_id: response.request_id,
        request_digest: response.request_digest,
        observed_binding: response.observed_binding.clone(),
        provider_metadata_digest: response.provider_metadata_digest,
        operation: response.operation,
        payload_digest: response.payload_digest,
        status: response.status,
        result_digest: response.result_digest,
        result_len: u64::try_from(response.result.len()).map_err(|_| BrokerError::Protocol)?,
    };
    if operation_response_digest(&fields)? != response.response_digest {
        return Err(BrokerError::Protocol.into());
    }
    if !matches!(
        response.status,
        STATUS_OK_V1
            | STATUS_REJECTED_V1
            | STATUS_CONFLICT_V1
            | STATUS_STALE_OR_REVOKED_V1
            | STATUS_AMBIGUOUS_V1
            | STATUS_UNAVAILABLE_V1
    ) {
        return Err(BrokerError::Protocol.into());
    }
    Ok(())
}
#[expect(
    clippy::if_not_else,
    reason = "the fail-closed branch and fixed V1 result matrix remain explicit"
)]
fn validate_operation_result(
    request: &OperationRequestV1,
    status: u8,
    result: &[u8],
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    if status == STATUS_CONFLICT_V1
        && !matches!(
            request.operation,
            OPERATION_SEALED_COMPARE_AND_SWAP_V1
                | OPERATION_SEALED_DELETE_V1
                | OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1
                | OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1
                | OPERATION_PROVIDER_INGEST_RETENTION_COMPARE_AND_SWAP_V1
                | OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1
                | OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1
                | OPERATION_MODERATION_CHECKPOINT_COMPARE_AND_SWAP_V1
                | OPERATION_PRIVACY_RELEASE_ANCHOR_COMPARE_AND_SET_V1
                | OPERATION_TRANSPARENCY_LEADER_LEASE_ACQUIRE_V1
                | OPERATION_TRANSPARENCY_LEADER_LEASE_RENEW_V1
                | OPERATION_TRANSPARENCY_LEADER_LEASE_RELEASE_V1
                | OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1
                | OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1
                | OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1
                | OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1
        )
    {
        return Err(BrokerError::Protocol);
    }
    if status == STATUS_AMBIGUOUS_V1
        && !matches!(
            request.operation,
            OPERATION_STREAM_TOKEN_SIGN_V1
                | OPERATION_STREAM_TOKEN_CHECK_V1
                | OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1
                | OPERATION_REPUTATION_JOURNAL_SUBMIT_V1
                | OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1
                | OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1
                | OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1
                | OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1
                | OPERATION_SEALED_COMPARE_AND_SWAP_V1
                | OPERATION_SEALED_DELETE_V1
                | OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1
                | OPERATION_PROVIDER_INGEST_RETENTION_COMPARE_AND_SWAP_V1
                | OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1
                | OPERATION_EVIDENCE_VIEWER_ISSUE_CHALLENGE_V1
                | OPERATION_EVIDENCE_VIEWER_VERIFY_AND_CONSUME_V1
                | OPERATION_EVIDENCE_VIEWER_GRANT_ISSUE_V1
                | OPERATION_EVIDENCE_VIEWER_GRANT_REVOKE_V1
                | OPERATION_EVIDENCE_VIEWER_ERASE_V1
                | OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1
                | OPERATION_MODERATION_CHECKPOINT_COMPARE_AND_SWAP_V1
                | OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1
                | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1
                | OPERATION_MODERATION_PANEL_NOTIFICATION_SOURCE_ATTEST_V1
                | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1
                | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1
                | OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1
                | OPERATION_GATEWAY_ACME_ORDER_CERTIFICATE_V1
                | OPERATION_POP_RUNTIME_OPEN_V1
                | OPERATION_POP_REGISTRY_SUBMIT_V1
                | OPERATION_POP_WALLET_WRAP_DEK_V1
                | OPERATION_POR_REPLAY_ARCHIVE_APPEND_V1
                | OPERATION_PRIVACY_RELEASE_ANCHOR_COMPARE_AND_SET_V1
                | OPERATION_TRANSPARENCY_LEADER_LEASE_ACQUIRE_V1
                | OPERATION_TRANSPARENCY_LEADER_LEASE_RENEW_V1
                | OPERATION_TRANSPARENCY_LEADER_LEASE_RELEASE_V1
                | OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1
                | OPERATION_BILLING_PUBLISH_STATEMENT_V1
                | OPERATION_BILLING_RECORD_ACKNOWLEDGEMENT_V1
                | OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1
        )
    {
        return Err(BrokerError::Protocol);
    }
    if status != STATUS_OK_V1 {
        // Error payloads are deliberately empty canonical values. Provider
        // diagnostics, credentials, and bearer material never cross the
        // broker boundary.
        decode_canonical::<()>(result, MAX_OPERATION_FRAME_BYTES_V1)?;
    } else {
        match request.operation {
            OPERATION_QUALIFY_V1
                if request.binding.slot
                    == IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry
                        .wire_id() =>
            {
                let qualification = decode_canonical::<QualificationResultWireV1>(
                    result,
                    MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
                )?;
                if Some(qualification.revision) != request.binding.revision
                    || Some(qualification.policy_digest) != request.binding.policy_digest
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_QUALIFY_V1
                if matches!(
                    request.binding.slot,
                    slot if slot
                        == IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator.wire_id()
                        || slot
                            == IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator
                                .wire_id()
                ) =>
            {
                let qualification =
                    governance_request_ingress_qualification_from_wire(decode_canonical::<
                        GovernanceRequestIngressQualificationWireV1,
                    >(
                        result,
                        MAX_OPERATION_FRAME_BYTES_V1,
                    )?)?;
                let expected_binding =
                    governance_request_ingress_binding_from_provider_binding(&request.binding)
                        .map_err(|_| BrokerError::Protocol)?;
                if Some(qualification.provider().revision) != request.binding.revision
                    || Some(qualification.provider().policy_digest) != request.binding.policy_digest
                    || qualification.binding() != expected_binding
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_BOOTLE_LANTERN_ISSUANCE_AUTHENTICATE_V1 => {
                let authenticate = decode_canonical::<BootleLanternAuthenticateRequestWireV1>(
                    &request.payload,
                    MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
                )?;
                let principal = decode_canonical::<BootleLanternAuthenticatedPrincipalWireV1>(
                    result,
                    MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
                )?;
                let is_live = principal.expires_at_height >= authenticate.committed_height;
                if principal.principal_digest == [0; 32]
                    || principal.issued_at_height == 0
                    || principal.issued_at_height > authenticate.committed_height
                    || !is_live
                    || principal.expires_at_height < principal.issued_at_height
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_BOOTLE_LANTERN_ISSUANCE_PREPARE_AUTHORIZATION_V1 => {
                let prepare = decode_canonical::<BootleLanternPrepareAuthorizationRequestWireV1>(
                    &request.payload,
                    MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
                )?;
                let authorization = decode_canonical::<BootleLanternAuthorizationWireV1>(
                    result,
                    MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
                )?;
                if authorization.authorization.len() != BOOTLE_LANTERN_AUTHORIZATION_BYTES_V1 {
                    return Err(BrokerError::Protocol);
                }
                let authorization = iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
                    BootleLanternIssuanceAuthorizationV1::decode_exact(
                        &authorization.authorization,
                    )
                    .map_err(|_| BrokerError::Protocol)?;
                iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
                    issuer_validate_prepared_blind_issuance_authorization_v1(
                        &prepare.context,
                        prepare.canonical_genesis_hash,
                        &prepare.policy,
                        &authorization,
                    )
                    .map_err(|_| BrokerError::Protocol)?;
                if authorization.requester_authorization_digest()
                    != prepare.requester_authorization_digest
                    || authorization.issued_at_height() != prepare.issued_at_height
                    || authorization.expires_at_height() != prepare.expires_at_height
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_BOOTLE_LANTERN_ISSUANCE_VALIDATE_REQUEST_V1 => {
                let (issue, authorization) = decode_bootle_lantern_issue_request(
                    &request.payload,
                    &request.binding,
                    session_network_id,
                )
                .map_err(|_| BrokerError::Protocol)?;
                let request_digest = decode_canonical::<[u8; 32]>(
                    result,
                    MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
                )?;
                let expected = iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
                    issuer_validate_blind_issuance_request_encoded_v1(
                        &issue.context,
                        issue.canonical_genesis_hash,
                        &issue.policy,
                        &authorization,
                        &issue.request,
                        issue.current_height,
                    )
                    .map_err(|_| BrokerError::Protocol)?;
                if request_digest == [0; 32] || request_digest != expected {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_BOOTLE_LANTERN_ISSUANCE_ISSUE_VALIDATED_V1 => {
                let (issue, authorization) = decode_bootle_lantern_issue_request(
                    &request.payload,
                    &request.binding,
                    session_network_id,
                )
                .map_err(|_| BrokerError::Protocol)?;
                let response = decode_canonical::<BootleLanternIssuanceResponseWireV1>(
                    result,
                    MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
                )?;
                if response.response.len() != BOOTLE_LANTERN_RESPONSE_BYTES_V1 {
                    return Err(BrokerError::Protocol);
                }
                iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
                    issuer_validate_cached_blind_issuance_response_encoded_v1(
                        &issue.context,
                        issue.canonical_genesis_hash,
                        &issue.policy,
                        &authorization,
                        &issue.request,
                        &response.response,
                    )
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_NATIVE_TRANSACTION_SIGN_V1 => {
                let signed = decode_canonical::<iroha_data_model::transaction::SignedTransaction>(
                    result,
                    MAX_NATIVE_SIGNED_TRANSACTION_BYTES_V1,
                )?;
                let expected = decode_native_transaction_payload(&request.payload)?;
                let soracloud_runtime_signer = request.binding.slot
                    == IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner.wire_id();
                if signed.payload() != &expected
                    || signed.authority() != expected.authority()
                    || (soracloud_runtime_signer
                        && (signed.attachments().is_some()
                            || signed.multisig_signatures().is_some()))
                    || signed.verify_signature().is_err()
                {
                    return Err(BrokerError::Protocol);
                }
                if native_transaction_signer_role_for_slot(request.binding.slot).is_some() {
                    let exact = native_transaction_signer_binding_from_wire(&request.binding)?;
                    if expected.authority() != exact.authority() {
                        return Err(BrokerError::Protocol);
                    }
                } else if request.binding.slot
                    == IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner.wire_id()
                {
                    let exact = soracloud_runtime_signer_binding_from_wire(&request.binding)?;
                    if expected.authority() != exact.authority() {
                        return Err(BrokerError::Protocol);
                    }
                } else if request.binding.slot
                    != IrohaRuntimeProviderSlotV1::ModerationTransactionSigner.wire_id()
                {
                    return Err(BrokerError::BindingMismatch);
                }
            }
            OPERATION_SORACLOUD_PROVENANCE_SIGN_V1 => {
                let signature = decode_canonical::<iroha_crypto::Signature>(
                    result,
                    MAX_NATIVE_TRANSACTION_FRAME_BYTES_V1,
                )?;
                let sign = decode_canonical::<SoracloudProvenanceSignRequestWireV1>(
                    &request.payload,
                    MAX_NATIVE_TRANSACTION_FRAME_BYTES_V1,
                )?;
                let exact = soracloud_runtime_signer_binding_from_wire(&request.binding)?;
                let purpose = iroha_data_model::soracloud::
                    SoracloudRuntimeProvenancePurposeV1::try_from_wire_id(sign.purpose)
                    .map_err(|_| BrokerError::Protocol)?;
                iroha_data_model::soracloud::validate_soracloud_runtime_provenance_preimage_v1(
                    purpose,
                    &sign.preimage,
                )
                .map_err(|_| BrokerError::Protocol)?;
                signature
                    .verify(exact.public_key(), &sign.preimage)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_QUALIFY_V1
                if request.binding.slot
                    == IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner.wire_id() =>
            {
                let qualification = decode_canonical::<SoracloudSignerQualificationWireV1>(
                    result,
                    MAX_OPERATION_FRAME_BYTES_V1,
                )?;
                if Some(qualification.revision) != request.binding.revision
                    || Some(qualification.policy_digest) != request.binding.policy_digest
                    || !qualification.active
                    || qualification.test_only
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_QUALIFY_V1
                if request.binding.slot
                    == IrohaRuntimeProviderSlotV1::StreamTokenSigner.wire_id() =>
            {
                validate_stream_token_metadata_result(&request.binding, result)?;
            }
            OPERATION_QUALIFY_V1
                if matches!(
                    request.binding.slot,
                    slot if slot == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id()
                        || slot == IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id()
                ) =>
            {
                let qualification = decode_canonical::<QualificationResultWireV1>(
                    result,
                    MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
                )?;
                if Some(qualification.revision) != request.binding.revision
                    || Some(qualification.policy_digest) != request.binding.policy_digest
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1 => {
                if request.binding.slot
                    != IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id()
                {
                    return Err(BrokerError::BindingMismatch);
                }
                let (_, mut aggregator) = decode_global_beacon_partial_sign_request(
                    &request.payload,
                    session_network_id,
                )?;
                let signed = decode_canonical::<GlobalBeaconPartialSignResultWireV1>(
                    result,
                    MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
                )?;
                aggregator
                    .accept_partial(signed.partial)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1 => {
                if request.binding.slot
                    != IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id()
                {
                    return Err(BrokerError::BindingMismatch);
                }
                let (prepared, session) = decode_global_beacon_seat_readiness_request(
                    &request.payload,
                    session_network_id,
                )?;
                let signed = decode_canonical::<GlobalBeaconPartialSignResultWireV1>(
                    result,
                    MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
                )?;
                iroha_core::beacon::seat_readiness::verify_global_threshold_beacon_seat_readiness_v1(&session, &prepared.authority, &prepared.context, &signed.partial).map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1 => {
                if request.binding.slot
                    != IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id()
                {
                    return Err(BrokerError::BindingMismatch);
                }
                let (_, projection) = decode_parliament_tle_partial_release_sign_request(
                    &request.payload,
                    session_network_id,
                )?;
                let signed = decode_canonical::<ParliamentTlePartialReleaseSignResultWireV1>(
                    result,
                    MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
                )?;
                verify_parliament_tle_partial_release_result(&projection, &signed.partial)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1 => {
                if request.binding.slot
                    != IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id()
                {
                    return Err(BrokerError::BindingMismatch);
                }
                let (attest, session) = decode_parliament_tle_capability_attest_request(
                    &request.payload,
                    session_network_id,
                )?;
                let result = decode_canonical::<ParliamentTleCapabilityAttestResultWireV1>(
                    result,
                    MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
                )?;
                verify_parliament_tle_capability_attest_result(
                    &session,
                    attest.participant_index,
                    &result,
                )
                .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1 => {
                if request.binding.slot
                    != IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id()
                {
                    return Err(BrokerError::BindingMismatch);
                }
                let (attest, session) = decode_global_beacon_capability_attest_request(
                    &request.payload,
                    session_network_id,
                )?;
                let result = decode_canonical::<GlobalBeaconCapabilityAttestResultWireV1>(
                    result,
                    MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
                )?;
                verify_global_beacon_capability_attest_result(
                    &session,
                    attest.signer_index,
                    &result,
                )
                .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1 => {
                let outcome = decode_canonical::<ModerationDurableHandoffOutcomeWireV1>(
                    result,
                    MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
                )?;
                if !matches!(outcome.outcome, 1 | 2) {
                    return Err(BrokerError::Protocol);
                }
                let handoff = decode_canonical::<ModerationDurableHandoffRequestWireV1>(
                    &request.payload,
                    MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
                )?;
                validate_moderation_handoff_request(&handoff, request.binding.slot, None)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1 => {
                let publish = decode_canonical::<
                    ModerationPanelNotificationArchiveHeadPublishRequestWireV1,
                >(
                    &request.payload, MAX_MODERATION_HANDOFF_FRAME_BYTES_V1
                )?;
                validate_moderation_panel_notification_archive_head_publish_request(
                    &publish,
                    &publish.network_id,
                )
                .map_err(|_| BrokerError::Protocol)?;
                let outcome = decode_canonical::<
                    ModerationPanelNotificationArchiveHeadPublishResultWireV1,
                >(result, MAX_MODERATION_HANDOFF_FRAME_BYTES_V1)?;
                if outcome.version != MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1
                    || outcome.slot
                        != IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id()
                    || outcome.operation_id != publish.head.operation_id
                    || outcome.head_digest != publish.head.head_digest
                    || outcome.chain_commitment != publish.head.chain_commitment
                    || !matches!(outcome.outcome, 1 | 2)
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1 => {
                decode_canonical::<()>(&request.payload, MAX_MODERATION_HANDOFF_FRAME_BYTES_V1)?;
                let readback = decode_canonical::<
                    ModerationPanelNotificationArchiveHeadReadResultWireV1,
                >(result, MAX_MODERATION_HANDOFF_FRAME_BYTES_V1)?;
                if readback.version != MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1
                    || readback.slot
                        != IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id()
                {
                    return Err(BrokerError::Protocol);
                }
                if let Some(canonical_head) = readback.canonical_head.as_ref() {
                    let head = decode_canonical::<
                        sorafs_node::moderation_orchestrator::
                            ModerationPanelNotificationArchiveHeadV1,
                    >(canonical_head, MAX_MODERATION_HANDOFF_CANONICAL_BYTES_V1)?;
                    if norito::to_bytes(&head)
                        .map_err(|_| BrokerError::Protocol)?
                        .as_slice()
                        != canonical_head.as_slice()
                        || head
                            .verify(
                                &head.archive_handle,
                                sorafs_node::moderation_orchestrator::
                                    ModerationRuntimeProviderQualificationV1::new(
                                        head.archive_revision,
                                        head.archive_policy_digest,
                                    ),
                                head.archive_id,
                                head.archive_public_key,
                            )
                            .is_err()
                    {
                        return Err(BrokerError::Protocol);
                    }
                }
            }
            OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1 => {
                let notification =
                    decode_canonical::<ModerationDurablePanelNotificationRequestWireV1>(
                        &request.payload,
                        MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1,
                    )?;
                validate_moderation_panel_notification_request(&notification, None)
                    .map_err(|_| BrokerError::Protocol)?;
                let receipt = decode_canonical::<ModerationPanelNotificationReceiptWireV1>(
                    result,
                    MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1,
                )?;
                validate_moderation_panel_notification_receipt(receipt, &notification)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1 => {
                decode_canonical::<bool>(result, MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1)?;
            }
            OPERATION_REPUTATION_JOURNAL_SUBMIT_V1 => {
                let outcome = decode_canonical::<ReputationJournalTransactionSubmitResultWireV1>(
                    result,
                    MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
                )?;
                reputation_journal_submit_result_from_wire(outcome)
                    .map(drop)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1 => {
                let request = decode_canonical::<ReputationThresholdSigningRequestWireV1>(
                    &request.payload,
                    MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
                )
                .and_then(reputation_threshold_request_from_wire)
                .map_err(|_| BrokerError::Protocol)?;
                let outcome = decode_canonical::<ReputationReconcileResultWireV1>(
                    result,
                    MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
                )?;
                match outcome.outcome {
                    0 if outcome.canonical_result.is_empty()
                        && outcome.failure_receipt == [0; 32] => {}
                    1 if !outcome.canonical_result.is_empty()
                        && outcome.failure_receipt == [0; 32] =>
                    {
                        reserve_external_canonical_decode(
                            outcome.canonical_result.len(),
                            MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
                        )?;
                        let signed =
                            sorafs_manifest::reputation::signed::decode_signed_reputation_snapshot(
                                &outcome.canonical_result,
                            )
                            .map_err(|_| BrokerError::Protocol)?;
                        let canonical = validate_reputation_signature(&request, &signed)
                            .map_err(|_| BrokerError::Protocol)?;
                        if canonical != outcome.canonical_result {
                            return Err(BrokerError::Protocol);
                        }
                    }
                    2 if outcome.canonical_result.is_empty()
                        && outcome.failure_receipt != [0; 32] => {}
                    _ => return Err(BrokerError::Protocol),
                }
            }
            OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1 => {
                let request = decode_canonical::<ReputationGovernanceDagPublicationRequestWireV1>(
                    &request.payload,
                    MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
                )
                .and_then(reputation_governance_request_from_wire)
                .map_err(|_| BrokerError::Protocol)?;
                let outcome = decode_canonical::<ReputationReconcileResultWireV1>(
                    result,
                    MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
                )?;
                match outcome.outcome {
                    0 if outcome.canonical_result.is_empty()
                        && outcome.failure_receipt == [0; 32] => {}
                    1 if !outcome.canonical_result.is_empty()
                        && outcome.failure_receipt == [0; 32] =>
                    {
                        let readback = decode_canonical::<
                            sorafs_node::reputation::runtime::ReputationGovernanceDagReadbackV1,
                        >(
                            &outcome.canonical_result,
                            MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
                        )
                        .map_err(|_| BrokerError::Protocol)?;
                        validate_reputation_governance_readback(&readback, &request.signed_result)
                            .map_err(|_| BrokerError::Protocol)?;
                    }
                    2 if outcome.canonical_result.is_empty()
                        && outcome.failure_receipt != [0; 32] => {}
                    _ => return Err(BrokerError::Protocol),
                }
            }
            OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1 => {
                let record = decode_canonical::<Option<Vec<u8>>>(
                    result,
                    MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1,
                )?;
                if let Some(record) = record {
                    reserve_external_canonical_decode(
                        record.len(),
                        MAX_REPUTATION_JOURNAL_CHECKPOINT_RECORD_BYTES_V1,
                    )?;
                    sorafs_node::reputation::runtime::
                        ReputationJournalSealedCheckpointRecordV1::from_canonical_bytes(
                            &record,
                            sorafs_node::reputation::runtime::
                                REPUTATION_JOURNAL_PRODUCER_MAX_CHECKPOINT_BYTES_V1,
                        )
                        .map_err(|_| BrokerError::Protocol)?;
                }
            }
            OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1 => {
                decode_canonical::<()>(result, MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1)?;
            }
            OPERATION_QUALIFY_V1
                if matches!(
                    request.binding.slot,
                    slot if slot
                        == IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter
                            .wire_id()
                        || slot
                            == IrohaRuntimeProviderSlotV1::ReputationThresholdSigner.wire_id()
                        || slot
                            == IrohaRuntimeProviderSlotV1::ReputationGovernanceDag.wire_id()
                        || slot
                            == IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint.wire_id()
                ) =>
            {
                let qualification = decode_canonical::<QualificationResultWireV1>(
                    result,
                    MAX_OPERATION_FRAME_BYTES_V1,
                )?;
                if Some(qualification.revision) != request.binding.revision
                    || Some(qualification.policy_digest) != request.binding.policy_digest
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_QUALIFY_V1
                if matches!(
                    request.binding.slot,
                    slot if slot == IrohaRuntimeProviderSlotV1::BillingFinalizedQuery.wire_id()
                        || slot
                            == IrohaRuntimeProviderSlotV1::BillingJournalVerifier.wire_id()
                        || slot
                            == IrohaRuntimeProviderSlotV1::BillingStatementSigner.wire_id()
                        || slot
                            == IrohaRuntimeProviderSlotV1::BillingStatementPublisher.wire_id()
                        || slot
                            == IrohaRuntimeProviderSlotV1::BillingAcknowledgementAuthority
                                .wire_id()
                        || slot
                            == IrohaRuntimeProviderSlotV1::BillingEpochWitnessStore.wire_id()
                ) =>
            {
                let qualification = decode_canonical::<QualificationResultWireV1>(
                    result,
                    MAX_BILLING_CONTROL_FRAME_BYTES_V1,
                )?;
                if Some(qualification.revision) != request.binding.revision
                    || Some(qualification.policy_digest) != request.binding.policy_digest
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_BILLING_IDENTITY_V1 => match request.binding.slot {
                slot if slot == IrohaRuntimeProviderSlotV1::BillingFinalizedQuery.wire_id()
                    || slot == IrohaRuntimeProviderSlotV1::BillingJournalVerifier.wire_id()
                    || slot
                        == IrohaRuntimeProviderSlotV1::BillingAcknowledgementAuthority
                            .wire_id() =>
                {
                    let identity = decode_canonical::<BillingAdapterIdentityWireV1>(
                        result,
                        MAX_BILLING_CONTROL_FRAME_BYTES_V1,
                    )?;
                    if identity.handle != request.binding.handle {
                        return Err(BrokerError::Protocol);
                    }
                }
                slot if slot == IrohaRuntimeProviderSlotV1::BillingStatementSigner.wire_id() => {
                    let identity = decode_canonical::<BillingStatementSignerIdentityWireV1>(
                        result,
                        MAX_BILLING_CONTROL_FRAME_BYTES_V1,
                    )?;
                    if identity.provider_handle != request.binding.handle
                        || !validate_billing_public_identity_text(
                            &identity.signer_id,
                            sorafs_node::hedging_billing_service::BILLING_SIGNER_ID_MAX_BYTES_V1,
                        )
                        || iroha_crypto::ed25519_parse_public_key(&identity.public_key).is_err()
                    {
                        return Err(BrokerError::Protocol);
                    }
                }
                slot if slot == IrohaRuntimeProviderSlotV1::BillingStatementPublisher.wire_id() => {
                    let identity = decode_canonical::<BillingStatementPublisherIdentityWireV1>(
                        result,
                        MAX_BILLING_CONTROL_FRAME_BYTES_V1,
                    )?;
                    if identity.provider_handle != request.binding.handle
                        || !validate_billing_public_identity_text(
                            &identity.publisher_id,
                            sorafs_node::hedging_billing_service::
                                BILLING_SIGNER_ID_MAX_BYTES_V1,
                        )
                        || !validate_billing_public_identity_text(
                            &identity.route_id,
                            sorafs_node::hedging_billing_service::
                                BILLING_PUBLICATION_ROUTE_MAX_BYTES_V1,
                        )
                        || iroha_crypto::ed25519_parse_public_key(&identity.public_key).is_err()
                    {
                        return Err(BrokerError::Protocol);
                    }
                }
                _ => return Err(BrokerError::Protocol),
            },
            OPERATION_BILLING_READINESS_V1
            | OPERATION_BILLING_VERIFY_PAGE_V1
            | OPERATION_BILLING_VERIFY_PERIOD_CLOSE_V1
            | OPERATION_BILLING_VERIFY_EPOCH_TRANSITION_V1
            | OPERATION_BILLING_VERIFY_ACKNOWLEDGEMENT_V1
            | OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1 => {
                decode_canonical::<()>(result, MAX_BILLING_CONTROL_FRAME_BYTES_V1)?;
            }
            OPERATION_BILLING_QUERY_CAPABILITIES_V1 => {
                let capabilities = decode_canonical::<BillingFinalizedQueryCapabilitiesWireV1>(
                    result,
                    MAX_BILLING_CONTROL_FRAME_BYTES_V1,
                )?;
                if !capabilities.supplies_period_closes {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_BILLING_FINALIZED_HEAD_V1 => {
                let head = decode_canonical::<
                    sorafs_node::hedging_billing_service::HedgingBillingFinalizedCursorV1,
                >(result, MAX_BILLING_CONTROL_FRAME_BYTES_V1)?;
                validate_billing_cursor(head).map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_BILLING_QUERY_PAGE_V1 => {
                let query = decode_canonical::<BillingQueryPageRequestWireV1>(
                    &request.payload,
                    MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
                )?;
                let page = decode_canonical::<
                    Option<
                        sorafs_node::hedging_billing_service::HedgingBillingFinalizedEventPageV1,
                    >,
                >(result, MAX_BILLING_RUNTIME_FRAME_BYTES_V1)?;
                if let Some(page) = page.as_ref() {
                    validate_billing_page_shape(page, Some((query.position, query.max_events)))
                        .map_err(|_| BrokerError::Protocol)?;
                }
            }
            OPERATION_BILLING_QUERY_PERIOD_CLOSE_V1 => {
                let query = decode_canonical::<BillingQueryPeriodCloseRequestWireV1>(
                    &request.payload,
                    MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
                )?;
                let close = decode_canonical::<
                    Option<
                        sorafs_node::hedging_billing_service::HedgingBillingFinalizedPeriodCloseV1,
                    >,
                >(result, MAX_BILLING_RUNTIME_FRAME_BYTES_V1)?;
                if let Some(close) = close.as_ref() {
                    validate_billing_period_close_shape(close, Some(query.period_end_unix))
                        .map_err(|_| BrokerError::Protocol)?;
                }
            }
            OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1 => {
                let sign = decode_canonical::<BillingSignDigestResultWireV1>(
                    result,
                    MAX_BILLING_CONTROL_FRAME_BYTES_V1,
                )?;
                if sign.signature == [0; 64] {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_BILLING_PUBLISH_STATEMENT_V1 => {
                let publish = decode_canonical::<BillingPublishStatementRequestWireV1>(
                    &request.payload,
                    MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
                )?;
                let receipt = decode_canonical::<
                    sorafs_node::hedging_billing_service::BillingStatementPublicationReceiptV1,
                >(result, MAX_BILLING_RUNTIME_FRAME_BYTES_V1)?;
                validate_billing_publication_receipt_shape(
                    &receipt,
                    publish.idempotency_key,
                    publish.signed_statement_digest,
                    publish.statement.signed_at_unix,
                )
                .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_BILLING_LOOKUP_PUBLICATION_V1 => {
                let lookup = decode_canonical::<BillingLookupRequestWireV1>(
                    &request.payload,
                    MAX_BILLING_CONTROL_FRAME_BYTES_V1,
                )?;
                let publication = decode_canonical::<Option<BillingAuthoritativePublicationWireV1>>(
                    result,
                    MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
                )?;
                if let Some(publication) = publication.as_ref() {
                    let statement_digest =
                        validate_billing_signed_statement_shape(&publication.signed_statement)
                            .map_err(|_| BrokerError::Protocol)?;
                    if publication
                        .signed_statement
                        .governed_statement
                        .statement
                        .statement_id
                        != lookup.record_id
                    {
                        return Err(BrokerError::Protocol);
                    }
                    validate_billing_publication_receipt_shape(
                        &publication.receipt,
                        lookup.record_id,
                        statement_digest,
                        publication.signed_statement.signed_at_unix,
                    )
                    .map_err(|_| BrokerError::Protocol)?;
                }
            }
            OPERATION_BILLING_RECORD_ACKNOWLEDGEMENT_V1 => {
                let expected = decode_canonical::<BillingAcknowledgementRequestWireV1>(
                    &request.payload,
                    MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
                )?;
                let recorded = decode_canonical::<
                    sorafs_node::hedging_billing_service::BillingStatementAcknowledgementV1,
                >(result, MAX_BILLING_RUNTIME_FRAME_BYTES_V1)?;
                if recorded != expected.acknowledgement {
                    return Err(BrokerError::Protocol);
                }
                validate_billing_acknowledgement_shape(
                    &recorded,
                    expected.statement.governed_statement.statement.statement_id,
                    expected.statement.network_id,
                )
                .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_BILLING_LOOKUP_ACKNOWLEDGEMENT_V1 => {
                let lookup = decode_canonical::<BillingLookupRequestWireV1>(
                    &request.payload,
                    MAX_BILLING_CONTROL_FRAME_BYTES_V1,
                )?;
                let acknowledgement = decode_canonical::<
                    Option<sorafs_node::hedging_billing_service::BillingStatementAcknowledgementV1>,
                >(result, MAX_BILLING_RUNTIME_FRAME_BYTES_V1)?;
                if let Some(acknowledgement) = acknowledgement.as_ref() {
                    validate_billing_acknowledgement_shape(
                        acknowledgement,
                        lookup.record_id,
                        acknowledgement.network_id,
                    )
                    .map_err(|_| BrokerError::Protocol)?;
                }
            }
            OPERATION_BILLING_LOAD_LATEST_EPOCH_V1 | OPERATION_BILLING_LOAD_EPOCH_V1 => {
                let record = decode_canonical::<
                    Option<
                        sorafs_node::hedging_billing_service::HedgingBillingEpochWitnessRecordV1,
                    >,
                >(result, MAX_BILLING_RUNTIME_FRAME_BYTES_V1)?;
                if let Some(record) = record.as_ref() {
                    record
                        .validate(
                            sorafs_node::hedging_billing_service::
                                HEDGING_BILLING_MAX_CHECKPOINT_BYTES_V1,
                        )
                        .map_err(|_| BrokerError::Protocol)?;
                    if request.operation == OPERATION_BILLING_LOAD_EPOCH_V1 {
                        let load = decode_canonical::<BillingLoadEpochRequestWireV1>(
                            &request.payload,
                            MAX_BILLING_CONTROL_FRAME_BYTES_V1,
                        )?;
                        if record.epoch_sequence != load.epoch_sequence {
                            return Err(BrokerError::Protocol);
                        }
                    }
                }
            }
            OPERATION_SIGN_V1 => {
                validate_governance_sign_operation_result(request, result)?;
            }
            OPERATION_STREAM_TOKEN_SIGN_V1 | OPERATION_STREAM_TOKEN_RECOVER_V1 => {
                validate_stream_token_receipt_result(request, result)?;
            }
            OPERATION_STREAM_TOKEN_OBSERVE_V1 => {
                decode_stream_token_observer_reply(&request.binding, &request.payload, result)?;
            }
            OPERATION_STREAM_TOKEN_CHECK_V1 => {
                decode_stream_token_check_result(&request.binding, &request.payload, result)?;
            }
            OPERATION_APPEAL_FINANCE_TRANSACTION_SIGN_V1 => {
                let signed = decode_canonical::<iroha_data_model::transaction::SignedTransaction>(
                    result,
                    MAX_APPEAL_FINANCE_TRANSACTION_FRAME_BYTES_V1,
                )?;
                let expected = decode_transaction_payload_bounded(
                    &request.payload,
                    MAX_APPEAL_FINANCE_TRANSACTION_BYTES_V1,
                )?;
                let exact = required_binding_ref!(&request.binding, appeal_finance_signer_binding);
                if signed.payload() != &expected
                    || signed.authority() != &exact.authority
                    || signed.verify_signature().is_err()
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_APPEAL_FINANCE_CHECKPOINT_SIGN_V1 => {
                let signed =
                    decode_canonical::<SignResultWireV1>(result, MAX_STREAM_TOKEN_FRAME_BYTES_V1)?;
                let digest = decode_canonical::<[u8; 32]>(
                    &request.payload,
                    MAX_STREAM_TOKEN_FRAME_BYTES_V1,
                )?;
                let public_key = exact_ed25519_public_key_bytes(
                    &required_binding_ref!(&request.binding, appeal_finance_checkpoint_binding)
                        .public_key,
                )?;
                verify_evidence_viewer_ed25519_signature(public_key, signed.signature, &digest)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_APPEAL_FINANCE_CHECKPOINT_LOAD_V1 => {
                let record = decode_canonical::<Option<
                    sorafs_node::appeal_finance_transaction_forwarder::
                        AppealFinanceSealedCheckpointRecordV1,
                >>(result, MAX_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1)?;
                if let Some(record) = record {
                    record
                        .validate(required_binding_value!(
                            &request.binding,
                            appeal_finance_checkpoint_max_bytes
                        ))
                        .map_err(|_| BrokerError::Protocol)?;
                }
            }
            OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1 => {
                decode_canonical::<()>(result, MAX_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1)?;
            }
            OPERATION_POTR_SIGN_V1 => {
                let signed = decode_canonical::<VariableSignatureResultWireV1>(
                    result,
                    MAX_POTR_FRAME_BYTES_V1,
                )?;
                let sign = decode_canonical::<PotrSignRequestWireV1>(
                    &request.payload,
                    MAX_POTR_FRAME_BYTES_V1,
                )?;
                if signed.signature.is_empty()
                    || signed.signature.len() > MAX_POTR_SIGNATURE_BYTES_V1
                {
                    return Err(BrokerError::Protocol);
                }
                let (role, algorithm) = if request.binding.slot
                    == IrohaRuntimeProviderSlotV1::PotrGatewaySigner.wire_id()
                {
                    (
                        "gateway",
                        sorafs_manifest::potr::PotrSignatureAlgorithm::Ed25519,
                    )
                } else {
                    (
                        "provider",
                        sorafs_manifest::potr::PotrSignatureAlgorithm::MlDsa65,
                    )
                };
                sorafs_manifest::potr::PotrSignatureV1 {
                    algorithm,
                    public_key: sign.expected_public_key.clone(),
                    signature: signed.signature.clone(),
                }
                .verify(role, &sign.payload)
                .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_GATEWAY_ACME_ORDER_CERTIFICATE_V1 => {
                let outcome = decode_canonical::<GatewayAcmeOrderOutcomeWireV1>(
                    result,
                    MAX_GATEWAY_ACME_FRAME_BYTES_V1,
                )?;
                validate_gateway_acme_outcome(&outcome).map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_GATEWAY_COMPLIANCE_RESOLVE_V1 => {
                let outcome =
                    decode_canonical::<GatewayComplianceResolveOutcomeWireV1>(result, 128 * 1024)?;
                validate_gateway_compliance_resolve_outcome(&outcome)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_GATEWAY_COMPLIANCE_FETCH_V1 => {
                let outcome = decode_canonical::<GatewayComplianceFetchOutcomeWireV1>(
                    result,
                    MAX_GATEWAY_COMPLIANCE_FRAME_BYTES_V1,
                )?;
                let fetch = decode_canonical::<GatewayComplianceFetchRequestWireV1>(
                    &request.payload,
                    MAX_GATEWAY_COMPLIANCE_FRAME_BYTES_V1,
                )?;
                validate_gateway_compliance_fetch_outcome(&outcome, &fetch)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_POP_RUNTIME_OPEN_V1 => {
                let result = decode_canonical::<PopRuntimeOpenResultWireV1>(
                    result,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                let exact = required_binding_ref!(&request.binding, pop_credential_runtime_binding);
                validate_pop_open_result(&result, exact).map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1 | OPERATION_POP_WALLET_RECIPIENT_OPEN_V1 => {
                let opened = decode_canonical::<PopRecipientOpenResultWireV1>(
                    result,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                validate_pop_recipient_open_result(&opened, request.operation)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_POP_ISSUER_SIGN_V1 => {
                let signed = decode_canonical::<PopIssuerSignResultWireV1>(
                    result,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                let sign = decode_canonical::<PopIssuerSignRequestWireV1>(
                    &request.payload,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                let exact = required_binding_ref!(&request.binding, pop_credential_runtime_binding);
                if sign.digest == [0; 32]
                    || sorafs_node::pop_credentials::PopIssuerSigningPurposeV1::try_from_wire_id(
                        sign.purpose,
                    )
                    .is_none()
                {
                    return Err(BrokerError::Protocol);
                }
                verify_evidence_viewer_ed25519_signature(
                    exact.issuer_public_key,
                    signed.signature,
                    &sign.digest,
                )
                .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_POP_AUTHENTICATE_V1 => {
                let principal = decode_canonical::<PopAuthenticatedPrincipalWireV1>(
                    result,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                let authenticate = decode_canonical::<PopAuthenticateRequestWireV1>(
                    &request.payload,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                validate_pop_principal(principal, &authenticate)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_POP_REGISTRY_SUBMIT_V1 => {
                decode_canonical::<()>(result, MAX_POP_RUNTIME_FRAME_BYTES_V1)?;
            }
            OPERATION_POP_REGISTRY_NEXT_V1 => {
                let next = decode_canonical::<PopRegistryNextResultWireV1>(
                    result,
                    MAX_POP_PROJECTION_BYTES_V1,
                )?;
                if let Some(projection) = next.projection.as_ref() {
                    let exact =
                        required_binding_ref!(&request.binding, pop_credential_runtime_binding);
                    validate_pop_projection(projection, exact)
                        .map_err(|_| BrokerError::Protocol)?;
                }
            }
            OPERATION_POP_ISSUANCE_DRAFT_V1 => {
                let draft = decode_canonical::<PopIssuanceDraftResultWireV1>(
                    result,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                let draft_request = decode_canonical::<PopIssuanceDraftRequestWireV1>(
                    &request.payload,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                let exact = required_binding_ref!(&request.binding, pop_credential_runtime_binding);
                validate_pop_draft(&draft, draft_request, exact)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_POP_WALLET_WRAP_DEK_V1 => {
                let wrapped = decode_canonical::<PopWalletWrapDekResultWireV1>(
                    result,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                if wrapped.wrapped_dek.is_empty()
                    || wrapped.wrapped_dek.len() > MAX_POP_WRAPPED_DEK_BYTES_V1
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_POP_WALLET_UNWRAP_DEK_V1 => {
                let unwrapped = decode_canonical::<PopWalletUnwrapDekResultWireV1>(
                    result,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                if unwrapped.dek == [0; 32] {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_POP_WALLET_WITNESS_V1 => {
                let witness = decode_canonical::<PopMembershipWitnessWireV1>(
                    result,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                validate_pop_witness_wire(&witness).map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_POP_FINALIZED_TIME_V1 => {
                let sample = decode_canonical::<PopFinalizedTimeResultWireV1>(
                    result,
                    MAX_POP_RUNTIME_FRAME_BYTES_V1,
                )?;
                validate_pop_finalized_time(sample).map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_POR_REPLAY_ARCHIVE_READINESS_V1 => {
                decode_canonical::<()>(result, MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1)?;
            }
            OPERATION_POR_REPLAY_ARCHIVE_CURRENT_HEAD_V1 => {
                let exact = por_replay_archive_exact_binding(&request.binding)?;
                let head = decode_canonical::<
                    Option<sorafs_node::PorFinalizedReplayArchiveReceiptV1>,
                >(result, MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1)?;
                if let Some(head) = head {
                    validate_por_replay_archive_receipt(&head, exact)
                        .map_err(|_| BrokerError::Protocol)?;
                }
            }
            OPERATION_POR_REPLAY_ARCHIVE_APPEND_V1 => {
                let exact = por_replay_archive_exact_binding(&request.binding)?;
                let append = decode_canonical::<PorReplayArchiveAppendRequestWireV1>(
                    &request.payload,
                    MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1,
                )?;
                let record = validate_por_replay_archive_append_request(&append)
                    .map_err(|_| BrokerError::Protocol)?;
                let receipt = decode_canonical::<sorafs_node::PorFinalizedReplayArchiveReceiptV1>(
                    result,
                    MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1,
                )?;
                receipt
                    .validate_record(exact, &record, Some(append.expected_previous_head))
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_POR_REPLAY_ARCHIVE_LOOKUP_V1 => {
                let lookup = decode_canonical::<PorReplayArchiveLookupRequestWireV1>(
                    &request.payload,
                    MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1,
                )?;
                let outcome = decode_canonical::<PorReplayArchiveLookupOutcomeWireV1>(
                    result,
                    MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1,
                )?;
                por_replay_archive_lookup_from_wire(&outcome, &lookup, &request.binding)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_PRIVACY_CYCLE_PRF_DERIVE_V1 => {
                let output = decode_canonical::<PrivacyCyclePrfOutputWireV1>(
                    result,
                    MAX_TRANSPARENCY_PRF_FRAME_BYTES_V1,
                )?;
                if output.output == [0; 32] {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_PRIVACY_RELEASE_ANCHOR_FINALIZED_HEAD_V1 => {
                let query = validate_privacy_release_anchor_query(decode_canonical::<
                    PrivacyReleaseAnchorFinalizedHeadRequestWireV1,
                >(
                    &request.payload,
                    MAX_PRIVACY_RELEASE_ANCHOR_FRAME_BYTES_V1,
                )?)?;
                let head = decode_canonical::<PrivacyReleaseAnchorHeadWireV1>(
                    result,
                    MAX_PRIVACY_RELEASE_ANCHOR_FRAME_BYTES_V1,
                )?
                .to_head()
                .map_err(|_| BrokerError::Protocol)?;
                if head.query_id() != query {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_PRIVACY_RELEASE_ANCHOR_COMPARE_AND_SET_V1 => {
                decode_canonical::<()>(result, MAX_PRIVACY_RELEASE_ANCHOR_FRAME_BYTES_V1)?;
            }
            OPERATION_TRANSPARENCY_LEADER_LEASE_ACQUIRE_V1 => {
                let configured = transparency_runtime_binding_from_wire(&request.binding)?;
                let acquire = decode_canonical::<TransparencyLeaderLeaseAcquireRequestWireV1>(
                    &request.payload,
                    MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
                )?
                .to_request()
                .map_err(|_| BrokerError::Protocol)?;
                let grant = decode_canonical::<TransparencyLeaderLeaseGrantWireV1>(
                    result,
                    MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
                )?
                .to_grant()
                .map_err(|_| BrokerError::Protocol)?;
                validate_transparency_leader_lease_acquire_grant(&acquire, &grant, &configured)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_TRANSPARENCY_LEADER_LEASE_RENEW_V1 => {
                let configured = transparency_runtime_binding_from_wire(&request.binding)?;
                let renew = decode_canonical::<TransparencyLeaderLeaseRenewRequestWireV1>(
                    &request.payload,
                    MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
                )?
                .to_request()
                .map_err(|_| BrokerError::Protocol)?;
                let grant = decode_canonical::<TransparencyLeaderLeaseGrantWireV1>(
                    result,
                    MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
                )?
                .to_grant()
                .map_err(|_| BrokerError::Protocol)?;
                validate_transparency_leader_lease_renew_grant(&renew, &grant, &configured)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_TRANSPARENCY_LEADER_LEASE_RELEASE_V1 => {
                let configured = transparency_runtime_binding_from_wire(&request.binding)?;
                let release = decode_canonical::<TransparencyLeaderLeaseReleaseRequestWireV1>(
                    &request.payload,
                    MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
                )?
                .to_request()
                .map_err(|_| BrokerError::Protocol)?;
                let receipt = decode_canonical::<TransparencyLeaderLeaseReleaseReceiptWireV1>(
                    result,
                    MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
                )?
                .to_receipt()
                .map_err(|_| BrokerError::Protocol)?;
                validate_transparency_leader_lease_release_receipt(&release, &receipt, &configured)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1 => {
                let publish = decode_canonical::<FencedPrivacyPublicationRequestWireV1>(
                    &request.payload,
                    MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1,
                )?
                .to_request()
                .map_err(|_| BrokerError::Protocol)?;
                let qualification = qualification_from_binding(&request.binding)?;
                decode_canonical::<FencedPrivacyPublicationReceiptWireV1>(
                    result,
                    MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1,
                )?
                .to_receipt(&publish, &request.binding.handle, qualification)
                .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1 => {
                let (required_ancestors, required_publications) =
                    decode_canonical::<FencedPrivacyHeadReadRequestWireV1>(
                        &request.payload,
                        MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1,
                    )?
                    .to_required_evidence()
                    .map_err(|_| BrokerError::Protocol)?;
                decode_canonical::<FencedTransparencyHeadAncestryProofWireV1>(
                    result,
                    MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1,
                )?
                .to_proof(&required_ancestors, &required_publications)
                .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_REPUTATION_RETENTION_LOAD_V1 => {
                let record = decode_canonical::<Option<Vec<u8>>>(
                    result,
                    MAX_REPUTATION_RETENTION_FRAME_BYTES_V1,
                )?;
                if let Some(record) = record {
                    if record.is_empty()
                        || record.len() > MAX_REPUTATION_RETENTION_APPROVAL_BYTES_V1
                    {
                        return Err(BrokerError::Protocol);
                    }
                    reserve_external_canonical_decode(
                        record.len(),
                        MAX_REPUTATION_RETENTION_APPROVAL_BYTES_V1,
                    )?;
                    iroha_core::query::reputation_finalized::
                        ReputationFinalizedArchiveRetentionApprovalRecordV1::
                            from_canonical_bytes(&record)
                            .map_err(|_| BrokerError::Protocol)?;
                }
            }
            OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1 => {
                decode_canonical::<()>(result, MAX_REPUTATION_RETENTION_FRAME_BYTES_V1)?;
            }
            OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1 => {
                let wrapped = decode_nested_canonical::<ModerationQuarantineWrapDekResultWireV1>(
                    result,
                    MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
                )?;
                validate_moderation_quarantine_wrapped_dek(&wrapped.wrapped_dek)?;
            }
            OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1 => {
                let unwrapped = decode_canonical::<ModerationQuarantineUnwrapDekResultWireV1>(
                    result,
                    MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
                )?;
                if unwrapped.dek == [0; 32] {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_EVIDENCE_VIEWER_ISSUE_CHALLENGE_V1
            | OPERATION_EVIDENCE_VIEWER_GRANT_ISSUE_V1 => {
                let secret = decode_canonical::<EvidenceViewerSecretResultWireV1>(
                    result,
                    MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
                )?;
                validate_evidence_viewer_secret(&secret.secret)
                    .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_EVIDENCE_VIEWER_VERIFY_AND_CONSUME_V1 => {
                let verified = decode_canonical::<EvidenceViewerWebAuthnResultWireV1>(
                    result,
                    MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
                )?;
                if verified.attestation_digest == [0; 32]
                    || verified.credential_id_digest == [0; 32]
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_EVIDENCE_VIEWER_GRANT_VERIFY_V1
            | OPERATION_EVIDENCE_VIEWER_GRANT_REVOKE_V1
            | OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1
            | OPERATION_MODERATION_CHECKPOINT_COMPARE_AND_SWAP_V1
            | OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1 => {
                decode_canonical::<()>(result, MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1)?;
            }
            OPERATION_EVIDENCE_VIEWER_RECEIPT_SIGN_V1 => {
                let signed = decode_canonical::<SignResultWireV1>(
                    result,
                    MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
                )?;
                let sign = decode_canonical::<PurposeSignRequestWireV1>(
                    &request.payload,
                    MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
                )?;
                validate_evidence_purpose_signing_request(&sign, &request.binding)
                    .map_err(|_| BrokerError::Protocol)?;
                let public_key = required_binding_value!(
                    &request.binding,
                    evidence_viewer_receipt_signer_public_key
                );
                verify_evidence_viewer_ed25519_signature(
                    public_key,
                    signed.signature,
                    &sign.payload,
                )
                .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_EVIDENCE_VIEWER_ERASE_V1 => {
                let erased = decode_canonical::<EvidenceViewerEraseResultWireV1>(
                    result,
                    MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
                )?;
                if erased.commit_digest == [0; 32] {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_EVIDENCE_VIEWER_CHECKPOINT_LOAD_V1 => {
                let record = decode_canonical::<Option<Vec<u8>>>(
                    result,
                    MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
                )?;
                if let Some(record) = record {
                    decode_evidence_viewer_checkpoint_record(&record, &request.binding)
                        .map_err(|_| BrokerError::Protocol)?;
                }
            }
            OPERATION_MODERATION_CHECKPOINT_LOAD_V1 => {
                let record = decode_canonical::<Option<Vec<u8>>>(
                    result,
                    MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
                )?;
                if let Some(record) = record {
                    decode_moderation_checkpoint_record(&record, &request.binding, None)
                        .map_err(|_| BrokerError::Protocol)?;
                }
            }
            OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1 => {
                let signed = decode_canonical::<SignResultWireV1>(
                    result,
                    MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
                )?;
                let install = decode_canonical::<EvidenceViewerArchiveInstallRequestWireV1>(
                    &request.payload,
                    MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
                )?;
                let public_key =
                    required_binding_value!(&request.binding, evidence_viewer_archive_public_key);
                verify_evidence_viewer_ed25519_signature(
                    public_key,
                    signed.signature,
                    &install.receipt_message,
                )
                .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_EVIDENCE_VIEWER_ARCHIVE_READ_V1 => {
                let readback = decode_canonical::<Option<EvidenceViewerArchiveReadbackWireV1>>(
                    result,
                    MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
                )?;
                if let Some(readback) = readback {
                    let max_bytes = usize::try_from(required_binding_value!(
                        &request.binding,
                        evidence_viewer_archive_max_bytes
                    ))
                    .map_err(|_| BrokerError::Protocol)?;
                    if readback.canonical_artifact.is_empty()
                        || readback.canonical_artifact.len() > max_bytes
                        || readback.signature == [0; 64]
                    {
                        return Err(BrokerError::Protocol);
                    }
                }
            }
            OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_QUALIFY_V1 => {
                let qualification = decode_canonical::<
                    ModerationPanelNotificationArchiveQualificationWireV1,
                >(result, MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1)?;
                let exact = required_binding_value!(
                    &request.binding,
                    moderation_panel_notification_archive_binding
                );
                if qualification.version
                    != MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1
                    || qualification.slot
                        != IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id()
                    || Some(qualification.revision) != request.binding.revision
                    || Some(qualification.policy_digest) != request.binding.policy_digest
                    || qualification.archive_id != exact.archive_id
                    || qualification.public_key != exact.public_key
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1 => {
                let signed = decode_canonical::<
                    ModerationPanelNotificationArchiveInstallResultWireV1,
                >(result, MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1)?;
                let install = decode_canonical::<
                    ModerationPanelNotificationArchiveInstallRequestWireV1,
                >(
                    &request.payload, MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1
                )?;
                let exact = required_binding_value!(
                    &request.binding,
                    moderation_panel_notification_archive_binding
                );
                if signed.version != MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1
                    || signed.slot
                        != IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id()
                {
                    return Err(BrokerError::Protocol);
                }
                verify_evidence_viewer_ed25519_signature(
                    exact.public_key,
                    signed.signature,
                    &install.receipt_message,
                )
                .map_err(|_| BrokerError::Protocol)?;
            }
            OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1 => {
                let readback = decode_canonical::<
                    Option<ModerationPanelNotificationArchiveReadbackWireV1>,
                >(result, MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1)?;
                if let Some(readback) = readback {
                    let exact = required_binding_value!(
                        &request.binding,
                        moderation_panel_notification_archive_binding
                    );
                    let max_bytes =
                        usize::try_from(exact.max_bytes).map_err(|_| BrokerError::Protocol)?;
                    if readback.version
                        != MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1
                        || readback.slot
                            != IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive
                                .wire_id()
                        || readback.canonical_artifact.is_empty()
                        || readback.canonical_artifact.len() > max_bytes
                        || readback.signature == [0; 64]
                    {
                        return Err(BrokerError::Protocol);
                    }
                }
            }
            OPERATION_MODERATION_PANEL_NOTIFICATION_SOURCE_ATTEST_V1 => {
                let signed = decode_canonical::<ModerationPanelNotificationSourceAttestResultWireV1>(
                    result,
                    MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
                )?;
                let attest = decode_canonical::<
                    ModerationPanelNotificationSourceAttestRequestWireV1,
                >(
                    &request.payload, MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1
                )?;
                if signed.version != MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1
                    || signed.slot
                        != IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id()
                    || signed.statement_digest == [0; 32]
                    || attest.statement.verify(signed.signature).is_err()
                {
                    return Err(BrokerError::Protocol);
                }
            }
            OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1 => {
                let head = decode_canonical::<
                    Option<
                        sorafs_node::evidence_viewer::transparency_producer::
                            EvidenceViewerSignedTransparencyHeadV1,
                    >,
                >(result, MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1)?;
                if let Some(head) = head {
                    validate_evidence_viewer_transparency_head_body(&head.body, &request.binding)
                        .map_err(|_| BrokerError::Protocol)?;
                    if head.signature == [0; 64] || head.head_digest == [0; 32] {
                        return Err(BrokerError::Protocol);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
fn sealed_slot_to_wire(slot: sorafs_node::GovernanceDagSealedStateSlot) -> u8 {
    match slot {
        sorafs_node::GovernanceDagSealedStateSlot::Checkpoint => 1,
        sorafs_node::GovernanceDagSealedStateSlot::PublishIntent => 2,
        sorafs_node::GovernanceDagSealedStateSlot::ProducerCheckpoint => 3,
        sorafs_node::GovernanceDagSealedStateSlot::ProducerPublishIntent => 4,
        sorafs_node::GovernanceDagSealedStateSlot::IpfsRequestReplay => 5,
        sorafs_node::GovernanceDagSealedStateSlot::SignedHeadRequestReplay => 6,
    }
}
fn sealed_slot_from_wire(
    slot: u8,
) -> Result<sorafs_node::GovernanceDagSealedStateSlot, BrokerError> {
    match slot {
        1 => Ok(sorafs_node::GovernanceDagSealedStateSlot::Checkpoint),
        2 => Ok(sorafs_node::GovernanceDagSealedStateSlot::PublishIntent),
        3 => Ok(sorafs_node::GovernanceDagSealedStateSlot::ProducerCheckpoint),
        4 => Ok(sorafs_node::GovernanceDagSealedStateSlot::ProducerPublishIntent),
        5 => Ok(sorafs_node::GovernanceDagSealedStateSlot::IpfsRequestReplay),
        6 => Ok(sorafs_node::GovernanceDagSealedStateSlot::SignedHeadRequestReplay),
        _ => Err(BrokerError::Protocol),
    }
}
fn sealed_slot_is_transient(slot: sorafs_node::GovernanceDagSealedStateSlot) -> bool {
    matches!(
        slot,
        sorafs_node::GovernanceDagSealedStateSlot::PublishIntent
            | sorafs_node::GovernanceDagSealedStateSlot::ProducerPublishIntent
    )
}
fn validate_sealed_record_fields(
    slot: sorafs_node::GovernanceDagSealedStateSlot,
    generation: u64,
    revision: [u8; 32],
    payload: &[u8],
) -> Result<(), BrokerError> {
    validate_sealed_payload_len(slot, payload.len())?;
    if generation == 0
        || revision == [0; 32]
        || sorafs_node::governance_dag_sealed_state_revision(slot, generation, payload) != revision
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_sealed_payload_len(
    slot: sorafs_node::GovernanceDagSealedStateSlot,
    payload_len: usize,
) -> Result<(), BrokerError> {
    if payload_len == 0
        || payload_len > sorafs_node::governance_dag_sealed_state_payload_max_bytes_v1(slot)
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_sealed_successor(
    slot: sorafs_node::GovernanceDagSealedStateSlot,
    current: Option<&sorafs_node::GovernanceDagSealedStateRecord>,
    expected_revision: Option<[u8; 32]>,
    next: &sorafs_node::GovernanceDagSealedStateRecord,
) -> Result<(), BrokerError> {
    validate_sealed_record_fields(slot, next.generation, next.revision, &next.payload)?;
    if let Some(current) = current {
        validate_sealed_record_fields(slot, current.generation, current.revision, &current.payload)
            .map_err(|_| BrokerError::Protocol)?;
    }
    if current.map(|record| record.revision) != expected_revision {
        return Err(BrokerError::Conflict);
    }
    if let Some(current) = current {
        let generation_is_monotonic = if sealed_slot_is_transient(slot) {
            next.generation >= current.generation
        } else {
            next.generation > current.generation
        };
        if !generation_is_monotonic {
            return Err(BrokerError::Rejected);
        }
    }
    Ok(())
}
fn validate_sealed_delete(
    slot: sorafs_node::GovernanceDagSealedStateSlot,
    expected_revision: [u8; 32],
) -> Result<(), BrokerError> {
    if !sealed_slot_is_transient(slot) || expected_revision == [0; 32] {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn qualification_from_binding(
    binding: &ProviderBindingWireV1,
) -> Result<sorafs_node::GovernanceDagRuntimeProviderQualificationV1, BrokerError> {
    let revision = required_binding_value!(binding, revision);
    let policy_digest = required_binding_value!(binding, policy_digest);
    if revision == 0 || policy_digest == [0; 32] {
        return Err(BrokerError::StaleOrRevoked);
    }
    Ok(sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(revision, policy_digest))
}
fn reputation_qualification_from_binding(
    binding: &ProviderBindingWireV1,
) -> Result<sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1, BrokerError>
{
    let revision = required_binding_value!(binding, revision);
    let policy_digest = required_binding_value!(binding, policy_digest);
    if revision == 0 || policy_digest == [0; 32] {
        return Err(BrokerError::StaleOrRevoked);
    }
    Ok(
        sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1::new(
            revision,
            policy_digest,
        ),
    )
}
fn moderation_quarantine_qualification_from_binding(
    binding: &ProviderBindingWireV1,
) -> Result<sorafs_node::ModerationQuarantineKeyProviderQualificationV1, BrokerError> {
    let revision = required_binding_value!(binding, revision);
    let policy_digest = required_binding_value!(binding, policy_digest);
    if revision == 0 || policy_digest == [0; 32] {
        return Err(BrokerError::StaleOrRevoked);
    }
    Ok(sorafs_node::ModerationQuarantineKeyProviderQualificationV1::new(revision, policy_digest))
}
fn moderation_quarantine_operation_error(
    error: sorafs_node::ModerationQuarantineKeyOperationErrorV1,
    wrap_may_have_dispatched: bool,
) -> BrokerError {
    match error {
        sorafs_node::ModerationQuarantineKeyOperationErrorV1::Rejected => BrokerError::Rejected,
        sorafs_node::ModerationQuarantineKeyOperationErrorV1::StaleOrRevoked => {
            BrokerError::StaleOrRevoked
        }
        sorafs_node::ModerationQuarantineKeyOperationErrorV1::Ambiguous
            if wrap_may_have_dispatched =>
        {
            BrokerError::Ambiguous
        }
        sorafs_node::ModerationQuarantineKeyOperationErrorV1::Unavailable
        | sorafs_node::ModerationQuarantineKeyOperationErrorV1::Ambiguous => {
            BrokerError::Unavailable
        }
    }
}
mod platform {
    include!("platform.rs");
}
/// Resolve the stock catalog through one validated production endpoint.
pub(super) fn resolve(
    bindings: &IrohaRuntimeProviderBindingsV1,
    endpoint_path: &iroha_config::parameters::actual::RuntimeProviderBrokerEndpointPath,
) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
    platform::resolve(
        bindings,
        &platform::EndpointPolicy::production(endpoint_path),
    )
}
/// Serve the exact stock catalog on one validated production endpoint.
pub(super) fn serve(
    bindings: &IrohaRuntimeProviderBindingsV1,
    policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    backends: RuntimeProviderBrokerBackendsV1,
) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
    platform::serve(bindings, policy, backends)
}
/// Serve the stock catalog with a fallible readiness publication.
pub(super) fn serve_with_fallible_readiness<R>(
    bindings: &IrohaRuntimeProviderBindingsV1,
    policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    backends: RuntimeProviderBrokerBackendsV1,
    lifecycle: Arc<RuntimeProviderBrokerLifecycleV1>,
    on_ready: R,
) -> Result<(), RuntimeProviderBrokerServerErrorV1>
where
    R: FnOnce() -> Result<(), RuntimeProviderBrokerReadinessErrorV1>,
{
    platform::serve_with_fallible_readiness(bindings, policy, backends, lifecycle, on_ready)
}
