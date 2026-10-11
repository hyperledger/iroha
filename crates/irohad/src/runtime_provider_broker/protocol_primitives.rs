// Exact V1 operation identifiers, status values, transcript domains, and
// sensitive foundational wire containers shared by broker clients and servers.
pub(super) const OPERATION_QUALIFY_V1: u16 = 1;
pub(super) const OPERATION_SIGN_V1: u16 = 2;
pub(super) const OPERATION_GOVERNANCE_REQUEST_AUTHENTICATE_V1: u16 = 3;
pub(super) const OPERATION_NATIVE_TRANSACTION_SIGN_V1: u16 = 4;
pub(super) const OPERATION_STREAM_TOKEN_SIGN_V1: u16 = 5;
pub(super) const OPERATION_APPEAL_FINANCE_TRANSACTION_SIGN_V1: u16 = 6;
pub(super) const OPERATION_APPEAL_FINANCE_CHECKPOINT_SIGN_V1: u16 = 7;
pub(super) const OPERATION_APPEAL_FINANCE_CHECKPOINT_LOAD_V1: u16 = 8;
pub(super) const OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1: u16 = 9;
pub(super) const OPERATION_SEALED_LOAD_V1: u16 = 10;
pub(super) const OPERATION_SEALED_COMPARE_AND_SWAP_V1: u16 = 11;
pub(super) const OPERATION_SEALED_DELETE_V1: u16 = 12;
pub(super) const OPERATION_POTR_SIGN_V1: u16 = 13;
pub(super) const OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1: u16 = 14;
pub(super) const OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1: u16 = 15;
pub(super) const OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1: u16 = 16;
pub(super) const OPERATION_REPUTATION_JOURNAL_SUBMIT_V1: u16 = 17;
pub(super) const OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1: u16 = 18;
pub(super) const OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1: u16 = 19;
pub(super) const OPERATION_PROVIDER_INGEST_RESOLVER_READINESS_V1: u16 = 20;
pub(super) const OPERATION_PROVIDER_INGEST_RESOLVE_SIGNER_V1: u16 = 21;
pub(super) const OPERATION_PROVIDER_INGEST_SIGN_V1: u16 = 22;
pub(super) const OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1: u16 = 23;
pub(super) const OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1: u16 = 24;
pub(super) const OPERATION_PROVIDER_INGEST_RETENTION_LOAD_V1: u16 = 25;
pub(super) const OPERATION_PROVIDER_INGEST_RETENTION_COMPARE_AND_SWAP_V1: u16 = 26;
pub(super) const OPERATION_PROVIDER_INGEST_SOURCE_READINESS_V1: u16 = 27;
pub(super) const OPERATION_PROVIDER_INGEST_SOURCE_FETCH_V1: u16 = 28;
pub(super) const OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1: u16 = 30;
pub(super) const OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1: u16 = 31;
pub(super) const OPERATION_EVIDENCE_VIEWER_ISSUE_CHALLENGE_V1: u16 = 40;
pub(super) const OPERATION_EVIDENCE_VIEWER_VERIFY_AND_CONSUME_V1: u16 = 41;
pub(super) const OPERATION_EVIDENCE_VIEWER_GRANT_ISSUE_V1: u16 = 42;
pub(super) const OPERATION_EVIDENCE_VIEWER_GRANT_VERIFY_V1: u16 = 43;
pub(super) const OPERATION_EVIDENCE_VIEWER_GRANT_REVOKE_V1: u16 = 44;
pub(super) const OPERATION_EVIDENCE_VIEWER_RECEIPT_SIGN_V1: u16 = 45;
pub(super) const OPERATION_EVIDENCE_VIEWER_ERASE_V1: u16 = 46;
pub(super) const OPERATION_EVIDENCE_VIEWER_CHECKPOINT_LOAD_V1: u16 = 47;
pub(super) const OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1: u16 = 48;
pub(super) const OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1: u16 = 49;
pub(super) const OPERATION_EVIDENCE_VIEWER_ARCHIVE_READ_V1: u16 = 50;
pub(super) const OPERATION_REPUTATION_RETENTION_LOAD_V1: u16 = 51;
pub(super) const OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1: u16 = 52;
pub(super) const OPERATION_GATEWAY_ACME_ORDER_CERTIFICATE_V1: u16 = 53;
pub(super) const OPERATION_GATEWAY_COMPLIANCE_RESOLVE_V1: u16 = 54;
pub(super) const OPERATION_GATEWAY_COMPLIANCE_FETCH_V1: u16 = 55;
pub(super) const OPERATION_POP_RUNTIME_OPEN_V1: u16 = 60;
pub(super) const OPERATION_POP_ISSUER_SIGN_V1: u16 = 61;
pub(super) const OPERATION_POP_AUTHENTICATE_V1: u16 = 62;
pub(super) const OPERATION_POP_REGISTRY_SUBMIT_V1: u16 = 63;
pub(super) const OPERATION_POP_REGISTRY_NEXT_V1: u16 = 64;
pub(super) const OPERATION_POP_ISSUANCE_DRAFT_V1: u16 = 65;
pub(super) const OPERATION_POP_WALLET_WRAP_DEK_V1: u16 = 66;
pub(super) const OPERATION_POP_WALLET_UNWRAP_DEK_V1: u16 = 67;
pub(super) const OPERATION_POP_WALLET_WITNESS_V1: u16 = 68;
pub(super) const OPERATION_POP_FINALIZED_TIME_V1: u16 = 69;
pub(super) const OPERATION_POR_REPLAY_ARCHIVE_READINESS_V1: u16 = 70;
pub(super) const OPERATION_POR_REPLAY_ARCHIVE_CURRENT_HEAD_V1: u16 = 71;
pub(super) const OPERATION_POR_REPLAY_ARCHIVE_APPEND_V1: u16 = 72;
pub(super) const OPERATION_POR_REPLAY_ARCHIVE_LOOKUP_V1: u16 = 73;
pub(super) const OPERATION_PRIVACY_CYCLE_PRF_DERIVE_V1: u16 = 74;
pub(super) const OPERATION_PRIVACY_RELEASE_ANCHOR_FINALIZED_HEAD_V1: u16 = 75;
pub(super) const OPERATION_PRIVACY_RELEASE_ANCHOR_COMPARE_AND_SET_V1: u16 = 76;
pub(super) const OPERATION_TRANSPARENCY_LEADER_LEASE_ACQUIRE_V1: u16 = 77;
pub(super) const OPERATION_TRANSPARENCY_LEADER_LEASE_RENEW_V1: u16 = 78;
pub(super) const OPERATION_TRANSPARENCY_LEADER_LEASE_RELEASE_V1: u16 = 79;
pub(super) const OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1: u16 = 80;
pub(super) const OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1: u16 = 81;
pub(super) const OPERATION_BILLING_IDENTITY_V1: u16 = 82;
pub(super) const OPERATION_BILLING_READINESS_V1: u16 = 83;
pub(super) const OPERATION_BILLING_QUERY_CAPABILITIES_V1: u16 = 84;
pub(super) const OPERATION_BILLING_FINALIZED_HEAD_V1: u16 = 85;
pub(super) const OPERATION_BILLING_QUERY_PAGE_V1: u16 = 86;
pub(super) const OPERATION_BILLING_QUERY_PERIOD_CLOSE_V1: u16 = 87;
pub(super) const OPERATION_BILLING_VERIFY_PAGE_V1: u16 = 88;
pub(super) const OPERATION_BILLING_VERIFY_PERIOD_CLOSE_V1: u16 = 89;
pub(super) const OPERATION_BILLING_VERIFY_EPOCH_TRANSITION_V1: u16 = 90;
pub(super) const OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1: u16 = 91;
pub(super) const OPERATION_BILLING_PUBLISH_STATEMENT_V1: u16 = 92;
pub(super) const OPERATION_BILLING_LOOKUP_PUBLICATION_V1: u16 = 93;
pub(super) const OPERATION_BILLING_VERIFY_ACKNOWLEDGEMENT_V1: u16 = 94;
pub(super) const OPERATION_BILLING_RECORD_ACKNOWLEDGEMENT_V1: u16 = 95;
pub(super) const OPERATION_BILLING_LOOKUP_ACKNOWLEDGEMENT_V1: u16 = 96;
pub(super) const OPERATION_BILLING_LOAD_LATEST_EPOCH_V1: u16 = 97;
pub(super) const OPERATION_BILLING_LOAD_EPOCH_V1: u16 = 98;
pub(super) const OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1: u16 = 99;
pub(super) const OPERATION_SORACLOUD_PROVENANCE_SIGN_V1: u16 = 100;
pub(super) const OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1: u16 = 101;
pub(super) const OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1: u16 = 102;
pub(super) const OPERATION_MODERATION_CHECKPOINT_LOAD_V1: u16 = 103;
pub(super) const OPERATION_MODERATION_CHECKPOINT_COMPARE_AND_SWAP_V1: u16 = 104;
pub(super) const OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1: u16 = 105;
pub(super) const OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1: u16 = 106;
pub(super) const OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_QUALIFY_V1: u16 = 111;
pub(super) const OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1: u16 = 112;
pub(super) const OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1: u16 = 113;
pub(super) const OPERATION_MODERATION_PANEL_NOTIFICATION_SOURCE_ATTEST_V1: u16 = 114;
pub(super) const OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1: u16 = 115;
pub(super) const OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1: u16 = 116;
pub(super) const OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1: u16 = 117;
pub(super) const OPERATION_POP_WALLET_RECIPIENT_OPEN_V1: u16 = 118;
pub(super) const OPERATION_BOOTLE_LANTERN_ISSUANCE_AUTHENTICATE_V1: u16 = 119;
pub(super) const OPERATION_BOOTLE_LANTERN_ISSUANCE_PREPARE_AUTHORIZATION_V1: u16 = 120;
pub(super) const OPERATION_BOOTLE_LANTERN_ISSUANCE_VALIDATE_REQUEST_V1: u16 = 121;
pub(super) const OPERATION_BOOTLE_LANTERN_ISSUANCE_ISSUE_VALIDATED_V1: u16 = 122;
pub(super) const OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1: u16 = 123;
pub(super) const OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1: u16 = 124;
pub(super) const OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1: u16 = 125;
pub(super) const OPERATION_STREAM_TOKEN_RECOVER_V1: u16 = 126;
pub(super) const OPERATION_STREAM_TOKEN_OBSERVE_V1: u16 = 127;
pub(super) const OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1: u16 = 128;
pub(super) const OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1: u16 = 129;
pub(super) const OPERATION_STREAM_TOKEN_CHECK_V1: u16 = 130;
// A real payload byte avoids relying on zero-sized archive reconstruction;
// the authenticated slot and operation provide the request-domain binding.
pub(super) const CHECKPOINT_LOAD_REQUEST_VERSION_V1: u8 = 1;
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::primitives::PurposeSignRequestWireV1"; pub(super) PurposeSignRequestWireV1 { pub(super) purpose: u8, pub(super) payload: Vec<u8>, });
impl_broker_debug_fields!(PurposeSignRequestWireV1 as value {
    "purpose" => value.purpose,
    "payload_len" => value.payload.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(PurposeSignRequestWireV1 { payload });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::primitives::SignResultWireV1"; pub(super) SignResultWireV1 { pub(super) signature: [u8; 64], });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::primitives::VariableSignatureResultWireV1"; pub(super) VariableSignatureResultWireV1 { pub(super) signature: Vec<u8>, });
impl_broker_debug_fields!(VariableSignatureResultWireV1 as value {
    "signature_len" => value.signature.len(),
} => finish_non_exhaustive);
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::primitives::PopIssuerSignRequestWireV1"; pub(super) PopIssuerSignRequestWireV1 { pub(super) purpose: u8, pub(super) digest: [u8; 32], });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::primitives::PopIssuerSignResultWireV1"; pub(super) PopIssuerSignResultWireV1 { pub(super) signature: [u8; 64], });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::GlobalBeaconPartialSignRequestWireV1"; pub(super) GlobalBeaconPartialSignRequestWireV1 {
    pub(super) session: iroha_data_model::consensus::GlobalThresholdBeaconKeySessionV1,
    pub(super) height: u64,
    pub(super) finalized_chain_anchor: iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1,
    pub(super) context: iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1,
});
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::GlobalBeaconSeatReadinessRequestWireV1"; pub(super) GlobalBeaconSeatReadinessRequestWireV1 {
    pub(super) session: iroha_data_model::consensus::GlobalThresholdBeaconKeySessionV1,
    pub(super) authority: iroha_data_model::sumeragi::epoch::ValidatorGenerationV1,
    pub(super) context: iroha_data_model::nexus::ValidatorSeatReadinessContextV1,
});
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::primitives::GlobalBeaconPartialSignResultWireV1"; pub(super) GlobalBeaconPartialSignResultWireV1 {
    pub(super) partial: iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1,
});
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::ParliamentTlePartialReleaseSignRequestWireV1"; pub(super) ParliamentTlePartialReleaseSignRequestWireV1 {
    pub(super) projection: iroha_core_timed_ovn::tle::AuthorizedTleReleaseProjectionV1,
});
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::ParliamentTlePartialReleaseSignResultWireV1"; pub(super) ParliamentTlePartialReleaseSignResultWireV1 {
    pub(super) partial: iroha_core_timed_ovn::tle::TlePartialReleaseShareV1,
});
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::ParliamentTleCapabilityAttestRequestWireV1"; pub(super) ParliamentTleCapabilityAttestRequestWireV1 {
    pub(super) key_session: iroha_core_timed_ovn::tle::TleKeySessionPublicStateV1,
    pub(super) participant_index: u16,
});
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::ParliamentTleCapabilityAttestResultWireV1"; pub(super) ParliamentTleCapabilityAttestResultWireV1 {
    pub(super) key_session_id: iroha_data_model::governance::types::TleKeySessionId,
    pub(super) transcript_hash: [u8; 32],
    pub(super) participant_index: u16,
});
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::GlobalBeaconCapabilityAttestRequestWireV1"; pub(super) GlobalBeaconCapabilityAttestRequestWireV1 {
    pub(super) session: iroha_data_model::consensus::GlobalThresholdBeaconKeySessionV1,
    pub(super) signer_index: u16,
});
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::GlobalBeaconCapabilityAttestResultWireV1"; pub(super) GlobalBeaconCapabilityAttestResultWireV1 {
    pub(super) session_id: [u8; 32],
    pub(super) transcript_hash: [u8; 32],
    pub(super) signer_index: u16,
});
// Borrowed serialization view of the sole canonical request frame.
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_broker::protocol::primitives::GlobalBeaconPartialSignRequestWireV1",
    frame = "irohad::runtime_provider_broker::protocol::primitives::GlobalBeaconPartialSignRequestWireV1"
)]
pub(super) struct GlobalBeaconPartialSignRequestRefV1<'a> {
    pub(super) session: norito::core::PayloadRef<
        'a,
        iroha_data_model::consensus::GlobalThresholdBeaconKeySessionV1,
    >,
    pub(super) height: u64,
    pub(super) finalized_chain_anchor:
        iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1,
    pub(super) context: iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1,
}

// Borrowed serialization view of the sole canonical request frame.
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_broker::protocol::primitives::GlobalBeaconSeatReadinessRequestWireV1",
    frame = "irohad::runtime_provider_broker::protocol::primitives::GlobalBeaconSeatReadinessRequestWireV1"
)]
pub(super) struct GlobalBeaconSeatReadinessRequestRefV1<'a> {
    pub(super) session: norito::core::PayloadRef<
        'a,
        iroha_data_model::consensus::GlobalThresholdBeaconKeySessionV1,
    >,
    pub(super) authority: norito::core::PayloadRef<
        'a,
        iroha_data_model::sumeragi::epoch::ValidatorGenerationV1,
    >,
    pub(super) context:
        iroha_data_model::nexus::ValidatorSeatReadinessContextV1,
}

// Borrowed serialization view of the sole canonical request frame.
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_broker::protocol::primitives::GlobalBeaconCapabilityAttestRequestWireV1",
    frame = "irohad::runtime_provider_broker::protocol::primitives::GlobalBeaconCapabilityAttestRequestWireV1"
)]
pub(super) struct GlobalBeaconCapabilityAttestRequestRefV1<'a> {
    pub(super) session: norito::core::PayloadRef<
        'a,
        iroha_data_model::consensus::GlobalThresholdBeaconKeySessionV1,
    >,
    pub(super) signer_index: u16,
}

pub(super) fn governance_signing_purpose_from_wire(
    value: u8,
) -> Result<sorafs_node::GovernanceDagSigningPurposeV1, BrokerError> {
    sorafs_node::GovernanceDagSigningPurposeV1::try_from_wire_id(value).ok_or(BrokerError::Rejected)
}
pub(super) fn validate_governance_purpose_signing_request(
    signing: &PurposeSignRequestWireV1,
    binding: &ProviderBindingWireV1,
) -> Result<sorafs_node::GovernanceDagSigningPurposeV1, BrokerError> {
    validate_signing_payload_len(signing.payload.len())?;
    let purpose = governance_signing_purpose_from_wire(signing.purpose)?;
    let peer_id = binding
        .governance_dag_publisher_peer_id
        .as_deref()
        .ok_or(BrokerError::BindingMismatch)?;
    let public_key = binding
        .governance_dag_publisher_public_key
        .ok_or(BrokerError::BindingMismatch)?;
    let valid = match purpose {
        sorafs_node::GovernanceDagSigningPurposeV1::LogNode => {
            sorafs_manifest::governance::
                validate_governance_log_node_signing_payload_for_publisher_v1(
                    &signing.payload,
                    peer_id,
                )
        }
        sorafs_node::GovernanceDagSigningPurposeV1::DagBlock => {
            sorafs_manifest::governance::
                validate_governance_dag_block_signing_payload_for_publisher_v1(
                    &signing.payload,
                    peer_id,
                    public_key,
                )
        }
        sorafs_node::GovernanceDagSigningPurposeV1::DagHead => {
            sorafs_manifest::governance::
                validate_governance_dag_head_signing_payload_for_publisher_v1(
                    &signing.payload,
                    peer_id,
                )
        }
        sorafs_node::GovernanceDagSigningPurposeV1::KeyTransition
        | sorafs_node::GovernanceDagSigningPurposeV1::QualificationArchive => {
            return sorafs_node::validate_governance_dag_control_signing_payload_v1(
                purpose,
                &signing.payload,
                peer_id,
                public_key,
            )
            .map(|()| purpose)
            .map_err(|_| BrokerError::Rejected);
        }
    };
    valid.map_err(|_| BrokerError::Rejected)?;
    Ok(purpose)
}
pub(super) fn validate_governance_sign_operation_result(
    request: &OperationRequestV1,
    result: &[u8],
) -> Result<(), BrokerError> {
    let signed =
        decode_canonical::<SignResultWireV1>(result, MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1)?;
    let sign = decode_canonical::<PurposeSignRequestWireV1>(
        &request.payload,
        MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1,
    )?;
    validate_governance_purpose_signing_request(&sign, &request.binding)
        .map_err(|_| BrokerError::Protocol)?;
    let public_key = request
        .binding
        .governance_dag_publisher_public_key
        .ok_or(BrokerError::BindingMismatch)?;
    verify_evidence_viewer_ed25519_signature(public_key, signed.signature, &sign.payload)
        .map_err(|_| BrokerError::Protocol)
}
pub(super) fn evidence_signing_purpose_from_wire(
    value: u8,
) -> Result<sorafs_node::evidence_viewer::EvidenceViewerSigningPurposeV1, BrokerError> {
    sorafs_node::evidence_viewer::EvidenceViewerSigningPurposeV1::try_from_wire_id(value)
        .ok_or(BrokerError::Rejected)
}
pub(super) fn validate_evidence_purpose_signing_request(
    signing: &PurposeSignRequestWireV1,
    binding: &ProviderBindingWireV1,
) -> Result<sorafs_node::evidence_viewer::EvidenceViewerSigningPurposeV1, BrokerError> {
    if signing.payload.is_empty()
        || signing.payload.len() > MAX_EVIDENCE_VIEWER_RECEIPT_MESSAGE_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    let purpose = evidence_signing_purpose_from_wire(signing.purpose)?;
    let public_key = binding
        .evidence_viewer_receipt_signer_public_key
        .ok_or(BrokerError::BindingMismatch)?;
    sorafs_node::evidence_viewer::validate_evidence_viewer_signing_message_v1(
        purpose,
        &signing.payload,
        &binding.handle,
        public_key,
    )
    .map_err(|_| BrokerError::Rejected)?;
    Ok(purpose)
}
pub(super) const STATUS_OK_V1: u8 = 0;
pub(super) const STATUS_REJECTED_V1: u8 = 1;
pub(super) const STATUS_CONFLICT_V1: u8 = 2;
pub(super) const STATUS_STALE_OR_REVOKED_V1: u8 = 3;
pub(super) const STATUS_AMBIGUOUS_V1: u8 = 4;
pub(super) const STATUS_UNAVAILABLE_V1: u8 = 5;
pub(super) const ERROR_UNAVAILABLE: &str = "runtime provider is unavailable";
pub(super) const ERROR_STALE_OR_REVOKED: &str = "runtime provider binding is stale or revoked";
pub(super) const ERROR_REJECTED: &str = "runtime provider request was rejected";
pub(super) const ERROR_CONFLICT: &str = "runtime provider compare-and-swap conflict";
pub(super) const ERROR_AMBIGUOUS: &str = "runtime provider outcome is ambiguous";
pub(super) const CATALOG_DIGEST_DOMAIN_V1: &[u8] = b"iroha.runtime-provider-broker.catalog.v1";
pub(super) const CLIENT_TRANSCRIPT_DOMAIN_V1: &[u8] =
    b"iroha.runtime-provider-broker.client-transcript.v1";
pub(super) const SERVER_TRANSCRIPT_DOMAIN_V1: &[u8] =
    b"iroha.runtime-provider-broker.server-transcript.v1";
pub(super) const PROVIDER_METADATA_DOMAIN_V1: &[u8] =
    b"iroha.runtime-provider-broker.provider-metadata.v1";
pub(super) const OPERATION_PAYLOAD_DOMAIN_V1: &[u8] =
    b"iroha.runtime-provider-broker.operation-payload.v1";
pub(super) const OPERATION_REQUEST_DOMAIN_V1: &[u8] =
    b"iroha.runtime-provider-broker.operation-request.v1";
pub(super) const OPERATION_RESULT_DOMAIN_V1: &[u8] =
    b"iroha.runtime-provider-broker.operation-result.v1";
pub(super) const OPERATION_RESPONSE_DOMAIN_V1: &[u8] =
    b"iroha.runtime-provider-broker.operation-response.v1";
pub(super) const PROVIDER_INGEST_SOURCE_STREAM_DOMAIN_V1: &[u8] =
    b"iroha.runtime-provider-broker.provider-ingest-source-stream.v1";
pub(super) const PROVIDER_INGEST_SOURCE_CHUNK_DOMAIN_V1: &[u8] =
    b"iroha.runtime-provider-broker.provider-ingest-source-chunk.v1";
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::PopRuntimeOpenResultWireV1"; pub(super) PopRuntimeOpenResultWireV1 { pub(super) issuer_signer_handle: String, pub(super) issuer_public_key: [u8; 32], pub(super) enrollment_recipient_key_id: String, pub(super) enrollment_recipient_public_key_digest: [u8; 32], pub(super) wallet_recipient_key_id: String, pub(super) wallet_recipient_public_key_digest: [u8; 32], pub(super) wallet_wrapping_key_id: String, });
define_broker_wire_struct!(move_sensitive frame "irohad::runtime_provider_broker::protocol::primitives::PopRecipientOpenRequestWireV1"; pub(super) PopRecipientOpenRequestWireV1 { pub(super) encrypted_payload: sorafs_manifest::hybrid_envelope::HybridPayloadEnvelopeV1, pub(super) aad: Vec<u8>, });
impl_broker_debug_fields!(PopRecipientOpenRequestWireV1 as value {
    "encrypted_payload" => "[REDACTED]",
    "aad_len" => value.aad.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(PopRecipientOpenRequestWireV1 { aad });
define_broker_wire_struct!(move_sensitive frame "irohad::runtime_provider_broker::protocol::primitives::PopRecipientOpenResultWireV1"; pub(super) PopRecipientOpenResultWireV1 { pub(super) plaintext: Vec<u8>, });
impl PopRecipientOpenResultWireV1 {
    pub(super) fn take_plaintext(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.plaintext)
    }
}
impl_broker_debug_fields!(PopRecipientOpenResultWireV1 as value {
    "plaintext" => "[REDACTED]",
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(PopRecipientOpenResultWireV1 { plaintext });
pub(super) fn validate_pop_open_result(
    result: &PopRuntimeOpenResultWireV1,
    exact: &PopCredentialRuntimeBindingWireV1,
) -> Result<(), BrokerError> {
    if result.issuer_signer_handle != exact.issuer_signer_handle
        || result.issuer_public_key != exact.issuer_public_key
        || result.enrollment_recipient_key_id != exact.enrollment_recipient_key_id
        || result.enrollment_recipient_public_key_digest
            != exact.enrollment_recipient_public_key_digest
        || result.wallet_recipient_key_id != exact.wallet_recipient_key_id
        || result.wallet_recipient_public_key_digest != exact.wallet_recipient_public_key_digest
        || result.wallet_wrapping_key_id != exact.wallet_wrapping_key_id
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
pub(super) fn validate_pop_cursor(
    cursor: sorafs_node::pop_credentials::PopFinalizedCursorV1,
) -> Result<(), BrokerError> {
    if cursor.block_height == 0 || cursor.block_hash == [0; 32] {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
const POP_RECIPIENT_AAD_MAX_BYTES_V1: usize = 64 * 1024;
const POP_HYBRID_AEAD_TAG_BYTES_V1: usize = 16;
fn pop_recipient_plaintext_limit(operation: u16) -> Result<usize, BrokerError> {
    match operation {
        OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1 => {
            Ok(sorafs_node::pop_credentials::POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1)
        }
        OPERATION_POP_WALLET_RECIPIENT_OPEN_V1 => {
            Ok(sorafs_node::pop_credentials::POP_WALLET_DELIVERY_MAX_BYTES_V1)
        }
        _ => Err(BrokerError::Rejected),
    }
}
pub(super) fn validate_pop_recipient_open_request(
    request: &PopRecipientOpenRequestWireV1,
    operation: u16,
) -> Result<(), BrokerError> {
    let plaintext_limit = pop_recipient_plaintext_limit(operation)?;
    let ciphertext_limit = plaintext_limit
        .checked_add(POP_HYBRID_AEAD_TAG_BYTES_V1)
        .ok_or(BrokerError::Rejected)?;
    if request.encrypted_payload.version
        != sorafs_manifest::hybrid_envelope::HYBRID_PAYLOAD_ENVELOPE_VERSION_V1
        || request.encrypted_payload.suite.as_str()
            != "x25519-mlkem768-chacha20poly1305-transcript-v1"
        || iroha_crypto::HybridKemCiphertext::from_parts(
            &request.encrypted_payload.kem.ephemeral_public,
            &request.encrypted_payload.kem.kyber_ciphertext,
        )
        .is_err()
        || request.aad.is_empty()
        || request.aad.len() > POP_RECIPIENT_AAD_MAX_BYTES_V1
        || request.encrypted_payload.ciphertext.len() <= POP_HYBRID_AEAD_TAG_BYTES_V1
        || request.encrypted_payload.ciphertext.len() > ciphertext_limit
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
pub(super) fn validate_pop_recipient_open_result(
    result: &PopRecipientOpenResultWireV1,
    operation: u16,
) -> Result<(), BrokerError> {
    let plaintext_limit = pop_recipient_plaintext_limit(operation)?;
    if result.plaintext.is_empty() || result.plaintext.len() > plaintext_limit {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
pub(super) struct ScrubbedBytes {
    pub(super) bytes: Vec<u8>,
    pub(super) inbound_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    pub(super) decode_admission: Option<Arc<DecodeResourceAdmissionV1>>,
    #[cfg(test)]
    drop_audit: Option<(usize, Arc<std::sync::atomic::AtomicUsize>)>,
}
#[cfg(test)]
mod operation_ordinal_tests {
    use super::*;

    #[test]
    fn post_soracloud_operation_ids_are_exact_and_ordered() {
        let exact = [
            (OPERATION_SORACLOUD_PROVENANCE_SIGN_V1, 100),
            (OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1, 101),
            (
                OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1,
                102,
            ),
            (OPERATION_MODERATION_CHECKPOINT_LOAD_V1, 103),
            (OPERATION_MODERATION_CHECKPOINT_COMPARE_AND_SWAP_V1, 104),
            (OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1, 105),
            (
                OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1,
                106,
            ),
            (
                OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_QUALIFY_V1,
                111,
            ),
            (
                OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1,
                112,
            ),
            (OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1, 113),
            (
                OPERATION_MODERATION_PANEL_NOTIFICATION_SOURCE_ATTEST_V1,
                114,
            ),
            (
                OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1,
                115,
            ),
            (
                OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1,
                116,
            ),
            (OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1, 117),
            (OPERATION_POP_WALLET_RECIPIENT_OPEN_V1, 118),
            (OPERATION_BOOTLE_LANTERN_ISSUANCE_AUTHENTICATE_V1, 119),
            (
                OPERATION_BOOTLE_LANTERN_ISSUANCE_PREPARE_AUTHORIZATION_V1,
                120,
            ),
            (OPERATION_BOOTLE_LANTERN_ISSUANCE_VALIDATE_REQUEST_V1, 121),
            (OPERATION_BOOTLE_LANTERN_ISSUANCE_ISSUE_VALIDATED_V1, 122),
            (OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1, 123),
            (OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1, 124),
            (OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1, 125),
            (OPERATION_STREAM_TOKEN_RECOVER_V1, 126),
            (OPERATION_STREAM_TOKEN_OBSERVE_V1, 127),
            (OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1, 128),
            (OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1, 129),
            (OPERATION_STREAM_TOKEN_CHECK_V1, 130),
        ];
        for (operation, expected) in exact {
            assert_eq!(operation, expected);
            assert!(super::super::operation_is_known(operation));
        }
        assert!(super::super::operation_is_known(
            OPERATION_POP_RUNTIME_OPEN_V1
        ));
        for unsupported in [107, 108, 109, 110, 131] {
            assert!(!super::super::operation_is_known(unsupported));
        }
    }
}

#[cfg(test)]
mod pop_recipient_wire_tests {
    use super::*;
    use rand::{SeedableRng as _, rngs::StdRng};
    fn exact_binding() -> PopCredentialRuntimeBindingWireV1 {
        PopCredentialRuntimeBindingWireV1 {
            issuer_policy_digest: [0x11; 32],
            issuer_id: "pop-issuer-production-primary".to_owned(),
            issuer_signer_handle: "software://sorafs/pop-credentials/primary".to_owned(),
            issuer_public_key: [0x12; 32],
            enrollment_recipient_key_id: "kms:pop/enrollment:primary".to_owned(),
            enrollment_recipient_public_key_digest: [0x13; 32],
            wallet_recipient_key_id: "kms:pop/wallet-recipient:primary".to_owned(),
            wallet_recipient_public_key_digest: [0x14; 32],
            wallet_wrapping_key_id: "kms:pop/wallet-wrap:primary".to_owned(),
        }
    }
    fn valid_open_request() -> PopRecipientOpenRequestWireV1 {
        let mut rng = StdRng::from_seed([0x21; 32]);
        let recipient = iroha_crypto::HybridKeyPair::generate(&mut rng)
            .expect("generate deterministic recipient");
        let aad = b"sorafs-pop-recipient-wire-test".to_vec();
        let encrypted_payload = sorafs_manifest::hybrid_envelope::encrypt_payload(
            b"private-payload",
            &aad,
            recipient.public(),
            &mut rng,
        )
        .expect("encrypt deterministic payload");
        PopRecipientOpenRequestWireV1 {
            encrypted_payload,
            aad,
        }
    }
    #[test]
    fn pop_runtime_operations_use_the_exact_first_release_ids() {
        let exact = exact_binding();
        let outcome = PopRuntimeOpenResultWireV1 {
            issuer_signer_handle: exact.issuer_signer_handle.clone(),
            issuer_public_key: exact.issuer_public_key,
            enrollment_recipient_key_id: exact.enrollment_recipient_key_id.clone(),
            enrollment_recipient_public_key_digest: exact.enrollment_recipient_public_key_digest,
            wallet_recipient_key_id: exact.wallet_recipient_key_id.clone(),
            wallet_recipient_public_key_digest: exact.wallet_recipient_public_key_digest,
            wallet_wrapping_key_id: exact.wallet_wrapping_key_id.clone(),
        };
        assert_eq!(validate_pop_open_result(&outcome, &exact), Ok(()));
        let mut substituted = outcome;
        substituted.wallet_recipient_public_key_digest = [0x99; 32];
        assert_eq!(
            validate_pop_open_result(&substituted, &exact),
            Err(BrokerError::Rejected)
        );
        assert_eq!(OPERATION_POP_RUNTIME_OPEN_V1, 60);
        assert_eq!(OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1, 117);
        assert_eq!(OPERATION_POP_WALLET_RECIPIENT_OPEN_V1, 118);
        assert!(super::super::operation_is_known(60));
    }
    #[test]
    fn pop_recipient_open_rejects_noncanonical_envelopes_and_redacts_values() {
        let request = valid_open_request();
        assert_eq!(
            validate_pop_recipient_open_request(
                &request,
                OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1,
            ),
            Ok(())
        );
        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private-payload"));
        let mut missing_aad = valid_open_request();
        missing_aad.aad.clear();
        assert_eq!(
            validate_pop_recipient_open_request(
                &missing_aad,
                OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1,
            ),
            Err(BrokerError::Rejected)
        );
        let mut wrong_version = valid_open_request();
        wrong_version.encrypted_payload.version = 0;
        assert_eq!(
            validate_pop_recipient_open_request(
                &wrong_version,
                OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1,
            ),
            Err(BrokerError::Rejected)
        );
        let mut wrong_suite = valid_open_request();
        wrong_suite.encrypted_payload.suite.push_str("-substituted");
        assert_eq!(
            validate_pop_recipient_open_request(
                &wrong_suite,
                OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1,
            ),
            Err(BrokerError::Rejected)
        );
        let mut malformed_kem = valid_open_request();
        malformed_kem.encrypted_payload.kem.ephemeral_public.pop();
        assert_eq!(
            validate_pop_recipient_open_request(
                &malformed_kem,
                OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1,
            ),
            Err(BrokerError::Rejected)
        );
        let mut oversized_ciphertext = valid_open_request();
        oversized_ciphertext.encrypted_payload.ciphertext.resize(
            sorafs_node::pop_credentials::POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1
                + POP_HYBRID_AEAD_TAG_BYTES_V1
                + 1,
            0xA5,
        );
        assert_eq!(
            validate_pop_recipient_open_request(
                &oversized_ciphertext,
                OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1,
            ),
            Err(BrokerError::Rejected)
        );
        let mut result = PopRecipientOpenResultWireV1 {
            plaintext: b"private-payload".to_vec(),
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private-payload"));
        assert_eq!(
            validate_pop_recipient_open_result(&result, OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1,),
            Ok(())
        );
        assert_eq!(result.take_plaintext(), b"private-payload".to_vec());
        assert!(result.plaintext.is_empty());
        let enrollment_too_large = PopRecipientOpenResultWireV1 {
            plaintext: vec![
                0xA5;
                sorafs_node::pop_credentials::POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1 + 1
            ],
        };
        assert_eq!(
            validate_pop_recipient_open_result(
                &enrollment_too_large,
                OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1,
            ),
            Err(BrokerError::Rejected)
        );
        assert_eq!(
            validate_pop_recipient_open_result(
                &enrollment_too_large,
                OPERATION_POP_WALLET_RECIPIENT_OPEN_V1,
            ),
            Ok(())
        );
    }
}
impl ScrubbedBytes {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            inbound_permit: None,
            decode_admission: None,
            #[cfg(test)]
            drop_audit: None,
        }
    }
    pub(super) fn with_inbound_permit(
        bytes: Vec<u8>,
        inbound_permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Self {
        Self {
            bytes,
            inbound_permit: Some(inbound_permit),
            decode_admission: None,
            #[cfg(test)]
            drop_audit: None,
        }
    }
    pub(super) fn with_decode_admission(
        bytes: Vec<u8>,
        decode_admission: Arc<DecodeResourceAdmissionV1>,
    ) -> Self {
        Self {
            bytes,
            inbound_permit: None,
            decode_admission: Some(decode_admission),
            #[cfg(test)]
            drop_audit: None,
        }
    }
    #[cfg(test)]
    pub(super) fn with_drop_audit(
        bytes: Vec<u8>,
        observed_scrubbed_len: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        let expected_len = bytes.len();
        Self {
            bytes,
            inbound_permit: None,
            decode_admission: None,
            drop_audit: Some((expected_len, observed_scrubbed_len)),
        }
    }
    pub(super) fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
    pub(super) fn enter_decode_admission(&self) -> Option<DecodeResourceAdmissionScopeV1> {
        self.decode_admission
            .as_ref()
            .map(DecodeResourceAdmissionV1::enter)
    }
}
impl std::ops::Deref for ScrubbedBytes {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}
impl std::ops::DerefMut for ScrubbedBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}
impl_broker_debug_fields!(ScrubbedBytes as value {
    "len" => value.bytes.len(),
    "inbound_budgeted" => value.inbound_permit.is_some(),
    "decode_budgeted" => value.decode_admission.is_some(),
} => finish_non_exhaustive);
impl PartialEq for ScrubbedBytes {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl Eq for ScrubbedBytes {}
impl Drop for ScrubbedBytes {
    fn drop(&mut self) {
        self.bytes.fill(0);
        #[cfg(test)]
        if let Some((expected_len, observed_scrubbed_len)) = &self.drop_audit {
            let observed =
                if self.bytes.len() == *expected_len && self.bytes.iter().all(|byte| *byte == 0) {
                    self.bytes.len()
                } else {
                    usize::MAX
                };
            observed_scrubbed_len.store(observed, std::sync::atomic::Ordering::SeqCst);
        }
        let _ = std::hint::black_box(&self.bytes);
    }
}
pub(super) struct ScrubbedReadChunk(pub(super) Box<[u8]>);
impl std::ops::Deref for ScrubbedReadChunk {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for ScrubbedReadChunk {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ScrubbedReadChunk {
    fn drop(&mut self) {
        self.0.fill(0);
        let _ = std::hint::black_box(&self.0);
    }
}
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::primitives::BrokerFrameV1"; pub(super) BrokerFrameV1 { pub(super) magic: [u8; 8], pub(super) version: u16, pub(super) kind: u8, pub(super) body: Vec<u8>, });
impl_broker_debug_fields!(BrokerFrameV1 as value {
    "version" => value.version,
    "kind" => value.kind,
    "body_len" => value.body.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(BrokerFrameV1 { body });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::ProviderBindingWireV1"; pub(super) ProviderBindingWireV1 { pub(super) slot: u16, pub(super) handle: String, pub(super) revision: Option<u64>, pub(super) policy_digest: Option<[u8; 32]>, pub(super) bootle_lantern_issuance_bindings: Option<BootleLanternIssuanceBindingsWireV1>, pub(super) stream_token_signer_binding: Option<crate::runtime_provider_registry::StreamTokenSignerRuntimeBindingV1>, pub(super) appeal_finance_signer_binding: Option<AppealFinanceSignerBindingWireV1>, pub(super) appeal_finance_checkpoint_binding: Option<AppealFinanceCheckpointBindingWireV1>, pub(super) appeal_finance_checkpoint_max_bytes: Option<u64>, pub(super) pop_credential_runtime_binding: Option<PopCredentialRuntimeBindingWireV1>, pub(super) por_replay_archive_binding: Option<sorafs_node::PorFinalizedReplayArchiveBindingV1>, pub(super) por_replay_archive_proof_limits: Option<PorReplayArchiveProofLimitsWireV1>, pub(super) potr_runtime_binding: Option<PotrRuntimeBindingWireV1>, pub(super) native_signer_binding: Option<NativeTransactionSignerBindingWireV1>, pub(super) governance_dag_publisher_peer_id: Option<Vec<u8>>, pub(super) governance_dag_publisher_public_key: Option<[u8; 32]>, pub(super) governance_request_ingress_binding: Option<GovernanceRequestIngressBindingWireV1>, pub(super) provider_ingest_signer_binding: Option<ProviderIngestSignerBindingWireV1>, pub(super) provider_ingest_source_limits: Option<ProviderIngestSourceLimitsWireV1>, pub(super) provider_ingest_checkpoint_max_bytes: Option<u64>, pub(super) provider_ingest_max_signed_transaction_bytes: Option<u64>, pub(super) evidence_viewer_webauthn_binding: Option<EvidenceViewerWebAuthnBindingWireV1>, pub(super) evidence_viewer_grant_ttl_ms: Option<u64>, pub(super) evidence_viewer_receipt_signer_public_key: Option<[u8; 32]>, pub(super) evidence_viewer_transparency_publisher_public_key: Option<[u8; 32]>, pub(super) evidence_viewer_checkpoint_max_bytes: Option<u64>, pub(super) moderation_checkpoint_max_bytes: Option<u64>, pub(super) moderation_checkpoint_attestation_public_key: Option<[u8; 32]>, pub(super) evidence_viewer_archive_id: Option<[u8; 32]>, pub(super) evidence_viewer_archive_public_key: Option<[u8; 32]>, pub(super) evidence_viewer_archive_max_bytes: Option<u64>, pub(super) moderation_panel_notification_archive_binding: Option<ModerationPanelNotificationArchiveBindingWireV1>, });
// Exact public identity and resource bound for moderation receipt archives.
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::primitives::ModerationPanelNotificationArchiveBindingWireV1"; pub(super) ModerationPanelNotificationArchiveBindingWireV1 { pub(super) archive_id: [u8; 32], pub(super) bootstrap_public_key: [u8; 32], pub(super) public_key: [u8; 32], pub(super) max_bytes: u64, pub(super) max_records: u64, });
define_broker_wire_struct!(copy pub(super) GovernanceRequestIngressBindingWireV1 { pub(super) scope: u8, pub(super) endpoint_binding: [u8; 32], pub(super) public_key: [u8; 32], pub(super) max_body_bytes: u64, pub(super) max_envelope_lifetime_secs: u64, pub(super) max_future_skew_secs: u64, });
define_broker_wire_struct!(copy pub(super) BootleLanternIssuanceBindingsWireV1 { pub(super) issuer_id: [u8; 32], pub(super) policy_id: [u8; 32], pub(super) authorization_lifetime_blocks: u64, });
define_broker_wire_struct!(owned pub(super) AppealFinanceSignerBindingWireV1 { pub(super) authority: iroha_data_model::account::AccountId, pub(super) public_key: iroha_crypto::PublicKey, pub(super) valid_from_block_height: u64, pub(super) revoked_at_block_height: Option<u64>, });
define_broker_wire_struct!(owned pub(super) AppealFinanceCheckpointBindingWireV1 { pub(super) public_key: iroha_crypto::PublicKey, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::PopCredentialRuntimeBindingWireV1"; pub(super) PopCredentialRuntimeBindingWireV1 { pub(super) issuer_policy_digest: [u8; 32], pub(super) issuer_id: String, pub(super) issuer_signer_handle: String, pub(super) issuer_public_key: [u8; 32], pub(super) enrollment_recipient_key_id: String, pub(super) enrollment_recipient_public_key_digest: [u8; 32], pub(super) wallet_recipient_key_id: String, pub(super) wallet_recipient_public_key_digest: [u8; 32], pub(super) wallet_wrapping_key_id: String, });
define_broker_wire_struct!(copy pub(super) PorReplayArchiveProofLimitsWireV1 { pub(super) max_successor_receipts: u32, pub(super) max_successor_proof_bytes: u64, });
impl From<crate::runtime_provider_registry::PorReplayArchiveProofLimitsV1>
    for PorReplayArchiveProofLimitsWireV1
{
    fn from(limits: crate::runtime_provider_registry::PorReplayArchiveProofLimitsV1) -> Self {
        Self {
            max_successor_receipts: limits.max_successor_receipts,
            max_successor_proof_bytes: limits.max_successor_proof_bytes,
        }
    }
}
impl From<&crate::runtime_provider_registry::PopCredentialRuntimeBindingV1>
    for PopCredentialRuntimeBindingWireV1
{
    fn from(binding: &crate::runtime_provider_registry::PopCredentialRuntimeBindingV1) -> Self {
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
define_broker_wire_struct!(copy pub(super) PotrAdmissionPolicyBindingWireV1 { pub(super) provider_id: [u8; 32], pub(super) policy_identity: [u8; 32], pub(super) policy_digest: [u8; 32], pub(super) policy_sequence: u64, pub(super) finalized_height: u64, pub(super) finalized_block_hash: [u8; 32], pub(super) admission_envelope_digest: [u8; 32], });
impl PotrAdmissionPolicyBindingWireV1 {
    pub(super) fn to_binding(self) -> sorafs_node::PotrAdmissionPolicyBindingV1 {
        sorafs_node::PotrAdmissionPolicyBindingV1 {
            provider_id: self.provider_id,
            policy_identity: self.policy_identity,
            policy_digest: self.policy_digest,
            policy_sequence: self.policy_sequence,
            finalized_height: self.finalized_height,
            finalized_block_hash: self.finalized_block_hash,
            admission_envelope_digest: self.admission_envelope_digest,
        }
    }
}
define_broker_wire_struct!(owned pub(super) PotrRuntimeBindingWireV1 { pub(super) gateway_handle: String, pub(super) gateway_signer_id: [u8; 32], pub(super) gateway_revision: u64, pub(super) gateway_policy_digest: [u8; 32], pub(super) provider_handle: String, pub(super) provider_signer_id: [u8; 32], pub(super) provider_revision: u64, pub(super) provider_policy_digest: [u8; 32], pub(super) gateway_public_key: [u8; 32], pub(super) reader_id: [u8; 32], pub(super) source_id: [u8; 32], pub(super) resolver_id: [u8; 32], pub(super) baseline_admission_policy: PotrAdmissionPolicyBindingWireV1, });
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
define_broker_wire_struct!(owned pub(super) NativeTransactionSignerBindingWireV1 { pub(super) role: u8, pub(super) authority: iroha_data_model::account::AccountId, pub(super) public_key: iroha_crypto::PublicKey, });
pub(super) const SORACLOUD_RUNTIME_SIGNER_ROLE_WIRE_V1: u8 = 5;
define_broker_wire_struct!(owned pub(super) EvidenceViewerWebAuthnBindingWireV1 { pub(super) rp_id: String, pub(super) allowed_origins: Vec<String>, pub(super) challenge_ttl_ms: u64, });
impl From<&EvidenceViewerWebAuthnBindingV1> for EvidenceViewerWebAuthnBindingWireV1 {
    fn from(binding: &EvidenceViewerWebAuthnBindingV1) -> Self {
        Self {
            rp_id: binding.rp_id.clone(),
            allowed_origins: binding.allowed_origins.clone(),
            challenge_ttl_ms: binding.challenge_ttl_ms,
        }
    }
}
define_broker_wire_struct!(copy pub(super) ProviderIngestSourceLimitsWireV1 { pub(super) operation_timeout_ms: u64, pub(super) max_content_bytes: u64, pub(super) max_source_providers: u32, pub(super) max_concurrent_streams: u32, });
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
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::primitives::ProviderIngestSignerBindingWireV1"; pub(super) ProviderIngestSignerBindingWireV1 { pub(super) runtime_handle: String, pub(super) adapter_revision: u64, pub(super) signer_policy_id: [u8; 32], pub(super) signer_policy_revision: u64, pub(super) signer_policy_predecessor_digest: Option<[u8; 32]>, pub(super) signer_policy_digest: [u8; 32], pub(super) algorithm: u8, pub(super) public_key: Vec<u8>, });
impl ProviderIngestSignerBindingWireV1 {
    pub(super) fn try_from_binding(
        binding: &sorafs_node::ProviderIngestCompletionSignerBindingV1,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        let slot = IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner;
        binding
            .validate()
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        let (algorithm, public_key) = binding
            .qualification
            .public_key
            .try_to_bytes()
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        let algorithm = provider_ingest_algorithm_to_wire(algorithm)
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot))?;
        if public_key.is_empty() || public_key.len() > MAX_PROVIDER_INGEST_PUBLIC_KEY_BYTES_V1 {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(slot));
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
    pub(super) fn to_binding(
        &self,
    ) -> Result<sorafs_node::ProviderIngestCompletionSignerBindingV1, BrokerError> {
        let algorithm =
            provider_ingest_algorithm_from_wire(self.algorithm).ok_or(BrokerError::Protocol)?;
        if self.runtime_handle.is_empty()
            || self.runtime_handle.len() > MAX_PROVIDER_HANDLE_BYTES_V1
            || self.runtime_handle.as_bytes().contains(&0)
            || self.adapter_revision == 0
            || self.signer_policy_id == [0; 32]
            || self.signer_policy_revision == 0
            || self.signer_policy_digest == [0; 32]
            || self.public_key.is_empty()
            || self.public_key.len() > MAX_PROVIDER_INGEST_PUBLIC_KEY_BYTES_V1
        {
            return Err(BrokerError::BindingMismatch);
        }
        let public_key = iroha_crypto::PublicKey::from_bytes(algorithm, &self.public_key)
            .map_err(|_| BrokerError::BindingMismatch)?;
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
            .map_err(|_| BrokerError::BindingMismatch)?;
        Ok(binding)
    }
}
pub(super) const fn provider_ingest_algorithm_to_wire(
    algorithm: iroha_crypto::Algorithm,
) -> Option<u8> {
    match algorithm {
        iroha_crypto::Algorithm::Ed25519 => Some(1),
        iroha_crypto::Algorithm::MlDsa => Some(2),
        _ => None,
    }
}
pub(super) const fn provider_ingest_algorithm_from_wire(
    wire: u8,
) -> Option<iroha_crypto::Algorithm> {
    match wire {
        1 => Some(iroha_crypto::Algorithm::Ed25519),
        2 => Some(iroha_crypto::Algorithm::MlDsa),
        _ => None,
    }
}
