//! SoraFS-related helpers exposed by Torii.
pub mod admission;
pub mod alias_cache;
#[cfg(feature = "app_api")]
pub mod api;
pub mod blinded;
#[cfg(all(test, feature = "app_api"))]
pub mod concurrency;
#[cfg(feature = "app_api")]
pub mod delegated_routing;
pub mod discovery;
#[cfg(feature = "app_api")]
pub(crate) mod evidence_viewer_api;
#[cfg(feature = "app_api")]
pub(crate) mod evidence_viewer_runtime;
pub mod gateway;
#[cfg(feature = "app_api")]
pub(crate) mod gateway_compliance_api;
pub mod gc;
#[cfg(feature = "app_api")]
pub(crate) mod hedging_billing_api;
pub mod hosts;
pub mod limits;
#[cfg(feature = "app_api")]
pub mod moderation_runtime;
#[cfg(feature = "app_api")]
pub mod native_transaction_signer;
#[cfg(feature = "app_api")]
pub(crate) mod orderbook_runtime;
#[cfg(any(feature = "app_api", test))]
pub(crate) mod orderbook_worker;
#[cfg(feature = "app_api")]
pub mod pop_api;
pub mod por;
#[cfg(feature = "app_api")]
pub mod potr_signing;
pub(crate) mod provider_attestation;
pub(crate) mod provider_source;
pub(crate) mod public_gateway;
#[cfg(feature = "app_api")]
pub(crate) mod publisher;
#[cfg(all(test, feature = "app_api"))]
pub mod quota;
#[cfg(feature = "app_api")]
pub mod registry;
#[cfg(feature = "app_api")]
pub(crate) mod reserve_api;
#[cfg(feature = "app_api")]
pub(crate) mod reserve_runtime;
#[cfg(any(feature = "app_api", test))]
pub(crate) mod reserve_worker;
pub mod site;
#[cfg(feature = "app_api")]
pub mod stream_token_admission;
#[cfg(feature = "app_api")]
pub(crate) mod stream_token_cleanup;
#[cfg(feature = "app_api")]
pub(crate) mod stream_token_runtime;
pub mod token;
pub use admission::{
    AdmissionRegistry, AdmissionRegistryError, AdmissionRegistryUpdateError,
    ProviderAdmissionAdvertError,
};
pub use alias_cache::{
    AliasCacheEnforcement, AliasCachePolicy, AliasCachePolicyExt, AliasCachePolicyHttpExt,
    AliasProofError, AliasProofEvaluation, AliasProofEvaluationExt, AliasProofState, CacheDecision,
    CacheDecisionOutcome, GovernanceAssessment, SuccessorAssessment, decode_alias_proof,
    decode_alias_proof_untrusted_signers, enforcement_from_config, policy_from_config,
    unix_now_secs,
};
pub use blinded::{
    BLINDED_CID_LEN, BlindedCidResolver, ResolveError as BlindedResolveError, SaltSchedule,
    SaltScheduleError,
};
#[cfg(all(test, feature = "app_api"))]
pub(crate) use concurrency::{StreamTokenConcurrencyPermit, StreamTokenConcurrencyTracker};
pub use discovery::{
    ProviderAdvertCache, ReplayCheckpointError, capability_name, parse_capability_name,
};
#[cfg(feature = "app_api")]
pub use gc::GcSweeperRuntime;
pub use hosts::{HostMappingInput, HostMappingSummary};
pub use limits::{
    QuotaExceeded, SorafsAction, SorafsQuotaConfig, SorafsQuotaEnforcer, SorafsQuotaWindow,
};
#[cfg(feature = "app_api")]
pub use por::{
    DrandHttpRandomnessProvider, PorAutomationError, PorCoordinatorRuntime, PorStorage,
    RandomnessProvider, VerifiedVrfProvider, VrfError, VrfProvider,
};
pub use por::{PorCoordinator, PorCoordinatorError, PorStatusFilter};
#[cfg(feature = "app_api")]
pub use potr_signing::{
    PotrAdmissionMaterialResolverV1, PotrAdmissionReaderError, PotrAdmissionReaderV1,
    PotrAdmissionRegistryResolverV1, PotrAdmissionSnapshotV1,
    PotrFinalizedAdmissionReaderConfigError, PotrFinalizedAdmissionReaderV1,
    PotrFinalizedPolicySnapshotV1, PotrFinalizedPolicySourceV1, PotrGatewaySignerV1,
    PotrProviderSignerV1, PotrRuntimeProviderBindingV1, PotrRuntimeProviderQualificationV1,
    PotrRuntimeReaderBindingsV1, PotrRuntimeSignerConfigError, PotrRuntimeSignerRolesV1,
    PotrRuntimeSignersV1, PotrSignerServiceError, PotrStateFinalizedPolicySourceV1,
};
#[cfg(all(test, feature = "app_api"))]
pub(crate) use quota::{StreamTokenQuotaError, StreamTokenQuotaTracker};
pub use sorafs_manifest::{
    capacity::ReplicationOrderV1,
    provider_advert::{EndpointKind, TransportProtocol},
};
#[cfg(feature = "app_api")]
pub use sorafs_node::{
    PotrAdmissionPolicyBindingError, PotrAdmissionPolicyBindingV1, PotrAdmissionPolicyProgressError,
};
#[cfg(feature = "app_api")]
pub use stream_token_admission::{
    StreamTokenAdmissionCaptureV1, StreamTokenGatewayAdmissionProviderV1,
    StreamTokenGatewayReconciliationReadV1, StreamTokenReconciliationOutcomeV1,
    StreamTokenReputationDeliveryV1,
};
#[cfg(any(test, feature = "test-fixtures"))]
pub use token::native_issuer_test_fixture;
#[cfg(test)]
pub(crate) use token::signer_test_support;
pub(crate) use token::{
    MAX_CLIENT_ID_BYTES, MAX_NONCE_BYTES, MAX_STREAM_TOKEN_BASE64_BYTES, StreamTokenQuotaSubject,
};
pub use token::{
    StreamTokenApprovedCustodyAnchorV1, StreamTokenHeaderError, StreamTokenIssuer,
    StreamTokenIssuerError, StreamTokenObserverReplyV1, StreamTokenSignerCallErrorV1,
    StreamTokenSignerClientV1, StreamTokenSignerPinsV1, StreamTokenSignerReceiptV1,
    StreamTokenStateObserverClientV1, TokenOverrides, decode_token_base64, encode_token_base64,
};

/// Whether local queue or pipeline-cache evidence shows the transaction may still land.
///
/// Such evidence blocks every absence-based resubmission decision.
#[cfg(feature = "app_api")]
pub(crate) fn pending_evidence_blocks_absence_retry(
    queue_pending: bool,
    cache_kind: Option<crate::PipelineStatusKind>,
) -> bool {
    queue_pending
        || matches!(
            cache_kind,
            Some(
                crate::PipelineStatusKind::Queued
                    | crate::PipelineStatusKind::Approved
                    | crate::PipelineStatusKind::Committed
                    | crate::PipelineStatusKind::Applied
            )
        )
}
/// Return the retained signed-transaction digest only when it binds the retained bytes exactly.
#[cfg(feature = "app_api")]
pub(crate) fn retained_transaction_digest(
    retained_digest: Option<[u8; 32]>,
    signed_transaction_bytes: Option<&[u8]>,
) -> Option<[u8; 32]> {
    let retained_digest = retained_digest.filter(|digest| *digest != [0; 32])?;
    let signed_transaction_bytes = signed_transaction_bytes?;
    (*blake3::hash(signed_transaction_bytes).as_bytes() == retained_digest)
        .then_some(retained_digest)
}

/// Authenticated chunks for current finalized native repair leases.
pub(crate) mod repair_source;
