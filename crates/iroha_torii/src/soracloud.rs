//! App-facing Soracloud control-plane shim.
//!
//! This module provides a deterministic control-plane surface for
//! `deploy`/`upgrade`/`rollback` workflows plus SCR host-admission snapshots.
//! Requests must carry signed payloads so admission can verify manifest
//! provenance before returning canonical transaction-instruction drafts. Torii
//! does not submit or confirm those drafts. Every top-level POST request schema
//! is strict and excludes inline account authority/private-key fields; caller
//! identity comes only from the verified HTTP signature or witness headers.
use crate::{JsonBody, NoritoJson, NoritoQuery, SharedAppState};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use iroha_core::soracloud_runtime::{SoracloudLocalReadKind, authoritative_soracloud_sequence};
use iroha_core::state::{StateReadOnly, WorldReadOnly};
use iroha_crypto::{Algorithm, Hash, PublicKey, Signature};
#[cfg(test)]
use iroha_data_model::soracloud::SoraServiceExactCurrentRevisionPreconditionV1;
use iroha_data_model::{
    Encode,
    account::AccountId,
    asset::AssetDefinitionId,
    isi::{self, InstructionBox},
    smart_contract::manifest::ManifestProvenance,
    soracloud::{
        AgentApartmentManifestV1, CIPHERTEXT_QUERY_PROOF_VERSION_V1,
        CIPHERTEXT_QUERY_RESPONSE_VERSION_V1, CiphertextInclusionProofV1,
        CiphertextQueryMetadataLevelV1, CiphertextQueryResponseV1, CiphertextQueryResultItemV1,
        CiphertextQuerySpecV1, DecryptionAuthorityPolicyV1, DecryptionRequestV1, FheJobSpecV1,
        SORA_AGENT_WALLET_REQUEST_ID_MAX_BYTES_V1, SecretEnvelopeEncryptionV1, SecretEnvelopeV1,
        SoraAgentApartmentActionV1, SoraAgentApartmentAuditEventV1, SoraAgentApartmentRecordV1,
        SoraAgentArtifactAllowRuleV1, SoraAgentAutonomyRunRecordV1, SoraAgentMailboxMessageV1,
        SoraAgentRuntimeStatusV1, SoraAppInfraAuditEventV1, SoraAppInfraManifestV1,
        SoraAppInfraMutationPreconditionV1, SoraAppInfraStateV1, SoraCertifiedResponsePolicyV1,
        SoraConfigExportV1, SoraContainerRuntimeV1, SoraDeploymentBundleV1,
        SoraHfSharedLeaseAuditEventV1, SoraHfSharedLeaseMemberV1, SoraHfSharedLeasePoolV1,
        SoraHfSourceRecordV1, SoraInrouHostCapabilityRecordV1, SoraLeaseVolumeBindingV1,
        SoraModelArtifactRecordV1, SoraModelProvenanceKindV1, SoraModelRegistryV1,
        SoraModelWeightVersionRecordV1, SoraNetworkPolicyV1, SoraRolloutStageV1,
        SoraRuntimeDeterministicValidatorHostV1, SoraRuntimeReceiptV1, SoraServiceAuditEventV1,
        SoraServiceConfigEntryV1, SoraServiceConfigMutationV1, SoraServiceDeploymentStateV1,
        SoraServiceExecutionPlaneV1, SoraServiceHandlerClassV1,
        SoraServiceLeaseReportingEpochRolloverV1, SoraServiceLeaseStateV1,
        SoraServiceLeaseStatusV1, SoraServiceLeaseUsageAuditV1, SoraServiceLifecycleActionV1,
        SoraServiceMutationPreconditionV1, SoraServiceRolloutStateV1, SoraServiceSecretEntryV1,
        SoraServiceSecretMutationV1, SoraStateBindingV1, SoraStateEncryptionV1,
        SoraStateMutabilityV1, SoraStateMutationOperationV1, SoraTlsModeV1,
        SoraTrainingJobRecordV1, SoraTrainingJobStatusV1, SoraUploadedModelBundleV1,
        SoracloudFheBootstrapKeyProofV1, SoracloudFheFullBootstrapExecutionProofV1,
        SoracloudFheInputAdmissionProofV1, SoracloudFhePolicyReferenceV1,
        SoracloudFhePublicKeyProofV1, SoracloudMutationDraftResponse, SoracloudTxInstruction,
        derive_hf_shared_lease_pool_id_v1, derive_hf_source_id_v1,
        encode_agent_artifact_allow_provenance_payload, encode_agent_deploy_provenance_payload,
        encode_agent_lease_renew_provenance_payload, encode_agent_message_ack_provenance_payload,
        encode_agent_message_send_provenance_payload,
        encode_agent_policy_revoke_provenance_payload, encode_agent_restart_provenance_payload,
        encode_agent_wallet_approve_provenance_payload,
        encode_agent_wallet_spend_provenance_payload, encode_app_infra_provenance_payload,
        encode_ciphertext_query_provenance_payload, encode_decryption_request_provenance_payload,
        encode_delete_service_config_provenance_payload,
        encode_delete_service_secret_provenance_payload, encode_fhe_job_run_provenance_payload,
        encode_hf_shared_lease_join_provenance_payload,
        encode_hf_shared_lease_leave_provenance_payload,
        encode_hf_shared_lease_renew_provenance_payload,
        encode_model_artifact_register_provenance_payload,
        encode_model_weight_promote_provenance_payload,
        encode_model_weight_register_provenance_payload,
        encode_model_weight_rollback_provenance_payload, encode_rollback_provenance_payload,
        encode_rollout_provenance_payload, encode_set_service_config_provenance_payload,
        encode_set_service_secret_provenance_payload, encode_state_mutation_provenance_payload,
        encode_training_job_checkpoint_provenance_payload,
        encode_training_job_retry_provenance_payload, encode_training_job_start_provenance_payload,
        encode_uploaded_model_bundle_register_provenance_payload,
        encode_uploaded_model_finalize_provenance_payload, is_canonical_agent_wallet_request_id_v1,
        is_canonical_hf_commit_oid_v1, is_canonical_hf_repo_id_v1,
    },
    sorafs::pin_registry::{
        ManifestDigest, ManifestRootCid, PinManifestRecord, PinStatus, StorageClass,
    },
};
use iroha_model_base::name::Name;
use iroha_primitives::{
    json::Json,
    numeric::{NumericOperationError, Quantity},
};
use mv::storage::StorageReadOnly;
use norito::derive::{JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize};
use sorafs_car::{CarBuildPlan, CarWriter, FileEntry};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};
mod bounded_public_response;
const CONTROL_PLANE_SCHEMA_VERSION: u16 = 1;
const PUBLIC_SERVICE_DISCOVERY_CONFIG_NAME: &str = "soracloud/public_service_discovery";
const PUBLIC_SERVICE_DISCOVERY_SCHEMA_VERSION_V1: u16 = 1;
pub const PUBLIC_SERVICE_DISCOVERY_INDEX_DOCUMENT: &str = "index.json";
const DEFAULT_AUDIT_LIMIT: usize = 20;
const MAX_AUDIT_LIMIT: usize = 500;
const AGENT_AUTONOMY_RECENT_RUN_LIMIT: usize = 20;
const CIPHERTEXT_QUERY_PROOF_SCHEME_V1: &str = "soracloud.audit_anchor.v1";
const HEALTH_COMPLIANCE_REPORT_VERSION_V1: u16 = 1;
const DEFAULT_HEALTH_COMPLIANCE_LIMIT: usize = 50;
const MAX_HEALTH_COMPLIANCE_LIMIT: usize = 500;
const TRAINING_JOB_STATUS_SCHEMA_VERSION_V1: u16 = 1;
pub const VERIFIED_ACCOUNT_HEADER: &str = "x-iroha-internal-soracloud-account";
pub const VERIFIED_SIGNER_HEADER: &str = "x-iroha-internal-soracloud-signer";
pub const VERIFIED_SIGNERS_HEADER: &str = "x-iroha-internal-soracloud-signers";
const TRAINING_MAX_IDENTIFIER_BYTES: usize = 128;
const MODEL_WEIGHT_STATUS_SCHEMA_VERSION_V1: u16 = 1;
const MODEL_ARTIFACT_STATUS_SCHEMA_VERSION_V1: u16 = 1;
const UPLOADED_MODEL_STATUS_SCHEMA_VERSION_V1: u16 = 1;
const HF_SHARED_LEASE_STATUS_SCHEMA_VERSION_V1: u16 = 1;
const SCR_HOST_MAX_CPU_MILLIS: u32 = 64_000;
const SCR_HOST_MAX_MEMORY_BYTES: u64 = 512 * 1024 * 1024 * 1024;
const SCR_HOST_MAX_EPHEMERAL_STORAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024;
const SCR_HOST_MAX_OPEN_FILES_PER_PROCESS: u32 = 131_072;
const SCR_HOST_MAX_TASKS: u16 = 16_384;
const SCR_HOST_MAX_START_GRACE_SECS: u32 = 600;
const SCR_HOST_MAX_STOP_GRACE_SECS: u32 = 600;
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SoracloudAction")]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoDeserialize,
    NoritoSerialize,
)]
#[norito(tag = "action", content = "value")]
#[norito(deny_unknown_fields)]
pub enum SoracloudAction {
    Deploy,
    Upgrade,
    Rollback,
    ConfigMutation,
    SecretMutation,
    StateMutation,
    FheJobRun,
    FhePolicyRegister,
    FhePolicyRotate,
    FhePolicyRevoke,
    DecryptionRequest,
    CiphertextQuery,
    Rollout,
    LeaseUsage,
    LeaseReportingEpochRollover,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentRuntimeStatus")]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoDeserialize,
    NoritoSerialize,
)]
#[norito(tag = "status", content = "value")]
#[norito(deny_unknown_fields)]
pub enum AgentRuntimeStatus {
    Running,
    LeaseExpired,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::TrainingJobStatus")]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoDeserialize,
    NoritoSerialize,
)]
#[norito(tag = "status", content = "value")]
#[norito(deny_unknown_fields)]
pub enum TrainingJobStatus {
    Running,
    Completed,
    RetryPending,
    Exhausted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MutationMode {
    Deploy,
    Upgrade,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedBundleRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedBundleRequest {
    pub bundle: SoraDeploymentBundleV1,
    pub initial_service_configs: BTreeMap<String, Json>,
    pub initial_service_secrets: BTreeMap<String, SecretEnvelopeV1>,
    pub precondition: SoraServiceMutationPreconditionV1,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedAppInfraRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedAppInfraRequest {
    pub deploy_services: Vec<SignedBundleRequest>,
    pub upgrade_services: Vec<SignedBundleRequest>,
    pub manifest: SoraAppInfraManifestV1,
    pub precondition: SoraAppInfraMutationPreconditionV1,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AppInfraStatusQuery")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AppInfraStatusQuery {
    #[norito(default)]
    pub app_name: Option<String>,
    #[norito(default)]
    pub audit_limit: Option<usize>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AppInfraStatusResponse")]
#[derive(Clone, Debug, JsonSerialize, NoritoSerialize)]
pub struct AppInfraStatusResponse {
    pub schema_version: u16,
    pub app_count: u32,
    pub audit_event_count: u32,
    pub apps: Vec<SoraAppInfraStateV1>,
    pub recent_audit_events: Vec<SoraAppInfraAuditEventV1>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::RollbackPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct RollbackPayload {
    pub service_name: String,
    pub target_version: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedRollbackRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedRollbackRequest {
    pub payload: RollbackPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::StateMutationOperation")]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoDeserialize,
    NoritoSerialize,
)]
#[norito(tag = "operation", content = "value")]
#[norito(deny_unknown_fields)]
pub enum StateMutationOperation {
    Upsert,
    Delete,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::StateMutationRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct StateMutationRequest {
    pub service_name: String,
    pub binding_name: String,
    pub key: String,
    pub operation: StateMutationOperation,
    #[norito(required)]
    pub value_size_bytes: Option<u64>,
    #[norito(required)]
    pub value_payload_hex: Option<String>,
    pub encryption: SoraStateEncryptionV1,
    pub governance_tx_hash: Hash,
    #[norito(required)]
    pub fhe_input_admission_proof: Option<SoracloudFheInputAdmissionProofV1>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedStateMutationRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedStateMutationRequest {
    pub payload: StateMutationRequest,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ServiceConfigSetRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ServiceConfigSetRequest {
    pub service_name: String,
    pub config_name: String,
    pub value_json: Json,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedServiceConfigSetRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedServiceConfigSetRequest {
    pub payload: ServiceConfigSetRequest,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ServiceConfigDeleteRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ServiceConfigDeleteRequest {
    pub service_name: String,
    pub config_name: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedServiceConfigDeleteRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedServiceConfigDeleteRequest {
    pub payload: ServiceConfigDeleteRequest,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ServiceSecretSetRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ServiceSecretSetRequest {
    pub service_name: String,
    pub secret_name: String,
    pub secret: SecretEnvelopeV1,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedServiceSecretSetRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedServiceSecretSetRequest {
    pub payload: ServiceSecretSetRequest,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ServiceSecretDeleteRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ServiceSecretDeleteRequest {
    pub service_name: String,
    pub secret_name: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedServiceSecretDeleteRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedServiceSecretDeleteRequest {
    pub payload: ServiceSecretDeleteRequest,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::RolloutStage")]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoDeserialize,
    NoritoSerialize,
)]
#[norito(tag = "stage", content = "value")]
#[norito(deny_unknown_fields)]
pub enum RolloutStage {
    Canary,
    Promoted,
    RolledBack,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::RolloutAdvancePayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct RolloutAdvancePayload {
    pub service_name: String,
    pub rollout_handle: String,
    pub healthy: bool,
    #[norito(required)]
    pub promote_to_percent: Option<u8>,
    pub governance_tx_hash: Hash,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedRolloutAdvanceRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedRolloutAdvanceRequest {
    pub payload: RolloutAdvancePayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentDeployPayload")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentDeployPayload {
    pub manifest: AgentApartmentManifestV1,
    pub lease_blocks: u64,
    pub autonomy_budget_units: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedAgentDeployRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedAgentDeployRequest {
    pub payload: AgentDeployPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentLeaseRenewPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentLeaseRenewPayload {
    pub apartment_name: String,
    pub lease_blocks: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedAgentLeaseRenewRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedAgentLeaseRenewRequest {
    pub payload: AgentLeaseRenewPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::HfSharedLeaseJoinPayload")]
#[derive(Clone, Debug, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct HfSharedLeaseJoinPayload {
    pub repo_id: String,
    pub revision: String,
    pub service_name: String,
    #[norito(required)]
    pub apartment_name: Option<String>,
    pub storage_class: StorageClass,
    pub lease_term_ms: u64,
    pub lease_asset_definition_id: AssetDefinitionId,
    pub base_fee: Quantity,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedHfSharedLeaseJoinRequest")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedHfSharedLeaseJoinRequest {
    pub payload: HfSharedLeaseJoinPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::HfLeaseLeavePayload")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct HfLeaseLeavePayload {
    pub repo_id: String,
    pub revision: String,
    pub storage_class: StorageClass,
    pub lease_term_ms: u64,
    #[norito(required)]
    pub service_name: Option<String>,
    #[norito(required)]
    pub apartment_name: Option<String>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedHfLeaseLeaveRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedHfLeaseLeaveRequest {
    pub payload: HfLeaseLeavePayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::HfLeaseRenewPayload")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct HfLeaseRenewPayload {
    pub repo_id: String,
    pub revision: String,
    pub service_name: String,
    #[norito(required)]
    pub apartment_name: Option<String>,
    pub storage_class: StorageClass,
    pub lease_term_ms: u64,
    pub lease_asset_definition_id: AssetDefinitionId,
    pub base_fee: Quantity,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedHfLeaseRenewRequest")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedHfLeaseRenewRequest {
    pub payload: HfLeaseRenewPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentRestartPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentRestartPayload {
    pub apartment_name: String,
    pub reason: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedAgentRestartRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedAgentRestartRequest {
    pub payload: AgentRestartPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentPolicyRevokePayload")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentPolicyRevokePayload {
    pub apartment_name: String,
    pub capability: String,
    #[norito(required)]
    pub reason: Option<String>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedAgentPolicyRevokeRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedAgentPolicyRevokeRequest {
    pub payload: AgentPolicyRevokePayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentWalletSpendPayload")]
#[derive(Clone, Debug, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentWalletSpendPayload {
    pub apartment_name: String,
    pub request_id: String,
    pub asset_definition: String,
    pub amount: Quantity,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedAgentWalletSpendRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedAgentWalletSpendRequest {
    pub payload: AgentWalletSpendPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentWalletApprovePayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentWalletApprovePayload {
    pub apartment_name: String,
    pub request_id: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedAgentWalletApproveRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedAgentWalletApproveRequest {
    pub payload: AgentWalletApprovePayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentMessageSendPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentMessageSendPayload {
    pub from_apartment: String,
    pub to_apartment: String,
    pub channel: String,
    pub payload: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedAgentMessageSendRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedAgentMessageSendRequest {
    pub payload: AgentMessageSendPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentMessageAckPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentMessageAckPayload {
    pub apartment_name: String,
    pub message_id: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedAgentMessageAckRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedAgentMessageAckRequest {
    pub payload: AgentMessageAckPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentArtifactAllowPayload")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentArtifactAllowPayload {
    pub apartment_name: String,
    pub artifact_hash: String,
    #[norito(required)]
    pub provenance_hash: Option<String>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedAgentArtifactAllowRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedAgentArtifactAllowRequest {
    pub payload: AgentArtifactAllowPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::FheJobRunPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct FheJobRunPayload {
    pub service_name: String,
    pub binding_name: String,
    pub job: FheJobSpecV1,
    pub policy_reference: SoracloudFhePolicyReferenceV1,
    #[norito(required)]
    pub public_key_proof: Option<SoracloudFhePublicKeyProofV1>,
    #[norito(required)]
    pub bootstrap_key_zero_refresh_proof: Option<SoracloudFheBootstrapKeyProofV1>,
    pub full_bootstrap_execution_proofs: Vec<SoracloudFheFullBootstrapExecutionProofV1>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedFheJobRunRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedFheJobRunRequest {
    pub payload: FheJobRunPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::TrainingJobStartPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct TrainingJobStartPayload {
    pub service_name: String,
    pub model_name: String,
    pub job_id: String,
    pub worker_group_size: u16,
    pub target_steps: u32,
    pub checkpoint_interval_steps: u32,
    pub max_retries: u8,
    pub step_compute_units: u64,
    pub compute_budget_units: u64,
    pub storage_budget_bytes: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedTrainingJobStartRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedTrainingJobStartRequest {
    pub payload: TrainingJobStartPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::TrainingJobCheckpointPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct TrainingJobCheckpointPayload {
    pub service_name: String,
    pub job_id: String,
    pub completed_step: u32,
    pub checkpoint_size_bytes: u64,
    pub metrics_hash: Hash,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedTrainingJobCheckpointRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedTrainingJobCheckpointRequest {
    pub payload: TrainingJobCheckpointPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::TrainingJobRetryPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct TrainingJobRetryPayload {
    pub service_name: String,
    pub job_id: String,
    pub reason: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedTrainingJobRetryRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedTrainingJobRetryRequest {
    pub payload: TrainingJobRetryPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ModelWeightRegisterPayload")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ModelWeightRegisterPayload {
    pub service_name: String,
    pub model_name: String,
    pub weight_version: String,
    pub training_job_id: String,
    #[norito(required)]
    pub parent_version: Option<String>,
    pub weight_artifact_hash: Hash,
    pub dataset_ref: String,
    pub training_config_hash: Hash,
    pub reproducibility_hash: Hash,
    pub provenance_attestation_hash: Hash,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedModelWeightRegisterRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedModelWeightRegisterRequest {
    pub payload: ModelWeightRegisterPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ModelWeightPromotePayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ModelWeightPromotePayload {
    pub service_name: String,
    pub model_name: String,
    pub weight_version: String,
    pub gate_approved: bool,
    pub gate_report_hash: Hash,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedModelWeightPromoteRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedModelWeightPromoteRequest {
    pub payload: ModelWeightPromotePayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ModelWeightRollbackPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ModelWeightRollbackPayload {
    pub service_name: String,
    pub model_name: String,
    pub target_version: String,
    pub reason: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedModelWeightRollbackRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedModelWeightRollbackRequest {
    pub payload: ModelWeightRollbackPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ModelArtifactRegisterPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ModelArtifactRegisterPayload {
    pub service_name: String,
    pub model_name: String,
    pub training_job_id: String,
    pub weight_artifact_hash: Hash,
    pub dataset_ref: String,
    pub training_config_hash: Hash,
    pub reproducibility_hash: Hash,
    pub provenance_attestation_hash: Hash,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedModelArtifactRegisterRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedModelArtifactRegisterRequest {
    pub payload: ModelArtifactRegisterPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::UploadedModelRegisterPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct UploadedModelRegisterPayload {
    pub bundle: SoraUploadedModelBundleV1,
    pub model_name: String,
    pub artifact_id: String,
    pub weight_artifact_hash: Hash,
    pub dataset_ref: String,
    pub training_config_hash: Hash,
    pub reproducibility_hash: Hash,
    pub provenance_attestation_hash: Hash,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedUploadedModelRegisterRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedUploadedModelRegisterRequest {
    pub payload: UploadedModelRegisterPayload,
    pub bundle_provenance: ManifestProvenance,
    pub finalize_provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::DecryptionRequestPayload")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct DecryptionRequestPayload {
    pub service_name: String,
    pub policy: DecryptionAuthorityPolicyV1,
    pub request: DecryptionRequestV1,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedDecryptionRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedDecryptionRequest {
    pub payload: DecryptionRequestPayload,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::SignedCiphertextQueryRequest")]
#[derive(Clone, Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct SignedCiphertextQueryRequest {
    pub query: CiphertextQuerySpecV1,
    pub provenance: ManifestProvenance,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ServiceConfigStatusQuery")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ServiceConfigStatusQuery {
    pub service_name: String,
    #[norito(default)]
    pub config_name: Option<String>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ServiceConfigStatusEntry {
    pub config_name: String,
    pub value_hash: Hash,
    pub value_json: norito::json::Value,
    pub last_update_sequence: u64,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ServiceConfigStatusResponse {
    pub schema_version: u16,
    pub service_name: String,
    pub current_version: String,
    pub config_generation: u64,
    pub config_entry_count: u32,
    pub configs: Vec<ServiceConfigStatusEntry>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ServiceSecretStatusQuery")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ServiceSecretStatusQuery {
    pub service_name: String,
    #[norito(default)]
    pub secret_name: Option<String>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ServiceSecretStatusEntry {
    pub secret_name: String,
    pub encryption: SecretEnvelopeEncryptionV1,
    pub key_id: String,
    pub key_version: u32,
    pub commitment: Hash,
    pub ciphertext_bytes: u64,
    pub last_update_sequence: u64,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ServiceSecretStatusResponse {
    pub schema_version: u16,
    pub service_name: String,
    pub current_version: String,
    pub secret_generation: u64,
    pub secret_entry_count: u32,
    pub secrets: Vec<ServiceSecretStatusEntry>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct CiphertextQueryResponse {
    pub action: SoracloudAction,
    pub response: CiphertextQueryResponseV1,
    pub signed_by: String,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct TrainingJobStatusResponse {
    pub schema_version: u16,
    pub job: TrainingJobStatusEntry,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct TrainingJobStatusEntry {
    pub service_name: String,
    pub model_name: String,
    pub job_id: String,
    pub status: TrainingJobStatus,
    pub worker_group_size: u16,
    pub target_steps: u32,
    pub completed_steps: u32,
    pub checkpoint_interval_steps: u32,
    #[norito(required)]
    pub last_checkpoint_step: Option<u32>,
    pub checkpoint_count: u32,
    pub retry_count: u8,
    pub max_retries: u8,
    pub step_compute_units: u64,
    pub compute_budget_units: u64,
    pub compute_consumed_units: u64,
    pub compute_remaining_units: u64,
    pub storage_budget_bytes: u64,
    pub storage_consumed_bytes: u64,
    pub storage_remaining_bytes: u64,
    #[norito(required)]
    pub latest_metrics_hash: Option<Hash>,
    #[norito(required)]
    pub last_failure_reason: Option<String>,
    pub created_sequence: u64,
    pub updated_sequence: u64,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ModelWeightStatusResponse {
    pub schema_version: u16,
    pub model: ModelWeightStatusEntry,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ModelWeightStatusEntry {
    pub service_name: String,
    pub model_name: String,
    #[norito(required)]
    pub current_version: Option<String>,
    pub version_count: u32,
    pub versions: Vec<ModelWeightVersionEntry>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ModelWeightVersionEntry {
    pub weight_version: String,
    #[norito(required)]
    pub parent_version: Option<String>,
    pub training_job_id: String,
    pub weight_artifact_hash: Hash,
    pub dataset_ref: String,
    pub training_config_hash: Hash,
    pub reproducibility_hash: Hash,
    pub provenance_attestation_hash: Hash,
    pub registered_sequence: u64,
    #[norito(required)]
    pub promoted_sequence: Option<u64>,
    #[norito(required)]
    pub gate_report_hash: Option<Hash>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ModelArtifactStatusResponse {
    pub schema_version: u16,
    pub service_name: String,
    pub model_name: String,
    pub artifact_count: u32,
    pub artifact: ModelArtifactStatusEntry,
    pub artifacts: Vec<ModelArtifactStatusEntry>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ModelArtifactStatusEntry {
    pub service_name: String,
    pub model_name: String,
    pub artifact_id: String,
    pub training_job_id: String,
    #[norito(required)]
    pub weight_version: Option<String>,
    pub weight_artifact_hash: Hash,
    pub dataset_ref: String,
    pub training_config_hash: Hash,
    pub reproducibility_hash: Hash,
    pub provenance_attestation_hash: Hash,
    pub registered_sequence: u64,
    #[norito(required)]
    pub consumed_by_version: Option<String>,
    #[norito(required)]
    pub chunk_manifest_root: Option<Hash>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct UploadedModelStatusResponse {
    pub schema_version: u16,
    pub bundle: SoraUploadedModelBundleV1,
    #[norito(required)]
    pub artifact: Option<ModelArtifactStatusEntry>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct HfSharedLeaseStatusResponse {
    pub schema_version: u16,
    pub source: SoraHfSourceRecordV1,
    #[norito(required)]
    pub pool: Option<SoraHfSharedLeasePoolV1>,
    #[norito(required)]
    pub member: Option<SoraHfSharedLeaseMemberV1>,
    #[norito(required)]
    pub latest_audit_event: Option<SoraHfSharedLeaseAuditEventV1>,
    pub audit_event_count: u32,
    pub storage_base_fee: Quantity,
}
#[derive(Clone, Debug, Default, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct HealthComplianceReportQuery {
    #[norito(default)]
    pub service_name: Option<String>,
    #[norito(default)]
    pub jurisdiction_tag: Option<String>,
    #[norito(default)]
    pub limit: Option<u32>,
}
#[derive(Clone, Debug, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct TrainingJobStatusQuery {
    pub service_name: String,
    pub job_id: String,
}
#[derive(Clone, Debug, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ModelWeightStatusQuery {
    pub service_name: String,
    pub model_name: String,
}
#[derive(Clone, Debug, Default, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ModelArtifactStatusQuery {
    pub service_name: String,
    #[norito(default)]
    pub model_name: Option<String>,
    #[norito(default)]
    pub artifact_id: Option<String>,
    #[norito(default)]
    pub training_job_id: Option<String>,
    #[norito(default)]
    pub weight_version: Option<String>,
}
#[derive(Clone, Debug, Default, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct UploadedModelStatusQuery {
    pub service_name: String,
    pub weight_version: String,
    #[norito(default)]
    pub model_id: Option<String>,
    #[norito(default)]
    pub model_name: Option<String>,
    #[norito(default)]
    pub bundle_root: Option<Hash>,
}
#[derive(Clone, Debug, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct HfSharedLeaseStatusQuery {
    pub repo_id: String,
    pub revision: String,
    pub storage_class: String,
    pub lease_term_ms: u64,
    #[norito(default)]
    /// Optional account filter as canonical I105 or on-chain account alias.
    pub account_id: Option<String>,
}
#[derive(Clone, Debug, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AgentAutonomyStatusQuery {
    pub apartment_name: String,
}
#[derive(Clone, Debug, Default, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AgentStatusQuery {
    #[norito(default)]
    pub apartment_name: Option<String>,
}
#[derive(Clone, Debug, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AgentMailboxStatusQuery {
    pub apartment_name: String,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ControlPlaneSnapshot {
    pub schema_version: u16,
    pub service_count: u32,
    pub audit_event_count: u32,
    pub active_inrou_hosts: Vec<SoraInrouHostCapabilityRecordV1>,
    pub services: Vec<ControlPlaneServiceSnapshot>,
    pub recent_audit_events: Vec<ControlPlaneAuditEvent>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalReadRouteMatch {
    pub service_name: String,
    pub service_version: String,
    pub handler_name: String,
    pub handler_class: SoracloudLocalReadKind,
    pub handler_path: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedHttpRouteMatch {
    pub service_name: String,
    pub service_version: String,
    pub request_path: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedMailboxRouteMatch {
    pub service_name: String,
    pub service_version: String,
    pub handler_name: String,
    pub handler_class: SoraServiceHandlerClassV1,
    pub handler_path: String,
    pub deployment: SoraServiceDeploymentStateV1,
    pub bundle: SoraDeploymentBundleV1,
    pub handler: iroha_data_model::soracloud::SoraServiceHandlerV1,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicRouteMatch {
    LocalRead(LocalReadRouteMatch),
    HostedHttp(HostedHttpRouteMatch),
    OrderedMailbox(Box<OrderedMailboxRouteMatch>),
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct HealthComplianceReportResponse {
    pub schema_version: u16,
    #[norito(required)]
    pub service_name: Option<String>,
    #[norito(required)]
    pub jurisdiction_tag: Option<String>,
    pub generated_at_sequence: u64,
    pub total_access_events: u32,
    pub break_glass_events: u32,
    pub non_break_glass_events: u32,
    pub consent_evidence_present_events: u32,
    pub consent_evidence_coverage_bps: u16,
    pub recent_access_events: Vec<HealthAccessAuditEntry>,
    pub jurisdiction_stats: Vec<HealthJurisdictionStat>,
    pub data_flow_attestations: Vec<HealthDataFlowAttestation>,
    pub policy_diff_history: Vec<HealthPolicyDiffEntry>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct HealthAccessAuditEntry {
    pub sequence: u64,
    pub service_name: String,
    pub binding_name: String,
    pub state_key: String,
    pub policy_name: String,
    pub jurisdiction_tag: String,
    #[norito(required)]
    pub consent_evidence_hash: Option<Hash>,
    pub break_glass: bool,
    #[norito(required)]
    pub break_glass_reason: Option<String>,
    pub governance_tx_hash: Hash,
    pub signed_by: String,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct HealthJurisdictionStat {
    pub jurisdiction_tag: String,
    pub access_event_count: u32,
    pub break_glass_event_count: u32,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct HealthDataFlowAttestation {
    pub service_name: String,
    pub current_version: String,
    pub binding_name: String,
    pub key_prefix: String,
    pub encryption: SoraStateEncryptionV1,
    pub mutability: SoraStateMutabilityV1,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct HealthPolicyDiffEntry {
    pub policy_name: String,
    pub jurisdiction_tag: String,
    pub policy_snapshot_hash: Hash,
    pub first_seen_sequence: u64,
    pub last_seen_sequence: u64,
    pub event_count: u32,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudPublicServiceDiscoveryV1 {
    pub schema_version: u16,
    pub service_name: String,
    pub service_version: String,
    pub execution_plane: String,
    pub runtime: String,
    pub route_host: String,
    pub path_prefix: String,
    pub base_url: String,
    #[norito(required)]
    pub healthcheck_path: Option<String>,
    #[norito(required)]
    pub healthcheck_url: Option<String>,
    pub service_manifest_hash: Hash,
    pub container_manifest_hash: Hash,
    pub deployment_bundle_hash: Hash,
    pub document_hash: Hash,
    pub content_cid: String,
    pub public_discovery_url: String,
    pub public_discovery_cid_host_url: String,
    pub manifest_digest_hex: String,
}
#[derive(Clone, Debug, JsonSerialize)]
struct SoracloudPublicServiceDiscoveryDocumentV1 {
    schema_version: u16,
    service_name: String,
    service_version: String,
    execution_plane: String,
    runtime: String,
    route_host: String,
    path_prefix: String,
    base_url: String,
    #[norito(required)]
    healthcheck_path: Option<String>,
    #[norito(required)]
    healthcheck_url: Option<String>,
    service_manifest_hash: Hash,
    container_manifest_hash: Hash,
    deployment_bundle_hash: Hash,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudPublicServiceDiscoveryRegistryV1 {
    pub schema_version: u16,
    pub service_name: String,
    pub current_version: String,
    pub revisions: BTreeMap<String, SoracloudPublicServiceDiscoveryV1>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ServicePublicDiscoveryResponse {
    pub schema_version: u16,
    pub service_name: String,
    pub current_version: String,
    pub requested_version: String,
    pub discovery: SoracloudPublicServiceDiscoveryV1,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ControlPlaneServiceLeaseSnapshot {
    pub authoritative_state: SoraServiceLeaseStateV1,
    pub effective_status: SoraServiceLeaseStatusV1,
    pub remaining_runtime_balance: Quantity,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ControlPlaneServiceSnapshot {
    pub service_name: String,
    pub current_version: String,
    pub revision_count: u32,
    pub config_generation: u64,
    pub secret_generation: u64,
    pub config_entry_count: u32,
    pub secret_entry_count: u32,
    #[norito(required)]
    pub service_lease: Option<ControlPlaneServiceLeaseSnapshot>,
    #[norito(required)]
    pub public_discovery_content_cid: Option<String>,
    #[norito(required)]
    pub public_discovery_url: Option<String>,
    #[norito(required)]
    pub public_discovery_cid_host_url: Option<String>,
    #[norito(required)]
    pub latest_revision: Option<ControlPlaneServiceRevision>,
    #[norito(required)]
    pub active_rollout: Option<RolloutRuntimeState>,
    #[norito(required)]
    pub last_rollout: Option<RolloutRuntimeState>,
}
#[derive(Clone, Debug)]
struct ScrHostAdmission {
    runtime: SoraContainerRuntimeV1,
    allow_state_writes: bool,
    allow_model_inference: bool,
    allow_model_training: bool,
    network: SoraNetworkPolicyV1,
    cpu_millis: u32,
    memory_bytes: u64,
    ephemeral_storage_bytes: u64,
    max_open_files_per_process: u32,
    max_tasks: u16,
    start_grace_secs: u32,
    stop_grace_secs: u32,
    healthcheck_path: Option<String>,
    sandbox_profile_hash: Hash,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ControlPlaneServiceRevision")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ControlPlaneServiceRevision {
    pub sequence: u64,
    pub action: SoracloudAction,
    pub service_version: String,
    pub service_manifest_hash: Hash,
    pub container_manifest_hash: Hash,
    pub replicas: u16,
    pub execution_plane: SoraServiceExecutionPlaneV1,
    #[norito(required)]
    pub route_host: Option<String>,
    #[norito(required)]
    pub route_path_prefix: Option<String>,
    #[norito(required)]
    pub route_service_port: Option<u16>,
    #[norito(required)]
    pub route_visibility: Option<String>,
    #[norito(required)]
    pub route_tls_mode: Option<String>,
    #[norito(required)]
    pub base_url: Option<String>,
    #[norito(required)]
    pub healthcheck_url: Option<String>,
    #[norito(required)]
    pub public_discovery_content_cid: Option<String>,
    #[norito(required)]
    pub public_discovery_url: Option<String>,
    #[norito(required)]
    pub public_discovery_cid_host_url: Option<String>,
    pub state_binding_count: u32,
    pub state_bindings: Vec<SoraStateBindingV1>,
    pub lease_volumes: Vec<SoraLeaseVolumeBindingV1>,
    pub allow_model_inference: bool,
    pub allow_model_training: bool,
    /// Runtime type admitted by SCR for this revision.
    pub runtime: SoraContainerRuntimeV1,
    /// Whether non-readonly state bindings are permitted.
    pub allow_state_writes: bool,
    /// Egress network policy admitted for the revision.
    pub network: SoraNetworkPolicyV1,
    /// Admitted CPU budget in millicores.
    pub cpu_millis: u32,
    /// Admitted resident-memory budget in bytes.
    pub memory_bytes: u64,
    /// Admitted ephemeral-storage budget in bytes.
    pub ephemeral_storage_bytes: u64,
    /// Admitted maximum open file descriptors for each tenant process.
    pub max_open_files_per_process: u32,
    /// Admitted maximum cooperative tasks/threads.
    pub max_tasks: u16,
    /// SCR startup grace period in seconds.
    pub start_grace_secs: u32,
    /// SCR shutdown grace period in seconds.
    pub stop_grace_secs: u32,
    /// Optional healthcheck path enforced by SCR.
    #[norito(required)]
    pub healthcheck_path: Option<String>,
    /// Required service-scoped configs declared by the container manifest.
    pub required_config_names: Vec<String>,
    /// Required service-scoped secrets declared by the container manifest.
    pub required_secret_names: Vec<String>,
    /// Explicit config exports declared by the container manifest.
    pub config_exports: Vec<SoraConfigExportV1>,
    /// Deterministic hash of sandbox/capability/resource admission inputs.
    pub sandbox_profile_hash: Hash,
    /// Monotonic simulated SCR process generation.
    pub process_generation: u64,
    /// Sequence that started the current process generation.
    pub process_started_sequence: u64,
    pub signed_by: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::ControlPlaneAuditEvent")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct ControlPlaneAuditEvent {
    pub sequence: u64,
    pub action: SoracloudAction,
    pub service_name: String,
    #[norito(required)]
    pub from_version: Option<String>,
    pub to_version: String,
    pub service_manifest_hash: Hash,
    pub container_manifest_hash: Hash,
    pub process_generation: u64,
    pub config_generation: u64,
    pub secret_generation: u64,
    pub config_snapshot_hash: Hash,
    pub secret_snapshot_hash: Hash,
    #[norito(required)]
    pub binding_name: Option<String>,
    #[norito(required)]
    pub state_key: Option<String>,
    pub config_mutations: Vec<SoraServiceConfigMutationV1>,
    pub secret_mutations: Vec<SoraServiceSecretMutationV1>,
    #[norito(required)]
    pub governance_tx_hash: Option<Hash>,
    #[norito(required)]
    pub rollout_state: Option<RolloutRuntimeState>,
    #[norito(required)]
    pub policy_name: Option<String>,
    #[norito(required)]
    pub policy_snapshot_hash: Option<Hash>,
    #[norito(required)]
    pub jurisdiction_tag: Option<String>,
    #[norito(required)]
    pub consent_evidence_hash: Option<Hash>,
    #[norito(required)]
    pub break_glass: Option<bool>,
    #[norito(required)]
    pub break_glass_reason: Option<String>,
    #[norito(required)]
    pub lease_usage: Option<SoraServiceLeaseUsageAuditV1>,
    #[norito(required)]
    pub service_lease_commitment: Option<Hash>,
    #[norito(required)]
    pub lease_reporting_epoch_rollover: Option<SoraServiceLeaseReportingEpochRolloverV1>,
    pub signed_by: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::CiphertextRuntimeRecord")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
struct CiphertextRuntimeRecord {
    encryption: SoraStateEncryptionV1,
    payload_bytes: u64,
    commitment: Hash,
    last_update_sequence: u64,
    governance_tx_hash: Hash,
    source_action: SoracloudAction,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::RolloutRuntimeState")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct RolloutRuntimeState {
    pub rollout_handle: String,
    pub baseline_version: String,
    pub candidate_version: String,
    pub canary_percent: u8,
    pub traffic_percent: u8,
    pub stage: RolloutStage,
    pub health_failures: u32,
    pub max_health_failures: u32,
    pub health_window_secs: u32,
    pub created_sequence: u64,
    pub updated_sequence: u64,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AgentStatusResponse {
    pub schema_version: u16,
    pub apartment_count: u32,
    pub event_count: u32,
    pub apartments: Vec<AgentApartmentStatusEntry>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AgentApartmentStatusEntry {
    pub apartment_name: String,
    pub manifest_hash: Hash,
    pub status: AgentRuntimeStatus,
    pub lease_started_height: u64,
    pub lease_expires_height: u64,
    pub lease_remaining_blocks: u64,
    pub restart_count: u32,
    pub state_quota_bytes: u64,
    pub tool_capability_count: u32,
    pub policy_capability_count: u32,
    pub revoked_policy_capability_count: u32,
    pub pending_wallet_request_count: u32,
    pub pending_mailbox_message_count: u32,
    pub autonomy_budget_ceiling_units: u64,
    pub autonomy_budget_remaining_units: u64,
    pub artifact_allowlist_count: u32,
    pub autonomy_run_count: u32,
    pub process_generation: u64,
    pub process_started_sequence: u64,
    pub last_active_sequence: u64,
    #[norito(required)]
    pub last_checkpoint_sequence: Option<u64>,
    pub checkpoint_count: u32,
    pub persistent_state_total_bytes: u64,
    pub persistent_state_key_count: u32,
    pub spend_limit_count: u32,
    pub upgrade_policy: iroha_data_model::soracloud::AgentUpgradePolicyV1,
    #[norito(required)]
    pub last_restart_sequence: Option<u64>,
    #[norito(required)]
    pub last_restart_reason: Option<String>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AgentMailboxStatusResponse {
    pub schema_version: u16,
    pub apartment_name: String,
    pub status: AgentRuntimeStatus,
    pub pending_message_count: u32,
    pub event_count: u32,
    pub messages: Vec<AgentMailboxMessageEntry>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AgentMailboxMessageEntry {
    pub message_id: String,
    pub from_apartment: String,
    pub channel: String,
    pub payload: String,
    pub payload_hash: Hash,
    pub enqueued_sequence: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentRuntimeReceiptRecord")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentRuntimeReceiptRecord {
    pub receipt_id: Hash,
    pub service_name: String,
    pub service_version: String,
    pub handler_name: String,
    pub handler_class: SoraServiceHandlerClassV1,
    pub request_commitment: Hash,
    pub result_commitment: Hash,
    pub certified_by: SoraCertifiedResponsePolicyV1,
    pub emitted_sequence: u64,
    #[norito(required)]
    pub execution_host: Option<SoraRuntimeDeterministicValidatorHostV1>,
    #[norito(required)]
    pub mailbox_message_id: Option<Hash>,
    #[norito(required)]
    pub journal_artifact_hash: Option<Hash>,
    #[norito(required)]
    pub checkpoint_artifact_hash: Option<Hash>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentAutonomyExecutionAuditRecord")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentAutonomyExecutionAuditRecord {
    pub sequence: u64,
    pub succeeded: bool,
    pub result_commitment: Hash,
    #[norito(required)]
    pub service_name: Option<String>,
    #[norito(required)]
    pub service_version: Option<String>,
    #[norito(required)]
    pub handler_name: Option<String>,
    #[norito(required)]
    pub runtime_receipt_id: Option<Hash>,
    #[norito(required)]
    pub journal_artifact_hash: Option<Hash>,
    #[norito(required)]
    pub checkpoint_artifact_hash: Option<Hash>,
    #[norito(required)]
    pub reason: Option<String>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AgentAutonomyStatusResponse {
    pub apartment_name: String,
    pub sequence: u64,
    pub status: AgentRuntimeStatus,
    pub lease_expires_height: u64,
    pub lease_remaining_blocks: u64,
    pub manifest_hash: Hash,
    pub revoked_policy_capability_count: u32,
    pub budget_ceiling_units: u64,
    pub budget_remaining_units: u64,
    pub allowlist_count: u32,
    pub run_count: u32,
    pub process_generation: u64,
    pub process_started_sequence: u64,
    pub last_active_sequence: u64,
    #[norito(required)]
    pub last_checkpoint_sequence: Option<u64>,
    pub checkpoint_count: u32,
    pub persistent_state_total_bytes: u64,
    pub persistent_state_key_count: u32,
    pub allowlist: Vec<AgentAutonomyAllowlistEntry>,
    pub recent_runs: Vec<AgentAutonomyRunRecord>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AgentAutonomyAllowlistEntry {
    pub artifact_hash: String,
    #[norito(required)]
    pub provenance_hash: Option<String>,
    pub added_sequence: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::soracloud::AgentAutonomyRunRecord")]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
pub struct AgentAutonomyRunRecord {
    pub run_id: String,
    pub artifact_hash: String,
    #[norito(required)]
    pub provenance_hash: Option<String>,
    pub budget_units: u64,
    pub run_label: String,
    #[norito(required)]
    pub workflow_input_json: Option<String>,
    pub approved_sequence: u64,
    #[norito(required)]
    pub authoritative_runtime_receipt: Option<AgentRuntimeReceiptRecord>,
    #[norito(required)]
    pub authoritative_execution_audit: Option<AgentAutonomyExecutionAuditRecord>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoracloudErrorKind {
    BadRequest,
    Unauthorized,
    NotFound,
    Conflict,
    Internal,
}
#[derive(Debug, JsonSerialize)]
struct SoracloudErrorBody {
    code: &'static str,
    message: String,
}
#[derive(Debug)]
pub struct SoracloudError {
    kind: SoracloudErrorKind,
    message: String,
}
impl SoracloudError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            kind: SoracloudErrorKind::BadRequest,
            message: message.into(),
        }
    }
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            kind: SoracloudErrorKind::Unauthorized,
            message: message.into(),
        }
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            kind: SoracloudErrorKind::NotFound,
            message: message.into(),
        }
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self {
            kind: SoracloudErrorKind::Conflict,
            message: message.into(),
        }
    }
    fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: SoracloudErrorKind::Internal,
            message: message.into(),
        }
    }
    fn code(&self) -> &'static str {
        match self.kind {
            SoracloudErrorKind::BadRequest => "bad_request",
            SoracloudErrorKind::Unauthorized => "invalid_signature",
            SoracloudErrorKind::NotFound => "not_found",
            SoracloudErrorKind::Conflict => "conflict",
            SoracloudErrorKind::Internal => "internal",
        }
    }
    fn status(&self) -> StatusCode {
        match self.kind {
            SoracloudErrorKind::BadRequest => StatusCode::BAD_REQUEST,
            SoracloudErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
            SoracloudErrorKind::NotFound => StatusCode::NOT_FOUND,
            SoracloudErrorKind::Conflict => StatusCode::CONFLICT,
            SoracloudErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
impl std::fmt::Display for SoracloudError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for SoracloudError {}
impl From<NumericOperationError> for SoracloudError {
    fn from(error: NumericOperationError) -> Self {
        Self::internal(format!(
            "failed to project authoritative Soracloud economic state: {error}"
        ))
    }
}
impl IntoResponse for SoracloudError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = SoracloudErrorBody {
            code: self.code(),
            message: self.message,
        };
        (status, JsonBody(body)).into_response()
    }
}
fn admit_scr_host_bundle(
    bundle: &SoraDeploymentBundleV1,
) -> Result<ScrHostAdmission, SoracloudError> {
    let container = &bundle.container;
    let resources = container.resources;
    let lifecycle = &container.lifecycle;
    if resources.cpu_millis.get() > SCR_HOST_MAX_CPU_MILLIS {
        return Err(SoracloudError::bad_request(format!(
            "container.resources.cpu_millis exceeds SCR cap ({SCR_HOST_MAX_CPU_MILLIS})"
        )));
    }
    if resources.memory_bytes.get() > SCR_HOST_MAX_MEMORY_BYTES {
        return Err(SoracloudError::bad_request(format!(
            "container.resources.memory_bytes exceeds SCR cap ({SCR_HOST_MAX_MEMORY_BYTES})"
        )));
    }
    if resources.ephemeral_storage_bytes.get() > SCR_HOST_MAX_EPHEMERAL_STORAGE_BYTES {
        return Err(SoracloudError::bad_request(format!(
            "container.resources.ephemeral_storage_bytes exceeds SCR cap ({SCR_HOST_MAX_EPHEMERAL_STORAGE_BYTES})"
        )));
    }
    if resources.max_open_files_per_process.get() > SCR_HOST_MAX_OPEN_FILES_PER_PROCESS {
        return Err(SoracloudError::bad_request(format!(
            "container.resources.max_open_files_per_process exceeds SCR cap ({SCR_HOST_MAX_OPEN_FILES_PER_PROCESS})"
        )));
    }
    if resources.max_tasks.get() > SCR_HOST_MAX_TASKS {
        return Err(SoracloudError::bad_request(format!(
            "container.resources.max_tasks exceeds SCR cap ({SCR_HOST_MAX_TASKS})"
        )));
    }
    if lifecycle.start_grace_secs.get() > SCR_HOST_MAX_START_GRACE_SECS {
        return Err(SoracloudError::bad_request(format!(
            "container.lifecycle.start_grace_secs exceeds SCR cap ({SCR_HOST_MAX_START_GRACE_SECS})"
        )));
    }
    if lifecycle.stop_grace_secs.get() > SCR_HOST_MAX_STOP_GRACE_SECS {
        return Err(SoracloudError::bad_request(format!(
            "container.lifecycle.stop_grace_secs exceeds SCR cap ({SCR_HOST_MAX_STOP_GRACE_SECS})"
        )));
    }
    if !container.capabilities.allow_state_writes
        && bundle
            .service
            .state_bindings
            .iter()
            .any(|binding| binding.mutability != SoraStateMutabilityV1::ReadOnly)
    {
        return Err(SoracloudError::bad_request(
            "container capability `allow_state_writes=false` conflicts with non-readonly state bindings",
        ));
    }
    if let SoraNetworkPolicyV1::Allowlist(entries) = &container.capabilities.network {
        if entries.is_empty() {
            return Err(SoracloudError::bad_request(
                "container capability network allowlist must not be empty",
            ));
        }
        let mut seen = BTreeSet::new();
        for entry in entries {
            if entry.host.is_empty() {
                return Err(SoracloudError::bad_request(
                    "container capability network allowlist contains an empty host",
                ));
            }
            if entry.host.trim() != entry.host
                || entry.host.chars().any(char::is_control)
                || entry.host.chars().any(char::is_whitespace)
            {
                return Err(SoracloudError::bad_request(
                    "container capability network allowlist contains invalid host characters",
                ));
            }
            if !seen.insert(entry.host.to_ascii_lowercase()) {
                return Err(SoracloudError::bad_request(
                    "container capability network allowlist must not contain duplicates",
                ));
            }
            if entry.ports.is_empty() {
                return Err(SoracloudError::bad_request(
                    "container capability network allowlist entries must include at least one port",
                ));
            }
            let mut seen_ports = BTreeSet::new();
            for port in &entry.ports {
                if *port == 0 {
                    return Err(SoracloudError::bad_request(
                        "container capability network allowlist contains invalid port 0",
                    ));
                }
                if !seen_ports.insert(*port) {
                    return Err(SoracloudError::bad_request(
                        "container capability network allowlist must not contain duplicate ports per host",
                    ));
                }
            }
        }
    }
    let network_policy = container.capabilities.network.clone();
    let healthcheck_path = lifecycle.healthcheck_path.as_deref().map(str::to_owned);
    let sandbox_profile = (
        container.runtime,
        network_policy.clone(),
        container.capabilities.allow_state_writes,
        container.capabilities.allow_model_inference,
        container.capabilities.allow_model_training,
        (
            resources.cpu_millis.get(),
            resources.memory_bytes.get(),
            resources.ephemeral_storage_bytes.get(),
            resources.max_open_files_per_process.get(),
            resources.max_tasks.get(),
        ),
        (
            lifecycle.start_grace_secs.get(),
            lifecycle.stop_grace_secs.get(),
            healthcheck_path.clone(),
        ),
    );
    let sandbox_profile_hash =
        Hash::new(&norito::to_bytes(&sandbox_profile).map_err(|err| {
            SoracloudError::internal(format!("failed to encode SCR profile: {err}"))
        })?);
    Ok(ScrHostAdmission {
        runtime: container.runtime,
        allow_state_writes: container.capabilities.allow_state_writes,
        allow_model_inference: container.capabilities.allow_model_inference,
        allow_model_training: container.capabilities.allow_model_training,
        network: network_policy,
        cpu_millis: resources.cpu_millis.get(),
        memory_bytes: resources.memory_bytes.get(),
        ephemeral_storage_bytes: resources.ephemeral_storage_bytes.get(),
        max_open_files_per_process: resources.max_open_files_per_process.get(),
        max_tasks: resources.max_tasks.get(),
        start_grace_secs: lifecycle.start_grace_secs.get(),
        stop_grace_secs: lifecycle.stop_grace_secs.get(),
        healthcheck_path,
        sandbox_profile_hash,
    })
}
fn parse_exact_name_identifier(
    field_name: &'static str,
    raw: &str,
) -> Result<Name, SoracloudError> {
    let parsed: Name = raw
        .parse()
        .map_err(|err| SoracloudError::bad_request(format!("invalid {field_name}: {err}")))?;
    if parsed.as_ref() != raw {
        return Err(SoracloudError::bad_request(format!(
            "{field_name} must use its exact canonical V1 spelling"
        )));
    }
    Ok(parsed)
}
fn parse_agent_apartment_identifier(
    field_name: &'static str,
    apartment_name: &str,
) -> Result<Name, SoracloudError> {
    parse_exact_name_identifier(field_name, apartment_name)
}
fn parse_agent_apartment_name(apartment_name: &str) -> Result<String, SoracloudError> {
    parse_agent_apartment_identifier("apartment_name", apartment_name)?;
    Ok(apartment_name.to_owned())
}
fn validate_agent_wallet_request_id(request_id: &str) -> Result<(), SoracloudError> {
    if !is_canonical_agent_wallet_request_id_v1(request_id) {
        return Err(SoracloudError::bad_request(format!(
            "request_id must be canonical V1 text of 1..={SORA_AGENT_WALLET_REQUEST_ID_MAX_BYTES_V1} bytes with no surrounding whitespace or control characters"
        )));
    }
    Ok(())
}
fn validate_agent_wallet_asset_definition(asset_definition: &str) -> Result<(), SoracloudError> {
    if asset_definition.is_empty() {
        return Err(SoracloudError::bad_request(
            "asset_definition must not be empty",
        ));
    }
    if asset_definition.trim() != asset_definition {
        return Err(SoracloudError::bad_request(
            "asset_definition must not contain surrounding whitespace",
        ));
    }
    Ok(())
}
fn parse_service_name(service_name: &str) -> Result<Name, SoracloudError> {
    parse_exact_name_identifier("service_name", service_name)
}
fn parse_optional_service_name(service_name: Option<&str>) -> Result<Option<Name>, SoracloudError> {
    service_name.map(parse_service_name).transpose()
}
fn parse_service_material_name(
    field_name: &'static str,
    value: &str,
) -> Result<String, SoracloudError> {
    if value.is_empty() {
        return Err(SoracloudError::bad_request(format!(
            "{field_name} must not be empty"
        )));
    }
    if value.trim() != value {
        return Err(SoracloudError::bad_request(format!(
            "{field_name} must not contain surrounding whitespace"
        )));
    }
    if value.len() > 256 {
        return Err(SoracloudError::bad_request(format!(
            "{field_name} exceeds max bytes (256)"
        )));
    }
    if value.starts_with('/') || value.contains("..") || value.chars().any(char::is_control) {
        return Err(SoracloudError::bad_request(format!(
            "{field_name} must use one exact canonical V1 material name"
        )));
    }
    Ok(value.to_owned())
}
fn parse_exact_nonempty_text(
    field_name: &'static str,
    value: &str,
) -> Result<String, SoracloudError> {
    if value.is_empty() {
        return Err(SoracloudError::bad_request(format!(
            "{field_name} must not be empty"
        )));
    }
    if value.trim() != value {
        return Err(SoracloudError::bad_request(format!(
            "{field_name} must not contain surrounding whitespace"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(SoracloudError::bad_request(format!(
            "{field_name} must not contain control characters"
        )));
    }
    Ok(value.to_owned())
}
fn parse_exact_query_limit(
    field_name: &'static str,
    value: usize,
    maximum: usize,
) -> Result<usize, SoracloudError> {
    if value == 0 || value > maximum {
        return Err(SoracloudError::bad_request(format!(
            "{field_name} must be in the inclusive V1 range 1..={maximum}"
        )));
    }
    Ok(value)
}
fn parse_training_model_name(model_name: &str) -> Result<String, SoracloudError> {
    let parsed: Name = model_name
        .parse()
        .map_err(|err| SoracloudError::bad_request(format!("invalid model_name: {err}")))?;
    if parsed.as_ref() != model_name {
        return Err(SoracloudError::bad_request(
            "model_name must use its exact canonical V1 spelling",
        ));
    }
    Ok(model_name.to_owned())
}
fn parse_hf_repo_id(repo_id: &str) -> Result<String, SoracloudError> {
    if !is_canonical_hf_repo_id_v1(repo_id) {
        return Err(SoracloudError::bad_request(
            "repo_id must be one exact fully-qualified `namespace/repository` identifier",
        ));
    }
    Ok(repo_id.to_owned())
}
fn parse_hf_revision(resolved_revision: &str) -> Result<String, SoracloudError> {
    if !is_canonical_hf_commit_oid_v1(resolved_revision) {
        return Err(SoracloudError::bad_request(
            "resolved_revision must be the full 40-character lowercase hexadecimal commit OID",
        ));
    }
    Ok(resolved_revision.to_owned())
}
fn parse_optional_account_id(
    state: &iroha_core::state::State,
    telemetry: &crate::routing::MaybeTelemetry,
    context: &'static str,
    account_id: Option<&str>,
) -> Result<Option<AccountId>, SoracloudError> {
    account_id
        .map(|literal| {
            if literal.trim() != literal {
                return Err(SoracloudError::bad_request(
                    "account_id must not contain surrounding whitespace",
                ));
            }
            crate::routing::parse_account_literal_with_state(state, literal, telemetry, context)
                .map(|(account_id, _)| account_id)
                .map_err(|err| SoracloudError::bad_request(format!("invalid account_id: {err}")))
        })
        .transpose()
}
fn parse_storage_class_query(storage_class: &str) -> Result<StorageClass, SoracloudError> {
    match storage_class {
        "hot" => Ok(StorageClass::Hot),
        "warm" => Ok(StorageClass::Warm),
        "cold" => Ok(StorageClass::Cold),
        _ => Err(SoracloudError::bad_request(
            "invalid storage_class: expected the exact lowercase value hot, warm, or cold",
        )),
    }
}
fn hf_source_id(repo_id: &str, resolved_revision: &str) -> Result<Hash, SoracloudError> {
    derive_hf_source_id_v1(repo_id, resolved_revision)
        .map_err(|error| SoracloudError::bad_request(error.to_string()))
}
fn hf_shared_lease_pool_id(
    source_id: Hash,
    storage_class: StorageClass,
    lease_term_ms: u64,
) -> Result<Hash, SoracloudError> {
    derive_hf_shared_lease_pool_id_v1(source_id, storage_class, lease_term_ms)
        .map_err(|error| SoracloudError::bad_request(error.to_string()))
}
fn verify_signature_for_signer(
    signature: &Signature,
    signer: &PublicKey,
    payload: &[u8],
) -> Result<(), iroha_crypto::Error> {
    match signer.try_algorithm() {
        Ok(Algorithm::Ed25519) => {
            iroha_crypto::ed25519_parse_signature(signature.payload())?;
        }
        Ok(Algorithm::MlDsa) => {
            iroha_crypto::mldsa65_parse_signature(signature.payload())?;
        }
        _ => {}
    }
    signature.verify(signer, payload)
}
fn parse_training_job_id(job_id: &str) -> Result<String, SoracloudError> {
    if job_id.is_empty() {
        return Err(SoracloudError::bad_request("job_id must not be empty"));
    }
    if job_id.len() > TRAINING_MAX_IDENTIFIER_BYTES {
        return Err(SoracloudError::bad_request(format!(
            "job_id exceeds max bytes ({TRAINING_MAX_IDENTIFIER_BYTES})"
        )));
    }
    if job_id.chars().any(char::is_control) {
        return Err(SoracloudError::bad_request(
            "job_id must not contain control characters",
        ));
    }
    if job_id.chars().any(char::is_whitespace) {
        return Err(SoracloudError::bad_request(
            "job_id must not contain whitespace",
        ));
    }
    if !job_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '#'))
    {
        return Err(SoracloudError::bad_request(
            "job_id must use only ASCII letters, digits, or [-_.:#]",
        ));
    }
    Ok(job_id.to_owned())
}
fn parse_model_weight_version(weight_version: &str) -> Result<String, SoracloudError> {
    if weight_version.is_empty() {
        return Err(SoracloudError::bad_request(
            "weight_version must not be empty",
        ));
    }
    if weight_version.len() > TRAINING_MAX_IDENTIFIER_BYTES {
        return Err(SoracloudError::bad_request(format!(
            "weight_version exceeds max bytes ({TRAINING_MAX_IDENTIFIER_BYTES})"
        )));
    }
    if weight_version.chars().any(char::is_control) {
        return Err(SoracloudError::bad_request(
            "weight_version must not contain control characters",
        ));
    }
    if weight_version.chars().any(char::is_whitespace) {
        return Err(SoracloudError::bad_request(
            "weight_version must not contain whitespace",
        ));
    }
    if !weight_version
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '#'))
    {
        return Err(SoracloudError::bad_request(
            "weight_version must use only ASCII letters, digits, or [-_.:#]",
        ));
    }
    Ok(weight_version.to_owned())
}
fn authoritative_training_job_status(status: SoraTrainingJobStatusV1) -> TrainingJobStatus {
    match status {
        SoraTrainingJobStatusV1::Running => TrainingJobStatus::Running,
        SoraTrainingJobStatusV1::Completed => TrainingJobStatus::Completed,
        SoraTrainingJobStatusV1::RetryPending => TrainingJobStatus::RetryPending,
        SoraTrainingJobStatusV1::Exhausted => TrainingJobStatus::Exhausted,
    }
}
fn authoritative_training_job_status_entry(
    service_name: &str,
    record: &SoraTrainingJobRecordV1,
) -> TrainingJobStatusEntry {
    TrainingJobStatusEntry {
        service_name: service_name.to_owned(),
        model_name: record.model_name.clone(),
        job_id: record.job_id.clone(),
        status: authoritative_training_job_status(record.status),
        worker_group_size: record.worker_group_size,
        target_steps: record.target_steps,
        completed_steps: record.completed_steps,
        checkpoint_interval_steps: record.checkpoint_interval_steps,
        last_checkpoint_step: record.last_checkpoint_step,
        checkpoint_count: record.checkpoint_count,
        retry_count: record.retry_count,
        max_retries: record.max_retries,
        step_compute_units: record.step_compute_units,
        compute_budget_units: record.compute_budget_units,
        compute_consumed_units: record.compute_consumed_units,
        compute_remaining_units: record
            .compute_budget_units
            .saturating_sub(record.compute_consumed_units),
        storage_budget_bytes: record.storage_budget_bytes,
        storage_consumed_bytes: record.storage_consumed_bytes,
        storage_remaining_bytes: record
            .storage_budget_bytes
            .saturating_sub(record.storage_consumed_bytes),
        latest_metrics_hash: record.latest_metrics_hash,
        last_failure_reason: record.last_failure_reason.clone(),
        created_sequence: record.created_sequence,
        updated_sequence: record.updated_sequence,
    }
}
fn authoritative_model_weight_version_entry(
    version: &SoraModelWeightVersionRecordV1,
) -> ModelWeightVersionEntry {
    ModelWeightVersionEntry {
        weight_version: version.weight_version.clone(),
        parent_version: version.parent_version.clone(),
        training_job_id: version.training_job_id.clone(),
        weight_artifact_hash: version.weight_artifact_hash,
        dataset_ref: version.dataset_ref.clone(),
        training_config_hash: version.training_config_hash,
        reproducibility_hash: version.reproducibility_hash,
        provenance_attestation_hash: version.provenance_attestation_hash,
        registered_sequence: version.registered_sequence,
        promoted_sequence: version.promoted_sequence,
        gate_report_hash: version.gate_report_hash,
    }
}
fn authoritative_model_weight_status_entry(
    service_name: &str,
    registry: &SoraModelRegistryV1,
    versions: Vec<ModelWeightVersionEntry>,
) -> ModelWeightStatusEntry {
    ModelWeightStatusEntry {
        service_name: service_name.to_owned(),
        model_name: registry.model_name.clone(),
        current_version: registry.current_version.clone(),
        version_count: u32::try_from(versions.len()).unwrap_or(u32::MAX),
        versions,
    }
}
fn authoritative_model_artifact_status_entry(
    service_name: &str,
    artifact: &SoraModelArtifactRecordV1,
) -> ModelArtifactStatusEntry {
    ModelArtifactStatusEntry {
        service_name: service_name.to_owned(),
        model_name: artifact.model_name.clone(),
        artifact_id: artifact.artifact_id.clone(),
        training_job_id: artifact.training_job_id.clone(),
        weight_version: artifact.weight_version.clone(),
        weight_artifact_hash: artifact.weight_artifact_hash,
        dataset_ref: artifact.dataset_ref.clone(),
        training_config_hash: artifact.training_config_hash,
        reproducibility_hash: artifact.reproducibility_hash,
        provenance_attestation_hash: artifact.provenance_attestation_hash,
        registered_sequence: artifact.registered_sequence,
        consumed_by_version: artifact.consumed_by_version.clone(),
        chunk_manifest_root: artifact.chunk_manifest_root,
    }
}
fn derive_state_key_digest(service_name: &str, binding_name: &str, state_key: &str) -> Hash {
    Hash::new(Encode::encode(&(
        "soracloud.ciphertext.query.key_digest.v1",
        service_name,
        binding_name,
        state_key,
    )))
}
fn soracloud_action_label(action: SoracloudAction) -> &'static str {
    match action {
        SoracloudAction::Deploy => "deploy",
        SoracloudAction::Upgrade => "upgrade",
        SoracloudAction::Rollback => "rollback",
        SoracloudAction::ConfigMutation => "config_mutation",
        SoracloudAction::SecretMutation => "secret_mutation",
        SoracloudAction::StateMutation => "state_mutation",
        SoracloudAction::FheJobRun => "fhe_job_run",
        SoracloudAction::FhePolicyRegister => "fhe_policy_register",
        SoracloudAction::FhePolicyRotate => "fhe_policy_rotate",
        SoracloudAction::FhePolicyRevoke => "fhe_policy_revoke",
        SoracloudAction::DecryptionRequest => "decryption_request",
        SoracloudAction::CiphertextQuery => "ciphertext_query",
        SoracloudAction::Rollout => "rollout",
        SoracloudAction::LeaseUsage => "lease_usage",
        SoracloudAction::LeaseReportingEpochRollover => "lease_reporting_epoch_rollover",
    }
}
fn audit_event_leaf_hash(event: &ControlPlaneAuditEvent) -> Hash {
    Hash::new(Encode::encode(&(
        "soracloud.audit.leaf.v1",
        event.sequence,
        soracloud_action_label(event.action),
        (
            event.service_name.as_str(),
            event.from_version.as_deref(),
            event.to_version.as_str(),
            event.service_manifest_hash,
            event.container_manifest_hash,
            event.process_generation,
            event.config_generation,
            event.secret_generation,
            event.config_snapshot_hash,
            event.secret_snapshot_hash,
        ),
        (
            (
                event.binding_name.as_deref(),
                event.state_key.as_deref(),
                event.config_mutations.clone(),
                event.secret_mutations.clone(),
                event.governance_tx_hash,
                event.rollout_state.clone(),
            ),
            (
                event.policy_name.as_deref(),
                event.policy_snapshot_hash,
                event.jurisdiction_tag.as_deref(),
                event.consent_evidence_hash,
                event.break_glass,
                event.break_glass_reason.as_deref(),
                event.lease_usage.clone(),
                event.service_lease_commitment,
                event.lease_reporting_epoch_rollover.clone(),
                event.signed_by.as_str(),
            ),
        ),
    )))
}
fn audit_anchor_hash(audit_log: &[ControlPlaneAuditEvent], anchor_sequence: u64) -> Hash {
    let mut accumulator = Hash::new(Encode::encode(&"soracloud.audit.anchor.seed.v1"));
    for event in audit_log
        .iter()
        .filter(|event| event.sequence <= anchor_sequence)
    {
        let leaf_hash = audit_event_leaf_hash(event);
        accumulator = Hash::new(Encode::encode(&(
            "soracloud.audit.anchor.step.v1",
            accumulator,
            event.sequence,
            leaf_hash,
        )));
    }
    accumulator
}
fn build_ciphertext_inclusion_proof(
    audit_log: &[ControlPlaneAuditEvent],
    service_name: &str,
    binding_name: &str,
    state_key: &str,
    record: &CiphertextRuntimeRecord,
    anchor_sequence: u64,
    anchor_hash: Hash,
) -> CiphertextInclusionProofV1 {
    let maybe_event = audit_log.iter().find(|event| {
        event.sequence == record.last_update_sequence
            && event.service_name == service_name
            && event.binding_name.as_deref() == Some(binding_name)
            && event.state_key.as_deref() == Some(state_key)
    });
    let (leaf_hash, event_sequence) = maybe_event.map_or_else(
        || {
            (
                Hash::new(Encode::encode(&(
                    "soracloud.audit.synthetic_leaf.v1",
                    service_name,
                    binding_name,
                    state_key,
                    record.payload_bytes,
                    record.commitment,
                    record.last_update_sequence,
                    record.governance_tx_hash,
                    soracloud_action_label(record.source_action),
                ))),
                record.last_update_sequence,
            )
        },
        |event| (audit_event_leaf_hash(event), event.sequence),
    );
    CiphertextInclusionProofV1 {
        schema_version: CIPHERTEXT_QUERY_PROOF_VERSION_V1,
        proof_scheme: CIPHERTEXT_QUERY_PROOF_SCHEME_V1.to_string(),
        leaf_hash,
        anchor_hash,
        anchor_sequence,
        event_sequence,
    }
}
fn verify_bundle_signature(request: &SignedBundleRequest) -> Result<(), SoracloudError> {
    admit_scr_host_bundle(&request.bundle)?;
    let payload = encode_bundle_signature_payload(
        &request.bundle,
        &request.initial_service_configs,
        &request.initial_service_secrets,
        &request.precondition,
    )?;
    verify_signature_for_signer(
        &request.provenance.signature,
        &request.provenance.signer,
        &payload,
    )
    .map_err(|_| SoracloudError::unauthorized("bundle provenance signature verification failed"))?;
    Ok(())
}
fn verify_app_infra_signature(request: &SignedAppInfraRequest) -> Result<(), SoracloudError> {
    request
        .manifest
        .validate()
        .map_err(|err| SoracloudError::bad_request(err.to_string()))?;
    let payload = encode_app_infra_provenance_payload(&request.manifest, &request.precondition)
        .map_err(|err| {
            SoracloudError::internal(format!("failed to encode app infra payload: {err}"))
        })?;
    verify_signature_for_signer(
        &request.provenance.signature,
        &request.provenance.signer,
        &payload,
    )
    .map_err(|_| {
        SoracloudError::unauthorized("app infra provenance signature verification failed")
    })?;
    Ok(())
}

macro_rules! define_provenance_signature_verifiers {
    ($(
        $verify_fn:ident(
            $request_ty:ty,
            $payload_field:ident,
            $encode_fn:ident,
            $failure:literal
        );
    )*) => {
        $(
            fn $verify_fn(request: &$request_ty) -> Result<(), SoracloudError> {
                let payload = $encode_fn(&request.$payload_field)?;
                verify_signature_for_signer(
                    &request.provenance.signature,
                    &request.provenance.signer,
                    &payload,
                )
                .map_err(|_| SoracloudError::unauthorized($failure))?;
                Ok(())
            }
        )*
    };
}

define_provenance_signature_verifiers! {
    verify_rollback_signature(
        SignedRollbackRequest,
        payload,
        encode_rollback_signature_payload,
        "rollback provenance signature verification failed"
    );
    verify_service_config_set_signature(
        SignedServiceConfigSetRequest,
        payload,
        encode_service_config_set_signature_payload,
        "service config provenance signature verification failed"
    );
    verify_service_config_delete_signature(
        SignedServiceConfigDeleteRequest,
        payload,
        encode_service_config_delete_signature_payload,
        "service config delete provenance signature verification failed"
    );
    verify_service_secret_set_signature(
        SignedServiceSecretSetRequest,
        payload,
        encode_service_secret_set_signature_payload,
        "service secret provenance signature verification failed"
    );
    verify_service_secret_delete_signature(
        SignedServiceSecretDeleteRequest,
        payload,
        encode_service_secret_delete_signature_payload,
        "service secret delete provenance signature verification failed"
    );
    verify_state_mutation_signature(
        SignedStateMutationRequest,
        payload,
        encode_state_mutation_signature_payload,
        "state mutation provenance signature verification failed"
    );
    verify_fhe_job_run_signature(
        SignedFheJobRunRequest,
        payload,
        encode_fhe_job_run_signature_payload,
        "fhe job run provenance signature verification failed"
    );
    verify_training_job_start_signature(
        SignedTrainingJobStartRequest,
        payload,
        encode_training_job_start_signature_payload,
        "training job start provenance signature verification failed"
    );
    verify_training_job_checkpoint_signature(
        SignedTrainingJobCheckpointRequest,
        payload,
        encode_training_job_checkpoint_signature_payload,
        "training checkpoint provenance signature verification failed"
    );
    verify_training_job_retry_signature(
        SignedTrainingJobRetryRequest,
        payload,
        encode_training_job_retry_signature_payload,
        "training retry provenance signature verification failed"
    );
    verify_model_weight_register_signature(
        SignedModelWeightRegisterRequest,
        payload,
        encode_model_weight_register_signature_payload,
        "model weight register provenance signature verification failed"
    );
    verify_model_weight_promote_signature(
        SignedModelWeightPromoteRequest,
        payload,
        encode_model_weight_promote_signature_payload,
        "model weight promote provenance signature verification failed"
    );
    verify_model_weight_rollback_signature(
        SignedModelWeightRollbackRequest,
        payload,
        encode_model_weight_rollback_signature_payload,
        "model weight rollback provenance signature verification failed"
    );
    verify_model_artifact_register_signature(
        SignedModelArtifactRegisterRequest,
        payload,
        encode_model_artifact_register_signature_payload,
        "model artifact register provenance signature verification failed"
    );
    verify_decryption_request_signature(
        SignedDecryptionRequest,
        payload,
        encode_decryption_request_signature_payload,
        "decryption request provenance signature verification failed"
    );
    verify_ciphertext_query_signature(
        SignedCiphertextQueryRequest,
        query,
        encode_ciphertext_query_signature_payload,
        "ciphertext query provenance signature verification failed"
    );
    verify_rollout_signature(
        SignedRolloutAdvanceRequest,
        payload,
        encode_rollout_signature_payload,
        "rollout provenance signature verification failed"
    );
    verify_agent_deploy_signature(
        SignedAgentDeployRequest,
        payload,
        encode_agent_deploy_signature_payload,
        "agent deploy provenance signature verification failed"
    );
    verify_agent_lease_renew_signature(
        SignedAgentLeaseRenewRequest,
        payload,
        encode_agent_lease_renew_signature_payload,
        "agent lease renew provenance signature verification failed"
    );
    verify_agent_restart_signature(
        SignedAgentRestartRequest,
        payload,
        encode_agent_restart_signature_payload,
        "agent restart provenance signature verification failed"
    );
    verify_agent_policy_revoke_signature(
        SignedAgentPolicyRevokeRequest,
        payload,
        encode_agent_policy_revoke_signature_payload,
        "agent policy revoke provenance signature verification failed"
    );
    verify_agent_wallet_spend_signature(
        SignedAgentWalletSpendRequest,
        payload,
        encode_agent_wallet_spend_signature_payload,
        "agent wallet spend provenance signature verification failed"
    );
    verify_agent_wallet_approve_signature(
        SignedAgentWalletApproveRequest,
        payload,
        encode_agent_wallet_approve_signature_payload,
        "agent wallet approve provenance signature verification failed"
    );
    verify_agent_message_send_signature(
        SignedAgentMessageSendRequest,
        payload,
        encode_agent_message_send_signature_payload,
        "agent message send provenance signature verification failed"
    );
    verify_agent_message_ack_signature(
        SignedAgentMessageAckRequest,
        payload,
        encode_agent_message_ack_signature_payload,
        "agent message ack provenance signature verification failed"
    );
    verify_agent_artifact_allow_signature(
        SignedAgentArtifactAllowRequest,
        payload,
        encode_agent_artifact_allow_signature_payload,
        "agent artifact allow provenance signature verification failed"
    );
    verify_hf_shared_lease_join_signature(
        SignedHfSharedLeaseJoinRequest,
        payload,
        encode_hf_shared_lease_join_signature_payload,
        "hf shared-lease join provenance signature verification failed"
    );
    verify_hf_lease_leave_signature(
        SignedHfLeaseLeaveRequest,
        payload,
        encode_hf_lease_leave_signature_payload,
        "hf shared-lease leave provenance signature verification failed"
    );
    verify_hf_lease_renew_signature(
        SignedHfLeaseRenewRequest,
        payload,
        encode_hf_lease_renew_signature_payload,
        "hf shared-lease renew provenance signature verification failed"
    );
}

fn app_service_bundle_instruction(
    request: SignedBundleRequest,
    mode: MutationMode,
    app_signer: &PublicKey,
) -> Result<InstructionBox, SoracloudError> {
    if &request.provenance.signer != app_signer {
        return Err(SoracloudError::unauthorized(
            "app infra service bundle signer must match the app infra provenance signer",
        ));
    }
    verify_bundle_signature(&request)?;
    admit_scr_host_bundle(&request.bundle)?;
    Ok(match mode {
        MutationMode::Deploy => InstructionBox::from(isi::soracloud::DeploySoracloudService {
            bundle: request.bundle,
            initial_service_configs: request.initial_service_configs,
            initial_service_secrets: request.initial_service_secrets,
            precondition: request.precondition,
            provenance: request.provenance,
        }),
        MutationMode::Upgrade => InstructionBox::from(isi::soracloud::UpgradeSoracloudService {
            bundle: request.bundle,
            initial_service_configs: request.initial_service_configs,
            initial_service_secrets: request.initial_service_secrets,
            precondition: request.precondition,
            provenance: request.provenance,
        }),
    })
}
fn encode_bundle_signature_payload(
    bundle: &SoraDeploymentBundleV1,
    initial_service_configs: &BTreeMap<String, Json>,
    initial_service_secrets: &BTreeMap<String, SecretEnvelopeV1>,
    precondition: &SoraServiceMutationPreconditionV1,
) -> Result<Vec<u8>, SoracloudError> {
    iroha_data_model::soracloud::encode_bundle_with_materials_provenance_payload(
        bundle,
        initial_service_configs,
        initial_service_secrets,
        precondition,
    )
    .map_err(|err| SoracloudError::internal(format!("failed to encode bundle payload: {err}")))
}
fn encode_rollback_signature_payload(payload: &RollbackPayload) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    encode_rollback_provenance_payload(
        payload.service_name.as_str(),
        payload.target_version.as_str(),
    )
    .map_err(|err| SoracloudError::internal(format!("failed to encode rollback payload: {err}")))
}
fn encode_service_config_set_signature_payload(
    payload: &ServiceConfigSetRequest,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_service_material_name("config_name", &payload.config_name)?;
    encode_set_service_config_provenance_payload(
        payload.service_name.as_str(),
        payload.config_name.as_str(),
        &payload.value_json,
    )
    .map_err(|err| {
        SoracloudError::internal(format!("failed to encode service config payload: {err}"))
    })
}
fn encode_service_config_delete_signature_payload(
    payload: &ServiceConfigDeleteRequest,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_service_material_name("config_name", &payload.config_name)?;
    encode_delete_service_config_provenance_payload(
        payload.service_name.as_str(),
        payload.config_name.as_str(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode service config delete payload: {err}"
        ))
    })
}
fn encode_service_secret_set_signature_payload(
    payload: &ServiceSecretSetRequest,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_service_material_name("secret_name", &payload.secret_name)?;
    encode_set_service_secret_provenance_payload(
        payload.service_name.as_str(),
        payload.secret_name.as_str(),
        &payload.secret,
    )
    .map_err(|err| {
        SoracloudError::internal(format!("failed to encode service secret payload: {err}"))
    })
}
fn encode_service_secret_delete_signature_payload(
    payload: &ServiceSecretDeleteRequest,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_service_material_name("secret_name", &payload.secret_name)?;
    encode_delete_service_secret_provenance_payload(
        payload.service_name.as_str(),
        payload.secret_name.as_str(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode service secret delete payload: {err}"
        ))
    })
}
fn encode_state_mutation_signature_payload(
    payload: &StateMutationRequest,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_exact_name_identifier("binding_name", &payload.binding_name)?;
    let (value_size_bytes, payload_commitment) = state_mutation_payload_metadata(payload)?;
    encode_state_mutation_provenance_payload(
        payload.service_name.as_str(),
        payload.binding_name.as_str(),
        payload.key.as_str(),
        state_mutation_operation_label(payload.operation),
        value_size_bytes,
        payload_commitment,
        payload.encryption,
        payload.governance_tx_hash,
        payload.fhe_input_admission_proof.clone(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!("failed to encode state mutation payload: {err}"))
    })
}
fn decode_state_mutation_payload(
    payload: &StateMutationRequest,
) -> Result<Option<Vec<u8>>, SoracloudError> {
    match payload.operation {
        StateMutationOperation::Upsert => {
            let Some(payload_hex) = payload.value_payload_hex.as_deref() else {
                return Err(SoracloudError::bad_request(
                    "value_payload_hex is required for state upserts",
                ));
            };
            let bytes = hex::decode(payload_hex).map_err(|err| {
                SoracloudError::bad_request(format!("invalid value_payload_hex: {err}"))
            })?;
            if bytes.is_empty() {
                return Err(SoracloudError::bad_request(
                    "value_payload_hex must encode a non-empty payload",
                ));
            }
            let actual_size = u64::try_from(bytes.len())
                .map_err(|_| SoracloudError::bad_request("value_payload_hex is too large"))?;
            if let Some(declared_size) = payload.value_size_bytes
                && declared_size != actual_size
            {
                return Err(SoracloudError::bad_request(format!(
                    "value_size_bytes {declared_size} does not match value_payload_hex length {actual_size}",
                )));
            }
            Ok(Some(bytes))
        }
        StateMutationOperation::Delete => {
            if payload.value_size_bytes.is_some() || payload.value_payload_hex.is_some() {
                return Err(SoracloudError::bad_request(
                    "delete mutations must not include value_size_bytes or value_payload_hex",
                ));
            }
            Ok(None)
        }
    }
}
fn state_mutation_payload_metadata(
    payload: &StateMutationRequest,
) -> Result<(Option<u64>, Option<Hash>), SoracloudError> {
    Ok(match decode_state_mutation_payload(payload)? {
        Some(bytes) => (
            Some(
                u64::try_from(bytes.len())
                    .map_err(|_| SoracloudError::bad_request("value_payload_hex is too large"))?,
            ),
            Some(Hash::new(&bytes)),
        ),
        None => (None, None),
    })
}
fn state_mutation_operation_label(operation: StateMutationOperation) -> &'static str {
    match operation {
        StateMutationOperation::Upsert => "upsert",
        StateMutationOperation::Delete => "delete",
    }
}
fn validate_fhe_job_run_proof_attachments(
    payload: &FheJobRunPayload,
) -> Result<(), SoracloudError> {
    payload
        .policy_reference
        .validate()
        .map_err(|err| SoracloudError::bad_request(format!("invalid policy_reference: {err}")))?;
    if let Some(proof) = &payload.public_key_proof {
        proof.validate().map_err(|err| {
            SoracloudError::bad_request(format!("invalid public_key_proof: {err}"))
        })?;
    }
    if let Some(proof) = &payload.bootstrap_key_zero_refresh_proof {
        proof.validate().map_err(|err| {
            SoracloudError::bad_request(format!("invalid bootstrap_key_zero_refresh_proof: {err}"))
        })?;
    }
    for (index, proof) in payload.full_bootstrap_execution_proofs.iter().enumerate() {
        proof.validate().map_err(|err| {
            SoracloudError::bad_request(format!(
                "invalid full_bootstrap_execution_proofs[{index}]: {err}"
            ))
        })?;
    }
    Ok(())
}
fn verify_uploaded_model_register_signature(
    request: &SignedUploadedModelRegisterRequest,
) -> Result<(), SoracloudError> {
    if request.bundle_provenance.signer != request.finalize_provenance.signer {
        return Err(SoracloudError::unauthorized(
            "uploaded model register bundle and finalize provenance signers must match",
        ));
    }
    let bundle_payload = encode_uploaded_model_register_bundle_signature_payload(&request.payload)?;
    verify_signature_for_signer(
        &request.bundle_provenance.signature,
        &request.bundle_provenance.signer,
        &bundle_payload,
    )
    .map_err(|_| {
        SoracloudError::unauthorized(
            "uploaded model register bundle provenance signature verification failed",
        )
    })?;
    let finalize_payload =
        encode_uploaded_model_register_finalize_signature_payload(&request.payload)?;
    verify_signature_for_signer(
        &request.finalize_provenance.signature,
        &request.finalize_provenance.signer,
        &finalize_payload,
    )
    .map_err(|_| {
        SoracloudError::unauthorized(
            "uploaded model register finalize provenance signature verification failed",
        )
    })?;
    Ok(())
}
fn encode_rollout_signature_payload(
    payload: &RolloutAdvancePayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_exact_nonempty_text("rollout_handle", &payload.rollout_handle)?;
    encode_rollout_provenance_payload(
        payload.service_name.as_str(),
        payload.rollout_handle.as_str(),
        payload.healthy,
        payload.promote_to_percent,
        payload.governance_tx_hash.clone(),
    )
    .map_err(|err| SoracloudError::internal(format!("failed to encode rollout payload: {err}")))
}
fn encode_fhe_job_run_signature_payload(
    payload: &FheJobRunPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_exact_name_identifier("binding_name", &payload.binding_name)?;
    encode_fhe_job_run_provenance_payload(
        payload.service_name.as_str(),
        payload.binding_name.as_str(),
        payload.job.clone(),
        payload.policy_reference.clone(),
        payload.public_key_proof.clone(),
        payload.bootstrap_key_zero_refresh_proof.clone(),
        payload.full_bootstrap_execution_proofs.clone(),
    )
    .map_err(|err| SoracloudError::internal(format!("failed to encode fhe job payload: {err}")))
}
fn encode_training_job_start_signature_payload(
    payload: &TrainingJobStartPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_training_model_name(&payload.model_name)?;
    parse_training_job_id(&payload.job_id)?;
    encode_training_job_start_provenance_payload(
        payload.service_name.as_str(),
        payload.model_name.as_str(),
        payload.job_id.as_str(),
        payload.worker_group_size,
        payload.target_steps,
        payload.checkpoint_interval_steps,
        payload.max_retries,
        payload.step_compute_units,
        payload.compute_budget_units,
        payload.storage_budget_bytes,
    )
    .map_err(|err| {
        SoracloudError::internal(format!("failed to encode training start payload: {err}"))
    })
}
fn encode_training_job_checkpoint_signature_payload(
    payload: &TrainingJobCheckpointPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_training_job_id(&payload.job_id)?;
    encode_training_job_checkpoint_provenance_payload(
        payload.service_name.as_str(),
        payload.job_id.as_str(),
        payload.completed_step,
        payload.checkpoint_size_bytes,
        payload.metrics_hash.clone(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode training checkpoint payload: {err}"
        ))
    })
}
fn encode_training_job_retry_signature_payload(
    payload: &TrainingJobRetryPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_training_job_id(&payload.job_id)?;
    encode_training_job_retry_provenance_payload(
        payload.service_name.as_str(),
        payload.job_id.as_str(),
        payload.reason.as_str(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!("failed to encode training retry payload: {err}"))
    })
}
fn encode_model_weight_register_signature_payload(
    payload: &ModelWeightRegisterPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_training_model_name(&payload.model_name)?;
    parse_model_weight_version(&payload.weight_version)?;
    parse_training_job_id(&payload.training_job_id)?;
    payload
        .parent_version
        .as_deref()
        .map(parse_model_weight_version)
        .transpose()?;
    encode_model_weight_register_provenance_payload(
        payload.service_name.as_str(),
        payload.model_name.as_str(),
        payload.weight_version.as_str(),
        payload.training_job_id.as_str(),
        payload.parent_version.as_deref(),
        payload.weight_artifact_hash.clone(),
        payload.dataset_ref.as_str(),
        payload.training_config_hash.clone(),
        payload.reproducibility_hash.clone(),
        payload.provenance_attestation_hash.clone(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode model weight register payload: {err}"
        ))
    })
}
fn encode_model_weight_promote_signature_payload(
    payload: &ModelWeightPromotePayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_training_model_name(&payload.model_name)?;
    parse_model_weight_version(&payload.weight_version)?;
    encode_model_weight_promote_provenance_payload(
        payload.service_name.as_str(),
        payload.model_name.as_str(),
        payload.weight_version.as_str(),
        payload.gate_approved,
        payload.gate_report_hash.clone(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode model weight promote payload: {err}"
        ))
    })
}
fn encode_model_weight_rollback_signature_payload(
    payload: &ModelWeightRollbackPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_training_model_name(&payload.model_name)?;
    parse_model_weight_version(&payload.target_version)?;
    encode_model_weight_rollback_provenance_payload(
        payload.service_name.as_str(),
        payload.model_name.as_str(),
        payload.target_version.as_str(),
        payload.reason.as_str(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode model weight rollback payload: {err}"
        ))
    })
}
fn encode_model_artifact_register_signature_payload(
    payload: &ModelArtifactRegisterPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    parse_training_model_name(&payload.model_name)?;
    parse_training_job_id(&payload.training_job_id)?;
    encode_model_artifact_register_provenance_payload(
        payload.service_name.as_str(),
        payload.model_name.as_str(),
        payload.training_job_id.as_str(),
        payload.weight_artifact_hash.clone(),
        payload.dataset_ref.as_str(),
        payload.training_config_hash.clone(),
        payload.reproducibility_hash.clone(),
        payload.provenance_attestation_hash.clone(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode model artifact register payload: {err}"
        ))
    })
}
fn encode_uploaded_model_register_bundle_signature_payload(
    payload: &UploadedModelRegisterPayload,
) -> Result<Vec<u8>, SoracloudError> {
    payload.bundle.validate().map_err(|err| {
        SoracloudError::bad_request(format!("invalid uploaded model bundle: {err}"))
    })?;
    encode_uploaded_model_bundle_register_provenance_payload(payload.bundle.clone()).map_err(
        |err| {
            SoracloudError::internal(format!(
                "failed to encode uploaded model register bundle payload: {err}"
            ))
        },
    )
}
fn encode_uploaded_model_register_finalize_signature_payload(
    payload: &UploadedModelRegisterPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_training_model_name(&payload.model_name)?;
    parse_training_job_id(&payload.artifact_id)?;
    parse_training_job_id(&payload.bundle.model_id)?;
    parse_model_weight_version(&payload.bundle.weight_version)?;
    parse_exact_nonempty_text("dataset_ref", &payload.dataset_ref)?;
    encode_uploaded_model_finalize_provenance_payload(
        payload.bundle.service_name.as_ref(),
        payload.model_name.as_str(),
        payload.bundle.model_id.as_str(),
        payload.artifact_id.as_str(),
        payload.bundle.weight_version.as_str(),
        payload.bundle.bundle_root,
        payload.weight_artifact_hash,
        payload.dataset_ref.as_str(),
        payload.training_config_hash,
        payload.reproducibility_hash,
        payload.provenance_attestation_hash,
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode uploaded model register finalize payload: {err}"
        ))
    })
}
fn encode_decryption_request_signature_payload(
    payload: &DecryptionRequestPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_service_name(&payload.service_name)?;
    encode_decryption_request_provenance_payload(
        payload.service_name.as_str(),
        payload.policy.clone(),
        payload.request.clone(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode decryption request payload: {err}"
        ))
    })
}
fn encode_ciphertext_query_signature_payload(
    payload: &CiphertextQuerySpecV1,
) -> Result<Vec<u8>, SoracloudError> {
    encode_ciphertext_query_provenance_payload(payload).map_err(|err| {
        SoracloudError::internal(format!("failed to encode ciphertext query payload: {err}"))
    })
}
fn encode_agent_deploy_signature_payload(
    payload: &AgentDeployPayload,
) -> Result<Vec<u8>, SoracloudError> {
    encode_agent_deploy_provenance_payload(
        payload.manifest.clone(),
        payload.lease_blocks,
        payload.autonomy_budget_units,
    )
    .map_err(|err| {
        SoracloudError::internal(format!("failed to encode agent deploy payload: {err}"))
    })
}
fn encode_agent_lease_renew_signature_payload(
    payload: &AgentLeaseRenewPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_agent_apartment_name(&payload.apartment_name)?;
    encode_agent_lease_renew_provenance_payload(
        payload.apartment_name.as_str(),
        payload.lease_blocks,
    )
    .map_err(|err| {
        SoracloudError::internal(format!("failed to encode agent lease renew payload: {err}"))
    })
}
fn encode_agent_restart_signature_payload(
    payload: &AgentRestartPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_agent_apartment_name(&payload.apartment_name)?;
    encode_agent_restart_provenance_payload(
        payload.apartment_name.as_str(),
        payload.reason.as_str(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!("failed to encode agent restart payload: {err}"))
    })
}
fn encode_agent_policy_revoke_signature_payload(
    payload: &AgentPolicyRevokePayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_agent_apartment_name(&payload.apartment_name)?;
    encode_agent_policy_revoke_provenance_payload(
        payload.apartment_name.as_str(),
        payload.capability.as_str(),
        payload.reason.as_deref(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode agent policy revoke payload: {err}"
        ))
    })
}
fn encode_agent_wallet_spend_signature_payload(
    payload: &AgentWalletSpendPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_agent_apartment_name(&payload.apartment_name)?;
    encode_agent_wallet_spend_provenance_payload(
        payload.apartment_name.as_str(),
        payload.request_id.as_str(),
        payload.asset_definition.as_str(),
        &payload.amount,
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode agent wallet spend payload: {err}"
        ))
    })
}
fn encode_agent_wallet_approve_signature_payload(
    payload: &AgentWalletApprovePayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_agent_apartment_name(&payload.apartment_name)?;
    encode_agent_wallet_approve_provenance_payload(
        payload.apartment_name.as_str(),
        payload.request_id.as_str(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode agent wallet approve payload: {err}"
        ))
    })
}
fn encode_agent_message_send_signature_payload(
    payload: &AgentMessageSendPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_agent_apartment_identifier("from_apartment", &payload.from_apartment)?;
    parse_agent_apartment_identifier("to_apartment", &payload.to_apartment)?;
    encode_agent_message_send_provenance_payload(
        payload.from_apartment.as_str(),
        payload.to_apartment.as_str(),
        payload.channel.as_str(),
        payload.payload.as_str(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode agent message send payload: {err}"
        ))
    })
}
fn encode_agent_message_ack_signature_payload(
    payload: &AgentMessageAckPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_agent_apartment_name(&payload.apartment_name)?;
    encode_agent_message_ack_provenance_payload(
        payload.apartment_name.as_str(),
        payload.message_id.as_str(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!("failed to encode agent message ack payload: {err}"))
    })
}
fn encode_agent_artifact_allow_signature_payload(
    payload: &AgentArtifactAllowPayload,
) -> Result<Vec<u8>, SoracloudError> {
    parse_agent_apartment_name(&payload.apartment_name)?;
    encode_agent_artifact_allow_provenance_payload(
        payload.apartment_name.as_str(),
        payload.artifact_hash.as_str(),
        payload.provenance_hash.as_deref(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode agent artifact allow payload: {err}"
        ))
    })
}
fn encode_hf_shared_lease_join_signature_payload(
    payload: &HfSharedLeaseJoinPayload,
) -> Result<Vec<u8>, SoracloudError> {
    let repo_id = parse_hf_repo_id(&payload.repo_id)?;
    let resolved_revision = parse_hf_revision(&payload.revision)?;
    let service_name = parse_service_name(&payload.service_name)?.to_string();
    let apartment_name = payload
        .apartment_name
        .as_deref()
        .map(parse_agent_apartment_name)
        .transpose()?;
    if payload.lease_term_ms == 0 {
        return Err(SoracloudError::bad_request(
            "lease_term_ms must be greater than zero",
        ));
    }
    if payload.base_fee.is_zero() {
        return Err(SoracloudError::bad_request(
            "base_fee must be greater than zero",
        ));
    }
    encode_hf_shared_lease_join_provenance_payload(
        &repo_id,
        &resolved_revision,
        &service_name,
        apartment_name.as_deref(),
        payload.storage_class,
        payload.lease_term_ms,
        &payload.lease_asset_definition_id,
        &payload.base_fee,
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode hf shared-lease join payload: {err}"
        ))
    })
}
fn encode_hf_lease_leave_signature_payload(
    payload: &HfLeaseLeavePayload,
) -> Result<Vec<u8>, SoracloudError> {
    let repo_id = parse_hf_repo_id(&payload.repo_id)?;
    let resolved_revision = parse_hf_revision(&payload.revision)?;
    let service_name = payload
        .service_name
        .as_deref()
        .map(|value| parse_service_name(value).map(|name| name.to_string()))
        .transpose()?;
    let apartment_name = payload
        .apartment_name
        .as_deref()
        .map(parse_agent_apartment_name)
        .transpose()?;
    if payload.lease_term_ms == 0 {
        return Err(SoracloudError::bad_request(
            "lease_term_ms must be greater than zero",
        ));
    }
    encode_hf_shared_lease_leave_provenance_payload(
        &repo_id,
        &resolved_revision,
        payload.storage_class,
        payload.lease_term_ms,
        service_name.as_deref(),
        apartment_name.as_deref(),
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode hf shared-lease leave payload: {err}"
        ))
    })
}
fn encode_hf_lease_renew_signature_payload(
    payload: &HfLeaseRenewPayload,
) -> Result<Vec<u8>, SoracloudError> {
    let repo_id = parse_hf_repo_id(&payload.repo_id)?;
    let resolved_revision = parse_hf_revision(&payload.revision)?;
    let service_name = parse_service_name(&payload.service_name)?.to_string();
    let apartment_name = payload
        .apartment_name
        .as_deref()
        .map(parse_agent_apartment_name)
        .transpose()?;
    if payload.lease_term_ms == 0 {
        return Err(SoracloudError::bad_request(
            "lease_term_ms must be greater than zero",
        ));
    }
    if payload.base_fee.is_zero() {
        return Err(SoracloudError::bad_request(
            "base_fee must be greater than zero",
        ));
    }
    encode_hf_shared_lease_renew_provenance_payload(
        &repo_id,
        &resolved_revision,
        &service_name,
        apartment_name.as_deref(),
        payload.storage_class,
        payload.lease_term_ms,
        &payload.lease_asset_definition_id,
        &payload.base_fee,
    )
    .map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode hf shared-lease renew payload: {err}"
        ))
    })
}
#[derive(Clone)]
struct SoracloudMutationSigner {
    authority: AccountId,
    request_signer: PublicKey,
}
fn verified_soracloud_request_identity(
    headers: &HeaderMap,
) -> Result<(AccountId, PublicKey, Vec<PublicKey>), SoracloudError> {
    let account_literal = headers
        .get(VERIFIED_ACCOUNT_HEADER)
        .ok_or_else(|| {
            SoracloudError::unauthorized(
                "signed request headers are required for Soracloud mutation endpoints",
            )
        })
        .and_then(|value| {
            std::str::from_utf8(value.as_bytes()).map_err(|_| {
                SoracloudError::internal(
                    "failed to decode verified Soracloud account header".to_owned(),
                )
            })
        })?;
    let account = AccountId::parse_encoded(account_literal).map_err(|_| {
        SoracloudError::internal("failed to parse verified Soracloud account header".to_owned())
    })?;
    if account.to_string() != account_literal {
        return Err(SoracloudError::internal(
            "verified Soracloud account header must use exact canonical V1 text".to_owned(),
        ));
    }
    let signer_literal = headers
        .get(VERIFIED_SIGNER_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            SoracloudError::unauthorized(
                "signed request headers are required for Soracloud mutation endpoints",
            )
        })?;
    let signer = signer_literal.parse::<PublicKey>().map_err(|_| {
        SoracloudError::internal("failed to parse verified Soracloud signer header".to_owned())
    })?;
    if signer.to_string() != signer_literal {
        return Err(SoracloudError::internal(
            "verified Soracloud signer header must use exact canonical V1 text".to_owned(),
        ));
    }
    let signer_set_literal = headers
        .get(VERIFIED_SIGNERS_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            SoracloudError::unauthorized(
                "signed request headers are required for Soracloud mutation endpoints",
            )
        })?;
    let decoded = BASE64_STANDARD.decode(signer_set_literal).map_err(|_| {
        SoracloudError::internal("failed to decode verified Soracloud signer-set header".to_owned())
    })?;
    if BASE64_STANDARD.encode(&decoded) != signer_set_literal {
        return Err(SoracloudError::internal(
            "verified Soracloud signer-set header must use exact canonical V1 base64".to_owned(),
        ));
    }
    let verified_signers: Vec<PublicKey> = norito::decode_from_bytes(&decoded).map_err(|_| {
        SoracloudError::internal(
            "failed to decode verified Soracloud signer-set payload".to_owned(),
        )
    })?;
    let canonical_signer_set = norito::to_bytes(&verified_signers).map_err(|_| {
        SoracloudError::internal(
            "failed to encode verified Soracloud signer-set payload".to_owned(),
        )
    })?;
    if canonical_signer_set != decoded {
        return Err(SoracloudError::internal(
            "verified Soracloud signer-set header must use exact canonical V1 Norito".to_owned(),
        ));
    }
    if verified_signers.is_empty() {
        return Err(SoracloudError::internal(
            "verified Soracloud signer-set header must not be empty".to_owned(),
        ));
    }
    if !verified_signers.iter().any(|verified| verified == &signer) {
        return Err(SoracloudError::internal(
            "verified Soracloud signer-set header does not include the primary signer".to_owned(),
        ));
    }
    Ok((account, signer, verified_signers))
}
fn require_soracloud_mutation_signer(
    headers: &HeaderMap,
    provenance: &ManifestProvenance,
) -> Result<SoracloudMutationSigner, SoracloudError> {
    let (authority, _request_signer, verified_signers) =
        verified_soracloud_request_identity(headers)?;
    if !verified_signers
        .iter()
        .any(|verified_signer| verified_signer == &provenance.signer)
    {
        return Err(SoracloudError::unauthorized(
            "mutation provenance signer must match one of the verified request signers",
        ));
    }
    Ok(SoracloudMutationSigner {
        authority,
        request_signer: provenance.signer.clone(),
    })
}
fn soracloud_draft_response(
    signer: &SoracloudMutationSigner,
    instructions: Vec<InstructionBox>,
) -> Response {
    match build_soracloud_mutation_draft(signer, instructions) {
        Ok(draft) => JsonBody(draft).into_response(),
        Err(error) => error.into_response(),
    }
}
fn build_soracloud_mutation_draft(
    signer: &SoracloudMutationSigner,
    instructions: Vec<InstructionBox>,
) -> Result<SoracloudMutationDraftResponse, SoracloudError> {
    if instructions.is_empty() {
        return Err(SoracloudError::conflict(
            "Soracloud mutation draft produced no transaction instructions",
        ));
    }
    let tx_instructions = instructions
        .into_iter()
        .map(soracloud_tx_instr_from_box)
        .collect();
    let draft = SoracloudMutationDraftResponse {
        ok: true,
        authority: signer.authority.clone(),
        signed_by: signer.request_signer.clone(),
        tx_instructions,
    };
    draft.validate().map_err(|error| {
        SoracloudError::internal(format!(
            "failed to build canonical Soracloud mutation draft: {error}"
        ))
    })?;
    Ok(draft)
}
fn soracloud_tx_instr_from_box(boxed: InstructionBox) -> SoracloudTxInstruction {
    let (wire_id, framed) = iroha_data_model::isi::framed_instruction_payload(&boxed)
        .expect("instruction must have a canonical V1 wire identifier and Norito frame");
    SoracloudTxInstruction {
        wire_id: wire_id.to_owned(),
        payload_hex: hex::encode(framed),
    }
}
#[cfg(test)]
fn error_chain_message(error: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = Vec::new();
    let mut current = Some(error);
    while let Some(err) = current {
        let message = err.to_string();
        if !message.is_empty() && parts.last() != Some(&message) {
            parts.push(message);
        }
        current = err.source();
    }
    parts.join(": ")
}
#[cfg(test)]
fn join_nested_message(primary: String, nested: String) -> String {
    if nested.is_empty() || nested == primary {
        primary
    } else if nested.starts_with(&primary) {
        nested
    } else {
        format!("{primary}: {nested}")
    }
}
#[cfg(test)]
fn instruction_execution_message(
    error: &iroha_data_model::isi::error::InstructionExecutionError,
) -> String {
    use iroha_data_model::isi::error::InstructionExecutionError;
    match error {
        InstructionExecutionError::InvalidParameter(inner) => {
            join_nested_message(error.to_string(), inner.to_string())
        }
        _ => error_chain_message(error),
    }
}
#[cfg(test)]
fn validation_fail_message(validation: &iroha_data_model::ValidationFail) -> String {
    match validation {
        iroha_data_model::ValidationFail::InstructionFailed(error) => {
            join_nested_message(validation.to_string(), instruction_execution_message(error))
        }
        _ => error_chain_message(validation),
    }
}
#[cfg(test)]
fn transaction_rejection_message(
    reason: &iroha_data_model::transaction::error::TransactionRejectionReason,
) -> String {
    use iroha_data_model::transaction::error::TransactionRejectionReason;
    match reason {
        TransactionRejectionReason::Validation(validation) => {
            join_nested_message(reason.to_string(), validation_fail_message(validation))
        }
        TransactionRejectionReason::InstructionExecution(error) => {
            join_nested_message(reason.to_string(), error.to_string())
        }
        _ => error_chain_message(reason),
    }
}
fn audit_action_to_control_plane_action(action: SoraServiceLifecycleActionV1) -> SoracloudAction {
    match action {
        SoraServiceLifecycleActionV1::Deploy => SoracloudAction::Deploy,
        SoraServiceLifecycleActionV1::Upgrade => SoracloudAction::Upgrade,
        SoraServiceLifecycleActionV1::ConfigMutation => SoracloudAction::ConfigMutation,
        SoraServiceLifecycleActionV1::SecretMutation => SoracloudAction::SecretMutation,
        SoraServiceLifecycleActionV1::StateMutation => SoracloudAction::StateMutation,
        SoraServiceLifecycleActionV1::FheJobRun => SoracloudAction::FheJobRun,
        SoraServiceLifecycleActionV1::FhePolicyRegister => SoracloudAction::FhePolicyRegister,
        SoraServiceLifecycleActionV1::FhePolicyRotate => SoracloudAction::FhePolicyRotate,
        SoraServiceLifecycleActionV1::FhePolicyRevoke => SoracloudAction::FhePolicyRevoke,
        SoraServiceLifecycleActionV1::DecryptionRequest => SoracloudAction::DecryptionRequest,
        SoraServiceLifecycleActionV1::CiphertextQuery => SoracloudAction::CiphertextQuery,
        SoraServiceLifecycleActionV1::Rollout => SoracloudAction::Rollout,
        SoraServiceLifecycleActionV1::Rollback => SoracloudAction::Rollback,
        SoraServiceLifecycleActionV1::LeaseUsage => SoracloudAction::LeaseUsage,
        SoraServiceLifecycleActionV1::LeaseReportingEpochRollover => {
            SoracloudAction::LeaseReportingEpochRollover
        }
    }
}
fn rollout_stage_to_control_plane_stage(stage: SoraRolloutStageV1) -> RolloutStage {
    match stage {
        SoraRolloutStageV1::Canary => RolloutStage::Canary,
        SoraRolloutStageV1::Promoted => RolloutStage::Promoted,
        SoraRolloutStageV1::RolledBack => RolloutStage::RolledBack,
    }
}
fn rollout_state_to_runtime_state(state: &SoraServiceRolloutStateV1) -> RolloutRuntimeState {
    RolloutRuntimeState {
        rollout_handle: state.rollout_handle.clone(),
        baseline_version: state.baseline_version.clone(),
        candidate_version: state.candidate_version.clone(),
        canary_percent: state.canary_percent,
        traffic_percent: state.traffic_percent,
        stage: rollout_stage_to_control_plane_stage(state.stage),
        health_failures: state.health_failures,
        max_health_failures: state.max_health_failures,
        health_window_secs: state.health_window_secs,
        created_sequence: state.created_sequence,
        updated_sequence: state.updated_sequence,
    }
}
fn audit_event_to_control_plane_audit_event(
    event: &SoraServiceAuditEventV1,
) -> ControlPlaneAuditEvent {
    ControlPlaneAuditEvent {
        sequence: event.sequence,
        action: audit_action_to_control_plane_action(event.action),
        service_name: event.service_name.to_string(),
        from_version: event.from_version.clone(),
        to_version: event.to_version.clone(),
        service_manifest_hash: event.service_manifest_hash,
        container_manifest_hash: event.container_manifest_hash,
        process_generation: event.process_generation,
        config_generation: event.config_generation,
        secret_generation: event.secret_generation,
        config_snapshot_hash: event.config_snapshot_hash,
        secret_snapshot_hash: event.secret_snapshot_hash,
        binding_name: event.binding_name.as_ref().map(ToString::to_string),
        state_key: event.state_key.clone(),
        config_mutations: event.config_mutations.clone(),
        secret_mutations: event.secret_mutations.clone(),
        governance_tx_hash: event.governance_tx_hash,
        rollout_state: event
            .rollout_state
            .as_ref()
            .map(rollout_state_to_runtime_state),
        policy_name: event.policy_name.as_ref().map(ToString::to_string),
        policy_snapshot_hash: event.policy_snapshot_hash,
        jurisdiction_tag: event.jurisdiction_tag.clone(),
        consent_evidence_hash: event.consent_evidence_hash,
        break_glass: event.break_glass,
        break_glass_reason: event.break_glass_reason.clone(),
        lease_usage: event.lease_usage.clone(),
        service_lease_commitment: event.service_lease_commitment,
        lease_reporting_epoch_rollover: event.lease_reporting_epoch_rollover.clone(),
        signed_by: event.signer.to_string(),
    }
}
fn state_mutation_operation_to_model(
    operation: StateMutationOperation,
) -> SoraStateMutationOperationV1 {
    match operation {
        StateMutationOperation::Upsert => SoraStateMutationOperationV1::Upsert,
        StateMutationOperation::Delete => SoraStateMutationOperationV1::Delete,
    }
}
fn authoritative_audit_log(
    app: &SharedAppState,
) -> Result<Vec<ControlPlaneAuditEvent>, SoracloudError> {
    let state_view = app.state.view();
    let world = state_view.world();
    let mut audit_log = Vec::new();
    for (sequence, event) in world.soracloud_service_audit_events().iter() {
        if *sequence != event.sequence {
            return Err(SoracloudError::internal(format!(
                "authoritative Soracloud audit event key {sequence} does not bind event sequence {}",
                event.sequence
            )));
        }
        event.validate().map_err(|error| {
            SoracloudError::internal(format!(
                "authoritative Soracloud audit event {sequence} is invalid: {error}"
            ))
        })?;
        audit_log.push(audit_event_to_control_plane_audit_event(event));
    }
    audit_log.sort_by_key(|event| event.sequence);
    Ok(audit_log)
}
fn authoritative_training_job_status_response(
    app: &SharedAppState,
    service_name: &str,
    job_id: &str,
) -> Result<TrainingJobStatusResponse, SoracloudError> {
    let service_name = parse_service_name(service_name)?.to_string();

    let job_id = parse_training_job_id(job_id)?;
    let state_view = app.state.view();
    let world = state_view.world();
    let record = world
        .soracloud_training_jobs()
        .get(&(service_name.clone(), job_id))
        .cloned()
        .ok_or_else(|| {
            SoracloudError::not_found(format!(
                "training job not found for service `{service_name}` in authoritative Soracloud state"
            ))
        })?;
    Ok(TrainingJobStatusResponse {
        schema_version: TRAINING_JOB_STATUS_SCHEMA_VERSION_V1,
        job: authoritative_training_job_status_entry(&service_name, &record),
    })
}
fn authoritative_model_weight_status_response(
    app: &SharedAppState,
    service_name: &str,
    model_name: &str,
) -> Result<ModelWeightStatusResponse, SoracloudError> {
    let service_name = parse_service_name(service_name)?.to_string();
    let model_name = parse_training_model_name(model_name)?;
    let state_view = app.state.view();
    let world = state_view.world();
    let registry = world
        .soracloud_model_registries()
        .get(&(service_name.clone(), model_name.clone()))
        .cloned()
        .ok_or_else(|| {
            SoracloudError::not_found(format!(
                "model `{model_name}` is not registered for service `{service_name}` in authoritative Soracloud state"
            ))
        })?;
    let versions = world
        .soracloud_model_weight_versions()
        .iter()
        .filter(|((stored_service, stored_model, _version), _record)| {
            stored_service == &service_name && stored_model == &model_name
        })
        .map(|(_key, record)| authoritative_model_weight_version_entry(record))
        .collect::<Vec<_>>();
    Ok(ModelWeightStatusResponse {
        schema_version: MODEL_WEIGHT_STATUS_SCHEMA_VERSION_V1,
        model: authoritative_model_weight_status_entry(&service_name, &registry, versions),
    })
}
fn authoritative_model_artifact_status_response(
    app: &SharedAppState,
    service_name: &str,
    model_name: Option<&str>,
    artifact_id: Option<&str>,
    training_job_id: Option<&str>,
    weight_version: Option<&str>,
) -> Result<ModelArtifactStatusResponse, SoracloudError> {
    let service_name = parse_service_name(service_name)?.to_string();
    let model_name = model_name.map(parse_training_model_name).transpose()?;
    let training_job_id = training_job_id.map(parse_training_job_id).transpose()?;
    let artifact_id = artifact_id
        .map(parse_training_job_id)
        .transpose()?
        .or_else(|| training_job_id.clone());
    let weight_version = weight_version.map(parse_model_weight_version).transpose()?;
    if model_name.is_none() && artifact_id.is_none() && training_job_id.is_none() {
        return Err(SoracloudError::bad_request(
            "model artifact status requires at least one of model_name, artifact_id, or training_job_id",
        ));
    }
    let state_view = app.state.view();
    let world = state_view.world();
    let mut artifacts = world
        .soracloud_model_artifacts()
        .iter()
        .filter(|((stored_service, stored_artifact_id), record)| {
            if stored_service != &service_name {
                return false;
            }
            if let Some(expected_model_name) = model_name.as_ref()
                && &record.model_name != expected_model_name
            {
                return false;
            }
            if let Some(expected_artifact_id) = artifact_id.as_ref()
                && stored_artifact_id != expected_artifact_id
            {
                return false;
            }
            if let Some(expected_training_job_id) = training_job_id.as_ref()
                && &record.training_job_id != expected_training_job_id
            {
                return false;
            }
            if let Some(expected_weight_version) = weight_version.as_ref()
                && record.weight_version.as_deref() != Some(expected_weight_version.as_str())
            {
                return false;
            }
            true
        })
        .map(|(_key, record)| record.clone())
        .collect::<Vec<_>>();
    artifacts.sort_by(|left, right| {
        right
            .registered_sequence
            .cmp(&left.registered_sequence)
            .then_with(|| left.artifact_id.cmp(&right.artifact_id))
    });
    let artifact = artifacts.first().cloned().ok_or_else(|| {
        SoracloudError::not_found(format!(
            "model artifact status not found for service `{service_name}` in authoritative Soracloud state"
        ))
    })?;
    let artifact_entries = artifacts
        .iter()
        .map(|entry| authoritative_model_artifact_status_entry(&service_name, entry))
        .collect::<Vec<_>>();
    Ok(ModelArtifactStatusResponse {
        schema_version: MODEL_ARTIFACT_STATUS_SCHEMA_VERSION_V1,
        service_name: service_name.clone(),
        model_name: artifact.model_name.clone(),
        artifact_count: u32::try_from(artifact_entries.len()).unwrap_or(u32::MAX),
        artifact: authoritative_model_artifact_status_entry(&service_name, &artifact),
        artifacts: artifact_entries,
    })
}
fn authoritative_uploaded_model_status_response(
    app: &SharedAppState,
    service_name: &str,
    model_id: &str,
    weight_version: &str,
) -> Result<UploadedModelStatusResponse, SoracloudError> {
    let service_name = parse_service_name(service_name)?.to_string();

    let model_id = parse_training_job_id(model_id)?;
    let weight_version = parse_model_weight_version(weight_version)?;
    let state_view = app.state.view();
    let world = state_view.world();
    let bundle = world
        .soracloud_uploaded_model_bundles()
        .get(&(service_name.clone(), model_id.clone(), weight_version.clone()))
        .cloned()
        .ok_or_else(|| {
            SoracloudError::not_found(format!(
                "uploaded model `{model_id}` version `{weight_version}` not found for service `{service_name}`"
            ))
        })?;
    let artifact = world.soracloud_model_artifacts().iter().find_map(
        |((stored_service, _artifact_id), record)| {
            (stored_service == &service_name
                && record.weight_version.as_deref() == Some(weight_version.as_str())
                && record.source_provenance.as_ref().is_some_and(|provenance| {
                    provenance.kind == SoraModelProvenanceKindV1::UserUpload
                        && provenance.id == model_id
                }))
            .then(|| authoritative_model_artifact_status_entry(&service_name, record))
        },
    );
    Ok(UploadedModelStatusResponse {
        schema_version: UPLOADED_MODEL_STATUS_SCHEMA_VERSION_V1,
        bundle,
        artifact,
    })
}
fn require_active_sorafs_uploaded_model_pin(
    app: &SharedAppState,
    bundle: &SoraUploadedModelBundleV1,
) -> Result<(), SoracloudError> {
    let state_view = app.state.view();
    let world = state_view.world();
    let Some(pin) = world.pin_manifests().get(&bundle.sorafs_manifest_digest) else {
        return Err(SoracloudError::conflict(format!(
            "SoraFS manifest {:?} for uploaded model `{}` version `{}` is not registered",
            bundle.sorafs_manifest_digest, bundle.model_id, bundle.weight_version
        )));
    };
    require_active_sorafs_uploaded_model_pin_record(pin, bundle)
}
fn require_active_sorafs_uploaded_model_pin_record(
    pin: &PinManifestRecord,
    bundle: &SoraUploadedModelBundleV1,
) -> Result<(), SoracloudError> {
    match pin.status {
        PinStatus::Approved(_) => Ok(()),
        PinStatus::Pending => Err(SoracloudError::conflict(format!(
            "SoraFS manifest {:?} for uploaded model `{}` version `{}` is not approved",
            bundle.sorafs_manifest_digest, bundle.model_id, bundle.weight_version
        ))),
        PinStatus::Retired(epoch) => Err(SoracloudError::conflict(format!(
            "SoraFS manifest {:?} for uploaded model `{}` version `{}` retired at epoch {epoch}",
            bundle.sorafs_manifest_digest, bundle.model_id, bundle.weight_version
        ))),
    }?;
    if pin.digest != bundle.sorafs_manifest_digest {
        return Err(SoracloudError::conflict(format!(
            "SoraFS manifest record digest {:?} does not match uploaded model digest {:?}",
            pin.digest, bundle.sorafs_manifest_digest
        )));
    }
    if pin.content_length != bundle.ciphertext_bytes {
        return Err(SoracloudError::conflict(format!(
            "SoraFS manifest {:?} content_length {} does not match uploaded model ciphertext_bytes {}",
            bundle.sorafs_manifest_digest, pin.content_length, bundle.ciphertext_bytes
        )));
    }
    Ok(())
}

fn authoritative_uploaded_model_status_from_query(
    app: &SharedAppState,
    query: &UploadedModelStatusQuery,
) -> Result<UploadedModelStatusResponse, SoracloudError> {
    let service_name = parse_service_name(&query.service_name)?.to_string();

    let weight_version = parse_model_weight_version(&query.weight_version)?;
    if query.model_id.is_some() && query.model_name.is_some() {
        return Err(SoracloudError::bad_request(
            "exactly one of model_id or model_name must be provided for uploaded model status",
        ));
    }
    let state_view = app.state.view();
    let world = state_view.world();
    let model_id = if let Some(model_id) = query.model_id.as_deref() {
        let model_id = parse_training_job_id(model_id)?;
        let bundle = world
            .soracloud_uploaded_model_bundles()
            .get(&(service_name.clone(), model_id.clone(), weight_version.clone()))
            .cloned()
            .ok_or_else(|| {
                SoracloudError::not_found(format!(
                    "uploaded model `{model_id}` version `{weight_version}` not found for service `{service_name}`"
                ))
            })?;
        if let Some(bundle_root) = query.bundle_root
            && bundle.bundle_root != bundle_root
        {
            return Err(SoracloudError::conflict(format!(
                "uploaded model `{model_id}` version `{weight_version}` bundle_root does not match query"
            )));
        }
        model_id
    } else {
        let model_name = query.model_name.as_deref().ok_or_else(|| {
            SoracloudError::bad_request(
                "model_id or model_name must be provided for uploaded model status".to_string(),
            )
        })?;
        let model_name = parse_training_model_name(model_name)?;
        world
            .soracloud_model_artifacts()
            .iter()
            .find_map(|((stored_service, _artifact_id), record)| {
                (stored_service == &service_name
                    && record.model_name == model_name
                    && record.weight_version.as_deref() == Some(weight_version.as_str())
                    && record
                        .source_provenance
                        .as_ref()
                        .is_some_and(|provenance| provenance.kind == SoraModelProvenanceKindV1::UserUpload)
                    && query.bundle_root.is_none_or(|bundle_root| {
                        record
                            .source_provenance
                            .as_ref()
                            .and_then(|provenance| {
                                world
                                    .soracloud_uploaded_model_bundles()
                                    .get(&(
                                        service_name.clone(),
                                        provenance.id.clone(),
                                        weight_version.clone(),
                                    ))
                            })
                            .is_some_and(|bundle| bundle.bundle_root == bundle_root)
                    }))
                .then(|| record.source_provenance.as_ref().map(|provenance| provenance.id.clone()))
                .flatten()
            })
            .ok_or_else(|| {
                SoracloudError::not_found(format!(
                    "uploaded model status not found for service `{service_name}`, model `{model_name}`, version `{weight_version}`"
                ))
            })?
    };
    authoritative_uploaded_model_status_response(app, &service_name, &model_id, &weight_version)
}
fn authoritative_hf_shared_lease_status_response(
    app: &SharedAppState,
    repo_id: &str,
    resolved_revision: &str,
    storage_class: StorageClass,
    lease_term_ms: u64,
    account_id: Option<&AccountId>,
) -> Result<HfSharedLeaseStatusResponse, SoracloudError> {
    if lease_term_ms == 0 {
        return Err(SoracloudError::bad_request(
            "lease_term_ms must be greater than zero",
        ));
    }
    let source_id = hf_source_id(repo_id, resolved_revision)?;
    let pool_id = hf_shared_lease_pool_id(source_id, storage_class, lease_term_ms)?;
    let member_key = account_id.map(|account_id| (pool_id.to_string(), account_id.to_string()));
    let state_view = app.state.view();
    let world = state_view.world();
    let source = world
        .soracloud_hf_sources()
        .get(&source_id)
        .cloned()
        .ok_or_else(|| {
            SoracloudError::not_found(format!(
                "hf source `{repo_id}@{resolved_revision}` not found in authoritative Soracloud state"
            ))
        })?;
    let pool = world
        .soracloud_hf_shared_lease_pools()
        .get(&pool_id)
        .cloned();
    let member = member_key.as_ref().and_then(|member_key| {
        world
            .soracloud_hf_shared_lease_members()
            .get(member_key)
            .cloned()
    });
    let latest_audit_event = world
        .soracloud_hf_shared_lease_audit_events()
        .iter()
        .filter(|(_sequence, event)| {
            event.pool_id == pool_id
                && account_id.is_none_or(|account_id| event.account_id == *account_id)
        })
        .map(|(_sequence, event)| event.clone())
        .max_by_key(|event| event.sequence);
    let storage_base_fee = pool
        .as_ref()
        .map_or_else(Quantity::zero, |pool| pool.base_fee.clone());
    Ok(HfSharedLeaseStatusResponse {
        schema_version: HF_SHARED_LEASE_STATUS_SCHEMA_VERSION_V1,
        source,
        pool,
        member,
        latest_audit_event,
        audit_event_count: authoritative_hf_shared_lease_event_count(world, &pool_id),
        storage_base_fee,
    })
}
fn authoritative_hf_shared_lease_event_count(world: &impl WorldReadOnly, pool_id: &Hash) -> u32 {
    u32::try_from(
        world
            .soracloud_hf_shared_lease_audit_events()
            .iter()
            .filter(|(_sequence, event)| event.pool_id == *pool_id)
            .count(),
    )
    .unwrap_or(u32::MAX)
}
fn authoritative_service_deployment_bundle(
    world: &impl WorldReadOnly,
    service_name: &str,
) -> Result<(SoraServiceDeploymentStateV1, SoraDeploymentBundleV1), SoracloudError> {
    let service_id = parse_service_name(service_name)?;
    let deployment = world
        .soracloud_service_deployments()
        .get(&service_id)
        .cloned()
        .ok_or_else(|| {
            SoracloudError::not_found(format!(
                "service `{service_name}` not found in authoritative Soracloud state"
            ))
        })?;
    if deployment.service_name != service_id {
        return Err(SoracloudError::internal(format!(
            "service `{service_name}` deployment record has substituted identity `{}`",
            deployment.service_name
        )));
    }
    let bundle = world
        .soracloud_service_revisions()
        .get(&(
            deployment.service_name.to_string(),
            deployment.current_service_version.clone(),
        ))
        .cloned()
        .ok_or_else(|| {
            SoracloudError::internal(format!(
                "service `{service_name}` active revision `{}` is missing from authoritative state",
                deployment.current_service_version
            ))
        })?;
    if bundle.service.service_name != deployment.service_name
        || bundle.service.service_version != deployment.current_service_version
        || bundle.service_manifest_hash() != deployment.current_service_manifest_hash
        || bundle.container_manifest_hash() != deployment.current_container_manifest_hash
    {
        return Err(SoracloudError::internal(format!(
            "service `{service_name}` deployment record does not bind active revision `{}`",
            deployment.current_service_version
        )));
    }
    bundle.validate_for_admission().map_err(|error| {
        SoracloudError::internal(format!(
            "service `{service_name}` active revision `{}` is not an admitted V1 bundle: {error}",
            deployment.current_service_version
        ))
    })?;
    Ok((deployment, bundle))
}
fn ensure_authoritative_rollout_draft_supported(
    world: &impl WorldReadOnly,
    service_name: &str,
) -> Result<(), SoracloudError> {
    let (deployment, bundle) = authoritative_service_deployment_bundle(world, service_name)?;
    if bundle.service.execution_plane == SoraServiceExecutionPlaneV1::HttpService
        && bundle.container.runtime == SoraContainerRuntimeV1::Inrou
    {
        return Err(SoracloudError::bad_request(format!(
            "service `{}` uses the first-release HttpService+Inrou runtime; staged rollout drafts are not supported; publish an atomic upgrade as the sole current revision",
            deployment.service_name
        )));
    }
    Ok(())
}
fn decode_public_service_discovery_registry(
    entry: &SoraServiceConfigEntryV1,
) -> Result<SoracloudPublicServiceDiscoveryRegistryV1, SoracloudError> {
    if entry.config_name != PUBLIC_SERVICE_DISCOVERY_CONFIG_NAME {
        return Err(SoracloudError::internal(format!(
            "authoritative public discovery config has substituted name `{}`",
            entry.config_name
        )));
    }
    let value_json = entry
        .value_json
        .clone()
        .try_into_any_norito::<norito::json::Value>()
        .map_err(|err| {
            SoracloudError::internal(format!(
                "failed to decode authoritative public discovery config json: {err}"
            ))
        })?;
    let canonical_bytes = norito::json::to_vec(&value_json).map_err(|err| {
        SoracloudError::internal(format!(
            "failed to encode authoritative public discovery config json: {err}"
        ))
    })?;
    if Hash::new(&canonical_bytes) != entry.value_hash {
        return Err(SoracloudError::internal(
            "authoritative public discovery config hash does not bind its JSON value",
        ));
    }
    let registry: SoracloudPublicServiceDiscoveryRegistryV1 = norito::json::from_value(value_json)
        .map_err(|err| {
            SoracloudError::internal(format!(
                "failed to parse authoritative public discovery registry: {err}"
            ))
        })?;
    if registry.schema_version != PUBLIC_SERVICE_DISCOVERY_SCHEMA_VERSION_V1 {
        return Err(SoracloudError::internal(format!(
            "authoritative public discovery registry uses schema version {}; expected {}",
            registry.schema_version, PUBLIC_SERVICE_DISCOVERY_SCHEMA_VERSION_V1
        )));
    }
    for (version, discovery) in &registry.revisions {
        if discovery.schema_version != PUBLIC_SERVICE_DISCOVERY_SCHEMA_VERSION_V1
            || discovery.service_name != registry.service_name
            || discovery.service_version != *version
        {
            return Err(SoracloudError::internal(format!(
                "authoritative public discovery revision `{version}` is not bound to its registry identity"
            )));
        }
    }
    Ok(registry)
}
fn authoritative_public_service_discovery_registry(
    deployment: &SoraServiceDeploymentStateV1,
) -> Result<Option<SoracloudPublicServiceDiscoveryRegistryV1>, SoracloudError> {
    let registry = deployment
        .service_configs
        .get(PUBLIC_SERVICE_DISCOVERY_CONFIG_NAME)
        .map(decode_public_service_discovery_registry)
        .transpose()?;
    if let Some(registry) = registry.as_ref()
        && (registry.service_name != deployment.service_name.as_ref()
            || registry.current_version != deployment.current_service_version
            || !registry
                .revisions
                .contains_key(&deployment.current_service_version))
    {
        return Err(SoracloudError::internal(format!(
            "authoritative public discovery registry for service `{}` does not bind its active revision `{}`",
            deployment.service_name, deployment.current_service_version
        )));
    }
    Ok(registry)
}
fn authoritative_public_service_discovery_for_version(
    deployment: &SoraServiceDeploymentStateV1,
    service_version: &str,
) -> Result<Option<SoracloudPublicServiceDiscoveryV1>, SoracloudError> {
    let Some(registry) = authoritative_public_service_discovery_registry(deployment)? else {
        return Ok(None);
    };
    Ok(registry.revisions.get(service_version).cloned())
}
fn public_service_discovery_document(
    discovery: &SoracloudPublicServiceDiscoveryV1,
) -> SoracloudPublicServiceDiscoveryDocumentV1 {
    SoracloudPublicServiceDiscoveryDocumentV1 {
        schema_version: discovery.schema_version,
        service_name: discovery.service_name.clone(),
        service_version: discovery.service_version.clone(),
        execution_plane: discovery.execution_plane.clone(),
        runtime: discovery.runtime.clone(),
        route_host: discovery.route_host.clone(),
        path_prefix: discovery.path_prefix.clone(),
        base_url: discovery.base_url.clone(),
        healthcheck_path: discovery.healthcheck_path.clone(),
        healthcheck_url: discovery.healthcheck_url.clone(),
        service_manifest_hash: discovery.service_manifest_hash,
        container_manifest_hash: discovery.container_manifest_hash,
        deployment_bundle_hash: discovery.deployment_bundle_hash,
    }
}
fn public_service_discovery_document_bytes(
    discovery: &SoracloudPublicServiceDiscoveryV1,
) -> Result<Vec<u8>, SoracloudError> {
    norito::json::to_vec(&public_service_discovery_document(discovery)).map_err(|error| {
        SoracloudError::internal(format!(
            "failed to encode canonical public discovery document: {error}"
        ))
    })
}
#[cfg(test)]
fn public_service_discovery_document_hash(
    discovery: &SoracloudPublicServiceDiscoveryV1,
) -> Result<Hash, SoracloudError> {
    public_service_discovery_document_bytes(discovery).map(Hash::new)
}
fn public_service_discovery_artifact_root_cid(
    document_bytes: Vec<u8>,
) -> Result<ManifestRootCid, SoracloudError> {
    let descriptor = sorafs_manifest::chunker_registry::default_descriptor();
    let (plan, payload) = CarBuildPlan::from_files_with_profile(
        vec![FileEntry {
            path: vec![PUBLIC_SERVICE_DISCOVERY_INDEX_DOCUMENT.to_owned()],
            data: document_bytes,
        }],
        descriptor.profile,
    )
    .map_err(|error| {
        SoracloudError::internal(format!(
            "failed to plan canonical public discovery artifact: {error}"
        ))
    })?;
    let mut sink = Vec::new();
    let car_stats = CarWriter::new(&plan, &payload)
        .and_then(|writer| writer.write_to(&mut sink))
        .map_err(|error| {
            SoracloudError::internal(format!(
                "failed to derive canonical public discovery artifact root: {error}"
            ))
        })?;
    let [root_cid] = car_stats.root_cids.as_slice() else {
        return Err(SoracloudError::internal(
            "canonical public discovery artifact did not produce exactly one root CID",
        ));
    };
    ManifestRootCid::try_from_slice(root_cid).map_err(|error| {
        SoracloudError::internal(format!(
            "canonical public discovery artifact produced an invalid root CID: {error}"
        ))
    })
}
fn is_canonical_public_service_discovery_content_cid(content_cid: &str) -> bool {
    let Some(bytes) = crate::sorafs::site::decode_content_cid(content_cid) else {
        return false;
    };
    crate::sorafs::site::encode_content_cid(&bytes) == content_cid
        && ManifestRootCid::try_from_slice(&bytes).is_ok()
}
fn is_canonical_public_service_discovery_manifest_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn sorafs_cid_host_suffix_for_public_service(hostname: &str) -> String {
    let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if hostname == "taira.sora.org" || hostname.ends_with(".taira.sora.org") {
        return "sorafs.taira.sora.org".to_owned();
    }
    if hostname == "sora.org" || hostname.ends_with(".sora.org") {
        return "sorafs.sora.org".to_owned();
    }
    if let Some((_, suffix)) = hostname.split_once('.') {
        return format!("sorafs.{suffix}");
    }
    format!("sorafs.{hostname}")
}
fn canonical_public_service_discovery_urls(
    base_url: &str,
    route_host: &str,
    content_cid: &str,
) -> Result<(String, String), SoracloudError> {
    let mut public_discovery_url = reqwest::Url::parse(base_url).map_err(|error| {
        SoracloudError::internal(format!(
            "authoritative public discovery base URL is invalid: {error}"
        ))
    })?;
    public_discovery_url.set_path(&format!(
        "/sorafs/cid/{content_cid}/{PUBLIC_SERVICE_DISCOVERY_INDEX_DOCUMENT}"
    ));
    public_discovery_url.set_query(None);
    public_discovery_url.set_fragment(None);
    let cid_host_suffix = sorafs_cid_host_suffix_for_public_service(route_host);
    let public_discovery_cid_host_url = format!(
        "https://{content_cid}.{cid_host_suffix}/{PUBLIC_SERVICE_DISCOVERY_INDEX_DOCUMENT}"
    );
    Ok((
        public_discovery_url.to_string(),
        public_discovery_cid_host_url,
    ))
}
#[derive(Debug)]
struct ValidatedPublicServiceDiscoveryArtifactV1 {
    document_bytes: Vec<u8>,
    manifest_digest: ManifestDigest,
    root_cid: ManifestRootCid,
}
fn validate_public_service_discovery_for_bundle(
    world: &impl WorldReadOnly,
    deployment: &SoraServiceDeploymentStateV1,
    bundle: &SoraDeploymentBundleV1,
    discovery: &SoracloudPublicServiceDiscoveryV1,
) -> Result<ValidatedPublicServiceDiscoveryArtifactV1, SoracloudError> {
    bundle.validate_for_admission().map_err(|error| {
        SoracloudError::internal(format!(
            "service `{}` public discovery revision `{}` is not an admitted V1 bundle: {error}",
            deployment.service_name, bundle.service.service_version
        ))
    })?;
    admit_scr_host_bundle(bundle).map_err(|error| {
        SoracloudError::internal(format!(
            "service `{}` public discovery revision `{}` fails authoritative SCR admission: {}",
            deployment.service_name, bundle.service.service_version, error.message
        ))
    })?;
    let route = bundle.service.route.as_ref().ok_or_else(|| {
        SoracloudError::internal(format!(
            "service `{}` has public discovery without an admitted route",
            deployment.service_name
        ))
    })?;
    if bundle.service.execution_plane != SoraServiceExecutionPlaneV1::HttpService
        || bundle.container.runtime != SoraContainerRuntimeV1::Inrou
        || route.visibility != iroha_data_model::soracloud::SoraRouteVisibilityV1::Public
    {
        return Err(SoracloudError::internal(format!(
            "service `{}` authoritative public discovery is not bound to a public HttpService+Inrou revision",
            deployment.service_name
        )));
    }
    let expected_base_url = bundle_base_url(bundle).ok_or_else(|| {
        SoracloudError::internal(format!(
            "service `{}` active route cannot form its authoritative base URL",
            deployment.service_name
        ))
    })?;
    let expected_healthcheck_url = bundle_healthcheck_url(bundle);
    let expected_bundle_hash = Hash::new(Encode::encode(bundle));
    let fields_match = discovery.schema_version == PUBLIC_SERVICE_DISCOVERY_SCHEMA_VERSION_V1
        && discovery.service_name == deployment.service_name.as_ref()
        && bundle.service.service_name == deployment.service_name
        && discovery.service_version == bundle.service.service_version
        && discovery.execution_plane == format!("{:?}", bundle.service.execution_plane)
        && discovery.runtime == format!("{:?}", bundle.container.runtime)
        && discovery.route_host == route.host
        && discovery.path_prefix == route.path_prefix
        && discovery.base_url == expected_base_url
        && discovery.healthcheck_path == bundle.container.lifecycle.healthcheck_path
        && discovery.healthcheck_url == expected_healthcheck_url
        && discovery.service_manifest_hash == bundle.service_manifest_hash()
        && discovery.container_manifest_hash == bundle.container_manifest_hash()
        && discovery.deployment_bundle_hash == expected_bundle_hash;
    if !fields_match {
        return Err(SoracloudError::internal(format!(
            "service `{}` authoritative public discovery record does not bind admitted revision `{}`",
            deployment.service_name, bundle.service.service_version
        )));
    }
    let document_bytes = public_service_discovery_document_bytes(discovery)?;
    if Hash::new(&document_bytes) != discovery.document_hash {
        return Err(SoracloudError::internal(format!(
            "service `{}` authoritative public discovery document hash does not bind its canonical index document",
            deployment.service_name
        )));
    }
    if !is_canonical_public_service_discovery_content_cid(&discovery.content_cid) {
        return Err(SoracloudError::internal(format!(
            "service `{}` authoritative public discovery content CID is not a canonical SoraFS manifest root CID",
            deployment.service_name
        )));
    }
    let artifact_root_cid = public_service_discovery_artifact_root_cid(document_bytes.clone())?;
    let expected_content_cid =
        crate::sorafs::site::encode_content_cid(artifact_root_cid.as_bytes());
    if discovery.content_cid != expected_content_cid {
        return Err(SoracloudError::internal(format!(
            "service `{}` authoritative public discovery content CID does not bind its canonical index document",
            deployment.service_name
        )));
    }
    if !is_canonical_public_service_discovery_manifest_digest(&discovery.manifest_digest_hex) {
        return Err(SoracloudError::internal(format!(
            "service `{}` authoritative public discovery manifest digest is not canonical lowercase 32-byte hexadecimal",
            deployment.service_name
        )));
    }
    let manifest_digest_bytes: [u8; 32] = hex::decode(&discovery.manifest_digest_hex)
        .map_err(|error| {
            SoracloudError::internal(format!(
                "service `{}` authoritative public discovery manifest digest cannot be decoded: {error}",
                deployment.service_name
            ))
        })?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            SoracloudError::internal(format!(
                "service `{}` authoritative public discovery manifest digest decoded to {} bytes instead of 32",
                deployment.service_name,
                bytes.len()
            ))
        })?;
    let manifest_digest = ManifestDigest::new(manifest_digest_bytes);
    let pin = world.pin_manifests().get(&manifest_digest).ok_or_else(|| {
        SoracloudError::internal(format!(
            "service `{}` authoritative public discovery manifest digest is absent from the SoraFS pin registry",
            deployment.service_name
        ))
    })?;
    if pin.digest != manifest_digest || pin.root_cid != artifact_root_cid {
        return Err(SoracloudError::internal(format!(
            "service `{}` authoritative public discovery pin record does not bind its manifest digest and canonical index root CID",
            deployment.service_name
        )));
    }
    let expected_content_length = u64::try_from(document_bytes.len()).map_err(|_| {
        SoracloudError::internal(format!(
            "service `{}` authoritative public discovery document exceeds the V1 u64 content-length domain",
            deployment.service_name
        ))
    })?;
    if pin.content_length != expected_content_length {
        return Err(SoracloudError::internal(format!(
            "service `{}` authoritative public discovery pin record content length does not bind its canonical index document",
            deployment.service_name
        )));
    }
    match pin.status {
        PinStatus::Approved(epoch) if pin.approved_epoch == Some(epoch) => {}
        PinStatus::Approved(epoch) => {
            return Err(SoracloudError::internal(format!(
                "service `{}` authoritative public discovery manifest approval epoch {epoch} does not match its immutable approval history",
                deployment.service_name
            )));
        }
        PinStatus::Pending => {
            return Err(SoracloudError::internal(format!(
                "service `{}` authoritative public discovery manifest is pending governance approval and is not eligible for replication",
                deployment.service_name
            )));
        }
        PinStatus::Retired(epoch) => {
            return Err(SoracloudError::internal(format!(
                "service `{}` authoritative public discovery manifest was retired at epoch {epoch}",
                deployment.service_name
            )));
        }
    }
    let (expected_public_discovery_url, expected_public_discovery_cid_host_url) =
        canonical_public_service_discovery_urls(
            &discovery.base_url,
            &discovery.route_host,
            &discovery.content_cid,
        )?;
    if discovery.public_discovery_url != expected_public_discovery_url
        || discovery.public_discovery_cid_host_url != expected_public_discovery_cid_host_url
    {
        return Err(SoracloudError::internal(format!(
            "service `{}` authoritative public discovery URLs do not bind its canonical content CID and route",
            deployment.service_name
        )));
    }
    Ok(ValidatedPublicServiceDiscoveryArtifactV1 {
        document_bytes,
        manifest_digest,
        root_cid: artifact_root_cid,
    })
}

fn authoritative_public_service_discovery_artifact_for_content_cid(
    world: &impl WorldReadOnly,
    content_cid: &str,
) -> Result<Option<ValidatedPublicServiceDiscoveryArtifactV1>, SoracloudError> {
    let mut authorized: Option<ValidatedPublicServiceDiscoveryArtifactV1> = None;
    for (service_id, deployment) in world.soracloud_service_deployments().iter() {
        if service_id != &deployment.service_name {
            return Err(SoracloudError::internal(format!(
                "authoritative service deployment key `{service_id}` does not bind embedded service name `{}`",
                deployment.service_name
            )));
        }
        let Some(registry) = authoritative_public_service_discovery_registry(deployment)? else {
            continue;
        };
        for (service_version, discovery) in &registry.revisions {
            if discovery.content_cid != content_cid {
                continue;
            }
            let bundle = world
                .soracloud_service_revisions()
                .get(&(service_id.to_string(), service_version.clone()))
                .ok_or_else(|| {
                    SoracloudError::internal(format!(
                        "service `{service_id}` public discovery revision `{service_version}` is missing its admitted bundle"
                    ))
                })?;
            let candidate =
                validate_public_service_discovery_for_bundle(world, deployment, bundle, discovery)?;
            if let Some(existing) = authorized.as_ref() {
                if existing.document_bytes.as_slice() != candidate.document_bytes.as_slice()
                    || existing.manifest_digest != candidate.manifest_digest
                    || existing.root_cid != candidate.root_cid
                {
                    return Err(SoracloudError::internal(format!(
                        "canonical public discovery content CID `{content_cid}` has conflicting authoritative service revision bindings"
                    )));
                }
            } else {
                authorized = Some(candidate);
            }
        }
    }
    Ok(authorized)
}

/// Reconstruct the one authoritative Inrou public-discovery document from committed state.
///
/// This deliberately does not provide a generic SoraFS lookup. The requested CID must be present
/// in the committed Soracloud discovery registry, bind an admitted public HttpService+Inrou
/// revision, and reference an exactly matching approved pin record. Returning the canonical bytes
/// reconstructed from that state keeps public read availability independent of which validator
/// receives the request while exposing no other preseeded or embedded-storage content.
pub fn authoritative_public_discovery_document_for_content_cid(
    world: &impl WorldReadOnly,
    content_cid: &str,
) -> Result<Option<Vec<u8>>, SoracloudError> {
    authoritative_public_service_discovery_artifact_for_content_cid(world, content_cid)
        .map(|artifact| artifact.map(|artifact| artifact.document_bytes))
}
fn bundle_base_url(bundle: &SoraDeploymentBundleV1) -> Option<String> {
    let route = bundle.service.route.as_ref()?;
    let scheme = match route.tls_mode {
        SoraTlsModeV1::Disabled => "http",
        SoraTlsModeV1::Optional | SoraTlsModeV1::Required => "https",
    };
    let mut base_url = reqwest::Url::parse(&format!("{scheme}://{}", route.host)).ok()?;
    let route_root = if route.path_prefix.trim().is_empty() {
        "/".to_owned()
    } else if route.path_prefix.ends_with('/') {
        route.path_prefix.clone()
    } else {
        format!("{}/", route.path_prefix)
    };
    base_url.set_path(&route_root);
    base_url.set_query(None);
    base_url.set_fragment(None);
    Some(base_url.to_string())
}
fn bundle_healthcheck_url(bundle: &SoraDeploymentBundleV1) -> Option<String> {
    let route = bundle.service.route.as_ref()?;
    let healthcheck_path = bundle.container.lifecycle.healthcheck_path.as_ref()?;
    let scheme = match route.tls_mode {
        SoraTlsModeV1::Disabled => "http",
        SoraTlsModeV1::Optional | SoraTlsModeV1::Required => "https",
    };
    let mut url = reqwest::Url::parse(&format!("{scheme}://{}", route.host)).ok()?;
    url.set_path(&join_public_route_paths(
        route.path_prefix.as_str(),
        healthcheck_path,
    ));
    url.set_query(None);
    url.set_fragment(None);
    Some(url.to_string())
}

fn service_secret_status_entry(entry: &SoraServiceSecretEntryV1) -> ServiceSecretStatusEntry {
    ServiceSecretStatusEntry {
        secret_name: entry.secret_name.clone(),
        encryption: entry.envelope.encryption,
        key_id: entry.envelope.key_id.clone(),
        key_version: entry.envelope.key_version.get(),
        commitment: entry.envelope.commitment,
        ciphertext_bytes: u64::try_from(entry.envelope.ciphertext.len()).unwrap_or(u64::MAX),
        last_update_sequence: entry.last_update_sequence,
    }
}

fn authoritative_service_config_status_response(
    app: &SharedAppState,
    service_name: &str,
    config_name: Option<&str>,
) -> Result<ServiceConfigStatusResponse, SoracloudError> {
    let state_view = app.state.view();
    let world = state_view.world();
    let (deployment, _bundle) = authoritative_service_deployment_bundle(world, service_name)?;
    let configs = deployment
        .service_configs
        .values()
        .filter(|entry| config_name.is_none_or(|filter| filter == entry.config_name.as_str()))
        .map(
            |entry| -> Result<ServiceConfigStatusEntry, SoracloudError> {
                let value_json = entry
                    .value_json
                    .try_into_any_norito::<norito::json::Value>()
                    .map_err(|err| {
                        SoracloudError::internal(format!(
                            "failed to decode authoritative service config json: {err}"
                        ))
                    })?;
                Ok::<_, SoracloudError>(ServiceConfigStatusEntry {
                    config_name: entry.config_name.clone(),
                    value_hash: entry.value_hash,
                    value_json,
                    last_update_sequence: entry.last_update_sequence,
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    if config_name.is_some() && configs.is_empty() {
        return Err(SoracloudError::not_found(format!(
            "service config `{}` not found for service `{service_name}`",
            config_name.unwrap_or_default()
        )));
    }
    Ok(ServiceConfigStatusResponse {
        schema_version: CONTROL_PLANE_SCHEMA_VERSION,
        service_name: deployment.service_name.to_string(),
        current_version: deployment.current_service_version,
        config_generation: deployment.config_generation,
        config_entry_count: u32::try_from(configs.len()).unwrap_or(u32::MAX),
        configs,
    })
}
fn authoritative_service_secret_status_response(
    app: &SharedAppState,
    service_name: &str,
    secret_name: Option<&str>,
) -> Result<ServiceSecretStatusResponse, SoracloudError> {
    let state_view = app.state.view();
    let world = state_view.world();
    let (deployment, _bundle) = authoritative_service_deployment_bundle(world, service_name)?;
    let secrets = deployment
        .service_secrets
        .values()
        .filter(|entry| secret_name.is_none_or(|filter| filter == entry.secret_name.as_str()))
        .map(service_secret_status_entry)
        .collect::<Vec<_>>();
    if secret_name.is_some() && secrets.is_empty() {
        return Err(SoracloudError::not_found(format!(
            "service secret `{}` not found for service `{service_name}`",
            secret_name.unwrap_or_default()
        )));
    }
    Ok(ServiceSecretStatusResponse {
        schema_version: CONTROL_PLANE_SCHEMA_VERSION,
        service_name: deployment.service_name.to_string(),
        current_version: deployment.current_service_version,
        secret_generation: deployment.secret_generation,
        secret_entry_count: u32::try_from(secrets.len()).unwrap_or(u32::MAX),
        secrets,
    })
}
fn authoritative_service_public_discovery_response(
    app: &SharedAppState,
    service_name: &str,
    requested_version: Option<&str>,
) -> Result<ServicePublicDiscoveryResponse, SoracloudError> {
    let state_view = app.state.view();
    let world = state_view.world();
    let (deployment, _active_bundle) =
        authoritative_service_deployment_bundle(world, service_name)?;
    let registry =
        authoritative_public_service_discovery_registry(&deployment)?.ok_or_else(|| {
            SoracloudError::not_found(format!(
                "service `{service_name}` has no authoritative public discovery record"
            ))
        })?;
    let current_version = deployment.current_service_version.clone();
    let requested_version = requested_version
        .unwrap_or(current_version.as_str())
        .to_owned();
    let discovery = registry
        .revisions
        .get(requested_version.as_str())
        .cloned()
        .ok_or_else(|| {
            SoracloudError::not_found(format!(
                "service `{service_name}` has no public discovery record for revision `{requested_version}`"
            ))
        })?;
    let bundle = world
        .soracloud_service_revisions()
        .get(&(deployment.service_name.to_string(), requested_version.clone()))
        .cloned()
        .ok_or_else(|| {
            SoracloudError::internal(format!(
                "service `{service_name}` public discovery revision `{requested_version}` is missing its admitted bundle"
            ))
        })?;
    validate_public_service_discovery_for_bundle(world, &deployment, &bundle, &discovery)?;
    Ok(ServicePublicDiscoveryResponse {
        schema_version: PUBLIC_SERVICE_DISCOVERY_SCHEMA_VERSION_V1,
        service_name: deployment.service_name.to_string(),
        current_version,
        requested_version,
        discovery,
    })
}
fn authoritative_agent_runtime_status(status: SoraAgentRuntimeStatusV1) -> AgentRuntimeStatus {
    match status {
        SoraAgentRuntimeStatusV1::Running => AgentRuntimeStatus::Running,
        SoraAgentRuntimeStatusV1::LeaseExpired => AgentRuntimeStatus::LeaseExpired,
    }
}
fn authoritative_agent_runtime_status_in_current_view(
    record: &SoraAgentApartmentRecordV1,
    current_height: u64,
) -> AgentRuntimeStatus {
    authoritative_agent_runtime_status(record.runtime_status_at_current_height(current_height))
}
fn authoritative_agent_mailbox_message_entry(
    message: &SoraAgentMailboxMessageV1,
) -> AgentMailboxMessageEntry {
    AgentMailboxMessageEntry {
        message_id: message.message_id.clone(),
        from_apartment: message.from_apartment.clone(),
        channel: message.channel.clone(),
        payload: message.payload.clone(),
        payload_hash: message.payload_hash,
        enqueued_sequence: message.enqueued_sequence,
    }
}
fn authoritative_agent_allowlist_entry(
    rule: &SoraAgentArtifactAllowRuleV1,
) -> AgentAutonomyAllowlistEntry {
    AgentAutonomyAllowlistEntry {
        artifact_hash: rule.artifact_hash.clone(),
        provenance_hash: rule.provenance_hash.clone(),
        added_sequence: rule.added_sequence,
    }
}
fn authoritative_agent_runtime_receipt_record(
    receipt: &SoraRuntimeReceiptV1,
) -> AgentRuntimeReceiptRecord {
    AgentRuntimeReceiptRecord {
        receipt_id: receipt.receipt_id,
        service_name: receipt.service_name.to_string(),
        service_version: receipt.service_version.clone(),
        handler_name: receipt.handler_name.to_string(),
        handler_class: receipt.handler_class,
        request_commitment: receipt.request_commitment,
        result_commitment: receipt.result_commitment,
        certified_by: receipt.certified_by,
        emitted_sequence: receipt.emitted_sequence,
        execution_host: receipt.execution_host.clone(),
        mailbox_message_id: receipt.mailbox_message_id,
        journal_artifact_hash: receipt.journal_artifact_hash,
        checkpoint_artifact_hash: receipt.checkpoint_artifact_hash,
    }
}
fn authoritative_agent_execution_audit_record(
    event: &SoraAgentApartmentAuditEventV1,
) -> Result<AgentAutonomyExecutionAuditRecord, SoracloudError> {
    let succeeded = event.succeeded.ok_or_else(|| {
        SoracloudError::internal(format!(
            "authoritative agent execution audit event {} is missing `succeeded`",
            event.sequence
        ))
    })?;
    let result_commitment = event.result_commitment.ok_or_else(|| {
        SoracloudError::internal(format!(
            "authoritative agent execution audit event {} is missing `result_commitment`",
            event.sequence
        ))
    })?;
    Ok(AgentAutonomyExecutionAuditRecord {
        sequence: event.sequence,
        succeeded,
        result_commitment,
        service_name: event.service_name.clone(),
        service_version: event.service_version.clone(),
        handler_name: event.handler_name.clone(),
        runtime_receipt_id: event.runtime_receipt_id,
        journal_artifact_hash: event.journal_artifact_hash,
        checkpoint_artifact_hash: event.checkpoint_artifact_hash,
        reason: event.reason.clone(),
    })
}
fn authoritative_agent_runtime_receipt_for_run(
    world: &impl WorldReadOnly,
    run: &SoraAgentAutonomyRunRecordV1,
) -> Option<AgentRuntimeReceiptRecord> {
    world
        .soracloud_runtime_receipts()
        .iter()
        .filter_map(|(_receipt_id, receipt)| {
            (receipt.request_commitment == run.request_commitment).then_some(receipt)
        })
        .max_by(|left, right| {
            left.emitted_sequence
                .cmp(&right.emitted_sequence)
                .then_with(|| left.receipt_id.cmp(&right.receipt_id))
        })
        .map(authoritative_agent_runtime_receipt_record)
}
fn authoritative_agent_execution_audit_for_run(
    world: &impl WorldReadOnly,
    apartment_name: &str,
    run: &SoraAgentAutonomyRunRecordV1,
) -> Result<Option<AgentAutonomyExecutionAuditRecord>, SoracloudError> {
    let mut latest = None;
    for (sequence, event) in world.soracloud_agent_apartment_audit_events().iter() {
        if event.action != SoraAgentApartmentActionV1::AutonomyRunExecuted
            || event.apartment_name.as_ref() != apartment_name
            || event.run_id.as_deref() != Some(run.run_id.as_str())
        {
            continue;
        }
        if *sequence != event.sequence {
            return Err(SoracloudError::internal(format!(
                "authoritative agent execution audit key {sequence} does not bind event sequence {}",
                event.sequence
            )));
        }
        event.validate().map_err(|error| {
            SoracloudError::internal(format!(
                "authoritative agent execution audit event {sequence} is invalid: {error}"
            ))
        })?;
        if latest.is_none_or(|current: &SoraAgentApartmentAuditEventV1| {
            event.sequence > current.sequence
        }) {
            latest = Some(event);
        }
    }
    latest
        .map(authoritative_agent_execution_audit_record)
        .transpose()
}
fn authoritative_agent_run_record(
    world: &impl WorldReadOnly,
    apartment_name: &str,
    record: &SoraAgentAutonomyRunRecordV1,
) -> Result<AgentAutonomyRunRecord, SoracloudError> {
    Ok(AgentAutonomyRunRecord {
        run_id: record.run_id.clone(),
        artifact_hash: record.artifact_hash.clone(),
        provenance_hash: record.provenance_hash.clone(),
        budget_units: record.budget_units,
        run_label: record.run_label.clone(),
        workflow_input_json: record.workflow_input_json.clone(),
        approved_sequence: record.approved_sequence,
        authoritative_runtime_receipt: authoritative_agent_runtime_receipt_for_run(world, record),
        authoritative_execution_audit: authoritative_agent_execution_audit_for_run(
            world,
            apartment_name,
            record,
        )?,
    })
}
fn authoritative_agent_status_entry(
    apartment_name: &str,
    record: &SoraAgentApartmentRecordV1,
    current_height: u64,
) -> AgentApartmentStatusEntry {
    AgentApartmentStatusEntry {
        apartment_name: apartment_name.to_owned(),
        manifest_hash: record.manifest_hash,
        status: authoritative_agent_runtime_status_in_current_view(record, current_height),
        lease_started_height: record.lease_started_height,
        lease_expires_height: record.lease_expires_height,
        lease_remaining_blocks: record.lease_expires_height.saturating_sub(current_height),
        restart_count: record.restart_count,
        state_quota_bytes: record.manifest.state_quota_bytes.get(),
        tool_capability_count: u32::try_from(record.manifest.tool_capabilities.len())
            .unwrap_or(u32::MAX),
        policy_capability_count: u32::try_from(record.manifest.policy_capabilities.len())
            .unwrap_or(u32::MAX),
        revoked_policy_capability_count: u32::try_from(record.revoked_policy_capabilities.len())
            .unwrap_or(u32::MAX),
        pending_wallet_request_count: u32::try_from(record.pending_wallet_requests.len())
            .unwrap_or(u32::MAX),
        pending_mailbox_message_count: u32::try_from(record.mailbox_queue.len())
            .unwrap_or(u32::MAX),
        autonomy_budget_ceiling_units: record.autonomy_budget_ceiling_units,
        autonomy_budget_remaining_units: record.autonomy_budget_remaining_units,
        artifact_allowlist_count: u32::try_from(record.artifact_allowlist.len())
            .unwrap_or(u32::MAX),
        autonomy_run_count: u32::try_from(record.autonomy_run_history.len()).unwrap_or(u32::MAX),
        process_generation: record.process_generation,
        process_started_sequence: record.process_started_sequence,
        last_active_sequence: record.last_active_sequence,
        last_checkpoint_sequence: record.last_checkpoint_sequence,
        checkpoint_count: record.checkpoint_count,
        persistent_state_total_bytes: record.persistent_state.total_bytes,
        persistent_state_key_count: u32::try_from(record.persistent_state.key_sizes.len())
            .unwrap_or(u32::MAX),
        spend_limit_count: u32::try_from(record.manifest.spend_limits.len()).unwrap_or(u32::MAX),
        upgrade_policy: record.manifest.upgrade_policy.clone(),
        last_restart_sequence: record.last_restart_sequence,
        last_restart_reason: record.last_restart_reason.clone(),
    }
}
fn authoritative_agent_status_response(
    app: &SharedAppState,
    apartment_name: Option<&str>,
) -> Result<AgentStatusResponse, SoracloudError> {
    let apartment_filter = apartment_name.map(parse_agent_apartment_name).transpose()?;
    let state_view = app.state.view();
    let world = state_view.world();
    let current_height = u64::try_from(state_view.height()).unwrap_or(u64::MAX);
    let mut apartments = world
        .soracloud_agent_apartments()
        .iter()
        .filter(|(apartment_name, _record)| {
            apartment_filter
                .as_ref()
                .is_none_or(|filter| filter.as_str() == apartment_name.as_str())
        })
        .map(|(apartment_name, record)| {
            authoritative_agent_status_entry(apartment_name, record, current_height)
        })
        .collect::<Vec<_>>();
    apartments.sort_by(|left, right| left.apartment_name.cmp(&right.apartment_name));
    Ok(AgentStatusResponse {
        schema_version: CONTROL_PLANE_SCHEMA_VERSION,
        apartment_count: u32::try_from(apartments.len()).unwrap_or(u32::MAX),
        event_count: u32::try_from(
            world
                .soracloud_agent_apartment_audit_events()
                .iter()
                .count(),
        )
        .unwrap_or(u32::MAX),
        apartments,
    })
}
fn authoritative_agent_mailbox_status_response(
    app: &SharedAppState,
    apartment_name: &str,
) -> Result<AgentMailboxStatusResponse, SoracloudError> {
    let apartment_name = parse_agent_apartment_name(apartment_name)?;
    let state_view = app.state.view();
    let world = state_view.world();
    let current_height = u64::try_from(state_view.height()).unwrap_or(u64::MAX);
    let record = world
        .soracloud_agent_apartments()
        .get(&apartment_name)
        .cloned()
        .ok_or_else(|| {
            SoracloudError::not_found(format!(
                "apartment `{apartment_name}` not found in authoritative Soracloud state"
            ))
        })?;
    let messages = record
        .mailbox_queue
        .iter()
        .map(authoritative_agent_mailbox_message_entry)
        .collect::<Vec<_>>();
    Ok(AgentMailboxStatusResponse {
        schema_version: CONTROL_PLANE_SCHEMA_VERSION,
        apartment_name,
        status: authoritative_agent_runtime_status_in_current_view(&record, current_height),
        pending_message_count: u32::try_from(messages.len()).unwrap_or(u32::MAX),
        event_count: u32::try_from(
            world
                .soracloud_agent_apartment_audit_events()
                .iter()
                .count(),
        )
        .unwrap_or(u32::MAX),
        messages,
    })
}
fn authoritative_agent_autonomy_status_response(
    app: &SharedAppState,
    apartment_name: &str,
) -> Result<AgentAutonomyStatusResponse, SoracloudError> {
    let apartment_name = parse_agent_apartment_name(apartment_name)?;
    let apartment_name_for_runs = apartment_name.clone();
    let state_view = app.state.view();
    let world = state_view.world();
    let sequence = authoritative_soracloud_sequence(world);
    let current_height = u64::try_from(state_view.height()).unwrap_or(u64::MAX);
    let record = world
        .soracloud_agent_apartments()
        .get(&apartment_name)
        .cloned()
        .ok_or_else(|| {
            SoracloudError::not_found(format!(
                "apartment `{apartment_name}` not found in authoritative Soracloud state"
            ))
        })?;
    Ok(AgentAutonomyStatusResponse {
        apartment_name,
        sequence,
        status: authoritative_agent_runtime_status_in_current_view(&record, current_height),
        lease_expires_height: record.lease_expires_height,
        lease_remaining_blocks: record.lease_expires_height.saturating_sub(current_height),
        manifest_hash: record.manifest_hash,
        revoked_policy_capability_count: u32::try_from(record.revoked_policy_capabilities.len())
            .unwrap_or(u32::MAX),
        budget_ceiling_units: record.autonomy_budget_ceiling_units,
        budget_remaining_units: record.autonomy_budget_remaining_units,
        allowlist_count: u32::try_from(record.artifact_allowlist.len()).unwrap_or(u32::MAX),
        run_count: u32::try_from(record.autonomy_run_history.len()).unwrap_or(u32::MAX),
        process_generation: record.process_generation,
        process_started_sequence: record.process_started_sequence,
        last_active_sequence: record.last_active_sequence,
        last_checkpoint_sequence: record.last_checkpoint_sequence,
        checkpoint_count: record.checkpoint_count,
        persistent_state_total_bytes: record.persistent_state.total_bytes,
        persistent_state_key_count: u32::try_from(record.persistent_state.key_sizes.len())
            .unwrap_or(u32::MAX),
        allowlist: record
            .artifact_allowlist
            .values()
            .map(authoritative_agent_allowlist_entry)
            .collect(),
        recent_runs: record
            .autonomy_run_history
            .iter()
            .rev()
            .take(AGENT_AUTONOMY_RECENT_RUN_LIMIT)
            .map(|run| authoritative_agent_run_record(world, apartment_name_for_runs.as_ref(), run))
            .collect::<Result<Vec<_>, _>>()?,
    })
}
fn authoritative_ciphertext_query_response(
    app: &SharedAppState,
    request: SignedCiphertextQueryRequest,
) -> Result<CiphertextQueryResponse, SoracloudError> {
    verify_ciphertext_query_signature(&request)?;
    request.query.validate().map_err(|err| {
        SoracloudError::bad_request(format!("ciphertext query failed validation: {err}"))
    })?;
    let state_view = app.state.view();
    let world = state_view.world();
    let service_name = request.query.service_name.clone();
    let binding_name = request.query.binding_name.clone();
    let signer = request.provenance.signer.to_string();
    let query_hash = Hash::new(Encode::encode(&request.query));
    let limit = usize::from(request.query.max_results.get());
    let deployment = world
        .soracloud_service_deployments()
        .get(&service_name)
        .cloned()
        .ok_or_else(|| {
            SoracloudError::not_found(format!(
                "service `{service_name}` not found in authoritative Soracloud state"
            ))
        })?;
    let bundle = world
        .soracloud_service_revisions()
        .get(&(
            service_name.as_ref().to_owned(),
            deployment.current_service_version.clone(),
        ))
        .cloned()
        .ok_or_else(|| {
            SoracloudError::conflict(format!(
                "service `{service_name}` active revision `{}` is missing from authoritative state",
                deployment.current_service_version
            ))
        })?;
    let binding = bundle
        .service
        .state_bindings
        .iter()
        .find(|binding| binding.binding_name == binding_name)
        .ok_or_else(|| {
            SoracloudError::not_found(format!(
                "binding `{binding_name}` is not declared for service `{service_name}`"
            ))
        })?;
    if binding.encryption == SoraStateEncryptionV1::Plaintext {
        return Err(SoracloudError::conflict(format!(
            "binding `{binding_name}` is plaintext; ciphertext query interface is not applicable"
        )));
    }
    if !request
        .query
        .state_key_prefix
        .starts_with(&binding.key_prefix)
    {
        return Err(SoracloudError::conflict(format!(
            "query prefix `{}` is outside binding prefix `{}`",
            request.query.state_key_prefix, binding.key_prefix
        )));
    }
    let audit_log = authoritative_audit_log(app)?;
    let served_sequence = audit_log
        .iter()
        .map(|event| event.sequence)
        .max()
        .unwrap_or(0);
    let anchor_hash = audit_anchor_hash(&audit_log, served_sequence);
    let mut rows = Vec::new();
    let mut truncated = false;
    for ((stored_service, stored_binding, state_key), entry) in
        world.soracloud_service_state_entries().iter()
    {
        if stored_service != service_name.as_ref() || stored_binding != binding_name.as_ref() {
            continue;
        }
        if entry.encryption == SoraStateEncryptionV1::Plaintext {
            continue;
        }
        if !state_key.starts_with(&request.query.state_key_prefix) {
            continue;
        }
        if rows.len() >= limit {
            truncated = true;
            break;
        }
        let runtime_record = CiphertextRuntimeRecord {
            encryption: entry.encryption,
            payload_bytes: entry.payload_bytes.get(),
            commitment: entry.payload_commitment,
            last_update_sequence: entry.last_update_sequence,
            governance_tx_hash: entry.governance_tx_hash,
            source_action: audit_action_to_control_plane_action(entry.source_action),
        };
        let proof = if request.query.include_proof {
            Some(build_ciphertext_inclusion_proof(
                &audit_log,
                service_name.as_ref(),
                binding_name.as_ref(),
                state_key,
                &runtime_record,
                served_sequence,
                anchor_hash,
            ))
        } else {
            None
        };
        rows.push(CiphertextQueryResultItemV1 {
            binding_name: binding_name.clone(),
            state_key: match request.query.metadata_level {
                CiphertextQueryMetadataLevelV1::Minimal => None,
                CiphertextQueryMetadataLevelV1::Standard => Some(state_key.clone()),
            },
            state_key_digest: derive_state_key_digest(
                service_name.as_ref(),
                binding_name.as_ref(),
                state_key,
            ),
            payload_bytes: entry.payload_bytes,
            ciphertext_commitment: entry.payload_commitment,
            encryption: entry.encryption,
            last_update_sequence: entry.last_update_sequence,
            governance_tx_hash: entry.governance_tx_hash,
            proof,
        });
    }
    let response = CiphertextQueryResponseV1 {
        schema_version: CIPHERTEXT_QUERY_RESPONSE_VERSION_V1,
        query_hash,
        service_name,
        binding_name,
        metadata_level: request.query.metadata_level,
        served_sequence,
        result_count: u16::try_from(rows.len()).unwrap_or(u16::MAX),
        truncated,
        results: rows,
    };
    response.validate().map_err(|err| {
        SoracloudError::internal(format!(
            "ciphertext query response validation failed unexpectedly: {err}"
        ))
    })?;
    Ok(CiphertextQueryResponse {
        action: SoracloudAction::CiphertextQuery,
        response,
        signed_by: signer,
    })
}
fn authoritative_health_compliance_report(
    app: &SharedAppState,
    service_name: Option<&str>,
    jurisdiction_tag: Option<&str>,
    limit: usize,
) -> Result<HealthComplianceReportResponse, SoracloudError> {
    let service_name = service_name
        .map(|value| parse_service_name(value).map(|name| name.to_string()))
        .transpose()?;
    let jurisdiction_tag = jurisdiction_tag
        .map(|literal| parse_exact_nonempty_text("jurisdiction_tag", literal))
        .transpose()?;
    let limit = parse_exact_query_limit("limit", limit, MAX_HEALTH_COMPLIANCE_LIMIT)?;
    let audit_log = authoritative_audit_log(app)?;
    let generated_at_sequence = audit_log
        .iter()
        .map(|event| event.sequence)
        .max()
        .unwrap_or(0);
    let access_events = audit_log
        .iter()
        .filter(|event| event.action == SoracloudAction::DecryptionRequest)
        .filter(|event| {
            service_name
                .as_deref()
                .is_none_or(|filter| filter == event.service_name.as_str())
        })
        .filter(|event| {
            jurisdiction_tag
                .as_deref()
                .is_none_or(|filter| event.jurisdiction_tag.as_deref() == Some(filter))
        })
        .collect::<Vec<_>>();
    for event in &access_events {
        for (field, present) in [
            ("binding_name", event.binding_name.is_some()),
            ("state_key", event.state_key.is_some()),
            ("policy_name", event.policy_name.is_some()),
            ("policy_snapshot_hash", event.policy_snapshot_hash.is_some()),
            ("jurisdiction_tag", event.jurisdiction_tag.is_some()),
            ("break_glass", event.break_glass.is_some()),
            ("governance_tx_hash", event.governance_tx_hash.is_some()),
        ] {
            if !present {
                return Err(SoracloudError::internal(format!(
                    "authoritative decryption audit event {} is missing `{field}`",
                    event.sequence
                )));
            }
        }
    }
    let total_access_events = u32::try_from(access_events.len()).map_err(|_| {
        SoracloudError::internal(
            "authoritative decryption audit count exceeds the V1 u32 response range",
        )
    })?;
    let break_glass_events = u32::try_from(
        access_events
            .iter()
            .filter(|event| event.break_glass == Some(true))
            .count(),
    )
    .map_err(|_| {
        SoracloudError::internal(
            "authoritative break-glass audit count exceeds the V1 u32 response range",
        )
    })?;
    let non_break_glass_events = total_access_events
        .checked_sub(break_glass_events)
        .ok_or_else(|| {
            SoracloudError::internal(
                "authoritative break-glass audit count exceeds total access events",
            )
        })?;
    let consent_evidence_present_events = u32::try_from(
        access_events
            .iter()
            .filter(|event| event.consent_evidence_hash.is_some())
            .count(),
    )
    .map_err(|_| {
        SoracloudError::internal(
            "authoritative consent-evidence audit count exceeds the V1 u32 response range",
        )
    })?;
    let consent_evidence_coverage_bps = if total_access_events == 0 {
        0
    } else {
        let numerator = u128::from(consent_evidence_present_events) * 10_000;
        let denominator = u128::from(total_access_events);
        u16::try_from(numerator / denominator).map_err(|_| {
            SoracloudError::internal(
                "authoritative consent-evidence coverage exceeds the V1 u16 response range",
            )
        })?
    };
    let mut recent_access_events = Vec::with_capacity(access_events.len().min(limit));
    for event in access_events.iter().rev().take(limit) {
        recent_access_events.push(HealthAccessAuditEntry {
            sequence: event.sequence,
            service_name: event.service_name.clone(),
            binding_name: event.binding_name.clone().ok_or_else(|| {
                SoracloudError::internal("validated decryption event lost binding_name")
            })?,
            state_key: event.state_key.clone().ok_or_else(|| {
                SoracloudError::internal("validated decryption event lost state_key")
            })?,
            policy_name: event.policy_name.clone().ok_or_else(|| {
                SoracloudError::internal("validated decryption event lost policy_name")
            })?,
            jurisdiction_tag: event.jurisdiction_tag.clone().ok_or_else(|| {
                SoracloudError::internal("validated decryption event lost jurisdiction_tag")
            })?,
            consent_evidence_hash: event.consent_evidence_hash,
            break_glass: event.break_glass.ok_or_else(|| {
                SoracloudError::internal("validated decryption event lost break_glass")
            })?,
            break_glass_reason: event.break_glass_reason.clone(),
            governance_tx_hash: event.governance_tx_hash.ok_or_else(|| {
                SoracloudError::internal("validated decryption event lost governance_tx_hash")
            })?,
            signed_by: event.signed_by.clone(),
        });
    }
    let mut jurisdiction_stats_acc: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    for event in &access_events {
        let tag = event.jurisdiction_tag.clone().ok_or_else(|| {
            SoracloudError::internal("validated decryption event lost jurisdiction_tag")
        })?;
        let entry = jurisdiction_stats_acc.entry(tag).or_insert((0, 0));
        entry.0 = entry.0.checked_add(1).ok_or_else(|| {
            SoracloudError::internal(
                "authoritative jurisdiction access count exceeds the V1 u32 response range",
            )
        })?;
        if event.break_glass == Some(true) {
            entry.1 = entry.1.checked_add(1).ok_or_else(|| {
                SoracloudError::internal(
                    "authoritative jurisdiction break-glass count exceeds the V1 u32 response range",
                )
            })?;
        }
    }
    let jurisdiction_stats = jurisdiction_stats_acc
        .into_iter()
        .map(
            |(jurisdiction_tag, (access_event_count, break_glass_event_count))| {
                HealthJurisdictionStat {
                    jurisdiction_tag,
                    access_event_count,
                    break_glass_event_count,
                }
            },
        )
        .collect::<Vec<_>>();
    let mut policy_history_acc: BTreeMap<(String, String, String), HealthPolicyDiffEntry> =
        BTreeMap::new();
    for event in &access_events {
        let policy_name = event.policy_name.clone().ok_or_else(|| {
            SoracloudError::internal("validated decryption event lost policy_name")
        })?;
        let policy_snapshot_hash = event.policy_snapshot_hash.ok_or_else(|| {
            SoracloudError::internal("validated decryption event lost policy_snapshot_hash")
        })?;
        let jurisdiction = event.jurisdiction_tag.clone().ok_or_else(|| {
            SoracloudError::internal("validated decryption event lost jurisdiction_tag")
        })?;
        let key = (
            policy_name.clone(),
            jurisdiction.clone(),
            policy_snapshot_hash.to_string(),
        );
        let entry = policy_history_acc
            .entry(key)
            .or_insert(HealthPolicyDiffEntry {
                policy_name,
                jurisdiction_tag: jurisdiction,
                policy_snapshot_hash,
                first_seen_sequence: event.sequence,
                last_seen_sequence: event.sequence,
                event_count: 0,
            });
        entry.first_seen_sequence = entry.first_seen_sequence.min(event.sequence);
        entry.last_seen_sequence = entry.last_seen_sequence.max(event.sequence);
        entry.event_count = entry.event_count.checked_add(1).ok_or_else(|| {
            SoracloudError::internal(
                "authoritative policy history count exceeds the V1 u32 response range",
            )
        })?;
    }
    let mut policy_diff_history = policy_history_acc.into_values().collect::<Vec<_>>();
    policy_diff_history.sort_by(|left, right| {
        right
            .last_seen_sequence
            .cmp(&left.last_seen_sequence)
            .then_with(|| left.policy_name.cmp(&right.policy_name))
            .then_with(|| left.jurisdiction_tag.cmp(&right.jurisdiction_tag))
    });
    if policy_diff_history.len() > limit {
        policy_diff_history.truncate(limit);
    }
    let state_view = app.state.view();
    let world = state_view.world();
    let mut data_flow_services = BTreeSet::new();
    if let Some(service_name) = service_name.clone() {
        data_flow_services.insert(service_name);
    } else {
        for event in &access_events {
            data_flow_services.insert(event.service_name.clone());
        }
    }
    let mut data_flow_attestations = Vec::new();
    for service_name in data_flow_services {
        let service_id = service_name.parse::<Name>().map_err(|error| {
            SoracloudError::internal(format!(
                "authoritative health audit references invalid service `{service_name}`: {error}"
            ))
        })?;
        let deployment = world
            .soracloud_service_deployments()
            .get(&service_id)
            .ok_or_else(|| {
                SoracloudError::internal(format!(
                    "authoritative health audit references missing service `{service_name}`"
                ))
            })?;
        let bundle = world
            .soracloud_service_revisions()
            .get(&(
                service_name.clone(),
                deployment.current_service_version.clone(),
            ))
            .ok_or_else(|| {
                SoracloudError::internal(format!(
                    "authoritative health audit service `{service_name}` is missing active revision `{}`",
                    deployment.current_service_version
                ))
            })?;
        if deployment.service_name != service_id
            || bundle.service.service_name != service_id
            || bundle.service.service_version != deployment.current_service_version
            || deployment.current_service_manifest_hash != bundle.service_manifest_hash()
            || deployment.current_container_manifest_hash != bundle.container_manifest_hash()
        {
            return Err(SoracloudError::internal(format!(
                "authoritative health audit service `{service_name}` does not bind its active revision `{}`",
                deployment.current_service_version
            )));
        }
        bundle.validate_for_admission().map_err(|error| {
            SoracloudError::internal(format!(
                "authoritative health audit service `{service_name}` has an invalid active revision: {error}"
            ))
        })?;
        for binding in &bundle.service.state_bindings {
            if binding.encryption == SoraStateEncryptionV1::Plaintext {
                continue;
            }
            data_flow_attestations.push(HealthDataFlowAttestation {
                service_name: service_name.clone(),
                current_version: deployment.current_service_version.clone(),
                binding_name: binding.binding_name.to_string(),
                key_prefix: binding.key_prefix.clone(),
                encryption: binding.encryption,
                mutability: binding.mutability,
            });
        }
    }
    Ok(HealthComplianceReportResponse {
        schema_version: HEALTH_COMPLIANCE_REPORT_VERSION_V1,
        service_name,
        jurisdiction_tag,
        generated_at_sequence,
        total_access_events,
        break_glass_events,
        non_break_glass_events,
        consent_evidence_present_events,
        consent_evidence_coverage_bps,
        recent_access_events,
        jurisdiction_stats,
        data_flow_attestations,
        policy_diff_history,
    })
}
fn deployment_bundle_to_control_plane_revision(
    world: &impl WorldReadOnly,
    deployment: &SoraServiceDeploymentStateV1,
    bundle: &SoraDeploymentBundleV1,
    latest_audit: Option<&SoraServiceAuditEventV1>,
    public_discovery: Option<&SoracloudPublicServiceDiscoveryV1>,
) -> Result<ControlPlaneServiceRevision, SoracloudError> {
    if deployment.service_name != bundle.service.service_name
        || deployment.current_service_version != bundle.service.service_version
        || deployment.current_service_manifest_hash != bundle.service_manifest_hash()
        || deployment.current_container_manifest_hash != bundle.container_manifest_hash()
    {
        return Err(SoracloudError::internal(format!(
            "service `{}` deployment state does not bind active revision `{}`",
            deployment.service_name, deployment.current_service_version
        )));
    }
    bundle.validate_for_admission().map_err(|error| {
        SoracloudError::internal(format!(
            "service `{}` active revision `{}` is not an admitted V1 bundle: {error}",
            deployment.service_name, deployment.current_service_version
        ))
    })?;
    let host_admission = admit_scr_host_bundle(bundle).map_err(|error| {
        SoracloudError::internal(format!(
            "service `{}` active revision `{}` fails authoritative SCR admission: {}",
            deployment.service_name, deployment.current_service_version, error.message
        ))
    })?;
    let latest_audit = latest_audit.ok_or_else(|| {
        SoracloudError::internal(format!(
            "service `{}` active revision `{}` has no authoritative lifecycle audit event",
            deployment.service_name, deployment.current_service_version
        ))
    })?;
    latest_audit.validate().map_err(|error| {
        SoracloudError::internal(format!(
            "service `{}` active revision `{}` lifecycle audit event is invalid: {error}",
            deployment.service_name, deployment.current_service_version
        ))
    })?;
    if latest_audit.action == SoraServiceLifecycleActionV1::Rollout
        && (latest_audit.governance_tx_hash.is_none() || latest_audit.rollout_state.is_none())
    {
        return Err(SoracloudError::internal(format!(
            "service `{}` active revision `{}` rollout audit event is missing governance or rollout identity",
            deployment.service_name, deployment.current_service_version
        )));
    }
    if !matches!(
        latest_audit.action,
        SoraServiceLifecycleActionV1::Deploy
            | SoraServiceLifecycleActionV1::Upgrade
            | SoraServiceLifecycleActionV1::Rollout
            | SoraServiceLifecycleActionV1::Rollback
    ) || latest_audit.service_name != deployment.service_name
        || latest_audit.to_version != deployment.current_service_version
        || latest_audit.service_manifest_hash != bundle.service_manifest_hash()
        || latest_audit.container_manifest_hash != bundle.container_manifest_hash()
    {
        return Err(SoracloudError::internal(format!(
            "service `{}` active revision `{}` lifecycle audit event does not bind the admitted bundle",
            deployment.service_name, deployment.current_service_version
        )));
    }
    if let Some(public_discovery) = public_discovery {
        validate_public_service_discovery_for_bundle(world, deployment, bundle, public_discovery)?;
    }
    let route = bundle.service.route.as_ref();
    let state_binding_count = u32::try_from(bundle.service.state_bindings.len()).map_err(|_| {
        SoracloudError::internal(format!(
            "service `{}` active revision `{}` state-binding count exceeds the V1 u32 response range",
            deployment.service_name, deployment.current_service_version
        ))
    })?;
    Ok(ControlPlaneServiceRevision {
        sequence: latest_audit.sequence,
        action: audit_action_to_control_plane_action(latest_audit.action),
        service_version: bundle.service.service_version.clone(),
        service_manifest_hash: bundle.service_manifest_hash(),
        container_manifest_hash: bundle.container_manifest_hash(),
        replicas: bundle.service.replicas.get(),
        execution_plane: bundle.service.execution_plane,
        route_host: route.map(|route| route.host.clone()),
        route_path_prefix: route.map(|route| route.path_prefix.clone()),
        route_service_port: route.map(|route| route.service_port.get()),
        route_visibility: route.map(|route| format!("{:?}", route.visibility)),
        route_tls_mode: route.map(|route| format!("{:?}", route.tls_mode)),
        base_url: bundle_base_url(bundle),
        healthcheck_url: bundle_healthcheck_url(bundle),
        public_discovery_content_cid: public_discovery.map(|entry| entry.content_cid.clone()),
        public_discovery_url: public_discovery.map(|entry| entry.public_discovery_url.clone()),
        public_discovery_cid_host_url: public_discovery
            .map(|entry| entry.public_discovery_cid_host_url.clone()),
        state_binding_count,
        state_bindings: bundle.service.state_bindings.clone(),
        lease_volumes: bundle.service.lease_volumes.clone(),
        allow_model_inference: host_admission.allow_model_inference,
        allow_model_training: host_admission.allow_model_training,
        runtime: host_admission.runtime,
        allow_state_writes: host_admission.allow_state_writes,
        network: host_admission.network,
        cpu_millis: host_admission.cpu_millis,
        memory_bytes: host_admission.memory_bytes,
        ephemeral_storage_bytes: host_admission.ephemeral_storage_bytes,
        max_open_files_per_process: host_admission.max_open_files_per_process,
        max_tasks: host_admission.max_tasks,
        start_grace_secs: host_admission.start_grace_secs,
        stop_grace_secs: host_admission.stop_grace_secs,
        healthcheck_path: host_admission.healthcheck_path,
        required_config_names: bundle.container.required_config_names.clone(),
        required_secret_names: bundle.container.required_secret_names.clone(),
        config_exports: bundle.container.config_exports.clone(),
        sandbox_profile_hash: host_admission.sandbox_profile_hash,
        process_generation: deployment.process_generation,
        process_started_sequence: deployment.process_started_sequence,
        signed_by: latest_audit.signer.to_string(),
    })
}
#[cfg(test)]
pub fn resolve_public_local_read_route(
    app: &SharedAppState,
    host: &str,
    request_path: &str,
) -> Option<LocalReadRouteMatch> {
    let normalized_host = normalize_public_route_host(host);
    if normalized_host.is_empty() {
        return None;
    }
    let normalized_path = normalize_public_route_path(request_path);
    let state_view = app.state.view();
    let world = state_view.world();
    let mut best_match: Option<(usize, LocalReadRouteMatch)> = None;
    for (service_id, deployment) in world.soracloud_service_deployments().iter() {
        let service_name = service_id.to_string();
        let Some(bundle) = world.soracloud_service_revisions().get(&(
            service_name.clone(),
            deployment.current_service_version.clone(),
        )) else {
            continue;
        };
        if bundle.service.execution_plane != SoraServiceExecutionPlaneV1::DeterministicService
            || !bundle.container.runtime.is_deterministic()
        {
            continue;
        }
        let Some(route) = bundle.service.route.as_ref() else {
            continue;
        };
        if route.visibility != iroha_data_model::soracloud::SoraRouteVisibilityV1::Public {
            continue;
        }
        if !route.host.eq_ignore_ascii_case(normalized_host) {
            continue;
        }
        for handler in &bundle.service.handlers {
            let handler_class = match handler.class {
                iroha_data_model::soracloud::SoraServiceHandlerClassV1::Asset => {
                    SoracloudLocalReadKind::Asset
                }
                iroha_data_model::soracloud::SoraServiceHandlerClassV1::Query => {
                    SoracloudLocalReadKind::Query
                }
                iroha_data_model::soracloud::SoraServiceHandlerClassV1::Update => {
                    continue;
                }
            };
            let full_route = join_public_route_paths(
                route.path_prefix.as_str(),
                handler.route_path.as_deref().unwrap_or("/"),
            );
            let Some(handler_path) = split_public_handler_path(normalized_path, &full_route) else {
                continue;
            };
            let route_len = full_route.len();
            let route_match = LocalReadRouteMatch {
                service_name: service_name.clone(),
                service_version: deployment.current_service_version.clone(),
                handler_name: handler.handler_name.to_string(),
                handler_class,
                handler_path,
            };
            let replace = best_match.as_ref().is_none_or(|(best_len, best)| {
                route_len > *best_len
                    || (route_len == *best_len
                        && (
                            route_match.service_name.as_str(),
                            route_match.service_version.as_str(),
                            route_match.handler_name.as_str(),
                        ) < (
                            best.service_name.as_str(),
                            best.service_version.as_str(),
                            best.handler_name.as_str(),
                        ))
            });
            if replace {
                best_match = Some((route_len, route_match));
            }
        }
    }
    best_match.map(|(_route_len, route_match)| route_match)
}
fn public_method_supports_handler(
    request_method: &str,
    handler_class: iroha_data_model::soracloud::SoraServiceHandlerClassV1,
) -> bool {
    match request_method {
        "GET" | "HEAD" => matches!(
            handler_class,
            iroha_data_model::soracloud::SoraServiceHandlerClassV1::Asset
                | iroha_data_model::soracloud::SoraServiceHandlerClassV1::Query
        ),
        "POST" | "PUT" | "PATCH" | "DELETE" => {
            handler_class == iroha_data_model::soracloud::SoraServiceHandlerClassV1::Update
        }
        _ => false,
    }
}
pub fn resolve_public_route(
    app: &SharedAppState,
    host: &str,
    request_method: &str,
    request_path: &str,
) -> Option<PublicRouteMatch> {
    let normalized_host = normalize_public_route_host(host);
    if normalized_host.is_empty() {
        return None;
    }
    let normalized_path = normalize_public_route_path(request_path);
    let state_view = app.state.view();
    let world = state_view.world();
    let current_height = u64::try_from(state_view.height()).unwrap_or(u64::MAX);
    let mut best_match: Option<(usize, PublicRouteMatch, (String, String, String))> = None;
    for (service_id, deployment) in world.soracloud_service_deployments().iter() {
        let service_name = service_id.to_string();
        let Some(bundle) = world.soracloud_service_revisions().get(&(
            service_name.clone(),
            deployment.current_service_version.clone(),
        )) else {
            continue;
        };
        let Some(route) = bundle.service.route.as_ref() else {
            continue;
        };
        if route.visibility != iroha_data_model::soracloud::SoraRouteVisibilityV1::Public {
            continue;
        }
        if !route.host.eq_ignore_ascii_case(normalized_host) {
            continue;
        }
        if bundle.service.execution_plane == SoraServiceExecutionPlaneV1::HttpService {
            if iroha_core::soracloud_runtime::validate_soracloud_deployment_lease_volume_bindings(
                deployment, bundle,
            )
            .is_err()
            {
                continue;
            }
            if !deployment
                .hosted_service_lease_active_at(current_height)
                .unwrap_or(false)
                || deployment
                    .lease_volume_states
                    .iter()
                    .any(|volume| !volume.is_active_at(current_height))
            {
                continue;
            }
            if bundle.container.runtime
                != iroha_data_model::soracloud::SoraContainerRuntimeV1::Inrou
            {
                continue;
            }
            let Some(request_path) =
                split_public_handler_path(normalized_path, route.path_prefix.as_str())
            else {
                continue;
            };
            let route_len = route.path_prefix.len();
            let route_match = PublicRouteMatch::HostedHttp(HostedHttpRouteMatch {
                service_name: service_name.clone(),
                service_version: deployment.current_service_version.clone(),
                request_path,
            });
            let sort_key = (
                service_name.clone(),
                deployment.current_service_version.clone(),
                String::new(),
            );
            let replace = best_match
                .as_ref()
                .is_none_or(|(best_len, _, best_sort_key)| {
                    route_len > *best_len || (route_len == *best_len && sort_key < *best_sort_key)
                });
            if replace {
                best_match = Some((route_len, route_match, sort_key));
            }
            continue;
        }
        if !bundle.container.runtime.is_deterministic() {
            continue;
        }
        for handler in &bundle.service.handlers {
            if !public_method_supports_handler(request_method, handler.class) {
                continue;
            }
            let route_match = match handler.class {
                iroha_data_model::soracloud::SoraServiceHandlerClassV1::Asset => {
                    let full_route = join_public_route_paths(
                        route.path_prefix.as_str(),
                        handler.route_path.as_deref().unwrap_or("/"),
                    );
                    let Some(handler_path) =
                        split_public_handler_path(normalized_path, &full_route)
                    else {
                        continue;
                    };
                    let route_len = full_route.len();
                    let route_match = PublicRouteMatch::LocalRead(LocalReadRouteMatch {
                        service_name: service_name.clone(),
                        service_version: deployment.current_service_version.clone(),
                        handler_name: handler.handler_name.to_string(),
                        handler_class: SoracloudLocalReadKind::Asset,
                        handler_path,
                    });
                    (route_len, route_match)
                }
                iroha_data_model::soracloud::SoraServiceHandlerClassV1::Query => {
                    let full_route = join_public_route_paths(
                        route.path_prefix.as_str(),
                        handler.route_path.as_deref().unwrap_or("/"),
                    );
                    let Some(handler_path) =
                        split_public_handler_path(normalized_path, &full_route)
                    else {
                        continue;
                    };
                    let route_len = full_route.len();
                    let route_match = PublicRouteMatch::LocalRead(LocalReadRouteMatch {
                        service_name: service_name.clone(),
                        service_version: deployment.current_service_version.clone(),
                        handler_name: handler.handler_name.to_string(),
                        handler_class: SoracloudLocalReadKind::Query,
                        handler_path,
                    });
                    (route_len, route_match)
                }
                iroha_data_model::soracloud::SoraServiceHandlerClassV1::Update => {
                    let full_route = join_public_route_paths(
                        route.path_prefix.as_str(),
                        handler.route_path.as_deref().unwrap_or("/"),
                    );
                    let Some(handler_path) =
                        split_public_handler_path(normalized_path, &full_route)
                    else {
                        continue;
                    };
                    let route_len = full_route.len();
                    let route_match =
                        PublicRouteMatch::OrderedMailbox(Box::new(OrderedMailboxRouteMatch {
                            service_name: service_name.clone(),
                            service_version: deployment.current_service_version.clone(),
                            handler_name: handler.handler_name.to_string(),
                            handler_class: handler.class,
                            handler_path,
                            deployment: deployment.clone(),
                            bundle: bundle.clone(),
                            handler: handler.clone(),
                        }));
                    (route_len, route_match)
                }
            };
            let (route_len, route_match) = route_match;
            let sort_key = (
                service_name.clone(),
                deployment.current_service_version.clone(),
                handler.handler_name.to_string(),
            );
            let replace = best_match
                .as_ref()
                .is_none_or(|(best_len, _, best_sort_key)| {
                    route_len > *best_len || (route_len == *best_len && sort_key < *best_sort_key)
                });
            if replace {
                best_match = Some((route_len, route_match, sort_key));
            }
        }
    }
    best_match.map(|(_route_len, route_match, _)| route_match)
}
fn normalize_public_route_host(host: &str) -> &str {
    host.trim()
        .trim_end_matches('.')
        .split(':')
        .next()
        .unwrap_or_default()
        .trim()
}
fn normalize_public_route_path(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}
fn join_public_route_paths(prefix: &str, handler_path: &str) -> String {
    let prefix = normalize_public_route_path(prefix).trim_end_matches('/');
    let handler_path = normalize_public_route_path(handler_path).trim_start_matches('/');
    match (prefix.is_empty(), handler_path.is_empty()) {
        (true, true) => "/".to_owned(),
        (true, false) => format!("/{handler_path}"),
        (false, true) => prefix.to_owned(),
        (false, false) => format!("{prefix}/{handler_path}"),
    }
}
fn split_public_handler_path(request_path: &str, full_route: &str) -> Option<String> {
    if full_route == "/" {
        return Some(request_path.to_owned());
    }
    if request_path == full_route {
        return Some("/".to_owned());
    }
    if request_path.starts_with(full_route)
        && request_path
            .as_bytes()
            .get(full_route.len())
            .is_some_and(|separator| *separator == b'/')
    {
        return Some(request_path[full_route.len()..].to_owned());
    }
    None
}
pub fn control_plane_snapshot(
    app: &SharedAppState,
    service_name: Option<&str>,
    audit_limit: usize,
) -> Result<ControlPlaneSnapshot, SoracloudError> {
    let limit = parse_exact_query_limit("audit_limit", audit_limit, MAX_AUDIT_LIMIT)?;
    let validated_audit_log = authoritative_audit_log(app)?;
    let state_view = app.state.view();
    let world = state_view.world();
    let current_height = u64::try_from(state_view.height()).map_err(|_| {
        SoracloudError::internal("committed block height exceeds the V1 u64 domain")
    })?;
    let latest_block_ms = state_view.query_ledger_time_ms();
    let wall_clock_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(latest_block_ms);
    let now_ms = wall_clock_ms.max(latest_block_ms);
    let active_inrou_hosts = world
        .soracloud_inrou_host_capabilities()
        .iter()
        .filter(|&(validator_account_id, capability)| {
            capability.validate().is_ok()
                && capability.validator_account_id == *validator_account_id
                && capability.can_host_replicas_at(now_ms)
                && iroha_core::soracloud_runtime::soracloud_validator_has_active_peer_binding(
                    world,
                    validator_account_id,
                    &capability.peer_id,
                    current_height,
                    |lane_id| state_view.is_lane_active_for_authority(lane_id),
                )
        })
        .map(|(_, capability)| capability.clone())
        .collect::<Vec<_>>();

    let mut services = Vec::new();
    for (service_id, deployment) in world.soracloud_service_deployments().iter() {
        let service_label = service_id.to_string();
        if service_name.is_some_and(|filter| filter != service_label) {
            continue;
        }
        let revision_key = (
            service_label.clone(),
            deployment.current_service_version.clone(),
        );
        let current_bundle = world
            .soracloud_service_revisions()
            .get(&revision_key)
            .cloned()
            .ok_or_else(|| {
                SoracloudError::internal(format!(
                    "service `{service_label}` active revision `{}` is missing from authoritative state",
                    deployment.current_service_version
                ))
            })?;
        if &deployment.service_name != service_id
            || deployment.current_service_manifest_hash != current_bundle.service_manifest_hash()
            || deployment.current_container_manifest_hash
                != current_bundle.container_manifest_hash()
        {
            return Err(SoracloudError::internal(format!(
                "service `{service_label}` deployment state does not bind its active revision `{}`",
                deployment.current_service_version
            )));
        }
        iroha_core::soracloud_runtime::validate_soracloud_deployment_lease_volume_bindings(
            deployment,
            &current_bundle,
        )
        .map_err(|message| {
            SoracloudError::internal(format!(
                "service `{service_label}` has invalid authoritative lease-volume state: {message}"
            ))
        })?;
        let current_public_discovery = authoritative_public_service_discovery_for_version(
            deployment,
            deployment.current_service_version.as_str(),
        )?;
        let latest_audit = world
            .soracloud_service_audit_events()
            .iter()
            .filter(|(_sequence, event)| {
                &event.service_name == service_id
                    && matches!(
                        event.action,
                        SoraServiceLifecycleActionV1::Deploy
                            | SoraServiceLifecycleActionV1::Upgrade
                            | SoraServiceLifecycleActionV1::Rollout
                            | SoraServiceLifecycleActionV1::Rollback
                    )
            })
            .map(|(_sequence, event)| event)
            .max_by_key(|event| event.sequence)
            .ok_or_else(|| {
                SoracloudError::internal(format!(
                    "service `{service_label}` active revision `{}` has no authoritative lifecycle audit event",
                    deployment.current_service_version
                ))
            })?;
        let accounted_storage_bytes = deployment.accounted_storage_bytes()?;
        let service_lease = deployment
            .service_lease
            .as_ref()
            .map(|lease| -> Result<_, NumericOperationError> {
                Ok(ControlPlaneServiceLeaseSnapshot {
                    authoritative_state: lease.clone(),
                    effective_status: lease.status_at(current_height, accounted_storage_bytes)?,
                    remaining_runtime_balance: lease
                        .remaining_balance(current_height, accounted_storage_bytes)?,
                })
            })
            .transpose()?;

        services.push(ControlPlaneServiceSnapshot {
            service_name: service_label.clone(),
            current_version: deployment.current_service_version.clone(),
            revision_count: deployment.revision_count,
            config_generation: deployment.config_generation,
            secret_generation: deployment.secret_generation,
            config_entry_count: u32::try_from(deployment.service_configs.len()).map_err(|_| {
                SoracloudError::internal(format!(
                    "service `{service_label}` config count exceeds the V1 u32 response range"
                ))
            })?,
            secret_entry_count: u32::try_from(deployment.service_secrets.len()).map_err(|_| {
                SoracloudError::internal(format!(
                    "service `{service_label}` secret count exceeds the V1 u32 response range"
                ))
            })?,
            service_lease,
            public_discovery_content_cid: current_public_discovery
                .as_ref()
                .map(|entry| entry.content_cid.clone()),
            public_discovery_url: current_public_discovery
                .as_ref()
                .map(|entry| entry.public_discovery_url.clone()),
            public_discovery_cid_host_url: current_public_discovery
                .as_ref()
                .map(|entry| entry.public_discovery_cid_host_url.clone()),
            latest_revision: Some(deployment_bundle_to_control_plane_revision(
                world,
                deployment,
                &current_bundle,
                Some(latest_audit),
                current_public_discovery.as_ref(),
            )?),
            active_rollout: deployment
                .active_rollout
                .as_ref()
                .map(rollout_state_to_runtime_state),
            last_rollout: deployment
                .last_rollout
                .as_ref()
                .map(rollout_state_to_runtime_state),
        });
    }
    let validated_audit_event_count = validated_audit_log.len();
    let mut recent_audit_events = validated_audit_log
        .into_iter()
        .filter(|event| service_name.is_none_or(|filter| filter == event.service_name))
        .collect::<Vec<_>>();
    recent_audit_events.sort_by_key(|event| std::cmp::Reverse(event.sequence));
    recent_audit_events.truncate(limit);
    Ok(ControlPlaneSnapshot {
        schema_version: CONTROL_PLANE_SCHEMA_VERSION,
        service_count: u32::try_from(services.len()).map_err(|_| {
            SoracloudError::internal("Soracloud service count exceeds the V1 u32 response range")
        })?,
        audit_event_count: u32::try_from(validated_audit_event_count).map_err(|_| {
            SoracloudError::internal(
                "Soracloud audit event count exceeds the V1 u32 response range",
            )
        })?,
        active_inrou_hosts,
        services,
        recent_audit_events,
    })
}
fn authoritative_app_infra_status_response(
    app: &SharedAppState,
    app_name: Option<&str>,
    audit_limit: usize,
) -> Result<AppInfraStatusResponse, SoracloudError> {
    let limit = parse_exact_query_limit("audit_limit", audit_limit, MAX_AUDIT_LIMIT)?;
    let app_filter = app_name
        .map(|literal| parse_exact_name_identifier("app_name", literal))
        .transpose()?;
    let state_view = app.state.view();
    let world = state_view.world();
    let mut apps = world
        .soracloud_app_infra_states()
        .iter()
        .filter(|(_name, state)| {
            app_filter
                .as_ref()
                .is_none_or(|filter| filter == &state.app_name)
        })
        .map(|(_name, state)| state.clone())
        .collect::<Vec<_>>();
    apps.sort_by(|left, right| left.app_name.as_ref().cmp(right.app_name.as_ref()));
    if app_filter.is_some() && apps.is_empty() {
        return Err(SoracloudError::not_found(format!(
            "app `{}` not found in authoritative Soracloud app infra state",
            app_name.unwrap_or_default()
        )));
    }
    let mut recent_audit_events = world
        .soracloud_app_infra_audit_events()
        .iter()
        .filter(|(_sequence, event)| {
            app_filter
                .as_ref()
                .is_none_or(|filter| filter == &event.app_name)
        })
        .map(|(_sequence, event)| event.clone())
        .collect::<Vec<_>>();
    recent_audit_events.sort_by_key(|event| std::cmp::Reverse(event.sequence));
    recent_audit_events.truncate(limit);
    Ok(AppInfraStatusResponse {
        schema_version: CONTROL_PLANE_SCHEMA_VERSION,
        app_count: u32::try_from(apps.len()).map_err(|_| {
            SoracloudError::internal("Soracloud app count exceeds the V1 u32 response range")
        })?,
        audit_event_count: u32::try_from(world.soracloud_app_infra_audit_events().iter().count())
            .map_err(|_| {
            SoracloudError::internal(
                "Soracloud app audit event count exceeds the V1 u32 response range",
            )
        })?,
        apps,
        recent_audit_events,
    })
}
pub async fn handle_deploy(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedBundleRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) =
        crate::check_access(&app, &headers, Some(remote_ip), "v1/soracloud/deploy").await
    {
        return err.into_response();
    }
    if let Err(err) = verify_bundle_signature(&request) {
        return err.into_response();
    }
    if let Err(err) = admit_scr_host_bundle(&request.bundle) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::DeploySoracloudService {
                bundle: request.bundle,
                initial_service_configs: request.initial_service_configs,
                initial_service_secrets: request.initial_service_secrets,
                precondition: request.precondition,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_upgrade(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedBundleRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) =
        crate::check_access(&app, &headers, Some(remote_ip), "v1/soracloud/upgrade").await
    {
        return err.into_response();
    }
    if let Err(err) = verify_bundle_signature(&request) {
        return err.into_response();
    }
    if let Err(err) = admit_scr_host_bundle(&request.bundle) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::UpgradeSoracloudService {
                bundle: request.bundle,
                initial_service_configs: request.initial_service_configs,
                initial_service_secrets: request.initial_service_secrets,
                precondition: request.precondition,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_app_deploy(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedAppInfraRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) =
        crate::check_access(&app, &headers, Some(remote_ip), "v1/soracloud/apps/deploy").await
    {
        return err.into_response();
    }
    if let Err(err) = verify_app_infra_signature(&request) {
        return err.into_response();
    }
    let SignedAppInfraRequest {
        deploy_services,
        upgrade_services,
        manifest,
        precondition,
        provenance,
    } = request;
    let signer = match require_soracloud_mutation_signer(&headers, &provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let app_signer = provenance.signer.clone();
    let mut instructions = Vec::new();
    for service_request in deploy_services {
        match app_service_bundle_instruction(service_request, MutationMode::Deploy, &app_signer) {
            Ok(instruction) => instructions.push(instruction),
            Err(err) => return err.into_response(),
        }
    }
    for service_request in upgrade_services {
        match app_service_bundle_instruction(service_request, MutationMode::Upgrade, &app_signer) {
            Ok(instruction) => instructions.push(instruction),
            Err(err) => return err.into_response(),
        }
    }
    instructions.push(InstructionBox::from(
        isi::soracloud::DeploySoracloudAppInfra {
            manifest,
            precondition,
            provenance,
        },
    ));
    soracloud_draft_response(&signer, instructions)
}
pub async fn handle_app_upgrade(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedAppInfraRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) =
        crate::check_access(&app, &headers, Some(remote_ip), "v1/soracloud/apps/upgrade").await
    {
        return err.into_response();
    }
    if let Err(err) = verify_app_infra_signature(&request) {
        return err.into_response();
    }
    let SignedAppInfraRequest {
        deploy_services,
        upgrade_services,
        manifest,
        precondition,
        provenance,
    } = request;
    let signer = match require_soracloud_mutation_signer(&headers, &provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let app_signer = provenance.signer.clone();
    let mut instructions = Vec::new();
    for service_request in deploy_services {
        match app_service_bundle_instruction(service_request, MutationMode::Deploy, &app_signer) {
            Ok(instruction) => instructions.push(instruction),
            Err(err) => return err.into_response(),
        }
    }
    for service_request in upgrade_services {
        match app_service_bundle_instruction(service_request, MutationMode::Upgrade, &app_signer) {
            Ok(instruction) => instructions.push(instruction),
            Err(err) => return err.into_response(),
        }
    }
    instructions.push(InstructionBox::from(
        isi::soracloud::UpgradeSoracloudAppInfra {
            manifest,
            precondition,
            provenance,
        },
    ));
    soracloud_draft_response(&signer, instructions)
}
pub async fn handle_app_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<AppInfraStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) =
        crate::check_access(&app, &headers, Some(remote_ip), "v1/soracloud/apps/status").await
    {
        return err.into_response();
    }
    match authoritative_app_infra_status_response(
        &app,
        query.app_name.as_deref(),
        query.audit_limit.unwrap_or(DEFAULT_AUDIT_LIMIT),
    ) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_named_app_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    Path(app_name): Path<String>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<AppInfraStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/apps/{app_name}/status",
    )
    .await
    {
        return err.into_response();
    }
    match authoritative_app_infra_status_response(
        &app,
        Some(&app_name),
        query.audit_limit.unwrap_or(DEFAULT_AUDIT_LIMIT),
    ) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_rollback(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedRollbackRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) =
        crate::check_access(&app, &headers, Some(remote_ip), "v1/soracloud/rollback").await
    {
        return err.into_response();
    }
    if let Err(err) = verify_rollback_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::RollbackSoracloudService {
                service_name,
                target_version: request.payload.target_version,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_rollout(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedRolloutAdvanceRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) =
        crate::check_access(&app, &headers, Some(remote_ip), "v1/soracloud/rollout").await
    {
        return err.into_response();
    }
    if let Err(err) = verify_rollout_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    {
        let state_view = app.state.view();
        if let Err(err) =
            ensure_authoritative_rollout_draft_supported(state_view.world(), service_name.as_ref())
        {
            return err.into_response();
        }
    }
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::AdvanceSoracloudRollout {
                service_name,
                rollout_handle: request.payload.rollout_handle,
                healthy: request.payload.healthy,
                promote_to_percent: request.payload.promote_to_percent,
                governance_tx_hash: request.payload.governance_tx_hash,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_state_mutation(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedStateMutationRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) =
        crate::check_access(&app, &headers, Some(remote_ip), "v1/soracloud/state/mutate").await
    {
        return err.into_response();
    }
    if let Err(err) = verify_state_mutation_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let binding_name =
        match parse_exact_name_identifier("binding_name", &request.payload.binding_name) {
            Ok(binding_name) => binding_name,
            Err(err) => return err.into_response(),
        };
    let value_payload = match decode_state_mutation_payload(&request.payload) {
        Ok(payload) => payload,
        Err(err) => return err.into_response(),
    };
    let value_size_bytes = value_payload.as_ref().map(|payload| {
        u64::try_from(payload.len()).expect("payload length already validated for u64")
    });
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(isi::soracloud::MutateSoracloudState {
            service_name,
            binding_name,
            state_key: request.payload.key,
            operation: state_mutation_operation_to_model(request.payload.operation),
            value_size_bytes,
            value_payload,
            encryption: request.payload.encryption,
            governance_tx_hash: request.payload.governance_tx_hash,
            fhe_input_admission_proof: request.payload.fhe_input_admission_proof,
            provenance: request.provenance,
        })],
    )
}
pub async fn handle_service_config_set(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedServiceConfigSetRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/service/config/set",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_service_config_set_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let config_name = request.payload.config_name.clone();
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::SetSoracloudServiceConfig {
                service_name,
                config_name: config_name.clone(),
                value_json: request.payload.value_json,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_service_config_delete(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedServiceConfigDeleteRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/service/config/delete",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_service_config_delete_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let config_name = request.payload.config_name.clone();
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::DeleteSoracloudServiceConfig {
                service_name,
                config_name: config_name.clone(),
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_service_config_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<ServiceConfigStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/service/config/status",
    )
    .await
    {
        return err.into_response();
    }
    let service_name = match parse_service_name(&query.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let config_name = match query
        .config_name
        .as_deref()
        .map(|name| parse_service_material_name("config_name", name))
        .transpose()
    {
        Ok(config_name) => config_name,
        Err(err) => return err.into_response(),
    };
    match authoritative_service_config_status_response(
        &app,
        service_name.as_ref(),
        config_name.as_deref(),
    ) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_service_public_discovery(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(service_name): Path<String>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/services/{service_name}/public-discovery",
    )
    .await
    {
        return err.into_response();
    }
    let service_name = match parse_service_name(&service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    match authoritative_service_public_discovery_response(&app, service_name.as_ref(), None) {
        Ok(response) => bounded_public_response::json(&response),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_service_revision_public_discovery(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path((service_name, service_version)): Path<(String, String)>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/services/{service_name}/revisions/{service_version}/public-discovery",
    )
    .await
    {
        return err.into_response();
    }
    let service_name = match parse_service_name(&service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let service_version = match parse_exact_nonempty_text("service_version", &service_version) {
        Ok(service_version) => service_version,
        Err(err) => return err.into_response(),
    };
    match authoritative_service_public_discovery_response(
        &app,
        service_name.as_ref(),
        Some(service_version.as_str()),
    ) {
        Ok(response) => bounded_public_response::json(&response),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_service_secret_set(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedServiceSecretSetRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/service/secret/set",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_service_secret_set_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let secret_name = request.payload.secret_name.clone();
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::SetSoracloudServiceSecret {
                service_name,
                secret_name: secret_name.clone(),
                secret: request.payload.secret,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_service_secret_delete(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedServiceSecretDeleteRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/service/secret/delete",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_service_secret_delete_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let secret_name = request.payload.secret_name.clone();
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::DeleteSoracloudServiceSecret {
                service_name,
                secret_name: secret_name.clone(),
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_service_secret_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<ServiceSecretStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/service/secret/status",
    )
    .await
    {
        return err.into_response();
    }
    let service_name = match parse_service_name(&query.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let secret_name = match query
        .secret_name
        .as_deref()
        .map(|name| parse_service_material_name("secret_name", name))
        .transpose()
    {
        Ok(secret_name) => secret_name,
        Err(err) => return err.into_response(),
    };
    match authoritative_service_secret_status_response(
        &app,
        service_name.as_ref(),
        secret_name.as_deref(),
    ) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_fhe_job_run(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedFheJobRunRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) =
        crate::check_access(&app, &headers, Some(remote_ip), "v1/soracloud/fhe/job/run").await
    {
        return err.into_response();
    }
    if let Err(err) = verify_fhe_job_run_signature(&request) {
        return err.into_response();
    }
    if let Err(err) = validate_fhe_job_run_proof_attachments(&request.payload) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let binding_name =
        match parse_exact_name_identifier("binding_name", &request.payload.binding_name) {
            Ok(binding_name) => binding_name,
            Err(err) => return err.into_response(),
        };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(isi::soracloud::RunSoracloudFheJob {
            service_name,
            binding_name,
            job: request.payload.job,
            policy_reference: request.payload.policy_reference,
            public_key_proof: request.payload.public_key_proof,
            bootstrap_key_zero_refresh_proof: request.payload.bootstrap_key_zero_refresh_proof,
            full_bootstrap_execution_proofs: request.payload.full_bootstrap_execution_proofs,
            provenance: request.provenance,
        })],
    )
}
pub async fn handle_decryption_request(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedDecryptionRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/decrypt/request",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_decryption_request_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::RecordSoracloudDecryptionRequest {
                service_name,
                policy: request.payload.policy,
                request: request.payload.request,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_health_access_request(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedDecryptionRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/health/access/request",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_decryption_request_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::RecordSoracloudDecryptionRequest {
                service_name,
                policy: request.payload.policy,
                request: request.payload.request,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_ciphertext_query(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedCiphertextQueryRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/ciphertext/query",
    )
    .await
    {
        return err.into_response();
    }
    match authoritative_ciphertext_query_response(&app, request) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_training_job_start(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedTrainingJobStartRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/training/job/start",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_training_job_start_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::StartSoracloudTrainingJob {
                service_name,
                model_name: request.payload.model_name,
                job_id: request.payload.job_id,
                worker_group_size: request.payload.worker_group_size,
                target_steps: request.payload.target_steps,
                checkpoint_interval_steps: request.payload.checkpoint_interval_steps,
                max_retries: request.payload.max_retries,
                step_compute_units: request.payload.step_compute_units,
                compute_budget_units: request.payload.compute_budget_units,
                storage_budget_bytes: request.payload.storage_budget_bytes,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_training_job_checkpoint(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedTrainingJobCheckpointRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/training/job/checkpoint",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_training_job_checkpoint_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::CheckpointSoracloudTrainingJob {
                service_name,
                job_id: request.payload.job_id,
                completed_step: request.payload.completed_step,
                checkpoint_size_bytes: request.payload.checkpoint_size_bytes,
                metrics_hash: request.payload.metrics_hash,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_training_job_retry(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedTrainingJobRetryRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/training/job/retry",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_training_job_retry_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::RetrySoracloudTrainingJob {
                service_name,
                job_id: request.payload.job_id,
                reason: request.payload.reason,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_training_job_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<TrainingJobStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/training/job/status",
    )
    .await
    {
        return err.into_response();
    }
    match authoritative_training_job_status_response(&app, &query.service_name, &query.job_id) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_model_weight_register(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedModelWeightRegisterRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/model/weight/register",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_model_weight_register_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::RegisterSoracloudModelWeight {
                service_name,
                model_name: request.payload.model_name,
                weight_version: request.payload.weight_version,
                training_job_id: request.payload.training_job_id,
                parent_version: request.payload.parent_version,
                weight_artifact_hash: request.payload.weight_artifact_hash,
                dataset_ref: request.payload.dataset_ref,
                training_config_hash: request.payload.training_config_hash,
                reproducibility_hash: request.payload.reproducibility_hash,
                provenance_attestation_hash: request.payload.provenance_attestation_hash,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_model_weight_promote(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedModelWeightPromoteRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/model/weight/promote",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_model_weight_promote_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::PromoteSoracloudModelWeight {
                service_name,
                model_name: request.payload.model_name,
                weight_version: request.payload.weight_version,
                gate_approved: request.payload.gate_approved,
                gate_report_hash: request.payload.gate_report_hash,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_model_weight_rollback(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedModelWeightRollbackRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/model/weight/rollback",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_model_weight_rollback_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::RollbackSoracloudModelWeight {
                service_name,
                model_name: request.payload.model_name,
                target_version: request.payload.target_version,
                reason: request.payload.reason,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_model_weight_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<ModelWeightStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/model/weight/status",
    )
    .await
    {
        return err.into_response();
    }
    match authoritative_model_weight_status_response(&app, &query.service_name, &query.model_name) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_model_artifact_register(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedModelArtifactRegisterRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/model/artifact/register",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_model_artifact_register_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::RegisterSoracloudModelArtifact {
                service_name,
                model_name: request.payload.model_name,
                training_job_id: request.payload.training_job_id,
                weight_artifact_hash: request.payload.weight_artifact_hash,
                dataset_ref: request.payload.dataset_ref,
                training_config_hash: request.payload.training_config_hash,
                reproducibility_hash: request.payload.reproducibility_hash,
                provenance_attestation_hash: request.payload.provenance_attestation_hash,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_model_artifact_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<ModelArtifactStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/model/artifact/status",
    )
    .await
    {
        return err.into_response();
    }
    match authoritative_model_artifact_status_response(
        &app,
        &query.service_name,
        query.model_name.as_deref(),
        query.artifact_id.as_deref(),
        query.training_job_id.as_deref(),
        query.weight_version.as_deref(),
    ) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_uploaded_model_register(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedUploadedModelRegisterRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/model/upload/register",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_uploaded_model_register_signature(&request) {
        return err.into_response();
    }
    if let Err(err) = require_active_sorafs_uploaded_model_pin(&app, &request.payload.bundle) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.bundle_provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let service_name = request.payload.bundle.service_name.clone();
    let finalize_payload = request.payload.clone();
    let instructions = vec![
        InstructionBox::from(isi::soracloud::RegisterSoracloudUploadedModelBundle {
            bundle: request.payload.bundle,
            provenance: request.bundle_provenance,
        }),
        InstructionBox::from(isi::soracloud::FinalizeSoracloudUploadedModelBundle {
            service_name,
            model_name: finalize_payload.model_name,
            model_id: finalize_payload.bundle.model_id,
            artifact_id: finalize_payload.artifact_id,
            weight_version: finalize_payload.bundle.weight_version,
            bundle_root: finalize_payload.bundle.bundle_root,
            weight_artifact_hash: finalize_payload.weight_artifact_hash,
            dataset_ref: finalize_payload.dataset_ref,
            training_config_hash: finalize_payload.training_config_hash,
            reproducibility_hash: finalize_payload.reproducibility_hash,
            provenance_attestation_hash: finalize_payload.provenance_attestation_hash,
            provenance: request.finalize_provenance,
        }),
    ];
    soracloud_draft_response(&signer, instructions)
}
pub async fn handle_uploaded_model_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<UploadedModelStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/model/upload/status",
    )
    .await
    {
        return err.into_response();
    }
    match authoritative_uploaded_model_status_from_query(&app, &query) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}

pub async fn handle_hf_shared_lease_join(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedHfSharedLeaseJoinRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/hf/lease/join",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_hf_shared_lease_join_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let repo_id = match parse_hf_repo_id(&request.payload.repo_id) {
        Ok(repo_id) => repo_id,
        Err(err) => return err.into_response(),
    };
    let resolved_revision = match parse_hf_revision(&request.payload.revision) {
        Ok(resolved_revision) => resolved_revision,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let apartment_name = match request
        .payload
        .apartment_name
        .as_deref()
        .map(|value| parse_agent_apartment_identifier("apartment_name", value))
        .transpose()
    {
        Ok(apartment_name) => apartment_name,
        Err(err) => return err.into_response(),
    };
    let storage_class = request.payload.storage_class;
    let lease_term_ms = request.payload.lease_term_ms;
    let lease_asset_definition_id = request.payload.lease_asset_definition_id.clone();
    let base_fee = request.payload.base_fee.clone();
    let instruction = InstructionBox::from(isi::soracloud::JoinSoracloudHfSharedLease {
        repo_id: repo_id.clone(),
        resolved_revision: resolved_revision.clone(),
        service_name,
        apartment_name,
        storage_class,
        lease_term_ms,
        lease_asset_definition_id,
        base_fee,
        provenance: request.provenance,
    });
    soracloud_draft_response(&signer, vec![instruction])
}
pub async fn handle_hf_shared_lease_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<HfSharedLeaseStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/hf/lease/status",
    )
    .await
    {
        return err.into_response();
    }
    let repo_id = match parse_hf_repo_id(&query.repo_id) {
        Ok(repo_id) => repo_id,
        Err(err) => return err.into_response(),
    };
    let resolved_revision = match parse_hf_revision(&query.revision) {
        Ok(resolved_revision) => resolved_revision,
        Err(err) => return err.into_response(),
    };
    let storage_class = match parse_storage_class_query(&query.storage_class) {
        Ok(storage_class) => storage_class,
        Err(err) => return err.into_response(),
    };
    let account_id = match parse_optional_account_id(
        app.state.as_ref(),
        &app.telemetry,
        "/v1/soracloud/hf/lease/status#account_id",
        query.account_id.as_deref(),
    ) {
        Ok(account_id) => account_id,
        Err(err) => return err.into_response(),
    };
    match authoritative_hf_shared_lease_status_response(
        &app,
        &repo_id,
        &resolved_revision,
        storage_class,
        query.lease_term_ms,
        account_id.as_ref(),
    ) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_hf_lease_leave(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedHfLeaseLeaveRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/hf/lease/leave",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_hf_lease_leave_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let repo_id = match parse_hf_repo_id(&request.payload.repo_id) {
        Ok(repo_id) => repo_id,
        Err(err) => return err.into_response(),
    };
    let resolved_revision = match parse_hf_revision(&request.payload.revision) {
        Ok(resolved_revision) => resolved_revision,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_optional_service_name(request.payload.service_name.as_deref()) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let apartment_name = match request
        .payload
        .apartment_name
        .as_deref()
        .map(|value| parse_agent_apartment_identifier("apartment_name", value))
        .transpose()
    {
        Ok(apartment_name) => apartment_name,
        Err(err) => return err.into_response(),
    };
    let storage_class = request.payload.storage_class;
    let lease_term_ms = request.payload.lease_term_ms;
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::LeaveSoracloudHfSharedLease {
                repo_id: repo_id.clone(),
                resolved_revision: resolved_revision.clone(),
                storage_class,
                lease_term_ms,
                service_name,
                apartment_name,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_hf_lease_renew(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedHfLeaseRenewRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/hf/lease/renew",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_hf_lease_renew_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let repo_id = match parse_hf_repo_id(&request.payload.repo_id) {
        Ok(repo_id) => repo_id,
        Err(err) => return err.into_response(),
    };
    let resolved_revision = match parse_hf_revision(&request.payload.revision) {
        Ok(resolved_revision) => resolved_revision,
        Err(err) => return err.into_response(),
    };
    let service_name = match parse_service_name(&request.payload.service_name) {
        Ok(service_name) => service_name,
        Err(err) => return err.into_response(),
    };
    let apartment_name = match request
        .payload
        .apartment_name
        .as_deref()
        .map(|value| parse_agent_apartment_identifier("apartment_name", value))
        .transpose()
    {
        Ok(apartment_name) => apartment_name,
        Err(err) => return err.into_response(),
    };
    let storage_class = request.payload.storage_class;
    let lease_term_ms = request.payload.lease_term_ms;
    let lease_asset_definition_id = request.payload.lease_asset_definition_id.clone();
    let base_fee = request.payload.base_fee.clone();
    let instruction = InstructionBox::from(isi::soracloud::RenewSoracloudHfSharedLease {
        repo_id: repo_id.clone(),
        resolved_revision: resolved_revision.clone(),
        service_name,
        apartment_name,
        storage_class,
        lease_term_ms,
        lease_asset_definition_id,
        base_fee,
        provenance: request.provenance,
    });
    soracloud_draft_response(&signer, vec![instruction])
}
pub async fn handle_agent_deploy(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedAgentDeployRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) =
        crate::check_access(&app, &headers, Some(remote_ip), "v1/soracloud/agent/deploy").await
    {
        return err.into_response();
    }
    if let Err(err) = verify_agent_deploy_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let autonomy_budget_units = request.payload.autonomy_budget_units;
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::DeploySoracloudAgentApartment {
                manifest: request.payload.manifest,
                lease_blocks: request.payload.lease_blocks,
                autonomy_budget_units,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_agent_lease_renew(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedAgentLeaseRenewRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/agent/lease/renew",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_agent_lease_renew_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let apartment_name =
        match parse_agent_apartment_identifier("apartment_name", &request.payload.apartment_name) {
            Ok(apartment_name) => apartment_name,
            Err(err) => return err.into_response(),
        };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::RenewSoracloudAgentLease {
                apartment_name,
                lease_blocks: request.payload.lease_blocks,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_agent_restart(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedAgentRestartRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/agent/restart",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_agent_restart_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let apartment_name =
        match parse_agent_apartment_identifier("apartment_name", &request.payload.apartment_name) {
            Ok(apartment_name) => apartment_name,
            Err(err) => return err.into_response(),
        };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::RestartSoracloudAgentApartment {
                apartment_name,
                reason: request.payload.reason,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_agent_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<AgentStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) =
        crate::check_access(&app, &headers, Some(remote_ip), "v1/soracloud/agent/status").await
    {
        return err.into_response();
    }
    match authoritative_agent_status_response(&app, query.apartment_name.as_deref()) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_agent_wallet_spend(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedAgentWalletSpendRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/agent/wallet/spend",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = validate_agent_wallet_request_id(&request.payload.request_id) {
        return err.into_response();
    }
    if let Err(err) = validate_agent_wallet_asset_definition(&request.payload.asset_definition) {
        return err.into_response();
    }
    if let Err(err) = verify_agent_wallet_spend_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let apartment_name =
        match parse_agent_apartment_identifier("apartment_name", &request.payload.apartment_name) {
            Ok(apartment_name) => apartment_name,
            Err(err) => return err.into_response(),
        };
    if request.payload.amount.is_zero() {
        return SoracloudError::bad_request("amount must be greater than zero").into_response();
    }
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::RequestSoracloudAgentWalletSpend {
                apartment_name,
                request_id: request.payload.request_id,
                asset_definition: request.payload.asset_definition,
                amount: request.payload.amount,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_agent_wallet_approve(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedAgentWalletApproveRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/agent/wallet/approve",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = validate_agent_wallet_request_id(&request.payload.request_id) {
        return err.into_response();
    }
    if let Err(err) = verify_agent_wallet_approve_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let apartment_name =
        match parse_agent_apartment_identifier("apartment_name", &request.payload.apartment_name) {
            Ok(apartment_name) => apartment_name,
            Err(err) => return err.into_response(),
        };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::ApproveSoracloudAgentWalletSpend {
                apartment_name,
                request_id: request.payload.request_id,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_agent_policy_revoke(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedAgentPolicyRevokeRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/agent/policy/revoke",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_agent_policy_revoke_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let apartment_name =
        match parse_agent_apartment_identifier("apartment_name", &request.payload.apartment_name) {
            Ok(apartment_name) => apartment_name,
            Err(err) => return err.into_response(),
        };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::RevokeSoracloudAgentPolicy {
                apartment_name,
                capability: request.payload.capability,
                reason: request.payload.reason,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_agent_message_send(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedAgentMessageSendRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/agent/message/send",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_agent_message_send_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let from_apartment =
        match parse_agent_apartment_identifier("from_apartment", &request.payload.from_apartment) {
            Ok(apartment_name) => apartment_name,
            Err(err) => return err.into_response(),
        };
    let to_apartment =
        match parse_agent_apartment_identifier("to_apartment", &request.payload.to_apartment) {
            Ok(apartment_name) => apartment_name,
            Err(err) => return err.into_response(),
        };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::EnqueueSoracloudAgentMessage {
                from_apartment,
                to_apartment,
                channel: request.payload.channel,
                payload: request.payload.payload,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_agent_message_ack(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedAgentMessageAckRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/agent/message/ack",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_agent_message_ack_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let apartment_name =
        match parse_agent_apartment_identifier("apartment_name", &request.payload.apartment_name) {
            Ok(apartment_name) => apartment_name,
            Err(err) => return err.into_response(),
        };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::AcknowledgeSoracloudAgentMessage {
                apartment_name,
                message_id: request.payload.message_id,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_agent_mailbox_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<AgentMailboxStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/agent/mailbox/status",
    )
    .await
    {
        return err.into_response();
    }
    match authoritative_agent_mailbox_status_response(&app, &query.apartment_name) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_agent_autonomy_allow(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<SignedAgentArtifactAllowRequest>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/agent/autonomy/allow",
    )
    .await
    {
        return err.into_response();
    }
    if let Err(err) = verify_agent_artifact_allow_signature(&request) {
        return err.into_response();
    }
    let signer = match require_soracloud_mutation_signer(&headers, &request.provenance) {
        Ok(signer) => signer,
        Err(err) => return err.into_response(),
    };
    let apartment_name =
        match parse_agent_apartment_identifier("apartment_name", &request.payload.apartment_name) {
            Ok(apartment_name) => apartment_name,
            Err(err) => return err.into_response(),
        };
    soracloud_draft_response(
        &signer,
        vec![InstructionBox::from(
            isi::soracloud::AllowSoracloudAgentAutonomyArtifact {
                apartment_name,
                artifact_hash: request.payload.artifact_hash,
                provenance_hash: request.payload.provenance_hash,
                provenance: request.provenance,
            },
        )],
    )
}
pub async fn handle_agent_autonomy_status(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<AgentAutonomyStatusQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/agent/autonomy/status",
    )
    .await
    {
        return err.into_response();
    }
    match authoritative_agent_autonomy_status_response(&app, &query.apartment_name) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
pub async fn handle_health_compliance_report(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<HealthComplianceReportQuery>,
) -> Response {
    let remote_ip = remote.ip();
    if let Err(err) = crate::check_access(
        &app,
        &headers,
        Some(remote_ip),
        "v1/soracloud/health/compliance/report",
    )
    .await
    {
        return err.into_response();
    }
    let limit = match query.limit {
        Some(value) => match usize::try_from(value) {
            Ok(value) => value,
            Err(_) => {
                return SoracloudError::bad_request("limit exceeds the V1 platform query range")
                    .into_response();
            }
        },
        None => DEFAULT_HEALTH_COMPLIANCE_LIMIT,
    };
    match authoritative_health_compliance_report(
        &app,
        query.service_name.as_deref(),
        query.jurisdiction_tag.as_deref(),
        limit,
    ) {
        Ok(response) => JsonBody(response).into_response(),
        Err(err) => err.into_response(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const TEST_HF_COMMIT_OID: &str = "0123456789abcdef0123456789abcdef01234567";
    use crate::tests_runtime_handlers::mk_app_state_for_tests_with_world;
    use iroha_crypto::{Algorithm, KeyPair, Signature};
    use iroha_data_model::{
        Encode,
        account::{Account, AccountId},
        asset::AssetDefinitionId,
        domain::Domain,
        isi::Grant,
        permission::Permission,
        prelude::Register,
        sns::{NameControllerV1, NameRecordV1},
        soracloud::{
            AgentApartmentManifestV1, CiphertextQuerySpecV1, DecryptionAuthorityPolicyV1,
            DecryptionRequestV1, FheJobSpecV1, SORA_AGENT_APARTMENT_AUDIT_EVENT_VERSION_V1,
            SORA_DEPLOYMENT_BUNDLE_VERSION_V1, SORA_HF_SHARED_LEASE_AUDIT_EVENT_VERSION_V1,
            SORA_HF_SHARED_LEASE_MEMBER_VERSION_V1, SORA_HF_SHARED_LEASE_POOL_VERSION_V1,
            SORA_HF_SOURCE_RECORD_VERSION_V1, SecretEnvelopeEncryptionV1, SecretEnvelopeV1,
            SoraAgentApartmentActionV1, SoraAgentApartmentAuditEventV1,
            SoraAgentAutonomyRunRecordV1, SoraAgentPersistentStateV1, SoraAgentRuntimeStatusV1,
            SoraContainerManifestV1, SoraHfSharedLeaseActionV1, SoraHfSharedLeaseAuditEventV1,
            SoraHfSharedLeaseMemberStatusV1, SoraHfSharedLeaseMemberV1, SoraHfSharedLeasePoolV1,
            SoraHfSharedLeaseStatusV1, SoraHfSourceRecordV1, SoraModelProvenanceKindV1,
            SoraModelProvenanceRefV1, SoraRouteTargetV1, SoraRouteVisibilityV1,
            SoraServiceAuditEventV1, SoraServiceConfigEntryV1, SoraServiceDeploymentStateV1,
            SoraServiceHandlerV1, SoraServiceLifecycleActionV1, SoraServiceManifestV1,
            SoraServiceSecretEntryV1, SoraServiceStateEntryV1, SoraStateEncryptionV1,
            SoraTlsModeV1, SoraUploadedModelBundleV1, SoraUploadedModelPackageFormatV1,
            SoraUploadedModelPricingPolicyV1,
        },
        sorafs::pin_registry::{
            ChunkerProfileHandle, ManifestDigest, ManifestRootCid, PinManifestRecord, PinPolicy,
            StorageClass,
        },
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use iroha_primitives::json::Json;
    use iroha_test_samples::{ALICE_ID, BOB_ID, SAMPLE_GENESIS_ACCOUNT_ID};
    use std::{
        fs, io,
        num::{NonZeroU16, NonZeroU32, NonZeroU64},
        path::{Path, PathBuf},
        sync::Arc,
    };

    fn agent_runtime_receipt_json_fixture() -> AgentRuntimeReceiptRecord {
        AgentRuntimeReceiptRecord {
            receipt_id: Hash::new(b"agent runtime receipt"),
            service_name: "agent_workflow_service".to_owned(),
            service_version: "workflow.v1".to_owned(),
            handler_name: "workflow".to_owned(),
            handler_class: SoraServiceHandlerClassV1::Query,
            request_commitment: Hash::new(b"agent runtime request"),
            result_commitment: Hash::new(b"agent runtime result"),
            certified_by: SoraCertifiedResponsePolicyV1::AuditReceipt,
            emitted_sequence: 9,
            execution_host: None,
            mailbox_message_id: None,
            journal_artifact_hash: None,
            checkpoint_artifact_hash: None,
        }
    }
    fn agent_autonomy_execution_audit_json_fixture() -> AgentAutonomyExecutionAuditRecord {
        AgentAutonomyExecutionAuditRecord {
            sequence: 10,
            succeeded: true,
            result_commitment: Hash::new(b"agent autonomy audit result"),
            service_name: None,
            service_version: None,
            handler_name: None,
            runtime_receipt_id: None,
            journal_artifact_hash: None,
            checkpoint_artifact_hash: None,
            reason: None,
        }
    }
    fn json_object_at_mut<'a>(
        value: &'a mut norito::json::Value,
        pointer: &str,
    ) -> &'a mut norito::json::Map {
        let target = if pointer.is_empty() {
            value
        } else {
            value.pointer_mut(pointer).expect("JSON pointer exists")
        };
        target
            .as_object_mut()
            .expect("JSON pointer names an object")
    }
    #[test]
    fn agent_autonomy_status_json_graph_requires_exact_v1_fields() {
        let canonical = AgentAutonomyStatusResponse {
            apartment_name: "ops_agent".parse().expect("valid apartment name"),
            sequence: 10,
            status: AgentRuntimeStatus::Running,
            lease_expires_height: 100,
            lease_remaining_blocks: 90,
            manifest_hash: Hash::new(b"agent manifest"),
            revoked_policy_capability_count: 0,
            budget_ceiling_units: 100,
            budget_remaining_units: 90,
            allowlist_count: 1,
            run_count: 1,
            process_generation: 3,
            process_started_sequence: 1,
            last_active_sequence: 10,
            last_checkpoint_sequence: None,
            checkpoint_count: 1,
            persistent_state_total_bytes: 64,
            persistent_state_key_count: 1,
            allowlist: vec![AgentAutonomyAllowlistEntry {
                artifact_hash: "hash:agent#1".to_owned(),
                provenance_hash: None,
                added_sequence: 2,
            }],
            recent_runs: vec![AgentAutonomyRunRecord {
                run_id: "ops_agent:autonomy:9".to_owned(),
                artifact_hash: "hash:agent#1".to_owned(),
                provenance_hash: None,
                budget_units: 10,
                run_label: "fixture".to_owned(),
                workflow_input_json: None,
                approved_sequence: 9,
                authoritative_runtime_receipt: Some(agent_runtime_receipt_json_fixture()),
                authoritative_execution_audit: Some(agent_autonomy_execution_audit_json_fixture()),
            }],
        };
        let canonical_value =
            norito::json::to_value(&canonical).expect("encode canonical agent autonomy status");
        norito::json::from_value::<AgentAutonomyStatusResponse>(canonical_value.clone())
            .expect("decode canonical agent autonomy status");
        for (pointer, required_field) in [
            ("", "last_checkpoint_sequence"),
            ("", "allowlist"),
            ("", "recent_runs"),
            ("/allowlist/0", "provenance_hash"),
            ("/recent_runs/0", "provenance_hash"),
            ("/recent_runs/0", "workflow_input_json"),
            ("/recent_runs/0", "authoritative_runtime_receipt"),
            ("/recent_runs/0", "authoritative_execution_audit"),
        ] {
            let mut missing = canonical_value.clone();
            assert!(
                json_object_at_mut(&mut missing, pointer)
                    .remove(required_field)
                    .is_some(),
                "fixture must contain {pointer}/{required_field}"
            );
            assert!(
                norito::json::from_value::<AgentAutonomyStatusResponse>(missing).is_err(),
                "agent autonomy status graph must require {pointer}/{required_field}"
            );
        }
        for pointer in ["", "/allowlist/0", "/recent_runs/0"] {
            let mut unknown = canonical_value.clone();
            json_object_at_mut(&mut unknown, pointer)
                .insert("legacy_field".to_owned(), norito::json::Value::Null);
            assert!(
                norito::json::from_value::<AgentAutonomyStatusResponse>(unknown).is_err(),
                "agent autonomy status graph must reject unknown fields at {pointer}"
            );
        }
    }
    fn checked_test_signature(private_key: &iroha_crypto::PrivateKey, payload: &[u8]) -> Signature {
        Signature::try_new(private_key, payload).expect("test fixture signing should succeed")
    }
    fn checked_test_keypair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("test fixture key derivation should succeed")
    }
    fn test_runtime() -> std::io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }
    #[test]
    fn fhe_policy_lifecycle_actions_keep_distinct_control_plane_identity() {
        for (source, expected, label) in [
            (
                SoraServiceLifecycleActionV1::FhePolicyRegister,
                SoracloudAction::FhePolicyRegister,
                "fhe_policy_register",
            ),
            (
                SoraServiceLifecycleActionV1::FhePolicyRotate,
                SoracloudAction::FhePolicyRotate,
                "fhe_policy_rotate",
            ),
            (
                SoraServiceLifecycleActionV1::FhePolicyRevoke,
                SoracloudAction::FhePolicyRevoke,
                "fhe_policy_revoke",
            ),
        ] {
            assert_eq!(audit_action_to_control_plane_action(source), expected);
            assert_eq!(soracloud_action_label(expected), label);
        }
    }
    fn checked_test_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm).unwrap_or_else(|err| {
            panic!("{algorithm:?} Soracloud fixture key generation should succeed: {err}")
        })
    }
    const SMALL_ORDER_ED25519_SIGNATURE_R: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const NONCANONICAL_ED25519_SIGNATURE_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    fn signature_with_malformed_ed25519_r(
        signature: &Signature,
        replacement_r: &[u8; 32],
    ) -> Signature {
        let mut payload = signature.payload().to_vec();
        payload[..replacement_r.len()].copy_from_slice(replacement_r);
        Signature::from_bytes(&payload)
    }
    #[test]
    fn checked_test_keypair_uses_fallible_seed_derivation() {
        assert_eq!(checked_test_keypair(0x50).algorithm(), Algorithm::Ed25519);
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
    #[test]
    fn soracloud_provenance_helper_rejects_malformed_ed25519_signature_r() {
        let keypair = checked_test_keypair(0x51);
        let payload = b"torii-soracloud-provenance";
        let signature = checked_test_signature(keypair.private_key(), payload);
        verify_signature_for_signer(&signature, keypair.public_key(), payload)
            .expect("valid Soracloud provenance signature should verify");
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_ED25519_SIGNATURE_R),
            ("noncanonical", NONCANONICAL_ED25519_SIGNATURE_R),
        ] {
            let malformed_signature =
                signature_with_malformed_ed25519_r(&signature, &replacement_r);
            assert_eq!(
                verify_signature_for_signer(&malformed_signature, keypair.public_key(), payload)
                    .expect_err("malformed Soracloud provenance signature R must fail admission"),
                iroha_crypto::Error::BadSignature,
                "{label} Soracloud provenance signature R was not rejected"
            );
        }
    }
    #[test]
    fn soracloud_provenance_helper_rejects_malformed_mldsa_signature_lengths() {
        let keypair = checked_test_keypair_with_algorithm(Algorithm::MlDsa);
        let payload = b"torii-soracloud-provenance-mldsa";
        let signature = checked_test_signature(keypair.private_key(), payload);
        verify_signature_for_signer(&signature, keypair.public_key(), payload)
            .expect("valid Soracloud ML-DSA provenance signature should verify");
        let valid_signature = signature.payload().to_vec();
        for (label, replacement_signature) in [
            (
                "short",
                valid_signature[..valid_signature.len() - 1].to_vec(),
            ),
            ("overlong", {
                let mut payload = valid_signature.clone();
                payload.push(0x63);
                payload
            }),
        ] {
            let malformed_signature = Signature::from_bytes(&replacement_signature);
            assert_eq!(
                verify_signature_for_signer(&malformed_signature, keypair.public_key(), payload)
                    .expect_err("malformed Soracloud ML-DSA signature length must fail admission"),
                iroha_crypto::Error::BadSignature,
                "{label} Soracloud ML-DSA signature length was not rejected"
            );
        }
    }
    fn workspace_fixture(path: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(path)
    }
    fn load_json<T>(path: &Path) -> T
    where
        T: norito::json::JsonDeserialize,
    {
        let bytes = fs::read(path).expect("read fixture");
        norito::json::from_slice(&bytes).expect("decode fixture")
    }
    fn fixture_bundle(version: &str) -> SoraDeploymentBundleV1 {
        let container: SoraContainerManifestV1 = load_json(&workspace_fixture(
            "fixtures/soracloud/sora_container_manifest_v1.json",
        ));
        let mut service: SoraServiceManifestV1 = load_json(&workspace_fixture(
            "fixtures/soracloud/sora_service_manifest_v1.json",
        ));
        service.service_version = version.to_string();
        service.container.manifest_hash = Hash::new(Encode::encode(&container));
        SoraDeploymentBundleV1 {
            schema_version: SORA_DEPLOYMENT_BUNDLE_VERSION_V1,
            container,
            service,
        }
    }
    fn fixture_inrou_placement_targets(
        count: u16,
    ) -> BTreeSet<iroha_data_model::soracloud::SoraInrouPlacementTargetV1> {
        (0..count)
            .map(|index| {
                let index = u8::try_from(index).expect("fixture target index fits u8");
                let validator_key_pair = KeyPair::try_from_seed(
                    vec![0x60_u8.wrapping_add(index); 32],
                    Algorithm::Ed25519,
                )
                .expect("fixture validator seed derives Ed25519 keypair");
                let peer_key_pair = KeyPair::try_from_seed(
                    vec![0x70_u8.wrapping_add(index); 32],
                    Algorithm::BlsNormal,
                )
                .expect("fixture peer seed derives BLS keypair");
                iroha_data_model::soracloud::SoraInrouPlacementTargetV1 {
                    validator_account_id: AccountId::new(validator_key_pair.public_key().clone()),
                    peer_id: iroha_model_base::peer::PeerId::from(
                        peer_key_pair.public_key().clone(),
                    )
                    .to_string(),
                }
            })
            .collect()
    }
    fn fixture_hosted_http_inrou_bundle(version: &str) -> SoraDeploymentBundleV1 {
        let mut bundle = fixture_bundle(version);
        bundle.container.runtime = iroha_data_model::soracloud::SoraContainerRuntimeV1::Inrou;
        bundle.container.capabilities.network = SoraNetworkPolicyV1::Isolated;
        bundle.container.entrypoint = "/app/main".to_owned();
        bundle.container.inrou = Some(iroha_data_model::soracloud::SoraInrouManifestV1 {
            schema_version: iroha_data_model::soracloud::SORA_INROU_MANIFEST_VERSION_V1,
            guest_images: BTreeMap::from([
                (
                    iroha_data_model::soracloud::SoraInrouGuestIsaV1::X8664,
                    iroha_data_model::soracloud::SoraInrouGuestImageV1 {
                        kernel_image_path: "/inrou/x86_64/vmlinux".to_owned(),
                        rootfs_image_path: "/inrou/x86_64/rootfs.ext4".to_owned(),
                        initrd_image_path: None,
                        published_artifact:
                            iroha_data_model::soracloud::SoraPublishedInrouGuestImageArtifactV1 {
                                manifest_digest_hex: "31".repeat(32),
                                content_cid:
                                    "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
                                        .to_owned(),
                            },
                    },
                ),
                (
                    iroha_data_model::soracloud::SoraInrouGuestIsaV1::Aarch64,
                    iroha_data_model::soracloud::SoraInrouGuestImageV1 {
                        kernel_image_path: "/inrou/aarch64/vmlinux".to_owned(),
                        rootfs_image_path: "/inrou/aarch64/rootfs.ext4".to_owned(),
                        initrd_image_path: None,
                        published_artifact:
                            iroha_data_model::soracloud::SoraPublishedInrouGuestImageArtifactV1 {
                                manifest_digest_hex: "32".repeat(32),
                                content_cid:
                                    "bafyr6ibsgizdemrsgizdemrsgizdemrsgizdemrsgizdemrsgizdemrsgi"
                                        .to_owned(),
                            },
                    },
                ),
            ]),
        });
        bundle.service.execution_plane =
            iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService;
        bundle.service.placement_targets =
            fixture_inrou_placement_targets(bundle.service.replicas.get());
        bundle.service.state_bindings.clear();
        bundle.service.handlers.clear();
        bundle.service.artifacts.clear();
        bundle.service.lease_volumes = vec![
            iroha_data_model::soracloud::SoraLeaseVolumeBindingV1 {
                volume_name: "root_disk".parse().expect("volume name"),
                kind: iroha_data_model::soracloud::SoraLeaseVolumeKindV1::PersistentRootLeaseVolume,
                storage_class: StorageClass::Warm,
                mount_path: "/".to_owned(),
                max_total_bytes: NonZeroU64::new(8 * 1024 * 1024 * 1024)
                    .expect("nonzero volume size"),
            },
            iroha_data_model::soracloud::SoraLeaseVolumeBindingV1 {
                volume_name: "service_state".parse().expect("volume name"),
                kind: iroha_data_model::soracloud::SoraLeaseVolumeKindV1::ServiceLeaseVolume,
                storage_class: StorageClass::Warm,
                mount_path: "/var/lib/soracloud/volumes/service_state".to_owned(),
                max_total_bytes: NonZeroU64::new(1024 * 1024).expect("nonzero volume size"),
            },
        ];
        bundle.service.container.manifest_hash = bundle.container_manifest_hash();
        bundle
            .validate_for_admission()
            .expect("hosted HTTP Inrou fixture must satisfy production validation");
        bundle
    }
    fn fixture_bundle_with_training(
        version: &str,
        allow_model_training: bool,
    ) -> SoraDeploymentBundleV1 {
        let mut bundle = fixture_bundle(version);
        bundle.container.capabilities.allow_model_training = allow_model_training;
        bundle.service.container.manifest_hash = bundle.container_manifest_hash();
        bundle
    }
    fn fixture_service_deployment(bundle: &SoraDeploymentBundleV1) -> SoraServiceDeploymentStateV1 {
        SoraServiceDeploymentStateV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_DEPLOYMENT_STATE_VERSION_V1,
            service_name: bundle.service.service_name.clone(),
            current_service_version: bundle.service.service_version.clone(),
            current_service_manifest_hash: bundle.service_manifest_hash(),
            current_container_manifest_hash: bundle.container_manifest_hash(),
            revision_count: 1,
            process_generation: 1,
            process_started_sequence: 1,
            active_rollout: None,
            last_rollout: None,
            config_generation: 0,
            secret_generation: 0,
            service_configs: BTreeMap::new(),
            service_secrets: BTreeMap::new(),
            fhe_policy_records: BTreeMap::new(),
            service_lease: None,
            lease_volume_states: Vec::new(),
        }
    }
    fn fixture_service_lease_volume_states(
        bundle: &SoraDeploymentBundleV1,
        lease: Option<&iroha_data_model::soracloud::SoraServiceLeaseStateV1>,
    ) -> Vec<iroha_data_model::soracloud::SoraServiceLeaseVolumeStateV1> {
        let Some(lease) = lease else {
            return Vec::new();
        };
        bundle
            .service
            .lease_volumes
            .iter()
            .map(
                |binding| iroha_data_model::soracloud::SoraServiceLeaseVolumeStateV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_SERVICE_LEASE_VOLUME_STATE_VERSION_V1,
                    economic_clock: lease.economic_clock,
                    volume_name: binding.volume_name.clone(),
                    kind: binding.kind,
                    storage_class: binding.storage_class,
                    mount_path: binding.mount_path.clone(),
                    max_total_bytes: binding.max_total_bytes.get(),
                    lease_started_height: lease.lease_started_height,
                    lease_expires_height: lease.lease_expires_height,
                    authoritative_generation: 1,
                },
            )
            .collect()
    }
    fn fixture_service_deploy_audit_event(
        bundle: &SoraDeploymentBundleV1,
    ) -> SoraServiceAuditEventV1 {
        SoraServiceAuditEventV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_AUDIT_EVENT_VERSION_V1,
            sequence: 1,
            block_height: 1,
            block_timestamp_ms: 1,
            action: SoraServiceLifecycleActionV1::Deploy,
            service_name: bundle.service.service_name.clone(),
            from_version: None,
            to_version: bundle.service.service_version.clone(),
            service_manifest_hash: bundle.service_manifest_hash(),
            container_manifest_hash: bundle.container_manifest_hash(),
            process_generation: 1,
            config_generation: 0,
            secret_generation: 0,
            config_snapshot_hash:
                iroha_data_model::soracloud::derive_soracloud_service_config_snapshot_hash_v1(
                    &BTreeMap::new(),
                ),
            secret_snapshot_hash:
                iroha_data_model::soracloud::derive_soracloud_service_secret_snapshot_hash_v1(
                    &BTreeMap::new(),
                ),
            governance_tx_hash: None,
            binding_name: None,
            state_key: None,
            config_mutations: Vec::new(),
            secret_mutations: Vec::new(),
            rollout_state: None,
            policy_name: None,
            policy_snapshot_hash: None,
            jurisdiction_tag: None,
            consent_evidence_hash: None,
            break_glass: None,
            break_glass_reason: None,
            lease_usage: None,
            service_lease_commitment: None,
            lease_reporting_epoch_rollover: None,
            signer: checked_test_keypair(0x5A).public_key().clone(),
        }
    }
    fn insert_revision(
        world: &mut iroha_core::state::World,
        bundle: &SoraDeploymentBundleV1,
        service_name: String,
    ) {
        world.soracloud_service_revisions_mut_for_testing().insert(
            (service_name, bundle.service.service_version.clone()),
            bundle.clone(),
        );
    }
    fn install_fixture_service(
        world: &mut iroha_core::state::World,
        bundle: &SoraDeploymentBundleV1,
        service_name: &Name,
    ) {
        insert_revision(world, bundle, service_name.as_ref().to_owned());
        world
            .soracloud_service_deployments_mut_for_testing()
            .insert(service_name.clone(), fixture_service_deployment(bundle));
    }
    fn fixture_fhe_job_spec() -> FheJobSpecV1 {
        load_json(&workspace_fixture(
            "fixtures/soracloud/fhe_job_spec_v1.json",
        ))
    }
    fn fixture_fhe_policy_reference() -> SoracloudFhePolicyReferenceV1 {
        SoracloudFhePolicyReferenceV1 {
            schema_version: iroha_data_model::soracloud::SORACLOUD_FHE_POLICY_REFERENCE_VERSION_V1,
            policy_name: "health_policy".parse().expect("policy name"),
            version: NonZeroU32::new(1).expect("non-zero policy version"),
            material_digest: Hash::new(b"governed-fhe-material-v1"),
        }
    }
    fn fixture_decryption_authority_policy() -> DecryptionAuthorityPolicyV1 {
        load_json(&workspace_fixture(
            "fixtures/soracloud/decryption_authority_policy_v1.json",
        ))
    }
    fn fixture_decryption_request() -> DecryptionRequestV1 {
        load_json(&workspace_fixture(
            "fixtures/soracloud/decryption_request_v1.json",
        ))
    }
    fn fixture_ciphertext_query_spec() -> CiphertextQuerySpecV1 {
        load_json(&workspace_fixture(
            "fixtures/soracloud/ciphertext_query_spec_v1.json",
        ))
    }
    fn hf_shared_lease_asset_definition() -> AssetDefinitionId {
        AssetDefinitionId::from_uuid_bytes([
            0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd,
            0xcd, 0x2f,
        ])
        .expect("valid asset definition")
    }
    fn decode_current_signed_request_frame<T>(request: &T, owner: &str) -> T
    where
        T: norito::NoritoSerialize
            + for<'de> norito::NoritoDeserialize<'de>
            + norito::json::JsonDeserializeOwned
            + 'static,
    {
        let bytes = crate::frame_test_support::assert_current_frame(request, owner);
        let mut wrong_owner = bytes.clone();
        wrong_owner[6] ^= 1;
        for invalid in [wrong_owner, bytes[..bytes.len() - 1].to_vec()] {
            let error = crate::utils::extractors::decode_body_as_norito_or_json::<T>(
                &axum::body::Bytes::from(invalid),
                crate::utils::TypedRequestContentFormat::Norito,
            )
            .err()
            .expect("invalid request frame must fail at the typed HTTP boundary");
            assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        }
        crate::utils::extractors::decode_body_as_norito_or_json::<T>(
            &axum::body::Bytes::from(bytes),
            crate::utils::TypedRequestContentFormat::Norito,
        )
        .expect("current signed request survives HTTP decoding")
    }
    #[test]
    fn signed_control_frames_preserve_provenance_and_reject_frame_owner_substitution() {
        let key_pair = checked_test_keypair(0x84);
        let rollback = signed_rollback_request("web_portal", "runtime", &key_pair);
        let mut rollback = decode_current_signed_request_frame(
            &rollback,
            "iroha_torii::soracloud::SignedRollbackRequest",
        );
        verify_rollback_signature(&rollback).expect("decoded rollback keeps its valid provenance");
        let payload = ServiceConfigDeleteRequest {
            service_name: rollback.payload.service_name.clone(),
            config_name: rollback.payload.target_version.clone(),
        };
        let signed_payload = encode_service_config_delete_signature_payload(&payload)
            .expect("encode current config-delete signature transcript");
        let delete = SignedServiceConfigDeleteRequest {
            payload,
            provenance: ManifestProvenance {
                signer: key_pair.public_key().clone(),
                signature: checked_test_signature(key_pair.private_key(), &signed_payload),
            },
        };
        let delete = decode_current_signed_request_frame(
            &delete,
            "iroha_torii::soracloud::SignedServiceConfigDeleteRequest",
        );
        verify_service_config_delete_signature(&delete)
            .expect("decoded config deletion keeps its own valid provenance");
        assert_ne!(
            norito::schema::identity::frame_hash::<SignedRollbackRequest>(),
            norito::schema::identity::frame_hash::<SignedServiceConfigDeleteRequest>(),
        );
        // HTTP frame ownership is distinct even though these existing provenance
        // transcripts have the same two-string tuple layout.
        let rollback_frame = norito::encode_canonical(&rollback).expect("rollback frame");
        assert!(matches!(
            norito::decode_canonical::<SignedServiceConfigDeleteRequest>(&rollback_frame),
            Err(norito::Error::SchemaMismatch),
        ));
        rollback.payload.target_version.push_str("-tampered");
        assert!(verify_rollback_signature(&rollback).is_err());
    }
    fn signed_rollback_request(
        service_name: &str,
        target_version: &str,
        key_pair: &KeyPair,
    ) -> SignedRollbackRequest {
        let payload = RollbackPayload {
            service_name: service_name.to_string(),
            target_version: target_version.to_owned(),
        };
        let encoded = encode_rollback_signature_payload(&payload).expect("encode rollback payload");
        let signature = checked_test_signature(key_pair.private_key(), &encoded);
        SignedRollbackRequest {
            payload,
            provenance: ManifestProvenance {
                signer: key_pair.public_key().clone(),
                signature,
            },
        }
    }
    fn verified_request_headers(account: &AccountId, signer: &PublicKey) -> axum::http::HeaderMap {
        verified_request_headers_with_signers(account, signer, std::slice::from_ref(signer))
    }
    fn verified_request_headers_with_signers(
        account: &AccountId,
        signer: &PublicKey,
        verified_signers: &[PublicKey],
    ) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            VERIFIED_ACCOUNT_HEADER,
            axum::http::HeaderValue::from_bytes(account.to_string().as_bytes())
                .expect("valid utf-8 account header"),
        );
        headers.insert(
            VERIFIED_SIGNER_HEADER,
            signer.to_string().parse().expect("valid signer header"),
        );
        headers.insert(
            VERIFIED_SIGNERS_HEADER,
            BASE64_STANDARD
                .encode(norito::to_bytes(&verified_signers.to_vec()).expect("encode signers"))
                .parse()
                .expect("valid signer-set header"),
        );
        headers
    }

    fn fixture_agent_run_record(
        apartment_name: &str,
        run_id: &str,
        approved_sequence: u64,
        process_generation: u64,
    ) -> SoraAgentAutonomyRunRecordV1 {
        let artifact_hash = "hash:artifact#1".to_owned();
        let provenance_hash = Some("hash:prov#1".to_owned());
        let budget_units = 25;
        let run_label = "nightly".to_owned();
        let workflow_input_json = Some("{\"inputs\":\"nightly\"}".to_owned());
        let request_commitment =
            iroha_data_model::soracloud::derive_agent_autonomy_request_commitment(
                apartment_name,
                &artifact_hash,
                provenance_hash.as_deref(),
                budget_units,
                run_id,
                &run_label,
                workflow_input_json.as_deref(),
                process_generation,
            );
        SoraAgentAutonomyRunRecordV1 {
            run_id: run_id.to_owned(),
            artifact_hash,
            provenance_hash,
            budget_units,
            run_label,
            workflow_input_json,
            approved_process_generation: process_generation,
            request_commitment,
            approved_sequence,
        }
    }
    fn fixture_autonomy_approval_event(
        apartment_name: &str,
        manifest_hash: Hash,
        signer: &KeyPair,
        run: &SoraAgentAutonomyRunRecordV1,
    ) -> SoraAgentApartmentAuditEventV1 {
        SoraAgentApartmentAuditEventV1 {
            schema_version: SORA_AGENT_APARTMENT_AUDIT_EVENT_VERSION_V1,
            sequence: run.approved_sequence,
            block_height: run.approved_sequence,
            block_timestamp_ms: run.approved_sequence,
            action: SoraAgentApartmentActionV1::AutonomyRunApproved,
            apartment_name: apartment_name.parse().expect("valid apartment name"),
            status: SoraAgentRuntimeStatusV1::Running,
            lease_expires_height: 100,
            manifest_hash,
            restart_count: 0,
            signer: signer.public_key().clone(),
            request_id: Some(run.run_id.clone()),
            asset_definition: None,
            amount: None,
            capability: None,
            reason: None,
            from_apartment: None,
            to_apartment: None,
            channel: None,
            payload_hash: None,
            artifact_hash: Some(run.artifact_hash.clone()),
            provenance_hash: run.provenance_hash.clone(),
            run_id: Some(run.run_id.clone()),
            run_label: Some(run.run_label.clone()),
            budget_units: Some(run.budget_units),
            service_name: None,
            service_version: None,
            handler_name: None,
            result_commitment: None,
            runtime_receipt_id: None,
            journal_artifact_hash: None,
            checkpoint_artifact_hash: None,
            succeeded: None,
        }
    }
    #[test]
    fn agent_execution_audit_projection_fails_closed_without_authoritative_outcome_fields() {
        let signer = checked_test_keypair(0x5B);
        let run = fixture_agent_run_record("ops_agent", "ops_agent:autonomy:1", 1, 1);
        let mut event = fixture_autonomy_approval_event(
            "ops_agent",
            Hash::new(b"agent manifest"),
            &signer,
            &run,
        );
        event.action = SoraAgentApartmentActionV1::AutonomyRunExecuted;
        event.result_commitment = Some(Hash::new(b"execution result"));
        let error = authoritative_agent_execution_audit_record(&event)
            .expect_err("missing authoritative succeeded projection must fail closed");
        assert_eq!(error.kind, SoracloudErrorKind::Internal);
        assert!(error.message.contains("missing `succeeded`"));

        event.succeeded = Some(false);
        event.result_commitment = None;
        let error = authoritative_agent_execution_audit_record(&event)
            .expect_err("missing authoritative result commitment must fail closed");
        assert_eq!(error.kind, SoracloudErrorKind::Internal);
        assert!(error.message.contains("missing `result_commitment`"));
    }
    fn seed_domain_name_lease(
        world: &mut iroha_core::state::World,
        owner: &AccountId,
        domain_id: &iroha_model_base::domain::DomainId,
    ) {
        let selector = iroha_core::sns::selector_for_domain(domain_id).expect("domain selector");
        let address =
            iroha_data_model::account::AccountAddress::from_account_id(owner).expect("address");
        let record = NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        world.smart_contract_state_mut_for_testing().insert(
            iroha_core::sns::record_storage_key(&selector),
            Encode::encode(&record),
        );
    }
    #[test]
    fn signed_mutation_request_rejects_inline_signing_material() {
        let key_pair = checked_test_keypair(0x60);
        let request = signed_rollback_request("inline-secret-test", "1.0.0", &key_pair);
        let mut payload = norito::json::Map::new();
        payload.insert(
            "service_name".to_owned(),
            norito::json::Value::from(request.payload.service_name),
        );
        payload.insert(
            "target_version".to_owned(),
            norito::json::Value::from(request.payload.target_version),
        );
        let mut fields = norito::json::Map::new();
        fields.insert("payload".to_owned(), norito::json::Value::Object(payload));
        fields.insert(
            "provenance".to_owned(),
            norito::json::to_value(&request.provenance)
                .expect("serialize valid request provenance"),
        );
        fields.insert(
            "authority".to_owned(),
            norito::json::Value::from("inline-authority-is-forbidden"),
        );
        let error =
            norito::json::from_value::<SignedRollbackRequest>(norito::json::Value::Object(fields))
                .expect_err("inline signing material must be rejected during decoding");
        assert!(
            error.to_string().contains("unknown field `authority`"),
            "unexpected inline-authority rejection: {error}"
        );
    }
    #[test]
    fn rollback_payload_requires_explicit_target_version() {
        for payload in [
            r#"{"service_name":"web_portal"}"#,
            r#"{"service_name":"web_portal","target_version":null}"#,
        ] {
            norito::json::from_str::<RollbackPayload>(payload)
                .expect_err("missing or null target_version must be rejected");
        }
    }
    #[test]
    fn rollback_payload_rejects_retired_history_fields() {
        let error = norito::json::from_str::<RollbackPayload>(
            r#"{"service_name":"web_portal","target_version":"1.0.0","previous_service_version":"0.9.0"}"#,
        )
        .expect_err("retired rollback history inference field must be rejected");
        assert!(
            error
                .to_string()
                .contains("unknown field `previous_service_version`"),
            "unexpected retired rollback field rejection: {error}"
        );
    }
    #[test]
    fn signed_bundle_request_requires_explicit_material_maps_and_precondition() {
        let request = SignedBundleRequest {
            bundle: fixture_bundle("1.0.0"),
            initial_service_configs: BTreeMap::new(),
            initial_service_secrets: BTreeMap::new(),
            precondition: SoraServiceMutationPreconditionV1::ServiceAbsent,
            provenance: signed_rollback_request(
                "web_portal",
                "1.0.0",
                &iroha_test_samples::ALICE_KEYPAIR,
            )
            .provenance,
        };
        let mut fields = norito::json::Map::new();
        fields.insert(
            "bundle".to_owned(),
            norito::json::to_value(&request.bundle).expect("serialize bundle"),
        );
        fields.insert(
            "initial_service_configs".to_owned(),
            norito::json::to_value(&request.initial_service_configs)
                .expect("serialize initial configs"),
        );
        fields.insert(
            "initial_service_secrets".to_owned(),
            norito::json::to_value(&request.initial_service_secrets)
                .expect("serialize initial secrets"),
        );
        fields.insert(
            "precondition".to_owned(),
            norito::json::to_value(&request.precondition).expect("serialize precondition"),
        );
        fields.insert(
            "provenance".to_owned(),
            norito::json::to_value(&request.provenance).expect("serialize provenance"),
        );
        let canonical = norito::json::Value::Object(fields);
        norito::json::from_value::<SignedBundleRequest>(canonical.clone())
            .expect("canonical signed bundle request must decode");

        for field in [
            "initial_service_configs",
            "initial_service_secrets",
            "precondition",
        ] {
            let mut missing = canonical.clone();
            assert!(
                missing
                    .as_object_mut()
                    .expect("signed bundle request JSON object")
                    .remove(field)
                    .is_some()
            );
            norito::json::from_value::<SignedBundleRequest>(missing)
                .expect_err("omitted signed bundle field must be rejected");

            let mut null = canonical.clone();
            null.as_object_mut()
                .expect("signed bundle request JSON object")
                .insert(field.to_owned(), norito::json::Value::Null);
            norito::json::from_value::<SignedBundleRequest>(null)
                .expect_err("null signed bundle field must be rejected");
        }
    }
    #[test]
    fn signed_app_infra_request_requires_explicit_service_vectors_and_closed_fields() {
        let manifest = SoraAppInfraManifestV1 {
            schema_version: iroha_data_model::soracloud::SORA_APP_INFRA_MANIFEST_VERSION_V1,
            app_name: "web_portal".parse().expect("valid app name"),
            app_version: "1.0.0".to_owned(),
            public_url: "https://web-portal.example".to_owned(),
            static_site: None,
            services: Vec::new(),
        };
        let provenance =
            signed_rollback_request("web_portal", "1.0.0", &iroha_test_samples::ALICE_KEYPAIR)
                .provenance;
        let mut fields = norito::json::Map::new();
        fields.insert("deploy_services".to_owned(), norito::json!([]));
        fields.insert("upgrade_services".to_owned(), norito::json!([]));
        fields.insert(
            "manifest".to_owned(),
            norito::json::to_value(&manifest).expect("serialize app manifest"),
        );
        fields.insert(
            "precondition".to_owned(),
            norito::json::to_value(&SoraAppInfraMutationPreconditionV1::AppAbsent)
                .expect("serialize app precondition"),
        );
        fields.insert(
            "provenance".to_owned(),
            norito::json::to_value(&provenance).expect("serialize app provenance"),
        );
        let canonical = norito::json::Value::Object(fields);
        norito::json::from_value::<SignedAppInfraRequest>(canonical.clone())
            .expect("canonical signed app request must decode");

        for field in ["deploy_services", "upgrade_services", "precondition"] {
            let mut missing = canonical.clone();
            assert!(
                missing
                    .as_object_mut()
                    .expect("signed app request JSON object")
                    .remove(field)
                    .is_some()
            );
            norito::json::from_value::<SignedAppInfraRequest>(missing)
                .expect_err("signed app request must reject an omitted required field");

            let mut null = canonical.clone();
            null.as_object_mut()
                .expect("signed app request JSON object")
                .insert(field.to_owned(), norito::json::Value::Null);
            norito::json::from_value::<SignedAppInfraRequest>(null)
                .expect_err("signed app request must reject a null required field");
        }

        let mut unknown = canonical;
        unknown
            .as_object_mut()
            .expect("signed app request JSON object")
            .insert("retired_v0".to_owned(), norito::json::Value::from(true));
        norito::json::from_value::<SignedAppInfraRequest>(unknown)
            .expect_err("signed app request must reject unknown fields");
    }
    #[test]
    fn service_control_payloads_are_closed_and_state_nulls_are_explicit() {
        macro_rules! assert_closed_value {
            ($value:expr, $ty:ty, $label:literal) => {{
                let value = $value;
                norito::json::from_value::<$ty>(value.clone()).expect(concat!(
                    "canonical ",
                    $label,
                    " must decode"
                ));
                let mut unknown = value;
                unknown
                    .as_object_mut()
                    .expect(concat!($label, " JSON object"))
                    .insert("retired_v0".to_owned(), norito::json::Value::from(true));
                norito::json::from_value::<$ty>(unknown)
                    .expect_err(concat!($label, " must reject unknown fields"));
            }};
        }

        let operation =
            norito::json::to_value(&StateMutationOperation::Delete).expect("serialize operation");
        assert_closed_value!(
            operation.clone(),
            StateMutationOperation,
            "state mutation operation"
        );
        let encryption = norito::json::to_value(&SoraStateEncryptionV1::ClientCiphertext)
            .expect("serialize state encryption");
        let governance_tx_hash = Hash::new(b"governance");
        let mut state_fields = norito::json::Map::new();
        state_fields.insert(
            "service_name".to_owned(),
            norito::json::Value::from("web_portal"),
        );
        state_fields.insert(
            "binding_name".to_owned(),
            norito::json::Value::from("private_state"),
        );
        state_fields.insert("key".to_owned(), norito::json::Value::from("/state/1"));
        state_fields.insert("operation".to_owned(), operation);
        state_fields.insert("value_size_bytes".to_owned(), norito::json::Value::Null);
        state_fields.insert("value_payload_hex".to_owned(), norito::json::Value::Null);
        state_fields.insert("encryption".to_owned(), encryption);
        state_fields.insert(
            "governance_tx_hash".to_owned(),
            norito::json::to_value(&governance_tx_hash).expect("serialize governance hash"),
        );
        state_fields.insert(
            "fhe_input_admission_proof".to_owned(),
            norito::json::Value::Null,
        );
        let state = norito::json::Value::Object(state_fields);
        assert_closed_value!(
            state.clone(),
            StateMutationRequest,
            "state mutation payload"
        );
        for field in [
            "value_size_bytes",
            "value_payload_hex",
            "fhe_input_admission_proof",
        ] {
            let mut missing = state.clone();
            assert!(
                missing
                    .as_object_mut()
                    .expect("state mutation JSON object")
                    .remove(field)
                    .is_some()
            );
            norito::json::from_value::<StateMutationRequest>(missing)
                .expect_err("state mutation payload must reject an omitted nullable key");

            let mut explicit_null = state.clone();
            explicit_null
                .as_object_mut()
                .expect("state mutation JSON object")
                .insert(field.to_owned(), norito::json::Value::Null);
            norito::json::from_value::<StateMutationRequest>(explicit_null)
                .expect("state mutation payload must accept an explicit null key");
        }

        assert_closed_value!(
            norito::json!({
                "service_name": "web_portal",
                "config_name": "runtime",
                "value_json": {"workers": 2_u64}
            }),
            ServiceConfigSetRequest,
            "service config set payload"
        );
        assert_closed_value!(
            norito::json!({
                "service_name": "web_portal",
                "config_name": "runtime"
            }),
            ServiceConfigDeleteRequest,
            "service config delete payload"
        );
        let secret = SecretEnvelopeV1 {
            schema_version: iroha_data_model::soracloud::SECRET_ENVELOPE_VERSION_V1,
            encryption: SecretEnvelopeEncryptionV1::ClientCiphertext,
            key_id: "kms/test".to_owned(),
            key_version: std::num::NonZeroU32::new(1).expect("non-zero key version"),
            nonce: vec![1],
            ciphertext: vec![2],
            commitment: Hash::new(b"secret"),
            aad_digest: None,
        };
        let mut secret_set = norito::json::Map::new();
        secret_set.insert(
            "service_name".to_owned(),
            norito::json::Value::from("web_portal"),
        );
        secret_set.insert(
            "secret_name".to_owned(),
            norito::json::Value::from("api_token"),
        );
        secret_set.insert(
            "secret".to_owned(),
            norito::json::to_value(&secret).expect("serialize secret envelope"),
        );
        assert_closed_value!(
            norito::json::Value::Object(secret_set),
            ServiceSecretSetRequest,
            "service secret set payload"
        );
        assert_closed_value!(
            norito::json!({
                "service_name": "web_portal",
                "secret_name": "api_token"
            }),
            ServiceSecretDeleteRequest,
            "service secret delete payload"
        );
    }
    #[test]
    fn signed_soracloud_mutation_graph_rejects_unknown_fields() {
        macro_rules! assert_unknown_rejected {
            ($($ty:ty),+ $(,)?) => {
                $(
                    let error = norito::json::from_str::<$ty>(r#"{"retired_v0":true}"#)
                        .expect_err(concat!(stringify!($ty), " must reject unknown fields"));
                    assert!(
                        matches!(
                            error,
                            norito::json::Error::UnknownField { ref field }
                                if field == "retired_v0"
                        ),
                        "{} reported the wrong error: {error}",
                        stringify!($ty)
                    );
                )+
            };
        }
        assert_unknown_rejected!(
            SignedBundleRequest,
            SignedAppInfraRequest,
            RollbackPayload,
            SignedRollbackRequest,
            StateMutationOperation,
            StateMutationRequest,
            SignedStateMutationRequest,
            ServiceConfigSetRequest,
            SignedServiceConfigSetRequest,
            ServiceConfigDeleteRequest,
            SignedServiceConfigDeleteRequest,
            ServiceSecretSetRequest,
            SignedServiceSecretSetRequest,
            ServiceSecretDeleteRequest,
            SignedServiceSecretDeleteRequest,
            RolloutAdvancePayload,
            SignedRolloutAdvanceRequest,
            AgentDeployPayload,
            SignedAgentDeployRequest,
            AgentLeaseRenewPayload,
            SignedAgentLeaseRenewRequest,
            HfSharedLeaseJoinPayload,
            SignedHfSharedLeaseJoinRequest,
            HfLeaseLeavePayload,
            SignedHfLeaseLeaveRequest,
            HfLeaseRenewPayload,
            SignedHfLeaseRenewRequest,
            AgentRestartPayload,
            SignedAgentRestartRequest,
            AgentPolicyRevokePayload,
            SignedAgentPolicyRevokeRequest,
            AgentWalletSpendPayload,
            SignedAgentWalletSpendRequest,
            AgentWalletApprovePayload,
            SignedAgentWalletApproveRequest,
            AgentMessageSendPayload,
            SignedAgentMessageSendRequest,
            AgentMessageAckPayload,
            SignedAgentMessageAckRequest,
            AgentArtifactAllowPayload,
            SignedAgentArtifactAllowRequest,
            FheJobRunPayload,
            SignedFheJobRunRequest,
            TrainingJobStartPayload,
            SignedTrainingJobStartRequest,
            TrainingJobCheckpointPayload,
            SignedTrainingJobCheckpointRequest,
            TrainingJobRetryPayload,
            SignedTrainingJobRetryRequest,
            ModelWeightRegisterPayload,
            SignedModelWeightRegisterRequest,
            ModelWeightPromotePayload,
            SignedModelWeightPromoteRequest,
            ModelWeightRollbackPayload,
            SignedModelWeightRollbackRequest,
            ModelArtifactRegisterPayload,
            SignedModelArtifactRegisterRequest,
            UploadedModelRegisterPayload,
            SignedUploadedModelRegisterRequest,
            DecryptionRequestPayload,
            SignedDecryptionRequest,
            SignedCiphertextQueryRequest,
        );
    }
    #[test]
    fn signed_soracloud_mutation_graph_requires_explicit_optional_keys() {
        macro_rules! assert_required_nullable {
            ($value:expr, $ty:ty, [$($field:literal),+ $(,)?], $label:literal) => {{
                let canonical = norito::json::to_value(&$value)
                    .expect(concat!("serialize canonical ", $label));
                norito::json::from_value::<$ty>(canonical.clone())
                    .expect(concat!("canonical ", $label, " must decode"));
                for field in [$($field),+] {
                    assert!(
                        canonical.get(field).is_some_and(norito::json::Value::is_null),
                        "{} must serialize `{field}` as explicit null",
                        $label
                    );
                    let mut missing = canonical.clone();
                    missing
                        .as_object_mut()
                        .expect(concat!($label, " JSON object"))
                        .remove(field);
                    norito::json::from_value::<$ty>(missing)
                        .expect_err(concat!($label, " must reject an omitted nullable key"));

                    let mut explicit_null = canonical.clone();
                    explicit_null
                        .as_object_mut()
                        .expect(concat!($label, " JSON object"))
                        .insert(field.to_owned(), norito::json::Value::Null);
                    norito::json::from_value::<$ty>(explicit_null)
                        .expect(concat!($label, " must accept explicit null"));
                }
            }};
        }

        let agent_deploy = AgentDeployPayload {
            manifest: fixture_agent_manifest(),
            lease_blocks: 120,
            autonomy_budget_units: 500,
        };
        let mut missing_budget =
            norito::json::to_value(&agent_deploy).expect("serialize agent deploy payload");
        missing_budget
            .as_object_mut()
            .expect("agent deploy payload object")
            .remove("autonomy_budget_units");
        norito::json::from_value::<AgentDeployPayload>(missing_budget)
            .expect_err("agent deployment must not infer an autonomy budget");

        let hf_shared_lease_join = HfSharedLeaseJoinPayload {
            repo_id: "openai/gpt-oss".to_owned(),
            revision: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            service_name: "vision_portal".to_owned(),
            apartment_name: None,
            storage_class: StorageClass::Warm,
            lease_term_ms: 604_800_000,
            lease_asset_definition_id: hf_shared_lease_asset_definition(),
            base_fee: "0.0000000001".parse().expect("canonical quantity"),
        };
        assert_required_nullable!(
            hf_shared_lease_join.clone(),
            HfSharedLeaseJoinPayload,
            ["apartment_name"],
            "HF shared-lease join payload"
        );
        assert_required_nullable!(
            HfLeaseLeavePayload {
                repo_id: hf_shared_lease_join.repo_id.clone(),
                revision: hf_shared_lease_join.revision.clone(),
                storage_class: StorageClass::Warm,
                lease_term_ms: hf_shared_lease_join.lease_term_ms,
                service_name: None,
                apartment_name: None,
            },
            HfLeaseLeavePayload,
            ["service_name", "apartment_name"],
            "HF lease-leave payload"
        );
        let hf_renew = HfLeaseRenewPayload {
            repo_id: hf_shared_lease_join.repo_id.clone(),
            revision: hf_shared_lease_join.revision.clone(),
            service_name: hf_shared_lease_join.service_name.clone(),
            apartment_name: None,
            storage_class: hf_shared_lease_join.storage_class,
            lease_term_ms: hf_shared_lease_join.lease_term_ms,
            lease_asset_definition_id: hf_shared_lease_join.lease_asset_definition_id.clone(),
            base_fee: hf_shared_lease_join.base_fee.clone(),
        };
        assert_required_nullable!(
            hf_renew.clone(),
            HfLeaseRenewPayload,
            ["apartment_name"],
            "HF lease-renew payload"
        );

        let key_pair = checked_test_keypair(0xE1);
        let provenance = ManifestProvenance {
            signer: key_pair.public_key().clone(),
            signature: checked_test_signature(key_pair.private_key(), b"hf request schema"),
        };
        for (request, label) in [
            (
                norito::json::to_value(&SignedHfSharedLeaseJoinRequest {
                    payload: hf_shared_lease_join,
                    provenance: provenance.clone(),
                })
                .expect("serialize signed HF shared-lease join request"),
                "signed HF shared-lease join request",
            ),
            (
                norito::json::to_value(&SignedHfLeaseRenewRequest {
                    payload: hf_renew,
                    provenance,
                })
                .expect("serialize signed HF lease-renew request"),
                "signed HF lease-renew request",
            ),
        ] {
            let object = request.as_object().expect("signed HF request object");
            assert_eq!(object.len(), 2, "{label} must contain exactly two keys");
            assert!(object.contains_key("payload"));
            assert!(object.contains_key("provenance"));
        }
        assert_required_nullable!(
            AgentPolicyRevokePayload {
                apartment_name: "ops_agent".to_owned(),
                capability: "agent.autonomy.run".to_owned(),
                reason: None,
            },
            AgentPolicyRevokePayload,
            ["reason"],
            "agent policy-revoke payload"
        );
        assert_required_nullable!(
            AgentArtifactAllowPayload {
                apartment_name: "ops_agent".to_owned(),
                artifact_hash: "hash:ABCD0123#01".to_owned(),
                provenance_hash: None,
            },
            AgentArtifactAllowPayload,
            ["provenance_hash"],
            "agent artifact-allow payload"
        );
        assert_required_nullable!(
            ModelWeightRegisterPayload {
                service_name: "web_portal".to_owned(),
                model_name: "model-1".to_owned(),
                weight_version: "1.0.0".to_owned(),
                training_job_id: "job-1".to_owned(),
                parent_version: None,
                weight_artifact_hash: Hash::new(b"weight-artifact"),
                dataset_ref: "dataset://synthetic/v2".to_owned(),
                training_config_hash: Hash::new(b"train-config"),
                reproducibility_hash: Hash::new(b"repro"),
                provenance_attestation_hash: Hash::new(b"attestation"),
            },
            ModelWeightRegisterPayload,
            ["parent_version"],
            "model-weight register payload"
        );
    }
    #[test]
    fn rollout_response_mirrors_are_closed_and_require_explicit_baseline() {
        macro_rules! assert_closed {
            ($value:expr, $ty:ty, $label:literal) => {{
                let mut value =
                    norito::json::to_value(&$value).expect(concat!("serialize canonical ", $label));
                norito::json::from_value::<$ty>(value.clone()).expect(concat!(
                    "canonical ",
                    $label,
                    " must decode"
                ));
                value
                    .as_object_mut()
                    .expect(concat!($label, " JSON object"))
                    .insert("retired_v0".to_owned(), norito::json::Value::from(true));
                norito::json::from_value::<$ty>(value)
                    .expect_err(concat!($label, " must reject unknown fields"));
            }};
        }
        assert_closed!(SoracloudAction::Deploy, SoracloudAction, "Soracloud action");
        assert_closed!(RolloutStage::Canary, RolloutStage, "rollout stage");

        let state = RolloutRuntimeState {
            rollout_handle: "web_portal:rollout:2".to_owned(),
            baseline_version: "1.0.0".to_owned(),
            candidate_version: "2.0.0".to_owned(),
            canary_percent: 10,
            traffic_percent: 10,
            stage: RolloutStage::Canary,
            health_failures: 0,
            max_health_failures: 3,
            health_window_secs: 30,
            created_sequence: 1,
            updated_sequence: 1,
        };
        assert_closed!(state.clone(), RolloutRuntimeState, "rollout runtime state");
        let canonical = norito::json::to_value(&state).expect("serialize rollout runtime state");
        assert!(
            canonical
                .get("baseline_version")
                .and_then(norito::json::Value::as_str)
                == Some("1.0.0")
        );
        let mut missing = canonical.clone();
        assert!(
            missing
                .as_object_mut()
                .expect("rollout runtime state JSON object")
                .remove("baseline_version")
                .is_some()
        );
        norito::json::from_value::<RolloutRuntimeState>(missing)
            .expect_err("rollout runtime state must reject omitted baseline_version");
        let mut explicit_null = canonical;
        explicit_null
            .as_object_mut()
            .expect("rollout runtime state JSON object")
            .insert("baseline_version".to_owned(), norito::json::Value::Null);
        norito::json::from_value::<RolloutRuntimeState>(explicit_null)
            .expect_err("rollout runtime state must reject null baseline_version");
    }
    #[test]
    fn service_control_response_types_reject_unknown_fields() {
        macro_rules! assert_unknown_rejected {
            ($($ty:ty),+ $(,)?) => {
                $(
                    let error = norito::json::from_str::<$ty>(r#"{"retired_v0":true}"#)
                        .expect_err(concat!(stringify!($ty), " must reject unknown fields"));
                    assert!(
                        matches!(
                            error,
                            norito::json::Error::UnknownField { ref field }
                                if field == "retired_v0"
                        ),
                        "{} reported the wrong error: {error}",
                        stringify!($ty)
                    );
                )+
            };
        }
        assert_unknown_rejected!(
            ServiceConfigStatusQuery,
            ServiceConfigStatusEntry,
            ServiceConfigStatusResponse,
            ServiceSecretStatusQuery,
            ServiceSecretStatusEntry,
            ServiceSecretStatusResponse,
            CiphertextQueryResponse,
            ControlPlaneSnapshot,
            ControlPlaneServiceLeaseSnapshot,
            ControlPlaneServiceSnapshot,
            ControlPlaneServiceRevision,
            ControlPlaneAuditEvent,
        );
    }
    #[test]
    fn soracloud_torii_json_graph_rejects_unknown_fields() {
        macro_rules! assert_unknown_rejected {
            ($($ty:ty),+ $(,)?) => {
                $(
                    let error = norito::json::from_str::<$ty>(r#"{"retired_v0":true}"#)
                        .expect_err(concat!(stringify!($ty), " must reject unknown fields"));
                    assert!(
                        matches!(
                            error,
                            norito::json::Error::UnknownField { ref field }
                                if field == "retired_v0"
                        ),
                        "{} reported the wrong error: {error}",
                        stringify!($ty)
                    );
                )+
            };
        }

        assert_unknown_rejected!(
            AgentRuntimeStatus,
            TrainingJobStatus,
            AppInfraStatusQuery,
            TrainingJobStatusResponse,
            TrainingJobStatusEntry,
            ModelWeightStatusResponse,
            ModelWeightStatusEntry,
            ModelWeightVersionEntry,
            ModelArtifactStatusResponse,
            ModelArtifactStatusEntry,
            UploadedModelStatusResponse,
            HfSharedLeaseStatusResponse,
            HealthComplianceReportQuery,
            TrainingJobStatusQuery,
            ModelWeightStatusQuery,
            ModelArtifactStatusQuery,
            UploadedModelStatusQuery,
            HfSharedLeaseStatusQuery,
            AgentAutonomyStatusQuery,
            AgentStatusQuery,
            AgentMailboxStatusQuery,
            HealthComplianceReportResponse,
            HealthAccessAuditEntry,
            HealthJurisdictionStat,
            HealthDataFlowAttestation,
            HealthPolicyDiffEntry,
            SoracloudPublicServiceDiscoveryV1,
            SoracloudPublicServiceDiscoveryRegistryV1,
            ServicePublicDiscoveryResponse,
            CiphertextRuntimeRecord,
            AgentStatusResponse,
            AgentApartmentStatusEntry,
            AgentMailboxStatusResponse,
            AgentMailboxMessageEntry,
            SoracloudMutationDraftResponse,
            SoracloudTxInstruction,
        );
    }
    #[test]
    fn soracloud_torii_body_keys_are_explicit_and_query_absence_is_semantic() {
        macro_rules! assert_explicit_body_keys {
            ($value:expr, $ty:ty, nulls = [$($nullable:literal),* $(,)?], collections = [$($collection:literal),* $(,)?], $label:literal) => {{
                let canonical = norito::json::to_value(&$value)
                    .expect(concat!("serialize canonical ", $label));
                norito::json::from_value::<$ty>(canonical.clone())
                    .expect(concat!("canonical ", $label, " must decode"));
                $(
                    assert!(
                        canonical
                            .get($nullable)
                            .is_some_and(norito::json::Value::is_null),
                        "{} must serialize `{}` as explicit null",
                        $label,
                        $nullable
                    );
                    let mut missing = canonical.clone();
                    missing
                        .as_object_mut()
                        .expect(concat!($label, " JSON object"))
                        .remove($nullable);
                    norito::json::from_value::<$ty>(missing)
                        .expect_err(concat!($label, " must reject an omitted nullable key"));
                )*
                $(
                    assert!(
                        canonical
                            .get($collection)
                            .and_then(norito::json::Value::as_array)
                            .is_some_and(Vec::is_empty),
                        "{} must serialize `{}` as an explicit empty list",
                        $label,
                        $collection
                    );
                    let mut missing = canonical.clone();
                    missing
                        .as_object_mut()
                        .expect(concat!($label, " JSON object"))
                        .remove($collection);
                    norito::json::from_value::<$ty>(missing)
                        .expect_err(concat!($label, " must reject an omitted collection key"));
                )*
            }};
        }

        assert_explicit_body_keys!(
            ModelWeightStatusEntry {
                service_name: "model_registry".to_owned(),
                model_name: "model-1".to_owned(),
                current_version: None,
                version_count: 0,
                versions: Vec::new(),
            },
            ModelWeightStatusEntry,
            nulls = ["current_version"],
            collections = ["versions"],
            "model-weight status entry"
        );
        assert_explicit_body_keys!(
            HealthComplianceReportResponse {
                schema_version: CONTROL_PLANE_SCHEMA_VERSION,
                service_name: None,
                jurisdiction_tag: None,
                generated_at_sequence: 0,
                total_access_events: 0,
                break_glass_events: 0,
                non_break_glass_events: 0,
                consent_evidence_present_events: 0,
                consent_evidence_coverage_bps: 0,
                recent_access_events: Vec::new(),
                jurisdiction_stats: Vec::new(),
                data_flow_attestations: Vec::new(),
                policy_diff_history: Vec::new(),
            },
            HealthComplianceReportResponse,
            nulls = ["service_name", "jurisdiction_tag"],
            collections = [
                "recent_access_events",
                "jurisdiction_stats",
                "data_flow_attestations",
                "policy_diff_history",
            ],
            "health compliance report"
        );
    }
    #[test]
    fn service_control_response_keys_are_explicit() {
        macro_rules! assert_required_nullable {
            ($value:expr, $ty:ty, [$($field:literal),+ $(,)?], $label:literal) => {{
                let canonical = norito::json::to_value(&$value)
                    .expect(concat!("serialize canonical ", $label));
                norito::json::from_value::<$ty>(canonical.clone())
                    .expect(concat!("canonical ", $label, " must decode"));
                for field in [$($field),+] {
                    let mut missing = canonical.clone();
                    assert!(
                        missing
                            .as_object_mut()
                            .expect(concat!($label, " JSON object"))
                            .remove(field)
                            .is_some()
                    );
                    norito::json::from_value::<$ty>(missing)
                        .expect_err(concat!($label, " must reject an omitted nullable key"));

                    let mut explicit_null = canonical.clone();
                    explicit_null
                        .as_object_mut()
                        .expect(concat!($label, " JSON object"))
                        .insert(field.to_owned(), norito::json::Value::Null);
                    norito::json::from_value::<$ty>(explicit_null)
                        .expect(concat!($label, " must accept an explicit null key"));
                }
            }};
        }
        macro_rules! assert_required_collection {
            ($value:expr, $ty:ty, [$($field:literal),+ $(,)?], $label:literal) => {{
                let canonical = norito::json::to_value(&$value)
                    .expect(concat!("serialize canonical ", $label));
                norito::json::from_value::<$ty>(canonical.clone())
                    .expect(concat!("canonical ", $label, " must decode"));
                for field in [$($field),+] {
                    let mut missing = canonical.clone();
                    assert!(
                        missing
                            .as_object_mut()
                            .expect(concat!($label, " JSON object"))
                            .remove(field)
                            .is_some()
                    );
                    norito::json::from_value::<$ty>(missing)
                        .expect_err(concat!($label, " must reject an omitted collection key"));

                    let mut null = canonical.clone();
                    null.as_object_mut()
                        .expect(concat!($label, " JSON object"))
                        .insert(field.to_owned(), norito::json::Value::Null);
                    norito::json::from_value::<$ty>(null)
                        .expect_err(concat!($label, " must reject a null collection key"));
                }
            }};
        }

        let bundle = fixture_bundle("1.0.0");
        let deployment = fixture_service_deployment(&bundle);
        let audit = fixture_service_deploy_audit_event(&bundle);
        let world = iroha_core::state::World::new();
        let revision = deployment_bundle_to_control_plane_revision(
            &world.view(),
            &deployment,
            &bundle,
            Some(&audit),
            None,
        )
        .expect("valid fixture revision should project");
        assert_required_nullable!(
            revision.clone(),
            ControlPlaneServiceRevision,
            [
                "route_host",
                "route_path_prefix",
                "base_url",
                "healthcheck_url",
                "public_discovery_content_cid",
                "public_discovery_url",
                "public_discovery_cid_host_url",
                "healthcheck_path",
            ],
            "control-plane service revision"
        );
        assert_required_collection!(
            revision,
            ControlPlaneServiceRevision,
            [
                "state_bindings",
                "lease_volumes",
                "required_config_names",
                "required_secret_names",
                "config_exports",
            ],
            "control-plane service revision"
        );

        let service = ControlPlaneServiceSnapshot {
            service_name: "web_portal".to_owned(),
            current_version: "1.0.0".to_owned(),
            revision_count: 1,
            config_generation: 0,
            secret_generation: 0,
            config_entry_count: 0,
            secret_entry_count: 0,
            service_lease: None,
            public_discovery_content_cid: None,
            public_discovery_url: None,
            public_discovery_cid_host_url: None,
            latest_revision: None,
            active_rollout: None,
            last_rollout: None,
        };
        assert_required_nullable!(
            service.clone(),
            ControlPlaneServiceSnapshot,
            [
                "service_lease",
                "public_discovery_content_cid",
                "public_discovery_url",
                "public_discovery_cid_host_url",
                "latest_revision",
                "active_rollout",
                "last_rollout",
            ],
            "control-plane service snapshot"
        );
        let audit = ControlPlaneAuditEvent {
            sequence: 1,
            action: SoracloudAction::Deploy,
            service_name: "web_portal".to_owned(),
            from_version: None,
            to_version: "1.0.0".to_owned(),
            service_manifest_hash: Hash::new(b"service"),
            container_manifest_hash: Hash::new(b"container"),
            process_generation: 1,
            config_generation: 0,
            secret_generation: 0,
            config_snapshot_hash:
                iroha_data_model::soracloud::derive_soracloud_service_config_snapshot_hash_v1(
                    &BTreeMap::new(),
                ),
            secret_snapshot_hash:
                iroha_data_model::soracloud::derive_soracloud_service_secret_snapshot_hash_v1(
                    &BTreeMap::new(),
                ),
            binding_name: None,
            state_key: None,
            config_mutations: Vec::new(),
            secret_mutations: Vec::new(),
            governance_tx_hash: None,
            rollout_state: None,
            policy_name: None,
            policy_snapshot_hash: None,
            jurisdiction_tag: None,
            consent_evidence_hash: None,
            break_glass: None,
            break_glass_reason: None,
            lease_usage: None,
            service_lease_commitment: None,
            lease_reporting_epoch_rollover: None,
            signed_by: "signer".to_owned(),
        };
        assert_required_nullable!(
            audit.clone(),
            ControlPlaneAuditEvent,
            [
                "from_version",
                "binding_name",
                "state_key",
                "governance_tx_hash",
                "rollout_state",
                "policy_name",
                "policy_snapshot_hash",
                "jurisdiction_tag",
                "consent_evidence_hash",
                "break_glass",
                "break_glass_reason",
                "lease_usage",
                "service_lease_commitment",
                "lease_reporting_epoch_rollover",
            ],
            "control-plane audit event"
        );
        let snapshot = ControlPlaneSnapshot {
            schema_version: CONTROL_PLANE_SCHEMA_VERSION,
            service_count: 1,
            audit_event_count: 1,
            active_inrou_hosts: Vec::new(),
            services: vec![service],
            recent_audit_events: vec![audit],
        };
        assert_required_collection!(
            snapshot,
            ControlPlaneSnapshot,
            ["active_inrou_hosts", "services", "recent_audit_events"],
            "control-plane snapshot"
        );

        assert_required_collection!(
            ServiceConfigStatusResponse {
                schema_version: CONTROL_PLANE_SCHEMA_VERSION,
                service_name: "web_portal".to_owned(),
                current_version: "1.0.0".to_owned(),
                config_generation: 0,
                config_entry_count: 0,
                configs: Vec::new(),
            },
            ServiceConfigStatusResponse,
            ["configs"],
            "service config status response"
        );
        assert_required_collection!(
            ServiceSecretStatusResponse {
                schema_version: CONTROL_PLANE_SCHEMA_VERSION,
                service_name: "web_portal".to_owned(),
                current_version: "1.0.0".to_owned(),
                secret_generation: 0,
                secret_entry_count: 0,
                secrets: Vec::new(),
            },
            ServiceSecretStatusResponse,
            ["secrets"],
            "service secret status response"
        );
    }
    #[test]
    fn rollout_advance_payload_rejects_unknown_fields() {
        let governance_tx_hash = Hash::new(b"governance");
        let mut fields = norito::json::Map::new();
        fields.insert(
            "service_name".to_owned(),
            norito::json::Value::from("web_portal"),
        );
        fields.insert(
            "rollout_handle".to_owned(),
            norito::json::Value::from("web_portal:rollout:2"),
        );
        fields.insert("healthy".to_owned(), norito::json::Value::from(true));
        fields.insert(
            "promote_to_percent".to_owned(),
            norito::json::Value::from(100_u64),
        );
        fields.insert(
            "governance_tx_hash".to_owned(),
            norito::json::to_value(&governance_tx_hash).expect("serialize governance hash"),
        );
        let canonical = norito::json::Value::Object(fields);
        norito::json::from_value::<RolloutAdvancePayload>(canonical.clone())
            .expect("canonical rollout advance payload must decode");

        let mut missing = canonical.clone();
        assert!(
            missing
                .as_object_mut()
                .expect("rollout advance payload JSON object")
                .remove("promote_to_percent")
                .is_some()
        );
        norito::json::from_value::<RolloutAdvancePayload>(missing)
            .expect_err("omitted rollout promotion target must be rejected");

        let mut null = canonical.clone();
        null.as_object_mut()
            .expect("rollout advance payload JSON object")
            .insert("promote_to_percent".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<RolloutAdvancePayload>(null)
                .expect("explicit null rollout promotion target must decode")
                .promote_to_percent
                .is_none()
        );

        let mut unknown = canonical;
        unknown
            .as_object_mut()
            .expect("rollout advance payload JSON object")
            .insert("retired_v0".to_owned(), norito::json::Value::from(true));
        let error = norito::json::from_value::<RolloutAdvancePayload>(unknown)
            .expect_err("rollout advance payload must reject unknown fields");
        assert!(
            matches!(
                error,
                norito::json::Error::UnknownField { ref field } if field == "retired_v0"
            ),
            "unexpected rollout unknown-field rejection: {error}"
        );
    }
    #[test]
    fn soracloud_post_requests_reject_inline_signing_fields_during_decode() {
        macro_rules! assert_rejects_inline_signing_fields {
            ($($request:ty),+ $(,)?) => {
                $(
                    for field in ["authority", "private_key"] {
                        let json = format!(r#"{{"{field}":"must-not-cross-torii"}}"#);
                        let error = norito::json::from_str::<$request>(&json)
                            .expect_err("retired inline signing field must fail JSON admission");
                        let message = error.to_string();
                        assert!(
                            message.contains("unknown field") && message.contains(field),
                            "{} admitted retired field `{field}`: {message}",
                            stringify!($request),
                        );
                    }
                )+
            };
        }
        assert_rejects_inline_signing_fields!(
            SignedBundleRequest,
            SignedAppInfraRequest,
            SignedRollbackRequest,
            SignedStateMutationRequest,
            SignedServiceConfigSetRequest,
            SignedServiceConfigDeleteRequest,
            SignedServiceSecretSetRequest,
            SignedServiceSecretDeleteRequest,
            SignedRolloutAdvanceRequest,
            SignedAgentDeployRequest,
            SignedAgentLeaseRenewRequest,
            SignedHfSharedLeaseJoinRequest,
            SignedHfLeaseLeaveRequest,
            SignedHfLeaseRenewRequest,
            SignedAgentRestartRequest,
            SignedAgentPolicyRevokeRequest,
            SignedAgentWalletSpendRequest,
            SignedAgentWalletApproveRequest,
            SignedAgentMessageSendRequest,
            SignedAgentMessageAckRequest,
            SignedAgentArtifactAllowRequest,
            SignedFheJobRunRequest,
            SignedTrainingJobStartRequest,
            SignedTrainingJobCheckpointRequest,
            SignedTrainingJobRetryRequest,
            SignedModelWeightRegisterRequest,
            SignedModelWeightPromoteRequest,
            SignedModelWeightRollbackRequest,
            SignedModelArtifactRegisterRequest,
            SignedUploadedModelRegisterRequest,
            SignedDecryptionRequest,
            SignedCiphertextQueryRequest,
        );
    }
    #[test]
    fn require_soracloud_mutation_signer_derives_authority_from_verified_headers() {
        let key_pair = checked_test_keypair(0x60);
        let account = AccountId::new(key_pair.public_key().clone());
        let headers = verified_request_headers(&account, key_pair.public_key());
        let provenance = ManifestProvenance {
            signer: key_pair.public_key().clone(),
            signature: checked_test_signature(key_pair.private_key(), b"mutation"),
        };
        let signer = require_soracloud_mutation_signer(&headers, &provenance)
            .expect("verified headers and matching provenance must identify the mutation signer");
        assert_eq!(signer.authority, account);
        assert_eq!(signer.request_signer, provenance.signer);
    }
    #[test]
    fn verified_soracloud_identity_requires_all_exact_internal_headers() {
        let key_pair = checked_test_keypair(0x65);
        let account = AccountId::new(key_pair.public_key().clone());
        let headers = verified_request_headers(&account, key_pair.public_key());
        let (decoded_account, decoded_signer, decoded_signers) =
            verified_soracloud_request_identity(&headers).expect("canonical internal headers");
        assert_eq!(decoded_account, account);
        assert_eq!(&decoded_signer, key_pair.public_key());
        assert_eq!(decoded_signers, vec![key_pair.public_key().clone()]);

        let mut missing_signer_set = headers.clone();
        missing_signer_set.remove(VERIFIED_SIGNERS_HEADER);
        let error = verified_soracloud_request_identity(&missing_signer_set)
            .expect_err("the exact V1 internal identity contract requires a signer set");
        assert_eq!(error.kind, SoracloudErrorKind::Unauthorized);

        for header_name in [
            VERIFIED_ACCOUNT_HEADER,
            VERIFIED_SIGNER_HEADER,
            VERIFIED_SIGNERS_HEADER,
        ] {
            let mut padded = headers.clone();
            let canonical = padded.get(header_name).expect("fixture header").as_bytes();
            let mut padded_value = Vec::with_capacity(canonical.len() + 2);
            padded_value.push(b' ');
            padded_value.extend_from_slice(canonical);
            padded_value.push(b' ');
            padded.insert(
                header_name,
                axum::http::HeaderValue::from_bytes(&padded_value)
                    .expect("HTTP header permits visible padding"),
            );
            let error = verified_soracloud_request_identity(&padded)
                .expect_err("internal identity headers must not be trimmed or coerced");
            assert_eq!(error.kind, SoracloudErrorKind::Internal);
        }
    }
    #[test]
    fn app_infra_request_rejects_inline_signing_fields_in_nested_service_bundles() {
        for field in ["authority", "private_key"] {
            let json = format!(r#"{{"deploy_services":[{{"{field}":"must-not-cross-torii"}}]}}"#);
            let error = norito::json::from_str::<SignedAppInfraRequest>(&json)
                .expect_err("nested service bundle signing material must fail JSON admission");
            let message = error.to_string();
            assert!(
                message.contains("unknown field") && message.contains(field),
                "nested retired field `{field}` was not rejected: {message}"
            );
        }
    }
    #[test]
    fn require_soracloud_mutation_signer_binds_provenance_to_request_signer() {
        let request_keypair = checked_test_keypair(0x61);
        let provenance_keypair = checked_test_keypair(0x62);
        let account = AccountId::new(request_keypair.public_key().clone());
        let headers = verified_request_headers(&account, request_keypair.public_key());
        let provenance = ManifestProvenance {
            signer: provenance_keypair.public_key().clone(),
            signature: checked_test_signature(provenance_keypair.private_key(), b"mutation"),
        };
        let error = match require_soracloud_mutation_signer(&headers, &provenance) {
            Ok(_) => panic!("provenance signer mismatch must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    }
    #[test]
    fn require_soracloud_mutation_signer_accepts_multisig_member_provenance() {
        let primary_request_keypair = checked_test_keypair(0x63);
        let provenance_keypair = checked_test_keypair(0x64);
        let account = AccountId::new(primary_request_keypair.public_key().clone());
        let headers = verified_request_headers_with_signers(
            &account,
            primary_request_keypair.public_key(),
            &[
                primary_request_keypair.public_key().clone(),
                provenance_keypair.public_key().clone(),
            ],
        );
        let provenance = ManifestProvenance {
            signer: provenance_keypair.public_key().clone(),
            signature: checked_test_signature(provenance_keypair.private_key(), b"mutation"),
        };
        let signer = require_soracloud_mutation_signer(&headers, &provenance)
            .expect("multisig member provenance must be accepted");
        assert_eq!(signer.authority, account);
        assert_eq!(signer.request_signer, provenance.signer);
    }
    #[test]
    fn control_plane_snapshot_uses_authoritative_soracloud_state() -> Result<(), eyre::Report> {
        use iroha_core::{smartcontracts::Execute, state::World};
        use iroha_data_model::block::BlockHeader;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let wonderland: iroha_model_base::domain::DomainId =
                DomainId::try_new("wonderland", "universal")?;
            let mut world = World::default();
            seed_domain_name_lease(&mut world, &SAMPLE_GENESIS_ACCOUNT_ID, &wonderland);
            let app = mk_app_state_for_tests_with_world(world);
            let block_header = BlockHeader {
                height: NonZeroU64::new(1).expect("non-zero block height"),
                prev_block_hash: None,
                merkle_root: None,
                da_proof_policies_hash: None,
                da_commitments_hash: None,
                da_pin_intents_hash: None,
                npos_effects_hash: None,
                global_beacon_pulse_hash: None,
                execution_context_hash: None,
                creation_time_ms: 0,
                view_change_index: 0,
                confidential_features: None,
            };
            let mut state_block = app.state.block(block_header);
            let mut stx = state_block.transaction();
            Register::domain(Domain::new(wonderland.clone()))
                .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut stx)?;
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut stx)?;
            Grant::account_permission(
                Permission::new("CanManageSoracloud".into(), Json::new(())),
                ALICE_ID.clone(),
            )
            .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut stx)?;
            let mut bundle = fixture_bundle("1.0.0");
            // Snapshot projection needs an admissible deployment; FHE bindings
            // remain unavailable until a replacement profile is qualified.
            bundle
                .service
                .state_bindings
                .retain(|binding| binding.encryption != SoraStateEncryptionV1::FheCiphertext);

            bundle.container.required_config_names = vec!["ui/theme".to_string()];
            bundle.container.config_exports = vec![
                SoraConfigExportV1 {
                    config_name: "ui/theme".to_string(),
                    target: iroha_data_model::soracloud::SoraConfigExportTargetV1::Env(
                        "UI_THEME_JSON".to_string(),
                    ),
                },
                SoraConfigExportV1 {
                    config_name: "ui/theme".to_string(),
                    target: iroha_data_model::soracloud::SoraConfigExportTargetV1::File(
                        "runtime/ui/theme.json".to_string(),
                    ),
                },
            ];
            bundle.service.container.manifest_hash = bundle.container_manifest_hash();
            let initial_service_configs = BTreeMap::from([(
                "ui/theme".to_string(),
                Json::from(norito::json!({
                    "accent": "citrus",
                    "mode": "light",
                })),
            )]);
            let provenance = {
                let payload = encode_bundle_signature_payload(
                    &bundle,
                    &initial_service_configs,
                    &BTreeMap::new(),
                    &SoraServiceMutationPreconditionV1::ServiceAbsent,
                )
                .expect("encode bundle payload");
                ManifestProvenance {
                    signer: ALICE_ID.expect_single_signatory().clone(),
                    signature: checked_test_signature(
                        iroha_test_samples::ALICE_KEYPAIR.private_key(),
                        &payload,
                    ),
                }
            };
            isi::soracloud::DeploySoracloudService {
                bundle,
                initial_service_configs,
                initial_service_secrets: BTreeMap::new(),
                precondition: SoraServiceMutationPreconditionV1::ServiceAbsent,
                provenance,
            }
            .execute(&ALICE_ID, &mut stx)?;
            stx.apply();
            state_block.commit_world_overlay_for_testing()?;
            let snapshot = control_plane_snapshot(&app, Some("web_portal"), 10)?;
            assert_eq!(snapshot.service_count, 1);
            assert_eq!(snapshot.audit_event_count, 1);
            assert_eq!(snapshot.services[0].current_version, "1.0.0");
            assert_eq!(
                snapshot.services[0]
                    .latest_revision
                    .as_ref()
                    .expect("latest revision")
                    .signed_by,
                ALICE_ID.expect_single_signatory().to_string()
            );
            assert_eq!(
                snapshot.services[0]
                    .latest_revision
                    .as_ref()
                    .expect("latest revision")
                    .config_exports
                    .len(),
                2
            );
            assert_eq!(snapshot.recent_audit_events.len(), 1);
            Ok(())
        })
    }
    #[test]
    fn error_chain_message_includes_nested_validation_details() {
        let error = iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::InstructionFailed(
                iroha_data_model::isi::error::InstructionExecutionError::InvalidParameter(
                    iroha_data_model::isi::error::InvalidParameterError::SmartContract(
                        "resources.cpu_millis exceeds SCR cap".to_owned(),
                    ),
                ),
            ),
        );
        let message = transaction_rejection_message(&error);
        assert!(message.contains("Validation failed"));
        assert!(message.contains("Instruction execution failed"));
        assert!(message.contains("Invalid instruction parameter"));
        assert!(message.contains("resources.cpu_millis exceeds SCR cap"));
    }
    #[test]
    fn audit_leaf_hash_binds_reporting_epoch_rollover_payload() {
        let bundle = fixture_bundle("1.0.0");
        let model_event = fixture_service_deploy_audit_event(&bundle);
        let mut event = audit_event_to_control_plane_audit_event(&model_event);
        let without_rollover = audit_event_leaf_hash(&event);
        event.action = SoracloudAction::LeaseReportingEpochRollover;
        event.from_version = Some(event.to_version.clone());
        event.lease_reporting_epoch_rollover = Some(SoraServiceLeaseReportingEpochRolloverV1 {
            schema_version:
                iroha_data_model::soracloud::SORA_SERVICE_LEASE_REPORTING_EPOCH_ROLLOVER_VERSION_V1,
            economic_clock:
                iroha_data_model::soracloud::SoraServiceLeaseClockV1::CanonicalBlockHeight,
            lease_started_height: 7,
            previous_reporting_epoch: 1,
            new_reporting_epoch: 2,
            reporter_account_id: ALICE_ID.clone(),
            active_service_version: event.to_version.clone(),
            replica_slot: 1,
            placement_incarnation: Hash::new(b"placement-1"),
            finalized_checkpoint_count: u32::try_from(
                iroha_data_model::soracloud::SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1,
            )
            .expect("reporter checkpoint protocol limit fits u32"),
            settled_egress_bytes_delta: 41,
            settled_egress_bytes: 100,
        });
        let first_rollover = audit_event_leaf_hash(&event);
        assert_ne!(first_rollover, without_rollover);
        event
            .lease_reporting_epoch_rollover
            .as_mut()
            .expect("rollover payload")
            .settled_egress_bytes += 1;
        assert_ne!(audit_event_leaf_hash(&event), first_rollover);
    }
    #[test]
    fn admit_scr_host_bundle_rejects_over_cap_cpu() {
        let mut bundle = fixture_bundle("1.0.0");
        bundle.container.resources.cpu_millis = NonZeroU32::new(64_001).expect("non-zero cpu");
        bundle.service.container.manifest_hash = bundle.container_manifest_hash();
        let error = admit_scr_host_bundle(&bundle).expect_err("SCR over-cap cpu should fail");
        assert!(
            error
                .message
                .contains("container.resources.cpu_millis exceeds SCR cap")
        );
    }
    #[test]
    fn admit_scr_host_bundle_rejects_padded_allowlist_hosts() {
        let mut bundle = fixture_bundle("1.0.0");
        bundle.container.capabilities.network = SoraNetworkPolicyV1::Allowlist(vec![
            iroha_data_model::soracloud::SoraNetworkAllowlistEntryV1::new(
                " api.example.test",
                [443],
            ),
        ]);
        bundle.service.container.manifest_hash = bundle.container_manifest_hash();
        let error = admit_scr_host_bundle(&bundle)
            .expect_err("padded allowlist host must fail rather than become inert");
        assert!(error.message.contains("invalid host characters"));
    }
    #[test]
    fn control_plane_revision_fails_closed_without_lifecycle_or_scr_admission_evidence() {
        let bundle = fixture_bundle("1.0.0");
        let deployment = fixture_service_deployment(&bundle);
        let world = iroha_core::state::World::new();
        let error = deployment_bundle_to_control_plane_revision(
            &world.view(),
            &deployment,
            &bundle,
            None,
            None,
        )
        .expect_err("a revision without lifecycle audit evidence must fail closed");
        assert_eq!(error.kind, SoracloudErrorKind::Internal);
        assert!(
            error
                .message
                .contains("no authoritative lifecycle audit event")
        );

        let mut over_cap_bundle = fixture_bundle("1.0.0");
        over_cap_bundle.container.resources.cpu_millis =
            NonZeroU32::new(SCR_HOST_MAX_CPU_MILLIS + 1).expect("non-zero cpu");
        over_cap_bundle.service.container.manifest_hash = over_cap_bundle.container_manifest_hash();
        let over_cap_deployment = fixture_service_deployment(&over_cap_bundle);
        let audit = fixture_service_deploy_audit_event(&over_cap_bundle);
        let error = deployment_bundle_to_control_plane_revision(
            &world.view(),
            &over_cap_deployment,
            &over_cap_bundle,
            Some(&audit),
            None,
        )
        .expect_err("an active revision that fails SCR admission must fail closed");
        assert_eq!(error.kind, SoracloudErrorKind::Internal);
        assert!(error.message.contains("fails authoritative SCR admission"));
    }

    #[test]
    fn rollout_draft_rejects_inrou_and_preserves_deterministic_ivm() {
        use iroha_core::state::World;

        let inrou_bundle = fixture_hosted_http_inrou_bundle("2026.03.0");
        let inrou_service_name = inrou_bundle.service.service_name.clone();
        let mut inrou_world = World::new();
        install_fixture_service(&mut inrou_world, &inrou_bundle, &inrou_service_name);
        let error = ensure_authoritative_rollout_draft_supported(
            &inrou_world.view(),
            inrou_service_name.as_ref(),
        )
        .expect_err("first-release Inrou must not expose staged rollout drafts");
        assert_eq!(error.kind, SoracloudErrorKind::BadRequest);
        assert!(error.message.contains("HttpService+Inrou"));
        assert!(error.message.contains("atomic upgrade"));
        assert!(error.message.contains("sole current revision"));

        let ivm_bundle = fixture_bundle("2026.03.0");
        let ivm_service_name = ivm_bundle.service.service_name.clone();
        let mut ivm_world = World::new();
        install_fixture_service(&mut ivm_world, &ivm_bundle, &ivm_service_name);
        ensure_authoritative_rollout_draft_supported(&ivm_world.view(), ivm_service_name.as_ref())
            .expect("deterministic IVM services must retain generic staged rollouts");
    }

    #[tokio::test]
    async fn resolve_public_local_read_route_uses_authoritative_service_route_state() {
        use iroha_core::state::World;
        let mut world = World::new();
        let bundle = fixture_bundle("2026.02.0");
        let service_name = bundle.service.service_name.clone();
        insert_revision(&mut world, &bundle, bundle.service.service_name.to_string());
        world
            .soracloud_service_deployments_mut_for_testing()
            .insert(service_name.clone(), fixture_service_deployment(&bundle));
        let app = mk_app_state_for_tests_with_world(world);
        let assets = resolve_public_local_read_route(&app, "portal.sora:443", "/app/assets")
            .expect("asset route");
        assert_eq!(assets.service_name, "web_portal");
        assert_eq!(assets.service_version, "2026.02.0");
        assert_eq!(assets.handler_name, "assets");
        assert_eq!(assets.handler_class, SoracloudLocalReadKind::Asset);
        assert_eq!(assets.handler_path, "/");
        let query = resolve_public_local_read_route(&app, "portal.sora", "/app/query/stats")
            .expect("query route");
        assert_eq!(query.handler_name, "query");
        assert_eq!(query.handler_class, SoracloudLocalReadKind::Query);
        assert_eq!(query.handler_path, "/stats");
        assert!(
            resolve_public_local_read_route(&app, "portal.sora", "/app/ciphertext/update")
                .is_none(),
            "replicated write handlers must not resolve through the local read fast path"
        );
        assert!(
            resolve_public_local_read_route(&app, "wrong.sora", "/app/assets").is_none(),
            "host matching must stay authoritative"
        );
    }
    #[tokio::test]
    async fn resolve_public_route_projects_http_service_inrous() {
        use iroha_core::state::World;
        let mut world = World::new();
        let bundle = fixture_hosted_http_inrou_bundle("2026.04.0");
        let service_name = bundle.service.service_name.clone();
        let lease = iroha_data_model::soracloud::SoraServiceLeaseStateV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_LEASE_STATE_VERSION_V1,
            economic_clock:
                iroha_data_model::soracloud::SoraServiceLeaseClockV1::CanonicalBlockHeight,
            status: iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
            quota_class: "taira-open".to_string(),
            replica_count: bundle.service.replicas,
            deployment_deposit: "1".parse().expect("deployment deposit quantity"),
            prepaid_runtime_balance: "50".parse().expect("prepaid runtime quantity"),
            runtime_price_per_block: "0.00025".parse().expect("runtime price quantity"),
            storage_price_per_gib_block: "0.000025".parse().expect("storage price quantity"),
            egress_price_per_mib: "0.000005".parse().expect("egress price quantity"),
            lease_started_height: 1,
            lease_expires_height: 100,
            reporting_epoch: 1,
            settled_egress_bytes: 0,
            egress_reporter_checkpoints: Vec::new(),
            accounted_egress_bytes: 0,
            last_status_reason: None,
        };
        let lease_volume_states = fixture_service_lease_volume_states(&bundle, Some(&lease));
        let deployment = SoraServiceDeploymentStateV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_DEPLOYMENT_STATE_VERSION_V1,
            service_name: service_name.clone(),
            current_service_version: bundle.service.service_version.clone(),
            current_service_manifest_hash: bundle.service_manifest_hash(),
            current_container_manifest_hash: bundle.container_manifest_hash(),
            revision_count: 1,
            process_generation: 1,
            process_started_sequence: 1,
            active_rollout: None,
            last_rollout: None,
            config_generation: 0,
            secret_generation: 0,
            service_configs: BTreeMap::new(),
            service_secrets: BTreeMap::new(),
            fhe_policy_records: BTreeMap::new(),
            service_lease: Some(lease),
            lease_volume_states,
        };
        insert_revision(&mut world, &bundle, bundle.service.service_name.to_string());
        world
            .soracloud_service_deployments_mut_for_testing()
            .insert(service_name.clone(), deployment.clone());
        let mut invalid_deployment = deployment;
        invalid_deployment
            .lease_volume_states
            .pop()
            .expect("hosted deployment has a lease-volume row");
        let mut invalid_volume_world = World::new();
        insert_revision(
            &mut invalid_volume_world,
            &bundle,
            bundle.service.service_name.to_string(),
        );
        invalid_volume_world
            .soracloud_service_deployments_mut_for_testing()
            .insert(service_name.clone(), invalid_deployment);

        let app = mk_app_state_for_tests_with_world(world);
        let route_match = resolve_public_route(&app, "portal.sora", "GET", "/app/v1/health")
            .expect("http service route");
        match route_match {
            PublicRouteMatch::HostedHttp(route_match) => {
                assert_eq!(route_match.service_name, "web_portal");
                assert_eq!(route_match.service_version, "2026.04.0");
                assert_eq!(route_match.request_path, "/v1/health");
            }
            other => panic!("expected hosted-http route, got {other:?}"),
        }
        assert!(
            resolve_public_route(&app, "wrong.sora", "GET", "/app/v1/health").is_none(),
            "host matching must stay authoritative for hosted http services"
        );
        let invalid_volume_app = mk_app_state_for_tests_with_world(invalid_volume_world);
        assert!(
            resolve_public_route(&invalid_volume_app, "portal.sora", "GET", "/app/v1/health")
                .is_none(),
            "public routing must fail closed when authoritative storage rows do not exactly match the admitted bundle"
        );
    }
    #[tokio::test]
    async fn resolve_public_route_splits_hosted_live_search_from_vault_handlers() {
        use iroha_core::state::World;
        use iroha_data_model::soracloud::SoraMailboxContractV1;
        let mut world = World::new();
        let mut live_bundle = fixture_hosted_http_inrou_bundle("2026.04.0");
        live_bundle.service.service_name = "travel_ops_live".parse().expect("service name");
        live_bundle.service.route = Some(SoraRouteTargetV1 {
            host: "travel.sora".to_owned(),
            path_prefix: "/api/v1".to_owned(),
            service_port: NonZeroU16::new(8787).expect("nonzero literal"),
            visibility: SoraRouteVisibilityV1::Public,
            tls_mode: SoraTlsModeV1::Required,
        });
        let mut vault_bundle = fixture_bundle("2026.04.0");
        vault_bundle.service.service_name = "travel_ops_vault".parse().expect("service name");
        vault_bundle.service.route = Some(SoraRouteTargetV1 {
            host: "travel.sora".to_owned(),
            path_prefix: "/api".to_owned(),
            service_port: NonZeroU16::new(8788).expect("nonzero literal"),
            visibility: SoraRouteVisibilityV1::Public,
            tls_mode: SoraTlsModeV1::Required,
        });
        vault_bundle.service.handlers = vec![
            SoraServiceHandlerV1 {
                handler_name: "auth_me".parse().expect("handler"),
                class: SoraServiceHandlerClassV1::Query,
                entrypoint: "serve_auth_me".to_owned(),
                route_path: Some("/auth/me".to_owned()),
                certified_response: SoraCertifiedResponsePolicyV1::AuditReceipt,
                mailbox: None,
            },
            SoraServiceHandlerV1 {
                handler_name: "saved_searches_get".parse().expect("handler"),
                class: SoraServiceHandlerClassV1::Query,
                entrypoint: "serve_saved_searches".to_owned(),
                route_path: Some("/v1/user/saved-searches".to_owned()),
                certified_response: SoraCertifiedResponsePolicyV1::AuditReceipt,
                mailbox: None,
            },
            SoraServiceHandlerV1 {
                handler_name: "saved_searches_put".parse().expect("handler"),
                class: SoraServiceHandlerClassV1::Update,
                entrypoint: "store_saved_search".to_owned(),
                route_path: Some("/v1/user/saved-searches".to_owned()),
                certified_response: SoraCertifiedResponsePolicyV1::None,
                mailbox: Some(SoraMailboxContractV1 {
                    queue_name: "user_updates".parse().expect("queue"),
                    max_pending_messages: NonZeroU32::new(128).expect("pending"),
                    max_message_bytes: NonZeroU64::new(131_072).expect("bytes"),
                    retention_blocks: NonZeroU32::new(64).expect("retention"),
                }),
            },
        ];
        for bundle in [live_bundle.clone(), vault_bundle.clone()] {
            let service_name = bundle.service.service_name.clone();
            insert_revision(&mut world, &bundle, bundle.service.service_name.to_string());
            let service_lease = if bundle.service.execution_plane
                == iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService
            {
                Some(iroha_data_model::soracloud::SoraServiceLeaseStateV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_SERVICE_LEASE_STATE_VERSION_V1,
                    economic_clock:
                        iroha_data_model::soracloud::SoraServiceLeaseClockV1::CanonicalBlockHeight,
                    status: iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
                    quota_class: "taira-open".to_string(),
                    replica_count: bundle.service.replicas,
                    deployment_deposit: "1".parse().expect("deployment deposit quantity"),
                    prepaid_runtime_balance: "50".parse().expect("prepaid runtime quantity"),
                    runtime_price_per_block: "0.00025".parse().expect("runtime price quantity"),
                    storage_price_per_gib_block: "0.000025"
                        .parse()
                        .expect("storage price quantity"),
                    egress_price_per_mib: "0.000005".parse().expect("egress price quantity"),
                    lease_started_height: 1,
                    lease_expires_height: 100,
                    reporting_epoch: 1,
                    settled_egress_bytes: 0,
                    egress_reporter_checkpoints: Vec::new(),
                    accounted_egress_bytes: 0,
                    last_status_reason: None,
                })
            } else {
                None
            };
            let lease_volume_states =
                fixture_service_lease_volume_states(&bundle, service_lease.as_ref());
            world
                .soracloud_service_deployments_mut_for_testing()
                .insert(
                    service_name.clone(),
                    SoraServiceDeploymentStateV1 {
                        schema_version:
                            iroha_data_model::soracloud::SORA_SERVICE_DEPLOYMENT_STATE_VERSION_V1,
                        service_name,
                        current_service_version: bundle.service.service_version.clone(),
                        current_service_manifest_hash: bundle.service_manifest_hash(),
                        current_container_manifest_hash: bundle.container_manifest_hash(),
                        revision_count: 1,
                        process_generation: 1,
                        process_started_sequence: 1,
                        active_rollout: None,
                        last_rollout: None,
                        config_generation: 0,
                        secret_generation: 0,
                        service_configs: BTreeMap::new(),
                        service_secrets: BTreeMap::new(),
                        fhe_policy_records: BTreeMap::new(),
                        service_lease,
                        lease_volume_states,
                    },
                );
        }
        let app = mk_app_state_for_tests_with_world(world);
        let live_route = resolve_public_route(&app, "travel.sora", "POST", "/api/v1/search")
            .expect("hosted live route");
        match live_route {
            PublicRouteMatch::HostedHttp(route_match) => {
                assert_eq!(route_match.service_name, "travel_ops_live");
                assert_eq!(route_match.request_path, "/search");
            }
            other => panic!("expected hosted-http live route, got {other:?}"),
        }
        let auth_route =
            resolve_public_route(&app, "travel.sora", "GET", "/api/auth/me").expect("auth route");
        match auth_route {
            PublicRouteMatch::LocalRead(route_match) => {
                assert_eq!(route_match.handler_name, "auth_me");
            }
            other => panic!("expected local-read auth route, got {other:?}"),
        }
        let saved_search_route =
            resolve_public_route(&app, "travel.sora", "GET", "/api/v1/user/saved-searches")
                .expect("saved searches route");
        match saved_search_route {
            PublicRouteMatch::LocalRead(route_match) => {
                assert_eq!(route_match.handler_name, "saved_searches_get");
            }
            other => panic!("expected local-read saved searches route, got {other:?}"),
        }
    }
    #[tokio::test]
    async fn resolve_public_route_rejects_http_service_with_expired_lease() {
        use iroha_core::state::World;
        let mut world = World::new();
        let bundle = fixture_hosted_http_inrou_bundle("2026.04.1");
        let service_name = bundle.service.service_name.clone();
        let lease = iroha_data_model::soracloud::SoraServiceLeaseStateV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_LEASE_STATE_VERSION_V1,
            economic_clock:
                iroha_data_model::soracloud::SoraServiceLeaseClockV1::CanonicalBlockHeight,
            status: iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Expired,
            quota_class: "taira-open".to_string(),
            replica_count: bundle.service.replicas,
            deployment_deposit: "1".parse().expect("deployment deposit quantity"),
            prepaid_runtime_balance: "50".parse().expect("prepaid runtime quantity"),
            runtime_price_per_block: "0.00025".parse().expect("runtime price quantity"),
            storage_price_per_gib_block: "0.000025".parse().expect("storage price quantity"),
            egress_price_per_mib: "0.000005".parse().expect("egress price quantity"),
            lease_started_height: 1,
            lease_expires_height: 100,
            reporting_epoch: 1,
            settled_egress_bytes: 0,
            egress_reporter_checkpoints: Vec::new(),
            accounted_egress_bytes: 0,
            last_status_reason: None,
        };
        let lease_volume_states = fixture_service_lease_volume_states(&bundle, Some(&lease));
        insert_revision(&mut world, &bundle, bundle.service.service_name.to_string());
        world
            .soracloud_service_deployments_mut_for_testing()
            .insert(
                service_name,
                SoraServiceDeploymentStateV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_SERVICE_DEPLOYMENT_STATE_VERSION_V1,
                    service_name: bundle.service.service_name.clone(),
                    current_service_version: bundle.service.service_version.clone(),
                    current_service_manifest_hash: bundle.service_manifest_hash(),
                    current_container_manifest_hash: bundle.container_manifest_hash(),
                    revision_count: 1,
                    process_generation: 1,
                    process_started_sequence: 1,
                    active_rollout: None,
                    last_rollout: None,
                    config_generation: 0,
                    secret_generation: 0,
                    service_configs: BTreeMap::new(),
                    service_secrets: BTreeMap::new(),
                    fhe_policy_records: BTreeMap::new(),
                    service_lease: Some(lease),
                    lease_volume_states,
                },
            );

        let app = mk_app_state_for_tests_with_world(world);
        assert!(
            resolve_public_route(&app, "portal.sora", "GET", "/app/v1/health").is_none(),
            "an expired hosted lease must fail closed before proxy routing"
        );
    }
    #[tokio::test]
    async fn resolve_public_route_rejects_ledger_only_mailbox_handlers() {
        use iroha_core::state::World;
        let mut world = World::new();
        let bundle = fixture_bundle("2026.02.0");
        let service_name = bundle.service.service_name.clone();
        insert_revision(&mut world, &bundle, bundle.service.service_name.to_string());
        world
            .soracloud_service_deployments_mut_for_testing()
            .insert(service_name, fixture_service_deployment(&bundle));
        let app = mk_app_state_for_tests_with_world(world);
        let route_match = resolve_public_route(&app, "portal.sora", "POST", "/app/update/search")
            .expect("ordered mailbox route");
        match route_match {
            PublicRouteMatch::OrderedMailbox(route_match) => {
                assert_eq!(route_match.service_name, "web_portal");
                assert_eq!(route_match.service_version, "2026.02.0");
                assert_eq!(route_match.handler_name, "update");
                assert_eq!(route_match.handler_class, SoraServiceHandlerClassV1::Update);
                assert_eq!(route_match.handler_path, "/search");
            }
            other => panic!("expected ordered-mailbox route, got {other:?}"),
        }
        let ciphertext_route =
            resolve_public_route(&app, "portal.sora", "POST", "/app/ciphertext/update/vault")
                .expect("ciphertext ordered mailbox route");
        match ciphertext_route {
            PublicRouteMatch::OrderedMailbox(route_match) => {
                assert_eq!(route_match.handler_name, "ciphertext_update");
                assert_eq!(route_match.handler_class, SoraServiceHandlerClassV1::Update);
                assert_eq!(route_match.handler_path, "/vault");
            }
            other => panic!("expected ciphertext ordered-mailbox route, got {other:?}"),
        }
    }
    #[tokio::test]
    async fn resolve_public_route_prefers_handler_class_for_http_method() {
        use iroha_core::state::World;
        use iroha_data_model::soracloud::SoraMailboxContractV1;
        let mut world = World::new();
        let mut bundle = fixture_bundle("2026.03.0");
        bundle.service.handlers = vec![
            SoraServiceHandlerV1 {
                handler_name: "preferences_get".parse().expect("handler"),
                class: SoraServiceHandlerClassV1::Query,
                entrypoint: "serve_user_preferences".to_owned(),
                route_path: Some("/v1/user/preferences".to_owned()),
                certified_response: SoraCertifiedResponsePolicyV1::AuditReceipt,
                mailbox: None,
            },
            SoraServiceHandlerV1 {
                handler_name: "preferences_put".parse().expect("handler"),
                class: SoraServiceHandlerClassV1::Update,
                entrypoint: "store_user_preferences".to_owned(),
                route_path: Some("/v1/user/preferences".to_owned()),
                certified_response: SoraCertifiedResponsePolicyV1::None,
                mailbox: Some(SoraMailboxContractV1 {
                    queue_name: "user_updates".parse().expect("queue"),
                    max_pending_messages: std::num::NonZeroU32::new(128).expect("pending"),
                    max_message_bytes: std::num::NonZeroU64::new(131_072).expect("bytes"),
                    retention_blocks: std::num::NonZeroU32::new(64).expect("retention"),
                }),
            },
        ];
        let service_name = bundle.service.service_name.clone();
        insert_revision(&mut world, &bundle, bundle.service.service_name.to_string());
        world
            .soracloud_service_deployments_mut_for_testing()
            .insert(service_name, fixture_service_deployment(&bundle));
        let app = mk_app_state_for_tests_with_world(world);
        let get_route =
            resolve_public_route(&app, "portal.sora", "GET", "/app/v1/user/preferences")
                .expect("query route");
        match get_route {
            PublicRouteMatch::LocalRead(route_match) => {
                assert_eq!(route_match.handler_name, "preferences_get");
                assert_eq!(route_match.handler_class, SoracloudLocalReadKind::Query);
            }
            other => panic!("expected query route, got {other:?}"),
        }
        let put_route =
            resolve_public_route(&app, "portal.sora", "PUT", "/app/v1/user/preferences")
                .expect("replicated update route");
        match put_route {
            PublicRouteMatch::OrderedMailbox(route_match) => {
                assert_eq!(route_match.handler_name, "preferences_put");
                assert_eq!(route_match.handler_class, SoraServiceHandlerClassV1::Update);
            }
            other => panic!("expected replicated update route, got {other:?}"),
        }
    }
    #[test]
    fn public_handler_methods_require_exact_uppercase_spelling() {
        assert!(public_method_supports_handler(
            "GET",
            SoraServiceHandlerClassV1::Query
        ));
        assert!(public_method_supports_handler(
            "HEAD",
            SoraServiceHandlerClassV1::Asset
        ));
        assert!(public_method_supports_handler(
            "POST",
            SoraServiceHandlerClassV1::Update
        ));
        for alias in ["get", "Get", "head", "Head", "post", "Post"] {
            assert!(
                !public_method_supports_handler(alias, SoraServiceHandlerClassV1::Query),
                "mixed/lowercase method alias `{alias}` must not select a query handler"
            );
            assert!(
                !public_method_supports_handler(alias, SoraServiceHandlerClassV1::Update),
                "mixed/lowercase method alias `{alias}` must not select an update handler"
            );
        }
        assert!(!public_method_supports_handler(
            "FETCH",
            SoraServiceHandlerClassV1::Update
        ));
    }
    #[test]
    fn authoritative_ciphertext_query_reads_world_state() -> Result<(), eyre::Report> {
        use iroha_core::state::World;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let mut world = World::default();
            let bundle = fixture_bundle("1.0.0");
            let service_name = bundle.service.service_name.clone();
            let binding_name: Name = "patient_records".parse()?;
            let state_key = "/state/health/patient-1".to_string();
            let governance_tx_hash = Hash::new(b"gov-state");
            install_fixture_service(&mut world, &bundle, &service_name);
            world
                .soracloud_service_audit_events_mut_for_testing()
                .insert(
                    1,
                    SoraServiceAuditEventV1 {
                        schema_version:
                            iroha_data_model::soracloud::SORA_SERVICE_AUDIT_EVENT_VERSION_V1,
                        sequence: 1,
                        block_height: 1,
                        block_timestamp_ms: 1,
                        action: SoraServiceLifecycleActionV1::StateMutation,
                        service_name: service_name.clone(),
                        from_version: None,
                        to_version: bundle.service.service_version.clone(),
                        service_manifest_hash: bundle.service_manifest_hash(),
                        container_manifest_hash: bundle.container_manifest_hash(),
                        process_generation: 1,
                        config_generation: 0,
                        secret_generation: 0,
                        config_snapshot_hash: iroha_data_model::soracloud::derive_soracloud_service_config_snapshot_hash_v1(&BTreeMap::new()),
                        secret_snapshot_hash: iroha_data_model::soracloud::derive_soracloud_service_secret_snapshot_hash_v1(&BTreeMap::new()),
                        governance_tx_hash: Some(governance_tx_hash),
                        binding_name: Some(binding_name.clone()),
                        state_key: Some(state_key.clone()),
                        config_mutations: Vec::new(),
                        secret_mutations: Vec::new(),
                        rollout_state: None,
                        policy_name: None,
                        policy_snapshot_hash: None,
                        jurisdiction_tag: None,
                        consent_evidence_hash: None,
                        break_glass: None,
                        break_glass_reason: None,
                        lease_usage: None,
                        service_lease_commitment: None,
                        lease_reporting_epoch_rollover: None,
                        signer: checked_test_keypair(0x70).public_key().clone(),
                    },
                );
            world
                .soracloud_service_state_entries_mut_for_testing()
                .insert(
                    (
                        service_name.as_ref().to_owned(),
                        binding_name.as_ref().to_owned(),
                        state_key.clone(),
                    ),
                    SoraServiceStateEntryV1 {
                        schema_version:
                            iroha_data_model::soracloud::SORA_SERVICE_STATE_ENTRY_VERSION_V1,
                        service_name: service_name.clone(),
                        service_version: bundle.service.service_version.clone(),
                        binding_name: binding_name.clone(),
                        state_key: state_key.clone(),
                        encryption: SoraStateEncryptionV1::FheCiphertext,
                        payload: b"ciphertext".to_vec(),
                        payload_bytes: NonZeroU64::new(10).expect("nonzero"),
                        payload_commitment: Hash::new(b"ciphertext"),
                        fhe_public_key_digest: None,
                        fhe_residual_multiple_bound: None,
                        fhe_bound_mode: None,
                        last_update_sequence: 1,
                        governance_tx_hash,
                        source_action: SoraServiceLifecycleActionV1::StateMutation,
                    },
                );
            let query_signer = checked_test_keypair(0x71);
            let app = mk_app_state_for_tests_with_world(world);
            let response = authoritative_ciphertext_query_response(
                &app,
                signed_ciphertext_query_request(fixture_ciphertext_query_spec(), &query_signer),
            )
            .map_err(|err| eyre::eyre!("authoritative ciphertext query failed: {err:?}"))?;
            assert_eq!(response.action, SoracloudAction::CiphertextQuery);
            assert_eq!(response.response.result_count, 1);
            assert_eq!(
                response.response.results[0].ciphertext_commitment,
                Hash::new(b"ciphertext")
            );
            assert_eq!(
                response.response.results[0]
                    .proof
                    .as_ref()
                    .expect("inclusion proof")
                    .event_sequence,
                1
            );
            Ok(())
        })
    }
    #[test]
    fn authoritative_health_compliance_report_reads_world_state() -> Result<(), eyre::Report> {
        use iroha_core::state::World;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let mut world = World::default();
            let bundle = fixture_bundle("1.0.0");
            let service_name = bundle.service.service_name.clone();
            let policy = fixture_decryption_authority_policy();
            let policy_snapshot_hash = Hash::new(Encode::encode(&policy));
            install_fixture_service(&mut world, &bundle, &service_name);
            for (sequence, state_key, break_glass, consent_evidence_hash) in [
                (
                    2,
                    "/state/health/patient-1",
                    false,
                    Some(Hash::new(b"consent-1")),
                ),
                (3, "/state/health/patient-2", true, None),
            ] {
                world
                    .soracloud_service_audit_events_mut_for_testing()
                    .insert(
                        sequence,
                        SoraServiceAuditEventV1 {
                            schema_version:
                                iroha_data_model::soracloud::SORA_SERVICE_AUDIT_EVENT_VERSION_V1,
                            sequence,
                            block_height: sequence,
                            block_timestamp_ms: sequence,
                            action: SoraServiceLifecycleActionV1::DecryptionRequest,
                            service_name: service_name.clone(),
                            from_version: None,
                            to_version: bundle.service.service_version.clone(),
                            service_manifest_hash: bundle.service_manifest_hash(),
                            container_manifest_hash: bundle.container_manifest_hash(),
                            process_generation: 1,
                            config_generation: 0,
                            secret_generation: 0,
                            config_snapshot_hash: iroha_data_model::soracloud::derive_soracloud_service_config_snapshot_hash_v1(&BTreeMap::new()),
                            secret_snapshot_hash: iroha_data_model::soracloud::derive_soracloud_service_secret_snapshot_hash_v1(&BTreeMap::new()),
                            governance_tx_hash: Some(Hash::new(Encode::encode(&(
                                "gov-health",
                                sequence,
                            )))),
                            binding_name: Some("patient_records".parse()?),
                            state_key: Some(state_key.to_string()),
                            config_mutations: Vec::new(),
                            secret_mutations: Vec::new(),
                            rollout_state: None,
                            policy_name: Some(policy.policy_name.clone()),
                            policy_snapshot_hash: Some(policy_snapshot_hash),
                            jurisdiction_tag: Some(policy.jurisdiction_tag.clone()),
                            consent_evidence_hash,
                            break_glass: Some(break_glass),
                            break_glass_reason: break_glass
                                .then(|| "emergency override".to_string()),
                            lease_usage: None,
                            service_lease_commitment: None,
                            lease_reporting_epoch_rollover: None,
                            signer: checked_test_keypair(0x70u8.wrapping_add(sequence as u8))
                                .public_key()
                                .clone(),
                        },
                    );
            }
            let app = mk_app_state_for_tests_with_world(world);
            let report = authoritative_health_compliance_report(
                &app,
                Some(service_name.as_ref()),
                Some("us_hipaa"),
                20,
            )
            .map_err(|err| eyre::eyre!("authoritative health report failed: {err:?}"))?;
            assert_eq!(report.total_access_events, 2);
            assert_eq!(report.break_glass_events, 1);
            assert_eq!(report.non_break_glass_events, 1);
            assert_eq!(report.consent_evidence_present_events, 1);
            assert_eq!(report.consent_evidence_coverage_bps, 5_000);
            assert_eq!(report.recent_access_events.len(), 2);
            assert!(
                report
                    .data_flow_attestations
                    .iter()
                    .any(|entry| entry.binding_name == "patient_records"),
                "expected authoritative data-flow attestation"
            );
            assert_eq!(report.policy_diff_history.len(), 1);
            assert_eq!(
                report.policy_diff_history[0].policy_snapshot_hash,
                policy_snapshot_hash
            );
            Ok(())
        })
    }
    #[test]
    fn soracloud_query_limits_and_filters_are_exact_v1_values() {
        let app = mk_app_state_for_tests_with_world(Default::default());
        for invalid in [0, MAX_AUDIT_LIMIT + 1] {
            let error = authoritative_app_infra_status_response(&app, None, invalid)
                .expect_err("app audit_limit must not be clamped");
            assert_eq!(error.kind, SoracloudErrorKind::BadRequest);

            let error = control_plane_snapshot(&app, None, invalid)
                .expect_err("control-plane audit_limit must not be clamped");
            assert_eq!(error.kind, SoracloudErrorKind::BadRequest);
        }
        for invalid in [0, MAX_HEALTH_COMPLIANCE_LIMIT + 1] {
            let error = authoritative_health_compliance_report(&app, None, None, invalid)
                .expect_err("health report limit must not be clamped");
            assert_eq!(error.kind, SoracloudErrorKind::BadRequest);
        }
        let error = authoritative_health_compliance_report(
            &app,
            None,
            Some(" us_hipaa"),
            DEFAULT_HEALTH_COMPLIANCE_LIMIT,
        )
        .expect_err("jurisdiction_tag must not be trimmed");
        assert_eq!(error.kind, SoracloudErrorKind::BadRequest);
    }
    #[test]
    fn health_compliance_projection_fails_closed_without_authoritative_governance() {
        use iroha_core::state::World;

        let mut world = World::default();
        let bundle = fixture_bundle("1.0.0");
        world
            .soracloud_service_audit_events_mut_for_testing()
            .insert(
            1,
            SoraServiceAuditEventV1 {
                schema_version: iroha_data_model::soracloud::SORA_SERVICE_AUDIT_EVENT_VERSION_V1,
                sequence: 1,
                block_height: 1,
                block_timestamp_ms: 1,
                action: SoraServiceLifecycleActionV1::DecryptionRequest,
                service_name: bundle.service.service_name.clone(),
                from_version: None,
                to_version: bundle.service.service_version.clone(),
                service_manifest_hash: bundle.service_manifest_hash(),
                container_manifest_hash: bundle.container_manifest_hash(),
                process_generation: 1,
                config_generation: 0,
                secret_generation: 0,
                config_snapshot_hash:
                    iroha_data_model::soracloud::derive_soracloud_service_config_snapshot_hash_v1(
                        &BTreeMap::new(),
                    ),
                secret_snapshot_hash:
                    iroha_data_model::soracloud::derive_soracloud_service_secret_snapshot_hash_v1(
                        &BTreeMap::new(),
                    ),
                governance_tx_hash: None,
                binding_name: Some("patient_records".parse().expect("binding name")),
                state_key: Some("/state/health/patient-1".to_owned()),
                config_mutations: Vec::new(),
                secret_mutations: Vec::new(),
                rollout_state: None,
                policy_name: Some("health_policy".parse().expect("policy name")),
                policy_snapshot_hash: Some(Hash::new(b"health policy")),
                jurisdiction_tag: Some("us_hipaa".to_owned()),
                consent_evidence_hash: None,
                break_glass: Some(false),
                break_glass_reason: None,
                lease_usage: None,
                service_lease_commitment: None,
                lease_reporting_epoch_rollover: None,
                signer: checked_test_keypair(0x74).public_key().clone(),
            },
        );
        let app = mk_app_state_for_tests_with_world(world);
        let error = authoritative_health_compliance_report(&app, None, None, 20)
            .expect_err("missing authoritative governance linkage must fail closed");
        assert_eq!(error.kind, SoracloudErrorKind::Internal);
        assert!(error.message.contains("governance_tx_hash"));
        assert!(
            error
                .message
                .contains("must be present for this lifecycle action")
        );
    }
    #[tokio::test]
    async fn health_compliance_report_rate_limit_keys_transport_remote_when_internal_header_missing()
     {
        let mut app = mk_app_state_for_tests_with_world(Default::default());
        Arc::get_mut(&mut app)
            .expect("unique app state")
            .rate_limiter = crate::limits::RateLimiter::new(Some(1), Some(1));
        let first = handle_health_compliance_report(
            State(app.clone()),
            HeaderMap::new(),
            axum::extract::ConnectInfo(std::net::SocketAddr::from(([198, 51, 100, 20], 0))),
            NoritoQuery(HealthComplianceReportQuery::default()),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);
        let second = handle_health_compliance_report(
            State(app),
            HeaderMap::new(),
            axum::extract::ConnectInfo(std::net::SocketAddr::from(([198, 51, 100, 21], 0))),
            NoritoQuery(HealthComplianceReportQuery::default()),
        )
        .await;
        assert_eq!(second.status(), StatusCode::OK);
    }
    #[test]
    fn authoritative_training_job_status_reads_world_state() -> Result<(), eyre::Report> {
        use iroha_core::state::World;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let mut world = World::default();
            let bundle = fixture_bundle_with_training("1.0.0", true);
            let service_name = bundle.service.service_name.clone();
            install_fixture_service(&mut world, &bundle, &service_name);
            world.soracloud_training_jobs_mut_for_testing().insert(
                (service_name.as_ref().to_owned(), "job-1".to_string()),
                iroha_data_model::soracloud::SoraTrainingJobRecordV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_TRAINING_JOB_RECORD_VERSION_V1,
                    service_name: service_name.clone(),
                    service_version: bundle.service.service_version.clone(),
                    model_name: "vision_model".to_string(),
                    job_id: "job-1".to_string(),
                    status: iroha_data_model::soracloud::SoraTrainingJobStatusV1::Completed,
                    worker_group_size: 4,
                    target_steps: 100,
                    completed_steps: 100,
                    checkpoint_interval_steps: 20,
                    last_checkpoint_step: Some(100),
                    checkpoint_count: 5,
                    retry_count: 1,
                    max_retries: 3,
                    step_compute_units: 50,
                    compute_budget_units: 40_000,
                    compute_consumed_units: 20_000,
                    storage_budget_bytes: 8_192,
                    storage_consumed_bytes: 4_096,
                    latest_metrics_hash: Some(Hash::new(b"metrics")),
                    last_failure_reason: None,
                    created_sequence: 1,
                    updated_sequence: 5,
                },
            );
            let app = mk_app_state_for_tests_with_world(world);
            let response = authoritative_training_job_status_response(&app, "web_portal", "job-1")
                .map_err(|err| {
                    eyre::eyre!("authoritative training job status query failed: {err:?}")
                })?;
            assert_eq!(response.job.job_id, "job-1");
            assert_eq!(response.job.status, TrainingJobStatus::Completed);
            assert_eq!(response.job.compute_remaining_units, 20_000);
            Ok(())
        })
    }
    #[test]
    fn authoritative_service_config_status_reads_world_state() -> Result<(), eyre::Report> {
        use iroha_core::state::World;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let mut world = World::default();
            let bundle = fixture_bundle("1.0.0");
            let service_name = bundle.service.service_name.clone();
            let config_value = norito::json!({
                "theme": "dark",
                "max_connections": 32
            });
            insert_revision(&mut world, &bundle, service_name.as_ref().to_owned());
            world
                .soracloud_service_deployments_mut_for_testing()
                .insert(
                service_name.clone(),
                SoraServiceDeploymentStateV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_SERVICE_DEPLOYMENT_STATE_VERSION_V1,
                    service_name: service_name.clone(),
                    current_service_version: bundle.service.service_version.clone(),
                    current_service_manifest_hash: bundle.service_manifest_hash(),
                    current_container_manifest_hash: bundle.container_manifest_hash(),
                    revision_count: 1,
                    process_generation: 1,
                    process_started_sequence: 1,
                    active_rollout: None,
                    last_rollout: None,
                    config_generation: 4,
                    secret_generation: 0,
                    service_configs: BTreeMap::from([(
                        "ui/theme".to_string(),
                        SoraServiceConfigEntryV1 {
                            schema_version:
                                iroha_data_model::soracloud::SORA_SERVICE_CONFIG_ENTRY_VERSION_V1,
                            config_name: "ui/theme".to_string(),
                            value_hash: Hash::new(
                                norito::json::to_vec(&config_value)
                                    .expect("config json should encode"),
                            ),
                            value_json: Json::from(config_value.clone()),
                            last_update_sequence: 12,
                        },
                    )]),
                    service_secrets: BTreeMap::new(),
                    fhe_policy_records: BTreeMap::new(),
                    service_lease: None,
                    lease_volume_states: Vec::new(),
                },
            );
            let app = mk_app_state_for_tests_with_world(world);
            let response =
                authoritative_service_config_status_response(&app, "web_portal", Some("ui/theme"))
                    .map_err(|err| {
                        eyre::eyre!("authoritative service config status query failed: {err:?}")
                    })?;
            assert_eq!(response.service_name, "web_portal");
            assert_eq!(response.current_version, "1.0.0");
            assert_eq!(response.config_generation, 4);
            assert_eq!(response.config_entry_count, 1);
            assert_eq!(response.configs[0].config_name, "ui/theme");
            assert_eq!(response.configs[0].value_json, config_value);
            assert_eq!(response.configs[0].last_update_sequence, 12);
            Ok(())
        })
    }
    #[test]
    fn authoritative_service_public_discovery_reads_world_state_and_fails_closed_on_substitution()
    -> Result<(), eyre::Report> {
        use iroha_core::state::World;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let mut world = World::default();
            let bundle = fixture_hosted_http_inrou_bundle("1.0.0");
            let service_name = bundle.service.service_name.clone();
            let content_cid = crate::sorafs::site::encode_content_cid(
                &sorafs_manifest::canonical_manifest_root_cid([0xD0; 32]),
            );
            let base_url = bundle_base_url(&bundle).expect("fixture base URL");
            let route_host = bundle
                .service
                .route
                .as_ref()
                .expect("fixture route")
                .host
                .clone();
            let (public_discovery_url, public_discovery_cid_host_url) =
                canonical_public_service_discovery_urls(&base_url, &route_host, &content_cid)
                    .map_err(|error| eyre::eyre!(error.message))?;
            let mut discovery = SoracloudPublicServiceDiscoveryV1 {
                schema_version: PUBLIC_SERVICE_DISCOVERY_SCHEMA_VERSION_V1,
                service_name: service_name.to_string(),
                service_version: bundle.service.service_version.clone(),
                execution_plane: format!("{:?}", bundle.service.execution_plane),
                runtime: format!("{:?}", bundle.container.runtime),
                route_host,
                path_prefix: bundle
                    .service
                    .route
                    .as_ref()
                    .expect("fixture route")
                    .path_prefix
                    .clone(),
                base_url,
                healthcheck_path: bundle.container.lifecycle.healthcheck_path.clone(),
                healthcheck_url: bundle_healthcheck_url(&bundle),
                service_manifest_hash: bundle.service_manifest_hash(),
                container_manifest_hash: bundle.container_manifest_hash(),
                deployment_bundle_hash: Hash::new(Encode::encode(&bundle)),
                document_hash: Hash::new([]),
                content_cid,
                public_discovery_url,
                public_discovery_cid_host_url,
                manifest_digest_hex: "de".repeat(32),
            };
            discovery.document_hash = public_service_discovery_document_hash(&discovery)
                .map_err(|error| eyre::eyre!(error.message))?;
            let discovery_document_bytes = public_service_discovery_document_bytes(&discovery)
                .map_err(|error| eyre::eyre!(error.message))?;
            let discovery_root_cid =
                public_service_discovery_artifact_root_cid(discovery_document_bytes.clone())
                    .map_err(|error| eyre::eyre!(error.message))?;
            discovery.content_cid =
                crate::sorafs::site::encode_content_cid(discovery_root_cid.as_bytes());
            (
                discovery.public_discovery_url,
                discovery.public_discovery_cid_host_url,
            ) = canonical_public_service_discovery_urls(
                &discovery.base_url,
                &discovery.route_host,
                &discovery.content_cid,
            )
            .map_err(|error| eyre::eyre!(error.message))?;
            let descriptor = sorafs_manifest::chunker_registry::default_descriptor();
            let (discovery_plan, discovery_payload) = CarBuildPlan::from_files_with_profile(
                vec![FileEntry {
                    path: vec![PUBLIC_SERVICE_DISCOVERY_INDEX_DOCUMENT.to_owned()],
                    data: discovery_document_bytes.clone(),
                }],
                descriptor.profile,
            )
            .expect("plan canonical public discovery artifact");
            let mut car_sink = io::sink();
            let discovery_car_stats = CarWriter::new(&discovery_plan, &discovery_payload)
                .expect("construct canonical public discovery CAR writer")
                .write_to(&mut car_sink)
                .expect("derive canonical public discovery CAR metadata");
            assert_eq!(
                discovery_car_stats.root_cids.as_slice(),
                &[discovery_root_cid.as_bytes().to_vec()]
            );
            let discovery_manifest = sorafs_manifest::ManifestBuilder::new()
                .root_cid(discovery_root_cid.as_bytes().to_vec())
                .dag_codec(sorafs_manifest::DagCodecId(discovery_car_stats.dag_codec))
                .chunking_profile(sorafs_manifest::ChunkingProfileV1::from_descriptor(
                    descriptor,
                ))
                .chunk_digest_sha3_256(sorafs_car::compute_chunk_plan_digest_sha3(
                    &discovery_plan.chunks,
                ))
                .por_root(
                    sorafs_car::compute_por_root(&discovery_payload, &discovery_plan)
                        .expect("derive canonical public discovery PoR root"),
                )
                .content_length(discovery_plan.content_length)
                .car_digest(*discovery_car_stats.car_archive_digest.as_bytes())
                .car_size(discovery_car_stats.car_size)
                .pin_policy(sorafs_manifest::PinPolicy::default())
                .build()
                .expect("build canonical public discovery manifest");
            let discovery_manifest_digest = ManifestDigest::from_manifest(&discovery_manifest)
                .expect("derive canonical public discovery manifest digest");
            discovery.manifest_digest_hex = hex::encode(discovery_manifest_digest.as_bytes());
            world.pin_manifests_mut_for_testing().insert(
                discovery_manifest_digest,
                sample_public_discovery_pin_record(
                    discovery_manifest_digest,
                    discovery_root_cid,
                    u64::try_from(discovery_document_bytes.len())
                        .expect("discovery document length"),
                    PinStatus::Approved(1),
                ),
            );
            let mut substituted_discovery = discovery.clone();
            substituted_discovery.deployment_bundle_hash = Hash::new(b"substituted bundle");
            let error = validate_public_service_discovery_for_bundle(
                &world.view(),
                &fixture_service_deployment(&bundle),
                &bundle,
                &substituted_discovery,
            )
            .expect_err("substituted public discovery bundle binding must fail closed");
            assert_eq!(error.kind, SoracloudErrorKind::Internal);
            assert!(error.message.contains("does not bind admitted revision"));
            let mut substituted_document_hash = discovery.clone();
            substituted_document_hash.document_hash = Hash::new(b"substituted index document");
            let error = validate_public_service_discovery_for_bundle(
                &world.view(),
                &fixture_service_deployment(&bundle),
                &bundle,
                &substituted_document_hash,
            )
            .expect_err("substituted public discovery document hash must fail closed");
            assert!(error.message.contains("document hash does not bind"));
            let mut noncanonical_cid = discovery.clone();
            noncanonical_cid.content_cid.make_ascii_uppercase();
            let error = validate_public_service_discovery_for_bundle(
                &world.view(),
                &fixture_service_deployment(&bundle),
                &bundle,
                &noncanonical_cid,
            )
            .expect_err("noncanonical public discovery CID must fail closed");
            assert!(error.message.contains("content CID is not a canonical"));
            let mut substituted_canonical_cid = discovery.clone();
            substituted_canonical_cid.content_cid = crate::sorafs::site::encode_content_cid(
                &sorafs_manifest::canonical_manifest_root_cid([0xD2; 32]),
            );
            (
                substituted_canonical_cid.public_discovery_url,
                substituted_canonical_cid.public_discovery_cid_host_url,
            ) = canonical_public_service_discovery_urls(
                &substituted_canonical_cid.base_url,
                &substituted_canonical_cid.route_host,
                &substituted_canonical_cid.content_cid,
            )
            .map_err(|error| eyre::eyre!(error.message))?;
            let error = validate_public_service_discovery_for_bundle(
                &world.view(),
                &fixture_service_deployment(&bundle),
                &bundle,
                &substituted_canonical_cid,
            )
            .expect_err("substituted canonical public discovery CID must fail closed");
            assert!(error.message.contains("does not bind its canonical index"));
            let mut noncanonical_digest = discovery.clone();
            noncanonical_digest
                .manifest_digest_hex
                .make_ascii_uppercase();
            let error = validate_public_service_discovery_for_bundle(
                &world.view(),
                &fixture_service_deployment(&bundle),
                &bundle,
                &noncanonical_digest,
            )
            .expect_err("noncanonical public discovery manifest digest must fail closed");
            assert!(error.message.contains("manifest digest is not canonical"));
            let mut substituted_url = discovery.clone();
            substituted_url
                .public_discovery_url
                .push_str("?substituted=1");
            let error = validate_public_service_discovery_for_bundle(
                &world.view(),
                &fixture_service_deployment(&bundle),
                &bundle,
                &substituted_url,
            )
            .expect_err("substituted public discovery URL must fail closed");
            assert!(error.message.contains("URLs do not bind"));
            world.pin_manifests_mut_for_testing().insert(
                discovery_manifest_digest,
                sample_public_discovery_pin_record(
                    discovery_manifest_digest,
                    discovery_root_cid,
                    u64::try_from(discovery_document_bytes.len())
                        .expect("discovery document length"),
                    PinStatus::Pending,
                ),
            );
            let error = validate_public_service_discovery_for_bundle(
                &world.view(),
                &fixture_service_deployment(&bundle),
                &bundle,
                &discovery,
            )
            .expect_err("pending public discovery pin must fail closed");
            assert!(error.message.contains("pending governance approval"));
            world.pin_manifests_mut_for_testing().insert(
                discovery_manifest_digest,
                sample_public_discovery_pin_record(
                    discovery_manifest_digest,
                    discovery_root_cid,
                    u64::try_from(discovery_document_bytes.len())
                        .expect("discovery document length"),
                    PinStatus::Retired(3),
                ),
            );
            let error = validate_public_service_discovery_for_bundle(
                &world.view(),
                &fixture_service_deployment(&bundle),
                &bundle,
                &discovery,
            )
            .expect_err("retired public discovery pin must fail closed");
            assert!(error.message.contains("retired at epoch 3"));
            let mut inconsistent_approval = sample_public_discovery_pin_record(
                discovery_manifest_digest,
                discovery_root_cid,
                u64::try_from(discovery_document_bytes.len()).expect("discovery document length"),
                PinStatus::Approved(4),
            );
            inconsistent_approval.approved_epoch = Some(5);
            world
                .pin_manifests_mut_for_testing()
                .insert(discovery_manifest_digest, inconsistent_approval);
            let error = validate_public_service_discovery_for_bundle(
                &world.view(),
                &fixture_service_deployment(&bundle),
                &bundle,
                &discovery,
            )
            .expect_err("inconsistent public discovery approval history must fail closed");
            assert!(
                error
                    .message
                    .contains("does not match its immutable approval history")
            );
            world.pin_manifests_mut_for_testing().insert(
                discovery_manifest_digest,
                sample_public_discovery_pin_record(
                    discovery_manifest_digest,
                    discovery_root_cid,
                    u64::try_from(discovery_document_bytes.len())
                        .expect("discovery document length"),
                    PinStatus::Approved(1),
                ),
            );
            let mismatched_pin_digest = ManifestDigest::new([0xE1; 32]);
            let mismatched_pin_root = ManifestRootCid::try_from_slice(
                &sorafs_manifest::canonical_manifest_root_cid([0xD3; 32]),
            )
            .expect("canonical mismatched pin root");
            world.pin_manifests_mut_for_testing().insert(
                mismatched_pin_digest,
                sample_public_discovery_pin_record(
                    mismatched_pin_digest,
                    mismatched_pin_root,
                    u64::try_from(discovery_document_bytes.len())
                        .expect("discovery document length"),
                    PinStatus::Approved(1),
                ),
            );
            let mut mismatched_pin = discovery.clone();
            mismatched_pin.manifest_digest_hex = hex::encode(mismatched_pin_digest.as_bytes());
            let error = validate_public_service_discovery_for_bundle(
                &world.view(),
                &fixture_service_deployment(&bundle),
                &bundle,
                &mismatched_pin,
            )
            .expect_err("public discovery pin root mismatch must fail closed");
            assert!(error.message.contains("pin record does not bind"));
            let historical_bundle = fixture_hosted_http_inrou_bundle("0.9.0");
            let mut historical_discovery = discovery.clone();
            historical_discovery.service_version =
                historical_bundle.service.service_version.clone();
            historical_discovery.service_manifest_hash = historical_bundle.service_manifest_hash();
            historical_discovery.container_manifest_hash =
                historical_bundle.container_manifest_hash();
            historical_discovery.deployment_bundle_hash =
                Hash::new(Encode::encode(&historical_bundle));
            historical_discovery.content_cid = crate::sorafs::site::encode_content_cid(
                &sorafs_manifest::canonical_manifest_root_cid([0xD1; 32]),
            );
            historical_discovery.manifest_digest_hex = "df".repeat(32);
            (
                historical_discovery.public_discovery_url,
                historical_discovery.public_discovery_cid_host_url,
            ) = canonical_public_service_discovery_urls(
                &historical_discovery.base_url,
                &historical_discovery.route_host,
                &historical_discovery.content_cid,
            )
            .map_err(|error| eyre::eyre!(error.message))?;
            historical_discovery.document_hash =
                public_service_discovery_document_hash(&historical_discovery)
                    .map_err(|error| eyre::eyre!(error.message))?;
            let historical_document_bytes =
                public_service_discovery_document_bytes(&historical_discovery)
                    .map_err(|error| eyre::eyre!(error.message))?;
            let historical_root_cid =
                public_service_discovery_artifact_root_cid(historical_document_bytes.clone())
                    .map_err(|error| eyre::eyre!(error.message))?;
            historical_discovery.content_cid =
                crate::sorafs::site::encode_content_cid(historical_root_cid.as_bytes());
            (
                historical_discovery.public_discovery_url,
                historical_discovery.public_discovery_cid_host_url,
            ) = canonical_public_service_discovery_urls(
                &historical_discovery.base_url,
                &historical_discovery.route_host,
                &historical_discovery.content_cid,
            )
            .map_err(|error| eyre::eyre!(error.message))?;
            let historical_manifest_digest = ManifestDigest::new(
                hex::decode(&historical_discovery.manifest_digest_hex)
                    .expect("decode historical discovery digest")
                    .try_into()
                    .expect("32-byte historical discovery digest"),
            );
            world.pin_manifests_mut_for_testing().insert(
                historical_manifest_digest,
                sample_public_discovery_pin_record(
                    historical_manifest_digest,
                    historical_root_cid,
                    u64::try_from(historical_document_bytes.len())
                        .expect("historical discovery document length"),
                    PinStatus::Approved(2),
                ),
            );
            let historical_content_cid = historical_discovery.content_cid.clone();
            let registry = SoracloudPublicServiceDiscoveryRegistryV1 {
                schema_version: PUBLIC_SERVICE_DISCOVERY_SCHEMA_VERSION_V1,
                service_name: service_name.to_string(),
                current_version: bundle.service.service_version.clone(),
                revisions: BTreeMap::from([
                    (
                        historical_bundle.service.service_version.clone(),
                        historical_discovery,
                    ),
                    (bundle.service.service_version.clone(), discovery.clone()),
                ]),
            };
            let registry_json = Json::new(registry);
            let registry_entry = SoraServiceConfigEntryV1 {
                schema_version: iroha_data_model::soracloud::SORA_SERVICE_CONFIG_ENTRY_VERSION_V1,
                config_name: PUBLIC_SERVICE_DISCOVERY_CONFIG_NAME.to_string(),
                value_hash: Hash::new(
                    norito::json::to_vec(&registry_json).expect("registry json should encode"),
                ),
                value_json: registry_json,
                last_update_sequence: 21,
            };
            let mut substituted_registry_entry = registry_entry.clone();
            substituted_registry_entry.value_hash = Hash::new(b"substituted registry");
            let error = decode_public_service_discovery_registry(&substituted_registry_entry)
                .expect_err("substituted public discovery registry hash must fail closed");
            assert_eq!(error.kind, SoracloudErrorKind::Internal);
            assert!(error.message.contains("hash does not bind its JSON value"));
            let service_lease = iroha_data_model::soracloud::SoraServiceLeaseStateV1 {
                schema_version: iroha_data_model::soracloud::SORA_SERVICE_LEASE_STATE_VERSION_V1,
                economic_clock:
                    iroha_data_model::soracloud::SoraServiceLeaseClockV1::CanonicalBlockHeight,
                status: iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
                quota_class: "taira-open".to_string(),
                replica_count: bundle.service.replicas,
                deployment_deposit: "1".parse().expect("deployment deposit quantity"),
                prepaid_runtime_balance: "50".parse().expect("prepaid runtime quantity"),
                runtime_price_per_block: "0.00025".parse().expect("runtime price quantity"),
                storage_price_per_gib_block: "0.000025".parse().expect("storage price quantity"),
                egress_price_per_mib: "0.000005".parse().expect("egress price quantity"),
                lease_started_height: 1,
                lease_expires_height: 100,
                reporting_epoch: 1,
                settled_egress_bytes: 0,
                egress_reporter_checkpoints: Vec::new(),
                accounted_egress_bytes: 0,
                last_status_reason: None,
            };
            let lease_volume_states =
                fixture_service_lease_volume_states(&bundle, Some(&service_lease));
            insert_revision(&mut world, &bundle, service_name.as_ref().to_owned());
            insert_revision(
                &mut world,
                &historical_bundle,
                service_name.as_ref().to_owned(),
            );
            world
                .soracloud_service_deployments_mut_for_testing()
                .insert(
                    service_name.clone(),
                    SoraServiceDeploymentStateV1 {
                        schema_version:
                            iroha_data_model::soracloud::SORA_SERVICE_DEPLOYMENT_STATE_VERSION_V1,
                        service_name: service_name.clone(),
                        current_service_version: bundle.service.service_version.clone(),
                        current_service_manifest_hash: bundle.service_manifest_hash(),
                        current_container_manifest_hash: bundle.container_manifest_hash(),
                        revision_count: 2,
                        process_generation: 1,
                        process_started_sequence: 1,
                        active_rollout: None,
                        last_rollout: None,
                        config_generation: 1,
                        secret_generation: 0,
                        service_configs: BTreeMap::from([(
                            PUBLIC_SERVICE_DISCOVERY_CONFIG_NAME.to_string(),
                            registry_entry,
                        )]),
                        service_secrets: BTreeMap::new(),
                        fhe_policy_records: BTreeMap::new(),
                        service_lease: Some(service_lease),
                        lease_volume_states,
                    },
                );
            world
                .soracloud_service_audit_events_mut_for_testing()
                .insert(1, fixture_service_deploy_audit_event(&bundle));
            let mut app = mk_app_state_for_tests_with_world(world);
            let mut app_inner = Arc::try_unwrap(app).unwrap_or_else(|_| {
                panic!("public discovery test requires a unique Torii app state")
            });
            app_inner.sorafs_gateway_config.untrusted_hosting.enabled = true;
            app_inner
                .sorafs_gateway_config
                .untrusted_hosting
                .cid_host_suffixes
                .taira = "sorafs.taira.sora.org".to_owned();
            app = Arc::new(app_inner);
            assert!(
                !app.sorafs_node.is_enabled(),
                "authoritative discovery readback must work on a storage-disabled validator"
            );
            let response =
                authoritative_service_public_discovery_response(&app, service_name.as_ref(), None)
                    .map_err(|err| {
                        eyre::eyre!("authoritative service public discovery query failed: {err:?}")
                    })?;
            assert_eq!(response.discovery.content_cid, discovery.content_cid);
            assert_eq!(
                response.discovery.public_discovery_cid_host_url,
                discovery.public_discovery_cid_host_url
            );
            let historical_response = authoritative_service_public_discovery_response(
                &app,
                service_name.as_ref(),
                Some("0.9.0"),
            )
            .map_err(|err| eyre::eyre!("historical public discovery query failed: {err:?}"))?;
            assert_eq!(
                historical_response.discovery.content_cid,
                historical_content_cid
            );
            let snapshot = control_plane_snapshot(&app, Some(service_name.as_ref()), 10)?;
            assert_eq!(snapshot.services.len(), 1);
            assert_eq!(
                snapshot.services[0].public_discovery_content_cid.as_deref(),
                Some(discovery.content_cid.as_str())
            );
            assert_eq!(
                snapshot.services[0]
                    .latest_revision
                    .as_ref()
                    .and_then(|revision| revision.public_discovery_url.as_deref()),
                Some(discovery.public_discovery_url.as_str())
            );
            let path_response = crate::sorafs::api::handle_get_sorafs_cid_path(
                State(Arc::clone(&app)),
                HeaderMap::new(),
                format!(
                    "/sorafs/cid/{}/{PUBLIC_SERVICE_DISCOVERY_INDEX_DOCUMENT}",
                    discovery.content_cid
                )
                .parse()
                .expect("valid public discovery path-gateway URI"),
                Path((
                    discovery.content_cid.clone(),
                    PUBLIC_SERVICE_DISCOVERY_INDEX_DOCUMENT.to_owned(),
                )),
            )
            .await;
            assert_eq!(path_response.status(), StatusCode::NOT_FOUND);
            use http_body_util::BodyExt as _;
            let path_body = path_response
                .into_body()
                .collect()
                .await
                .expect("collect storage-disabled path response")
                .to_bytes();
            assert!(
                std::str::from_utf8(path_body.as_ref())
                    .expect("storage-disabled response is UTF-8 JSON")
                    .contains("sorafs storage API is not enabled on this node")
            );
            let mut cid_host_headers = HeaderMap::new();
            cid_host_headers.insert(
                axum::http::header::HOST,
                axum::http::HeaderValue::from_str(&format!(
                    "{}.sorafs.taira.sora.org",
                    discovery.content_cid
                ))
                .expect("canonical public discovery CID host"),
            );
            let cid_host_response = crate::sorafs::api::handle_get_sorafs_site_path(
                State(Arc::clone(&app)),
                cid_host_headers,
                Path(PUBLIC_SERVICE_DISCOVERY_INDEX_DOCUMENT.to_owned()),
            )
            .await;
            // The authoritative document is served directly for its bound CID
            // host, even when the general storage API is disabled.
            assert_eq!(cid_host_response.status(), StatusCode::OK);
            let cid_host_body = cid_host_response
                .into_body()
                .collect()
                .await
                .expect("collect authoritative CID-host response")
                .to_bytes();
            assert_eq!(cid_host_body.as_ref(), discovery_document_bytes.as_slice());
            let blocked_other_path = crate::sorafs::api::handle_get_sorafs_cid_path(
                State(Arc::clone(&app)),
                HeaderMap::new(),
                format!("/sorafs/cid/{}/manifest.to", discovery.content_cid)
                    .parse()
                    .expect("valid blocked preseed path URI"),
                Path((discovery.content_cid.clone(), "manifest.to".to_owned())),
            )
            .await;
            assert_eq!(blocked_other_path.status(), StatusCode::NOT_FOUND);
            let unbound_content_cid = crate::sorafs::site::encode_content_cid(
                &sorafs_manifest::canonical_manifest_root_cid([0xA7; 32]),
            );
            let blocked_unbound_index = crate::sorafs::api::handle_get_sorafs_cid_path(
                State(Arc::clone(&app)),
                HeaderMap::new(),
                format!(
                    "/sorafs/cid/{unbound_content_cid}/{PUBLIC_SERVICE_DISCOVERY_INDEX_DOCUMENT}"
                )
                .parse()
                .expect("valid unbound discovery path URI"),
                Path((
                    unbound_content_cid,
                    PUBLIC_SERVICE_DISCOVERY_INDEX_DOCUMENT.to_owned(),
                )),
            )
            .await;
            assert_eq!(blocked_unbound_index.status(), StatusCode::NOT_FOUND);
            Ok(())
        })
    }
    #[test]
    fn authoritative_service_secret_status_reads_world_state() -> Result<(), eyre::Report> {
        use iroha_core::state::World;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let mut world = World::default();
            let bundle = fixture_bundle("1.0.0");
            let service_name = bundle.service.service_name.clone();
            let secret = SecretEnvelopeV1 {
                schema_version: iroha_data_model::soracloud::SECRET_ENVELOPE_VERSION_V1,
                encryption: SecretEnvelopeEncryptionV1::ClientCiphertext,
                key_id: "kms/config/test".to_string(),
                key_version: std::num::NonZeroU32::new(7).expect("non-zero"),
                nonce: vec![1, 2, 3, 4],
                ciphertext: b"encrypted-db-password".to_vec(),
                commitment: Hash::new(b"service-secret"),
                aad_digest: None,
            };
            insert_revision(&mut world, &bundle, service_name.as_ref().to_owned());
            world
                .soracloud_service_deployments_mut_for_testing()
                .insert(
                service_name.clone(),
                SoraServiceDeploymentStateV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_SERVICE_DEPLOYMENT_STATE_VERSION_V1,
                    service_name: service_name.clone(),
                    current_service_version: bundle.service.service_version.clone(),
                    current_service_manifest_hash: bundle.service_manifest_hash(),
                    current_container_manifest_hash: bundle.container_manifest_hash(),
                    revision_count: 1,
                    process_generation: 1,
                    process_started_sequence: 1,
                    active_rollout: None,
                    last_rollout: None,
                    config_generation: 0,
                    secret_generation: 3,
                    service_configs: BTreeMap::new(),
                    service_secrets: BTreeMap::from([(
                        "db/password".to_string(),
                        SoraServiceSecretEntryV1 {
                            schema_version:
                                iroha_data_model::soracloud::SORA_SERVICE_SECRET_ENTRY_VERSION_V1,
                            secret_name: "db/password".to_string(),
                            envelope: secret.clone(),
                            last_update_sequence: 9,
                        },
                    )]),
                    fhe_policy_records: BTreeMap::new(),
                    service_lease: None,
                    lease_volume_states: Vec::new(),
                },
            );
            let app = mk_app_state_for_tests_with_world(world);
            let response = authoritative_service_secret_status_response(
                &app,
                "web_portal",
                Some("db/password"),
            )
            .map_err(|err| {
                eyre::eyre!("authoritative service secret status query failed: {err:?}")
            })?;
            assert_eq!(response.service_name, "web_portal");
            assert_eq!(response.current_version, "1.0.0");
            assert_eq!(response.secret_generation, 3);
            assert_eq!(response.secret_entry_count, 1);
            assert_eq!(response.secrets[0].secret_name, "db/password");
            assert_eq!(
                response.secrets[0].encryption,
                SecretEnvelopeEncryptionV1::ClientCiphertext
            );
            assert_eq!(response.secrets[0].key_id, "kms/config/test");
            assert_eq!(response.secrets[0].key_version, 7);
            assert_eq!(response.secrets[0].commitment, Hash::new(b"service-secret"));
            assert_eq!(
                response.secrets[0].ciphertext_bytes,
                u64::try_from(secret.ciphertext.len()).expect("fits in u64")
            );
            assert_eq!(response.secrets[0].last_update_sequence, 9);
            Ok(())
        })
    }
    #[test]
    fn authoritative_model_weight_status_reads_world_state() -> Result<(), eyre::Report> {
        use iroha_core::state::World;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let mut world = World::default();
            let bundle = fixture_bundle_with_training("1.0.0", true);
            let service_name = bundle.service.service_name.clone();
            install_fixture_service(&mut world, &bundle, &service_name);
            world.soracloud_model_registries_mut_for_testing().insert(
                (service_name.as_ref().to_owned(), "vision_model".to_string()),
                iroha_data_model::soracloud::SoraModelRegistryV1 {
                    schema_version: iroha_data_model::soracloud::SORA_MODEL_REGISTRY_VERSION_V1,
                    service_name: service_name.clone(),
                    service_version: bundle.service.service_version.clone(),
                    model_name: "vision_model".to_string(),
                    current_version: Some("v2".to_string()),
                    updated_sequence: 9,
                },
            );
            world
                .soracloud_model_weight_versions_mut_for_testing()
                .insert(
                (
                    service_name.as_ref().to_owned(),
                    "vision_model".to_string(),
                    "v2".to_string(),
                ),
                iroha_data_model::soracloud::SoraModelWeightVersionRecordV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_MODEL_WEIGHT_VERSION_RECORD_VERSION_V1,
                    service_name: service_name.clone(),
                    service_version: bundle.service.service_version.clone(),
                    model_name: "vision_model".to_string(),
                    weight_version: "v2".to_string(),
                    parent_version: Some("v1".to_string()),
                    training_job_id: "job-1".to_string(),
                    source_provenance: Some(
                        iroha_data_model::soracloud::SoraModelProvenanceRefV1 {
                            kind:
                                iroha_data_model::soracloud::SoraModelProvenanceKindV1::TrainingJob,
                            id: "job-1".to_string(),
                        },
                    ),
                    weight_artifact_hash: Hash::new(b"weights"),
                    dataset_ref: "dataset://train".to_string(),
                    training_config_hash: Hash::new(b"train-config"),
                    reproducibility_hash: Hash::new(b"repro"),
                    provenance_attestation_hash: Hash::new(b"prov"),
                    registered_sequence: 7,
                    promoted_sequence: Some(9),
                    gate_report_hash: Some(Hash::new(b"gate")),
                    promoted_by: Some(checked_test_keypair(0x74).public_key().clone()),
                },
            );
            let app = mk_app_state_for_tests_with_world(world);
            let response =
                authoritative_model_weight_status_response(&app, "web_portal", "vision_model")
                    .map_err(|err| {
                        eyre::eyre!("authoritative model weight status query failed: {err:?}")
                    })?;
            assert_eq!(response.model.current_version.as_deref(), Some("v2"));
            assert_eq!(response.model.version_count, 1);
            assert_eq!(response.model.versions[0].training_job_id, "job-1");
            Ok(())
        })
    }
    #[test]
    fn authoritative_model_artifact_status_reads_world_state() -> Result<(), eyre::Report> {
        use iroha_core::state::World;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let mut world = World::default();
            let bundle = fixture_bundle_with_training("1.0.0", true);
            let service_name = bundle.service.service_name.clone();
            install_fixture_service(&mut world, &bundle, &service_name);
            world.soracloud_model_artifacts_mut_for_testing().insert(
                (service_name.as_ref().to_owned(), "job-1".to_string()),
                iroha_data_model::soracloud::SoraModelArtifactRecordV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_MODEL_ARTIFACT_RECORD_VERSION_V1,
                    service_name: service_name.clone(),
                    service_version: bundle.service.service_version.clone(),
                    model_name: "vision_model".to_string(),
                    artifact_id: "job-1".to_string(),
                    training_job_id: "job-1".to_string(),
                    weight_version: Some("v2".to_string()),
                    source_provenance: Some(
                        iroha_data_model::soracloud::SoraModelProvenanceRefV1 {
                            kind:
                                iroha_data_model::soracloud::SoraModelProvenanceKindV1::TrainingJob,
                            id: "job-1".to_string(),
                        },
                    ),
                    weight_artifact_hash: Hash::new(b"weights"),
                    dataset_ref: "dataset://train".to_string(),
                    training_config_hash: Hash::new(b"train-config"),
                    reproducibility_hash: Hash::new(b"repro"),
                    provenance_attestation_hash: Hash::new(b"prov"),
                    registered_sequence: 8,
                    consumed_by_version: Some("v2".to_string()),
                    chunk_manifest_root: None,
                },
            );
            let app = mk_app_state_for_tests_with_world(world);
            let response = authoritative_model_artifact_status_response(
                &app,
                "web_portal",
                Some("vision_model"),
                Some("job-1"),
                Some("job-1"),
                Some("v2"),
            )
            .map_err(|err| {
                eyre::eyre!("authoritative model artifact status query failed: {err:?}")
            })?;
            assert_eq!(response.artifact.training_job_id, "job-1");
            assert_eq!(response.artifact.artifact_id, "job-1");
            assert_eq!(response.artifact.consumed_by_version.as_deref(), Some("v2"));
            Ok(())
        })
    }
    #[test]
    fn authoritative_uploaded_model_status_reads_world_state() -> Result<(), eyre::Report> {
        use iroha_core::state::World;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let mut world = World::default();
            let service_name: Name = "web_portal".parse().expect("service name");
            let bundle_root = Hash::new(b"bundle-root");
            let chunk_manifest_root = Hash::new(b"chunk-manifest-root");
            world
                .soracloud_uploaded_model_bundles_mut_for_testing()
                .insert(
                    (
                        service_name.as_ref().to_owned(),
                        "upload-1".to_string(),
                        "v1".to_string(),
                    ),
                    SoraUploadedModelBundleV1 {
                        schema_version:
                            iroha_data_model::soracloud::SORA_UPLOADED_MODEL_BUNDLE_VERSION_V1,
                        service_name: service_name.clone(),
                        model_id: "upload-1".to_string(),
                        weight_version: "v1".to_string(),
                        family: "decoder-only".to_string(),
                        modalities: vec!["text".to_string(), "image".to_string()],
                        plaintext_root: Hash::new(b"plaintext-root"),
                        package_format:
                            SoraUploadedModelPackageFormatV1::NormalizedHuggingFaceSafetensorsV1,
                        bundle_root,
                        sorafs_manifest_digest:
                            iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0xA5; 32]),
                        chunk_count: 1,
                        plaintext_bytes: 16,
                        ciphertext_bytes: 24,
                        chunk_manifest_root,
                        pricing_policy: SoraUploadedModelPricingPolicyV1 {
                            storage_price: "0.000000001".parse().expect("canonical storage price"),
                        },
                    },
                );
            world.soracloud_model_artifacts_mut_for_testing().insert(
                (service_name.as_ref().to_owned(), "artifact-1".to_string()),
                iroha_data_model::soracloud::SoraModelArtifactRecordV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_MODEL_ARTIFACT_RECORD_VERSION_V1,
                    service_name: service_name.clone(),
                    service_version: "1.0.0".to_string(),
                    model_name: "vision_model".to_string(),
                    artifact_id: "artifact-1".to_string(),
                    training_job_id: "artifact-1".to_string(),
                    weight_version: Some("v1".to_string()),
                    source_provenance: Some(SoraModelProvenanceRefV1 {
                        kind: SoraModelProvenanceKindV1::UserUpload,
                        id: "upload-1".to_string(),
                    }),
                    weight_artifact_hash: Hash::new(b"weights"),
                    dataset_ref: "hf://repo".to_string(),
                    training_config_hash: Hash::new(b"cfg"),
                    reproducibility_hash: Hash::new(b"repro"),
                    provenance_attestation_hash: Hash::new(b"prov"),
                    registered_sequence: 11,
                    consumed_by_version: Some("v1".to_string()),
                    chunk_manifest_root: Some(chunk_manifest_root),
                },
            );
            let app = mk_app_state_for_tests_with_world(world);
            let response =
                authoritative_uploaded_model_status_response(&app, "web_portal", "upload-1", "v1")
                    .map_err(|err| eyre::eyre!("uploaded model status query failed: {err:?}"))?;
            assert_eq!(
                response.bundle.sorafs_manifest_digest.as_bytes(),
                &[0xA5; 32]
            );
            assert_eq!(
                response
                    .artifact
                    .as_ref()
                    .map(|artifact| artifact.artifact_id.as_str()),
                Some("artifact-1")
            );
            let err = authoritative_uploaded_model_status_from_query(
                &app,
                &UploadedModelStatusQuery {
                    service_name: "web_portal".to_string(),
                    weight_version: "v1".to_string(),
                    model_id: Some("upload-1".to_string()),
                    model_name: None,
                    bundle_root: Some(Hash::new(b"wrong-bundle-root")),
                },
            )
            .expect_err("bundle_root mismatch must be rejected");
            assert_eq!(err.status(), StatusCode::CONFLICT);
            assert!(err.message.contains("bundle_root does not match"));
            let err = authoritative_uploaded_model_status_from_query(
                &app,
                &UploadedModelStatusQuery {
                    service_name: "web_portal".to_string(),
                    weight_version: "v1".to_string(),
                    model_id: None,
                    model_name: Some("vision_model".to_string()),
                    bundle_root: Some(Hash::new(b"wrong-bundle-root")),
                },
            )
            .expect_err("model-name status with mismatched bundle_root must be rejected");
            assert_eq!(err.status(), StatusCode::NOT_FOUND);
            assert!(err.message.contains("uploaded model status not found"));
            Ok(())
        })
    }
    #[test]
    fn authoritative_uploaded_model_status_rejects_orphan_user_upload_artifact() {
        use iroha_core::state::World;
        let mut world = World::default();
        let service_name: Name = "web_portal".parse().expect("service name");
        world.soracloud_model_artifacts_mut_for_testing().insert(
            (service_name.as_ref().to_owned(), "artifact-1".to_string()),
            iroha_data_model::soracloud::SoraModelArtifactRecordV1 {
                schema_version: iroha_data_model::soracloud::SORA_MODEL_ARTIFACT_RECORD_VERSION_V1,
                service_name,
                service_version: "1.0.0".to_string(),
                model_name: "vision_model".to_string(),
                artifact_id: "artifact-1".to_string(),
                training_job_id: "artifact-1".to_string(),
                weight_version: Some("v1".to_string()),
                source_provenance: Some(SoraModelProvenanceRefV1 {
                    kind: SoraModelProvenanceKindV1::UserUpload,
                    id: "orphan-upload".to_string(),
                }),
                weight_artifact_hash: Hash::new(b"weights"),
                dataset_ref: "hf://repo".to_string(),
                training_config_hash: Hash::new(b"cfg"),
                reproducibility_hash: Hash::new(b"repro"),
                provenance_attestation_hash: Hash::new(b"prov"),
                registered_sequence: 11,
                consumed_by_version: Some("v1".to_string()),
                chunk_manifest_root: Some(Hash::new(b"chunk-manifest-root")),
            },
        );
        let app = mk_app_state_for_tests_with_world(world);
        let err = authoritative_uploaded_model_status_from_query(
            &app,
            &UploadedModelStatusQuery {
                service_name: "web_portal".to_string(),
                weight_version: "v1".to_string(),
                model_id: None,
                model_name: Some("vision_model".to_string()),
                bundle_root: None,
            },
        )
        .expect_err("artifact-only user upload status must not be authoritative");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert!(err.message.contains("orphan-upload"));
    }
    #[test]
    fn authoritative_uploaded_model_status_ignores_non_upload_artifacts() {
        use iroha_core::state::World;
        let payload = sample_uploaded_model_register_payload();
        let service_name = payload.bundle.service_name.clone();
        let mut world = World::default();
        world
            .soracloud_uploaded_model_bundles_mut_for_testing()
            .insert(
                (
                    service_name.as_ref().to_owned(),
                    payload.bundle.model_id.clone(),
                    payload.bundle.weight_version.clone(),
                ),
                payload.bundle.clone(),
            );
        world.soracloud_model_artifacts_mut_for_testing().insert(
            (
                service_name.as_ref().to_owned(),
                "training-artifact".to_string(),
            ),
            iroha_data_model::soracloud::SoraModelArtifactRecordV1 {
                schema_version: iroha_data_model::soracloud::SORA_MODEL_ARTIFACT_RECORD_VERSION_V1,
                service_name: service_name.clone(),
                service_version: "1.0.0".to_string(),
                model_name: payload.model_name.clone(),
                artifact_id: "training-artifact".to_string(),
                training_job_id: payload.bundle.model_id.clone(),
                weight_version: Some(payload.bundle.weight_version.clone()),
                source_provenance: Some(SoraModelProvenanceRefV1 {
                    kind: SoraModelProvenanceKindV1::TrainingJob,
                    id: payload.bundle.model_id.clone(),
                }),
                weight_artifact_hash: Hash::new(b"weights"),
                dataset_ref: "dataset://train".to_string(),
                training_config_hash: Hash::new(b"cfg"),
                reproducibility_hash: Hash::new(b"repro"),
                provenance_attestation_hash: Hash::new(b"prov"),
                registered_sequence: 11,
                consumed_by_version: Some(payload.bundle.weight_version.clone()),
                chunk_manifest_root: None,
            },
        );
        let app = mk_app_state_for_tests_with_world(world);
        let response = authoritative_uploaded_model_status_response(
            &app,
            service_name.as_ref(),
            &payload.bundle.model_id,
            &payload.bundle.weight_version,
        )
        .expect("uploaded bundle status should still resolve");
        assert!(
            response.artifact.is_none(),
            "training-job artifacts must not be projected as uploaded-model artifacts"
        );
    }
    #[test]
    fn authoritative_uploaded_model_status_rejects_malformed_queries() {
        use iroha_core::state::World;
        let app = mk_app_state_for_tests_with_world(World::default());
        let assert_bad_request = |query: UploadedModelStatusQuery, expected: &str| {
            let err = authoritative_uploaded_model_status_from_query(&app, &query)
                .expect_err("malformed uploaded-model status query must fail");
            assert_eq!(err.status(), StatusCode::BAD_REQUEST);
            assert!(
                err.message.contains(expected),
                "expected `{expected}` in `{}`",
                err.message
            );
        };
        assert_bad_request(
            UploadedModelStatusQuery {
                service_name: "web portal".to_string(),
                weight_version: "v1".to_string(),
                model_id: Some("upload-1".to_string()),
                model_name: None,
                bundle_root: None,
            },
            "invalid service_name",
        );
        assert_bad_request(
            UploadedModelStatusQuery {
                service_name: " web_portal".to_string(),
                weight_version: "v1".to_string(),
                model_id: Some("upload-1".to_string()),
                model_name: None,
                bundle_root: None,
            },
            "invalid service_name: White space not allowed in `Name` constructs",
        );
        assert_bad_request(
            UploadedModelStatusQuery {
                service_name: "cafe\u{301}".to_string(),
                weight_version: "v1".to_string(),
                model_id: Some("upload-1".to_string()),
                model_name: None,
                bundle_root: None,
            },
            "invalid service_name: Name must already use the exact NFC spelling",
        );
        assert_bad_request(
            UploadedModelStatusQuery {
                service_name: "web_portal".to_string(),
                weight_version: "v1 shadow".to_string(),
                model_id: Some("upload-1".to_string()),
                model_name: None,
                bundle_root: None,
            },
            "weight_version must not contain whitespace",
        );
        assert_bad_request(
            UploadedModelStatusQuery {
                service_name: "web_portal".to_string(),
                weight_version: "v1 ".to_string(),
                model_id: Some("upload-1".to_string()),
                model_name: None,
                bundle_root: None,
            },
            "weight_version must not contain whitespace",
        );
        assert_bad_request(
            UploadedModelStatusQuery {
                service_name: "web_portal".to_string(),
                weight_version: "v1".to_string(),
                model_id: Some("upload 1".to_string()),
                model_name: None,
                bundle_root: None,
            },
            "job_id must not contain whitespace",
        );
        assert_bad_request(
            UploadedModelStatusQuery {
                service_name: "web_portal".to_string(),
                weight_version: "v1".to_string(),
                model_id: Some(" upload-1".to_string()),
                model_name: None,
                bundle_root: None,
            },
            "job_id must not contain whitespace",
        );
        assert_bad_request(
            UploadedModelStatusQuery {
                service_name: "web_portal".to_string(),
                weight_version: "v1".to_string(),
                model_id: None,
                model_name: Some("vision model".to_string()),
                bundle_root: None,
            },
            "invalid model_name",
        );
        assert_bad_request(
            UploadedModelStatusQuery {
                service_name: "web_portal".to_string(),
                weight_version: "v1".to_string(),
                model_id: None,
                model_name: Some("cafe\u{301}".to_string()),
                bundle_root: None,
            },
            "invalid model_name: Name must already use the exact NFC spelling",
        );
        assert_bad_request(
            UploadedModelStatusQuery {
                service_name: "web_portal".to_string(),
                weight_version: "v1".to_string(),
                model_id: None,
                model_name: None,
                bundle_root: None,
            },
            "model_id or model_name must be provided",
        );
        assert_bad_request(
            UploadedModelStatusQuery {
                service_name: "web_portal".to_string(),
                weight_version: "v1".to_string(),
                model_id: Some("upload-1".to_string()),
                model_name: Some("vision_model".to_string()),
                bundle_root: None,
            },
            "exactly one of model_id or model_name",
        );
    }
    fn signed_fhe_job_run_request(
        payload: FheJobRunPayload,
        key_pair: &KeyPair,
    ) -> SignedFheJobRunRequest {
        let encoded =
            encode_fhe_job_run_signature_payload(&payload).expect("encode fhe job run payload");
        let signature = checked_test_signature(key_pair.private_key(), &encoded);
        SignedFheJobRunRequest {
            payload,
            provenance: ManifestProvenance {
                signer: key_pair.public_key().clone(),
                signature,
            },
        }
    }
    fn sample_uploaded_model_register_payload() -> UploadedModelRegisterPayload {
        UploadedModelRegisterPayload {
            bundle: SoraUploadedModelBundleV1 {
                schema_version: iroha_data_model::soracloud::SORA_UPLOADED_MODEL_BUNDLE_VERSION_V1,
                service_name: "web_portal".parse().expect("service name"),
                model_id: "upload-1".to_string(),
                weight_version: "v1".to_string(),
                family: "decoder-only".to_string(),
                modalities: vec!["text".to_string()],
                plaintext_root: Hash::new(b"plaintext-root"),
                package_format:
                    SoraUploadedModelPackageFormatV1::NormalizedHuggingFaceSafetensorsV1,
                bundle_root: Hash::new(b"bundle-root"),
                sorafs_manifest_digest: iroha_data_model::sorafs::pin_registry::ManifestDigest::new(
                    [0xA5; 32],
                ),
                chunk_count: 1,
                plaintext_bytes: 16,
                ciphertext_bytes: 24,
                chunk_manifest_root: Hash::new(b"chunk-manifest-root"),
                pricing_policy: SoraUploadedModelPricingPolicyV1 {
                    storage_price: "0.000000001".parse().expect("canonical storage price"),
                },
            },
            model_name: "vision_model".to_string(),
            artifact_id: "artifact-1".to_string(),
            weight_artifact_hash: Hash::new(b"weights"),
            dataset_ref: "dataset://upload".to_string(),
            training_config_hash: Hash::new(b"cfg"),
            reproducibility_hash: Hash::new(b"repro"),
            provenance_attestation_hash: Hash::new(b"prov"),
        }
    }
    fn sample_uploaded_model_pin_record(
        digest: ManifestDigest,
        content_length: u64,
        status: PinStatus,
    ) -> PinManifestRecord {
        let manifest: sorafs_manifest::ManifestV1 = norito::decode_from_bytes(include_bytes!(
            "../../../fixtures/sorafs_gateway/1.0.0/manifest_v1.to"
        ))
        .expect("decode canonical SoraFS fixture manifest");
        let root_cid = ManifestRootCid::try_from_slice(&manifest.root_cid)
            .expect("fixture manifest root CID must be canonical");
        let policy = PinPolicy {
            min_replicas: 1,
            storage_class: StorageClass::Warm,
            retention_epoch: u64::MAX,
        };
        let mut record = PinManifestRecord::new(
            digest,
            root_cid,
            ChunkerProfileHandle {
                profile_id: 1,
                namespace: "sorafs".to_string(),
                name: "sf1".to_string(),
                semver: "1.0.0".to_string(),
                multihash_code: 0x1e,
            },
            manifest.chunk_digest_sha3_256,
            manifest.por_root,
            content_length,
            policy,
            ALICE_ID.clone(),
            1,
            None,
            None,
            Metadata::default(),
        );
        match status {
            PinStatus::Pending => {}
            PinStatus::Approved(epoch) => record.approve(epoch, None),
            PinStatus::Retired(epoch) => record.retire(epoch, None),
        }
        record
    }
    fn sample_public_discovery_pin_record(
        digest: ManifestDigest,
        root_cid: ManifestRootCid,
        content_length: u64,
        status: PinStatus,
    ) -> PinManifestRecord {
        let mut record = sample_uploaded_model_pin_record(digest, content_length, status);
        record.root_cid = root_cid;
        record
    }
    fn signed_uploaded_model_register_request(
        payload: UploadedModelRegisterPayload,
        key_pair: &KeyPair,
    ) -> SignedUploadedModelRegisterRequest {
        let bundle_encoded = encode_uploaded_model_register_bundle_signature_payload(&payload)
            .expect("encode uploaded model bundle payload");
        let finalize_encoded = encode_uploaded_model_register_finalize_signature_payload(&payload)
            .expect("encode uploaded model finalize payload");
        SignedUploadedModelRegisterRequest {
            payload,
            bundle_provenance: ManifestProvenance {
                signer: key_pair.public_key().clone(),
                signature: checked_test_signature(key_pair.private_key(), &bundle_encoded),
            },
            finalize_provenance: ManifestProvenance {
                signer: key_pair.public_key().clone(),
                signature: checked_test_signature(key_pair.private_key(), &finalize_encoded),
            },
        }
    }
    #[test]
    fn uploaded_model_register_pin_gate_rejects_missing_inactive_or_mismatched_pin() {
        use iroha_core::state::World;
        let payload = sample_uploaded_model_register_payload();
        let digest = payload.bundle.sorafs_manifest_digest;
        let missing_app = mk_app_state_for_tests_with_world(World::default());
        let missing_err = require_active_sorafs_uploaded_model_pin(&missing_app, &payload.bundle)
            .expect_err("missing pin must fail before upload registration");
        assert_eq!(missing_err.status(), StatusCode::CONFLICT);
        assert!(missing_err.message.contains("is not registered"));
        for (status, expected_message) in [
            (PinStatus::Pending, "is not approved"),
            (PinStatus::Retired(3), "retired at epoch"),
        ] {
            let record =
                sample_uploaded_model_pin_record(digest, payload.bundle.ciphertext_bytes, status);
            let err = require_active_sorafs_uploaded_model_pin_record(&record, &payload.bundle)
                .expect_err("inactive pin must fail before upload registration");
            assert_eq!(err.status(), StatusCode::CONFLICT);
            assert!(err.message.contains(expected_message));
        }
        let digest_mismatch_record = sample_uploaded_model_pin_record(
            ManifestDigest::new([0xB6; 32]),
            payload.bundle.ciphertext_bytes,
            PinStatus::Approved(1),
        );
        let digest_mismatch_err = require_active_sorafs_uploaded_model_pin_record(
            &digest_mismatch_record,
            &payload.bundle,
        )
        .expect_err("pin digest mismatch must fail before upload registration");
        assert_eq!(digest_mismatch_err.status(), StatusCode::CONFLICT);
        assert!(digest_mismatch_err.message.contains("record digest"));
        let length_mismatch_record = sample_uploaded_model_pin_record(
            digest,
            payload.bundle.ciphertext_bytes + 1,
            PinStatus::Approved(1),
        );
        let length_mismatch_err = require_active_sorafs_uploaded_model_pin_record(
            &length_mismatch_record,
            &payload.bundle,
        )
        .expect_err("pin length mismatch must fail before upload registration");
        assert_eq!(length_mismatch_err.status(), StatusCode::CONFLICT);
        assert!(length_mismatch_err.message.contains("content_length"));
    }
    #[test]
    fn uploaded_model_register_signature_rejects_signer_mismatch() {
        let key_pair = checked_test_keypair(0x81);
        let other_key_pair = checked_test_keypair(0x82);
        let payload = sample_uploaded_model_register_payload();
        let finalize_encoded = encode_uploaded_model_register_finalize_signature_payload(&payload)
            .expect("encode uploaded model finalize payload");
        let request = signed_uploaded_model_register_request(payload, &key_pair);
        let mut request = decode_current_signed_request_frame(
            &request,
            "iroha_torii::soracloud::SignedUploadedModelRegisterRequest",
        );
        verify_uploaded_model_register_signature(&request)
            .expect("both original signed domains survive the current request frame");
        request.finalize_provenance = ManifestProvenance {
            signer: other_key_pair.public_key().clone(),
            signature: checked_test_signature(other_key_pair.private_key(), &finalize_encoded),
        };
        let err = verify_uploaded_model_register_signature(&request)
            .expect_err("mismatched upload register signers must fail");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        assert!(err.message.contains("signers must match"));
    }
    #[test]
    fn uploaded_model_register_signature_rejects_swapped_same_signer_provenances() {
        let key_pair = checked_test_keypair(0x83);
        let payload = sample_uploaded_model_register_payload();
        let bundle_encoded = encode_uploaded_model_register_bundle_signature_payload(&payload)
            .expect("encode uploaded model bundle payload");
        let finalize_encoded = encode_uploaded_model_register_finalize_signature_payload(&payload)
            .expect("encode uploaded model finalize payload");
        let request = SignedUploadedModelRegisterRequest {
            payload,
            bundle_provenance: ManifestProvenance {
                signer: key_pair.public_key().clone(),
                signature: checked_test_signature(key_pair.private_key(), &finalize_encoded),
            },
            finalize_provenance: ManifestProvenance {
                signer: key_pair.public_key().clone(),
                signature: checked_test_signature(key_pair.private_key(), &bundle_encoded),
            },
        };
        let err = verify_uploaded_model_register_signature(&request)
            .expect_err("swapped upload register provenances must fail");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        assert!(
            err.message
                .contains("bundle provenance signature verification failed")
        );
    }
    #[test]
    fn uploaded_model_register_signature_rejects_tampered_bundle_payload() {
        let key_pair = checked_test_keypair(0x84);
        let payload = sample_uploaded_model_register_payload();
        let mut request = signed_uploaded_model_register_request(payload, &key_pair);
        request.payload.bundle.model_id = "upload-replayed".to_string();
        let err = verify_uploaded_model_register_signature(&request)
            .expect_err("tampered upload bundle payload must fail");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        assert!(
            err.message
                .contains("bundle provenance signature verification failed")
        );
    }
    #[test]
    fn uploaded_model_register_signature_rejects_tampered_finalize_payload() {
        let key_pair = checked_test_keypair(0x85);
        let payload = sample_uploaded_model_register_payload();
        let mut request = signed_uploaded_model_register_request(payload, &key_pair);
        request.payload.dataset_ref = "dataset://replayed".to_string();
        let err = verify_uploaded_model_register_signature(&request)
            .expect_err("tampered upload finalize payload must fail");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        assert!(
            err.message
                .contains("finalize provenance signature verification failed")
        );
    }
    fn signed_ciphertext_query_request(
        query: CiphertextQuerySpecV1,
        key_pair: &KeyPair,
    ) -> SignedCiphertextQueryRequest {
        let encoded = encode_ciphertext_query_signature_payload(&query)
            .expect("encode ciphertext query payload");
        let signature = checked_test_signature(key_pair.private_key(), &encoded);
        SignedCiphertextQueryRequest {
            query,
            provenance: ManifestProvenance {
                signer: key_pair.public_key().clone(),
                signature,
            },
        }
    }
    fn fixture_agent_manifest() -> AgentApartmentManifestV1 {
        let mut manifest: AgentApartmentManifestV1 = load_json(&workspace_fixture(
            "fixtures/soracloud/agent_apartment_manifest_v1.json",
        ));
        manifest.policy_capabilities.push(
            "agent.autonomy.run"
                .parse::<Name>()
                .expect("valid capability"),
        );
        manifest.policy_capabilities.push(
            "agent.autonomy.allow"
                .parse::<Name>()
                .expect("valid capability"),
        );
        manifest.validate().expect("agent manifest should validate");
        manifest
    }
    #[test]
    fn bundle_signature_payload_layout_is_canonical_layout() {
        let bundle = fixture_bundle("1.0.0");
        let precondition = SoraServiceMutationPreconditionV1::ServiceAbsent;
        let encoded = encode_bundle_signature_payload(
            &bundle,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &precondition,
        )
        .expect("encode signature payload");
        let expected =
            iroha_data_model::soracloud::encode_bundle_with_materials_provenance_payload(
                &bundle,
                &BTreeMap::new(),
                &BTreeMap::new(),
                &precondition,
            )
            .expect("encode canonical layout");
        assert_eq!(encoded, expected);
        assert_ne!(
            encoded,
            norito::to_bytes(&bundle).expect("encode legacy layout"),
            "bundle signatures must commit to bundle, inline materials, and the exact mutation precondition",
        );
        let different_precondition = SoraServiceMutationPreconditionV1::ExactCurrentRevision(
            SoraServiceExactCurrentRevisionPreconditionV1 {
                service_version: "0.9.0".to_owned(),
                service_manifest_hash: bundle.service_manifest_hash(),
                container_manifest_hash: bundle.container_manifest_hash(),
                process_generation: 1,
                config_generation: 0,
                secret_generation: 0,
            },
        );
        assert_ne!(
            encoded,
            encode_bundle_signature_payload(
                &bundle,
                &BTreeMap::new(),
                &BTreeMap::new(),
                &different_precondition,
            )
            .expect("encode changed precondition"),
            "changing only the mutation precondition must change the signed payload",
        );
    }
    #[test]
    fn state_mutation_signature_payload_layout_is_canonical_layout() {
        let governance_tx_hash = Hash::new(b"governance");
        let payload = StateMutationRequest {
            service_name: "health_portal".to_owned(),
            binding_name: "private_state".to_owned(),
            key: "/state/private/records/1".to_owned(),
            operation: StateMutationOperation::Upsert,
            value_size_bytes: Some(3),
            value_payload_hex: Some("010203".to_string()),
            encryption: SoraStateEncryptionV1::ClientCiphertext,
            governance_tx_hash,
            fhe_input_admission_proof: None,
        };
        let payload_commitment = Hash::new([1_u8, 2, 3]);
        let encoded =
            encode_state_mutation_signature_payload(&payload).expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.service_name.as_str(),
            payload.binding_name.as_str(),
            payload.key.as_str(),
            "upsert",
            payload.value_size_bytes,
            Some(payload_commitment),
            payload.encryption,
            governance_tx_hash,
            None::<SoracloudFheInputAdmissionProofV1>,
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn state_mutation_signature_payload_uses_delete_operation_label() {
        let governance_tx_hash = Hash::new(b"delete-governance");
        let payload = StateMutationRequest {
            service_name: "health_portal".to_owned(),
            binding_name: "private_state".to_owned(),
            key: "/state/private/records/1".to_owned(),
            operation: StateMutationOperation::Delete,
            value_size_bytes: None,
            value_payload_hex: None,
            encryption: SoraStateEncryptionV1::ClientCiphertext,
            governance_tx_hash,
            fhe_input_admission_proof: None,
        };
        let encoded =
            encode_state_mutation_signature_payload(&payload).expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.service_name.as_str(),
            payload.binding_name.as_str(),
            payload.key.as_str(),
            "delete",
            None::<u64>,
            None::<Hash>,
            payload.encryption,
            governance_tx_hash,
            None::<SoracloudFheInputAdmissionProofV1>,
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn fhe_job_run_signature_payload_binds_exact_governed_reference() {
        let job = fixture_fhe_job_spec();
        let policy_reference = fixture_fhe_policy_reference();
        let payload = FheJobRunPayload {
            service_name: "health_portal".to_owned(),
            binding_name: "private_state".to_owned(),
            job: job.clone(),
            policy_reference: policy_reference.clone(),
            public_key_proof: None,
            bootstrap_key_zero_refresh_proof: None,
            full_bootstrap_execution_proofs: Vec::new(),
        };
        let encoded =
            encode_fhe_job_run_signature_payload(&payload).expect("encode signature payload");
        let expected = encode_fhe_job_run_provenance_payload(
            payload.service_name.as_str(),
            payload.binding_name.as_str(),
            job,
            policy_reference,
            None,
            None,
            Vec::new(),
        )
        .expect("encode canonical payload");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn fhe_job_and_decryption_payloads_are_closed_and_require_explicit_proof_keys() {
        let job = fixture_fhe_job_spec();
        let policy_reference = fixture_fhe_policy_reference();
        let canonical = norito::json!({
            "service_name": "health_portal",
            "binding_name": "private_state",
            "job": (norito::json::to_value(&job).expect("serialize FHE job spec")),
            "policy_reference": (norito::json::to_value(&policy_reference)
                .expect("serialize FHE policy reference")),
            "public_key_proof": null,
            "bootstrap_key_zero_refresh_proof": null,
            "full_bootstrap_execution_proofs": [],
        });
        norito::json::from_value::<FheJobRunPayload>(canonical.clone())
            .expect("canonical FHE job payload must decode");
        for field in [
            "public_key_proof",
            "bootstrap_key_zero_refresh_proof",
            "full_bootstrap_execution_proofs",
        ] {
            let mut missing = canonical.clone();
            missing
                .as_object_mut()
                .expect("FHE job payload object")
                .remove(field);
            norito::json::from_value::<FheJobRunPayload>(missing)
                .expect_err("an omitted FHE proof key must fail");
        }
        let mut null_proof_list = canonical.clone();
        null_proof_list
            .as_object_mut()
            .expect("FHE job payload object")
            .insert(
                "full_bootstrap_execution_proofs".to_owned(),
                norito::json::Value::Null,
            );
        norito::json::from_value::<FheJobRunPayload>(null_proof_list)
            .expect_err("a null FHE execution-proof list must fail");
        let mut unknown_job = canonical;
        unknown_job
            .as_object_mut()
            .expect("FHE job payload object")
            .insert("legacy_proof".to_owned(), norito::json::Value::Null);
        norito::json::from_value::<FheJobRunPayload>(unknown_job)
            .expect_err("an unknown FHE job payload key must fail");

        let mut unknown_decryption = norito::json!({
            "service_name": "health_portal",
            "policy": (norito::json::to_value(&fixture_decryption_authority_policy())
                .expect("serialize decryption policy")),
            "request": (norito::json::to_value(&fixture_decryption_request())
                .expect("serialize decryption request")),
        });
        norito::json::from_value::<DecryptionRequestPayload>(unknown_decryption.clone())
            .expect("canonical decryption payload must decode");
        unknown_decryption
            .as_object_mut()
            .expect("decryption payload object")
            .insert("legacy_request".to_owned(), norito::json::Value::Null);
        norito::json::from_value::<DecryptionRequestPayload>(unknown_decryption)
            .expect_err("an unknown decryption payload key must fail");
    }
    #[test]
    fn fhe_job_run_signature_rejects_policy_reference_substitution() {
        let payload = FheJobRunPayload {
            service_name: "health_portal".to_owned(),
            binding_name: "private_state".to_owned(),
            job: fixture_fhe_job_spec(),
            policy_reference: fixture_fhe_policy_reference(),
            public_key_proof: None,
            bootstrap_key_zero_refresh_proof: None,
            full_bootstrap_execution_proofs: Vec::new(),
        };
        let key_pair = checked_test_keypair(0x90);
        let mut request = signed_fhe_job_run_request(payload, &key_pair);
        request.payload.policy_reference.material_digest =
            Hash::new(b"different-governed-fhe-material");
        let err = verify_fhe_job_run_signature(&request)
            .expect_err("signed jobs must bind the exact governed material digest");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }
    #[test]
    fn fhe_job_run_preflight_validates_reference_and_attachment_syntax_only() {
        let mut payload = FheJobRunPayload {
            service_name: "health_portal".to_owned(),
            binding_name: "private_state".to_owned(),
            job: fixture_fhe_job_spec(),
            policy_reference: fixture_fhe_policy_reference(),
            public_key_proof: None,
            bootstrap_key_zero_refresh_proof: None,
            full_bootstrap_execution_proofs: Vec::new(),
        };
        validate_fhe_job_run_proof_attachments(&payload)
            .expect("state-bound execution material is resolved by the instruction executor");
        payload.policy_reference.schema_version = 0;
        let err = validate_fhe_job_run_proof_attachments(&payload)
            .expect_err("unsupported governed reference versions must fail at Torii");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid policy_reference"));
    }
    #[test]
    fn decryption_request_signature_payload_layout_is_canonical_tuple() {
        let policy = fixture_decryption_authority_policy();
        let request = fixture_decryption_request();
        let payload = DecryptionRequestPayload {
            service_name: "health_portal".to_owned(),
            policy: policy.clone(),
            request: request.clone(),
        };
        let encoded = encode_decryption_request_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(payload.service_name.as_str(), policy, request))
            .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn ciphertext_query_signature_payload_layout_is_canonical_layout() {
        let query = fixture_ciphertext_query_spec();
        let encoded =
            encode_ciphertext_query_signature_payload(&query).expect("encode signature payload");
        let expected = norito::to_bytes(&query).expect("encode canonical layout");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn rollback_signature_payload_layout_is_canonical_tuple() {
        let payload = RollbackPayload {
            service_name: "web_portal".to_owned(),
            target_version: "1.0.0".to_owned(),
        };
        let encoded =
            encode_rollback_signature_payload(&payload).expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.service_name.as_str(),
            payload.target_version.as_str(),
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn rollout_signature_payload_layout_is_canonical_tuple() {
        let governance_tx_hash = Hash::new(b"governance");
        let payload = RolloutAdvancePayload {
            service_name: "web_portal".to_owned(),
            rollout_handle: "web_portal:rollout:2".to_owned(),
            healthy: true,
            promote_to_percent: Some(100),
            governance_tx_hash: governance_tx_hash.clone(),
        };
        let encoded = encode_rollout_signature_payload(&payload).expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.service_name.as_str(),
            payload.rollout_handle.as_str(),
            payload.healthy,
            payload.promote_to_percent,
            governance_tx_hash,
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn agent_deploy_signature_payload_layout_is_canonical_tuple() {
        let manifest = fixture_agent_manifest();
        let payload = AgentDeployPayload {
            manifest: manifest.clone(),
            lease_blocks: 120,
            autonomy_budget_units: 500,
        };
        let encoded =
            encode_agent_deploy_signature_payload(&payload).expect("encode signature payload");
        let expected =
            norito::to_bytes(&(manifest, 120u64, 500u64)).expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn agent_lease_renew_signature_payload_layout_is_canonical_tuple() {
        let payload = AgentLeaseRenewPayload {
            apartment_name: "ops_agent".to_owned(),
            lease_blocks: 120,
        };
        let encoded =
            encode_agent_lease_renew_signature_payload(&payload).expect("encode signature payload");
        let expected = norito::to_bytes(&(payload.apartment_name.as_str(), payload.lease_blocks))
            .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn agent_restart_signature_payload_layout_is_canonical_tuple() {
        let payload = AgentRestartPayload {
            apartment_name: "ops_agent".to_owned(),
            reason: "manual-restart".to_owned(),
        };
        let encoded =
            encode_agent_restart_signature_payload(&payload).expect("encode signature payload");
        let expected =
            norito::to_bytes(&(payload.apartment_name.as_str(), payload.reason.as_str()))
                .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn agent_policy_revoke_signature_payload_layout_is_canonical_tuple() {
        let payload = AgentPolicyRevokePayload {
            apartment_name: "ops_agent".to_owned(),
            capability: "agent.autonomy.run".to_owned(),
            reason: Some("manual-review".to_owned()),
        };
        let encoded = encode_agent_policy_revoke_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.apartment_name.as_str(),
            payload.capability.as_str(),
            payload.reason.as_deref(),
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn agent_wallet_spend_signature_payload_layout_is_canonical_tuple() {
        let payload = AgentWalletSpendPayload {
            apartment_name: "ops_agent".to_owned(),
            request_id: "ops-wallet-request-1".to_owned(),
            asset_definition: "61CtjvNd9T3THAR65GsMVHr82Bjc".to_owned(),
            amount: "0.001".parse().expect("canonical quantity"),
        };
        let encoded = encode_agent_wallet_spend_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.apartment_name.as_str(),
            payload.request_id.as_str(),
            payload.asset_definition.as_str(),
            payload.amount.clone(),
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn agent_wallet_request_id_validation_is_exact_v1() {
        for valid in ["wallet-request-1", "wallet request 1"] {
            validate_agent_wallet_request_id(valid).expect("canonical request ID");
        }
        for invalid in [
            "",
            " wallet-request-1",
            "wallet-request-1 ",
            "wallet\nrequest",
        ] {
            validate_agent_wallet_request_id(invalid)
                .expect_err("noncanonical request ID must fail closed");
        }
        validate_agent_wallet_request_id(
            &"x".repeat(SORA_AGENT_WALLET_REQUEST_ID_MAX_BYTES_V1 + 1),
        )
        .expect_err("oversized request ID must fail closed");
    }
    #[test]
    fn agent_wallet_asset_definition_validation_is_exact_v1() {
        validate_agent_wallet_asset_definition("61CtjvNd9T3THAR65GsMVHr82Bjc")
            .expect("canonical asset definition text");
        for invalid in ["", " 61CtjvNd9T3THAR65GsMVHr82Bjc", "asset ", "\tasset"] {
            validate_agent_wallet_asset_definition(invalid)
                .expect_err("noncanonical asset definition text must fail closed");
        }
    }
    // Exact-quantity boundary coverage is kept in an included child so this
    // production route module remains within the repository source budget.
    include!("soracloud/wallet_quantity_tests.rs");
    include!("soracloud/control_plane_lease_tests.rs");
    #[test]
    fn control_plane_snapshot_exposes_canonical_quantities_without_nano_aliases() {
        let mut authoritative_state = fixture_control_plane_service_lease("1.0.0", 0x72);
        authoritative_state.prepaid_runtime_balance =
            "340282366920938463463374607431768211456.0000000001"
                .parse()
                .expect("wide exact prepaid quantity");
        let snapshot = ControlPlaneServiceSnapshot {
            service_name: "web_portal".to_owned(),
            current_version: "1.0.0".to_owned(),
            revision_count: 1,
            config_generation: 0,
            secret_generation: 0,
            config_entry_count: 0,
            secret_entry_count: 0,
            service_lease: Some(ControlPlaneServiceLeaseSnapshot {
                authoritative_state,
                effective_status: SoraServiceLeaseStatusV1::Active,
                remaining_runtime_balance: "0.0000000000000000000000000001"
                    .parse()
                    .expect("scale-28 remaining quantity"),
            }),
            public_discovery_content_cid: None,
            public_discovery_url: None,
            public_discovery_cid_host_url: None,
            latest_revision: None,
            active_rollout: None,
            last_rollout: None,
        };
        let value = norito::json::to_value(&snapshot).expect("serialize control-plane snapshot");
        let object = value.as_object().expect("control-plane snapshot object");
        assert!(
            object
                .get("active_rollout")
                .is_some_and(norito::json::Value::is_null),
            "inactive rollout state must serialize as explicit null"
        );
        assert!(
            object
                .get("last_rollout")
                .is_some_and(norito::json::Value::is_null),
            "missing rollout history must serialize as explicit null"
        );
        let lease = object
            .get("service_lease")
            .and_then(norito::json::Value::as_object)
            .expect("typed service lease snapshot");
        assert_eq!(
            lease
                .get("authoritative_state")
                .and_then(norito::json::Value::as_object)
                .and_then(|state| state.get("prepaid_runtime_balance"))
                .and_then(norito::json::Value::as_str),
            Some("340282366920938463463374607431768211456.0000000001")
        );
        assert_eq!(
            lease
                .get("remaining_runtime_balance")
                .and_then(norito::json::Value::as_str),
            Some("0.0000000000000000000000000001")
        );
        for retired in [
            "quota_class",
            "service_lease_status",
            "lease_expires_height",
            "prepaid_runtime_balance",
            "remaining_runtime_balance",
            "prepaid_runtime_balance_nanos",
            "remaining_runtime_balance_nanos",
        ] {
            assert!(
                !object.contains_key(retired),
                "retired fixed-nano field {retired} must not be exposed"
            );
        }
    }

    #[test]
    fn agent_wallet_approve_signature_payload_layout_is_canonical_tuple() {
        let payload = AgentWalletApprovePayload {
            apartment_name: "ops_agent".to_owned(),
            request_id: "ops_agent:wallet:7".to_owned(),
        };
        let encoded = encode_agent_wallet_approve_signature_payload(&payload)
            .expect("encode signature payload");
        let expected =
            norito::to_bytes(&(payload.apartment_name.as_str(), payload.request_id.as_str()))
                .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn agent_message_send_signature_payload_layout_is_canonical_tuple() {
        let payload = AgentMessageSendPayload {
            from_apartment: "ops_agent".to_owned(),
            to_apartment: "worker_agent".to_owned(),
            channel: "ops.sync".to_owned(),
            payload: "rotate-key-42".to_owned(),
        };
        let encoded = encode_agent_message_send_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.from_apartment.as_str(),
            payload.to_apartment.as_str(),
            payload.channel.as_str(),
            payload.payload.as_str(),
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn agent_message_ack_signature_payload_layout_is_canonical_tuple() {
        let payload = AgentMessageAckPayload {
            apartment_name: "worker_agent".to_owned(),
            message_id: "worker_agent:mail:3".to_owned(),
        };
        let encoded =
            encode_agent_message_ack_signature_payload(&payload).expect("encode signature payload");
        let expected =
            norito::to_bytes(&(payload.apartment_name.as_str(), payload.message_id.as_str()))
                .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn agent_artifact_allow_signature_payload_layout_is_canonical_tuple() {
        let payload = AgentArtifactAllowPayload {
            apartment_name: "ops_agent".to_owned(),
            artifact_hash: "hash:ABCD0123#01".to_owned(),
            provenance_hash: Some("hash:PROV0001#01".to_owned()),
        };
        let encoded = encode_agent_artifact_allow_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.apartment_name.as_str(),
            payload.artifact_hash.as_str(),
            payload.provenance_hash.as_deref(),
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn training_job_start_signature_payload_layout_is_canonical_tuple() {
        let payload = TrainingJobStartPayload {
            service_name: "web_portal".to_owned(),
            model_name: "model-1".to_owned(),
            job_id: "job-1".to_owned(),
            worker_group_size: 4,
            target_steps: 100,
            checkpoint_interval_steps: 20,
            max_retries: 3,
            step_compute_units: 500,
            compute_budget_units: 50_000,
            storage_budget_bytes: 4_096,
        };
        let encoded = encode_training_job_start_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.service_name.as_str(),
            payload.model_name.as_str(),
            payload.job_id.as_str(),
            payload.worker_group_size,
            payload.target_steps,
            payload.checkpoint_interval_steps,
            payload.max_retries,
            payload.step_compute_units,
            payload.compute_budget_units,
            payload.storage_budget_bytes,
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn training_job_checkpoint_signature_payload_layout_is_canonical_tuple() {
        let metrics_hash = Hash::new(b"metrics");
        let payload = TrainingJobCheckpointPayload {
            service_name: "web_portal".to_owned(),
            job_id: "job-1".to_owned(),
            completed_step: 20,
            checkpoint_size_bytes: 1_024,
            metrics_hash: metrics_hash.clone(),
        };
        let encoded = encode_training_job_checkpoint_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.service_name.as_str(),
            payload.job_id.as_str(),
            payload.completed_step,
            payload.checkpoint_size_bytes,
            metrics_hash,
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn training_job_retry_signature_payload_layout_is_canonical_tuple() {
        let payload = TrainingJobRetryPayload {
            service_name: "web_portal".to_owned(),
            job_id: "job-1".to_owned(),
            reason: "worker unavailable".to_owned(),
        };
        let encoded = encode_training_job_retry_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.service_name.as_str(),
            payload.job_id.as_str(),
            payload.reason.as_str(),
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn model_artifact_register_signature_payload_layout_is_canonical_tuple() {
        let weight_artifact_hash = Hash::new(b"weight-artifact");
        let training_config_hash = Hash::new(b"train-config");
        let reproducibility_hash = Hash::new(b"repro");
        let provenance_attestation_hash = Hash::new(b"attestation");
        let payload = ModelArtifactRegisterPayload {
            service_name: "web_portal".to_owned(),
            model_name: "model-1".to_owned(),
            training_job_id: "job-1".to_owned(),
            weight_artifact_hash: weight_artifact_hash.clone(),
            dataset_ref: "dataset://synthetic/v2".to_owned(),
            training_config_hash: training_config_hash.clone(),
            reproducibility_hash: reproducibility_hash.clone(),
            provenance_attestation_hash: provenance_attestation_hash.clone(),
        };
        let encoded = encode_model_artifact_register_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.service_name.as_str(),
            payload.model_name.as_str(),
            payload.training_job_id.as_str(),
            weight_artifact_hash,
            payload.dataset_ref.as_str(),
            training_config_hash,
            reproducibility_hash,
            provenance_attestation_hash,
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn model_weight_register_signature_payload_layout_is_canonical_tuple() {
        let weight_artifact_hash = Hash::new(b"weight-artifact");
        let training_config_hash = Hash::new(b"train-config");
        let reproducibility_hash = Hash::new(b"repro");
        let provenance_attestation_hash = Hash::new(b"attestation");
        let payload = ModelWeightRegisterPayload {
            service_name: "web_portal".to_owned(),
            model_name: "model-1".to_owned(),
            weight_version: "1.0.0".to_owned(),
            training_job_id: "job-1".to_owned(),
            parent_version: Some("0.9.0".to_owned()),
            weight_artifact_hash: weight_artifact_hash.clone(),
            dataset_ref: "dataset://synthetic/v2".to_owned(),
            training_config_hash: training_config_hash.clone(),
            reproducibility_hash: reproducibility_hash.clone(),
            provenance_attestation_hash: provenance_attestation_hash.clone(),
        };
        let encoded = encode_model_weight_register_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.service_name.as_str(),
            payload.model_name.as_str(),
            payload.weight_version.as_str(),
            payload.training_job_id.as_str(),
            payload.parent_version.as_deref(),
            weight_artifact_hash,
            payload.dataset_ref.as_str(),
            training_config_hash,
            reproducibility_hash,
            provenance_attestation_hash,
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn model_weight_promote_signature_payload_layout_is_canonical_tuple() {
        let gate_report_hash = Hash::new(b"gate-report");
        let payload = ModelWeightPromotePayload {
            service_name: "web_portal".to_owned(),
            model_name: "model-1".to_owned(),
            weight_version: "1.0.0".to_owned(),
            gate_approved: true,
            gate_report_hash: gate_report_hash.clone(),
        };
        let encoded = encode_model_weight_promote_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.service_name.as_str(),
            payload.model_name.as_str(),
            payload.weight_version.as_str(),
            payload.gate_approved,
            gate_report_hash,
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn model_weight_rollback_signature_payload_layout_is_canonical_tuple() {
        let payload = ModelWeightRollbackPayload {
            service_name: "web_portal".to_owned(),
            model_name: "model-1".to_owned(),
            target_version: "0.9.0".to_owned(),
            reason: "gate regression".to_owned(),
        };
        let encoded = encode_model_weight_rollback_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            payload.service_name.as_str(),
            payload.model_name.as_str(),
            payload.target_version.as_str(),
            payload.reason.as_str(),
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn hf_shared_lease_join_signature_payload_layout_is_canonical_tuple() {
        let payload = HfSharedLeaseJoinPayload {
            repo_id: "openai/gpt-oss".to_owned(),
            revision: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            service_name: "vision_portal".to_owned(),
            apartment_name: Some("ops_agent".to_owned()),
            storage_class: StorageClass::Warm,
            lease_term_ms: 604_800_000,
            lease_asset_definition_id: hf_shared_lease_asset_definition(),
            base_fee: "0.0000000001".parse().expect("sub-nano quantity"),
        };
        let encoded = encode_hf_shared_lease_join_signature_payload(&payload)
            .expect("encode signature payload");
        let expected = norito::to_bytes(&(
            "openai/gpt-oss",
            "0123456789abcdef0123456789abcdef01234567",
            "vision_portal",
            Some("ops_agent"),
            StorageClass::Warm,
            604_800_000_u64,
            hf_shared_lease_asset_definition(),
            payload.base_fee.clone(),
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
        let canonical_json = String::from_utf8(
            norito::json::to_vec(&payload).expect("serialize exact HF shared-lease join payload"),
        )
        .expect("HF shared-lease join JSON is UTF-8");
        assert!(canonical_json.contains(r#""base_fee":"0.0000000001""#));
        assert!(
            canonical_json.contains(r#""revision":"0123456789abcdef0123456789abcdef01234567""#)
        );
        let missing_revision = canonical_json.replace(
            r#""revision":"0123456789abcdef0123456789abcdef01234567","#,
            "",
        );
        assert!(
            norito::json::from_str::<HfSharedLeaseJoinPayload>(&missing_revision).is_err(),
            "HF shared-lease join revision must be explicit"
        );
        assert!(!canonical_json.contains("base_fee_nanos"));
        for hostile in [
            canonical_json.replace(r#""base_fee":"0.0000000001""#, r#""base_fee":1"#),
            canonical_json.replace(r#""base_fee":"0.0000000001""#, r#""base_fee_nanos":1"#),
        ] {
            assert!(
                norito::json::from_str::<HfSharedLeaseJoinPayload>(&hostile).is_err(),
                "accepted noncanonical or retired HF base-fee payload `{hostile}`"
            );
        }
    }
    #[test]
    fn hf_revision_parser_requires_immutable_canonical_commit_oid() {
        assert!(parse_hf_revision("0123456789abcdef0123456789abcdef01234567").is_ok());
        for revision in [
            "main",
            "refs/pr/7",
            "0123456789abcdef",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            " 0123456789abcdef0123456789abcdef01234567",
        ] {
            parse_hf_revision(revision)
                .expect_err("mutable or noncanonical revision must be rejected");
        }
    }
    #[test]
    fn soracloud_identity_parsers_require_exact_canonical_v1_spelling() {
        assert_eq!(
            parse_service_name("café").expect("canonical NFC service name"),
            "café".parse::<Name>().expect("canonical service name")
        );
        assert_eq!(
            parse_agent_apartment_name("ops_agent").expect("canonical apartment name"),
            "ops_agent"
        );
        assert_eq!(
            parse_training_model_name("model_one").expect("canonical training model name"),
            "model_one"
        );

        for noncanonical in [" café", "cafe\u{301}"] {
            parse_service_name(noncanonical)
                .expect_err("noncanonical service spelling must be rejected");
        }
        for noncanonical in [" ops_agent", "ops_agent ", "ops\tagent"] {
            parse_agent_apartment_name(noncanonical)
                .expect_err("noncanonical apartment spelling must be rejected");
        }
        for noncanonical in [" model_one", "model_one ", "mode\nl_one"] {
            parse_training_model_name(noncanonical)
                .expect_err("noncanonical training model spelling must be rejected");
        }
        for noncanonical in [" job-1", "job-1 ", "job 1", "jób-1"] {
            parse_training_job_id(noncanonical)
                .expect_err("noncanonical training job id must be rejected");
        }
        for noncanonical in [" v1", "v1 ", "version 1", "vé1"] {
            parse_model_weight_version(noncanonical)
                .expect_err("noncanonical model weight version must be rejected");
        }
        for noncanonical in [" config", "config ", "/config", "a/../config"] {
            parse_service_material_name("config_name", noncanonical)
                .expect_err("noncanonical material name must be rejected");
        }
        for noncanonical in ["", " run-1", "run-1 ", "run\n1"] {
            parse_exact_nonempty_text("run_id", noncanonical)
                .expect_err("noncanonical exact text must be rejected");
        }
    }
    #[test]
    fn hf_lease_leave_signature_payload_layout_is_canonical_tuple() {
        let payload = HfLeaseLeavePayload {
            repo_id: "openai/gpt-oss".to_owned(),
            revision: "1123456789abcdef0123456789abcdef01234567".to_owned(),
            storage_class: StorageClass::Warm,
            lease_term_ms: 604_800_000,
            service_name: Some("vision_portal".to_owned()),
            apartment_name: Some("ops_agent".to_owned()),
        };
        let encoded =
            encode_hf_lease_leave_signature_payload(&payload).expect("encode signature payload");
        let expected = norito::to_bytes(&(
            "openai/gpt-oss",
            "1123456789abcdef0123456789abcdef01234567",
            StorageClass::Warm,
            604_800_000_u64,
            Some("vision_portal"),
            Some("ops_agent"),
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }
    #[test]
    fn hf_lease_renew_signature_payload_layout_is_canonical_tuple() {
        let payload = HfLeaseRenewPayload {
            repo_id: "openai/gpt-oss".to_owned(),
            revision: "2123456789abcdef0123456789abcdef01234567".to_owned(),
            service_name: "vision_portal".to_owned(),
            apartment_name: Some("ops_agent".to_owned()),
            storage_class: StorageClass::Warm,
            lease_term_ms: 604_800_000,
            lease_asset_definition_id: hf_shared_lease_asset_definition(),
            base_fee: "340282366920938463463374607431768211456.0000000001"
                .parse()
                .expect("wide exact quantity"),
        };
        let encoded =
            encode_hf_lease_renew_signature_payload(&payload).expect("encode signature payload");
        let expected = norito::to_bytes(&(
            "openai/gpt-oss",
            "2123456789abcdef0123456789abcdef01234567",
            "vision_portal",
            Some("ops_agent"),
            StorageClass::Warm,
            604_800_000_u64,
            hf_shared_lease_asset_definition(),
            payload.base_fee.clone(),
        ))
        .expect("encode canonical tuple");
        assert_eq!(encoded, expected);
    }

    #[test]
    fn admit_scr_host_bundle_exposes_model_inference_capability() {
        let mut bundle = fixture_bundle("2026.04.0");
        bundle.container.capabilities.allow_model_inference = true;
        bundle.service.container.manifest_hash = bundle.container_manifest_hash();
        let admission = admit_scr_host_bundle(&bundle).expect("SCR admission should succeed");
        assert!(admission.allow_model_inference);
        let deployment = fixture_service_deployment(&bundle);
        let audit = fixture_service_deploy_audit_event(&bundle);
        let world = iroha_core::state::World::new();
        let revision = deployment_bundle_to_control_plane_revision(
            &world.view(),
            &deployment,
            &bundle,
            Some(&audit),
            None,
        )
        .expect("admitted fixture revision should project");
        assert!(revision.allow_model_inference);
    }
    #[test]
    fn parse_storage_class_query_requires_exact_lowercase_labels() {
        assert_eq!(
            parse_storage_class_query("warm").expect("warm should parse"),
            StorageClass::Warm
        );
        for noncanonical in ["Hot", "WARM", " cold", "cold ", "archive"] {
            parse_storage_class_query(noncanonical)
                .expect_err("noncanonical storage-class query must fail");
        }
    }
    #[test]
    fn torii_hf_repo_parser_and_source_id_use_the_shared_canonical_identity() {
        let repo_id =
            parse_hf_repo_id("OpenAI/GPT-OSS").expect("case-sensitive canonical repository ID");
        assert_eq!(repo_id, "OpenAI/GPT-OSS");
        for alias in ["GPT-OSS", "OpenAI//GPT-OSS", "OpenAI/./GPT-OSS"] {
            assert!(parse_hf_repo_id(alias).is_err());
            assert!(hf_source_id(alias, TEST_HF_COMMIT_OID).is_err());
        }
        assert_ne!(
            hf_source_id("OpenAI/GPT-OSS", TEST_HF_COMMIT_OID).expect("uppercase source identity"),
            hf_source_id("openai/GPT-OSS", TEST_HF_COMMIT_OID).expect("lowercase source identity")
        );
    }
    #[test]
    fn authoritative_hf_shared_lease_status_reads_member_world_state() -> Result<(), eyre::Report> {
        use iroha_core::state::World;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let repo_id = "openai/gpt-oss";
            let resolved_revision = TEST_HF_COMMIT_OID;
            let storage_class = StorageClass::Warm;
            let lease_term_ms = 604_800_000_u64;
            let source_id = hf_source_id(repo_id, resolved_revision)
                .map_err(|err| eyre::eyre!("failed to derive hf source id: {err:?}"))?;
            let pool_id = hf_shared_lease_pool_id(source_id, storage_class, lease_term_ms)
                .map_err(|err| eyre::eyre!("failed to derive hf pool id: {err:?}"))?;
            let asset_definition = hf_shared_lease_asset_definition();
            let mut world = World::default();
            world.soracloud_hf_sources_mut_for_testing().insert(
                source_id,
                SoraHfSourceRecordV1 {
                    schema_version: SORA_HF_SOURCE_RECORD_VERSION_V1,
                    source_id,
                    repo_id: repo_id.to_owned(),
                    resolved_revision: resolved_revision.to_owned(),
                    created_at_ms: 10,
                    updated_at_ms: 20,
                },
            );
            world
                .soracloud_hf_shared_lease_pools_mut_for_testing()
                .insert(
                    pool_id,
                    SoraHfSharedLeasePoolV1 {
                        schema_version: SORA_HF_SHARED_LEASE_POOL_VERSION_V1,
                        pool_id,
                        source_id,
                        storage_class,
                        lease_asset_definition_id: asset_definition.clone(),
                        base_fee: "0.00001".parse().expect("base fee"),
                        lease_term_ms,
                        window_started_at_ms: 10,
                        window_expires_at_ms: lease_term_ms + 10,
                        active_member_count: 1,
                        status: SoraHfSharedLeaseStatusV1::Active,
                        queued_next_window: Some(
                            iroha_data_model::soracloud::SoraHfSharedLeaseQueuedWindowV1 {
                                sponsor_account_id: ALICE_ID.clone(),
                                lease_asset_definition_id: asset_definition.clone(),
                                base_fee: "0.00002".parse().expect("base fee"),
                                sponsored_at_ms: 15,
                                window_started_at_ms: lease_term_ms + 10,
                                window_expires_at_ms: (lease_term_ms * 2) + 10,
                                service_name: "vision_portal_v2".parse().expect("service"),
                                apartment_name: Some("ops_agent_v2".parse().expect("apartment")),
                            },
                        ),
                    },
                );
            world
                .soracloud_hf_shared_lease_members_mut_for_testing()
                .insert(
                    (pool_id.to_string(), ALICE_ID.to_string()),
                    SoraHfSharedLeaseMemberV1 {
                        schema_version: SORA_HF_SHARED_LEASE_MEMBER_VERSION_V1,
                        pool_id,
                        source_id,
                        account_id: ALICE_ID.clone(),
                        status: SoraHfSharedLeaseMemberStatusV1::Active,
                        joined_at_ms: 10,
                        updated_at_ms: 20,
                        total_paid: "0.00001".parse().expect("total paid"),
                        total_refunded: Quantity::zero(),
                        last_charge: "0.00001".parse().expect("last charge"),
                        service_bindings: std::collections::BTreeSet::from([
                            "vision_portal".to_owned()
                        ]),
                        apartment_bindings: std::collections::BTreeSet::from([
                            "ops_agent".to_owned()
                        ]),
                    },
                );
            world
                .soracloud_hf_shared_lease_audit_events_mut_for_testing()
                .insert(
                    7,
                    SoraHfSharedLeaseAuditEventV1 {
                        schema_version: SORA_HF_SHARED_LEASE_AUDIT_EVENT_VERSION_V1,
                        sequence: 7,
                        action: SoraHfSharedLeaseActionV1::Renew,
                        pool_id,
                        source_id,
                        account_id: ALICE_ID.clone(),
                        occurred_at_ms: 10,
                        active_member_count: 1,
                        charged: "0.00002".parse().expect("charged amount"),
                        refunded: Quantity::zero(),
                        lease_expires_at_ms: (lease_term_ms * 2) + 10,
                        failure_reason: None,
                        service_name: Some("vision_portal_v2".to_owned()),
                        apartment_name: Some("ops_agent_v2".to_owned()),
                    },
                );
            world
                .soracloud_hf_shared_lease_audit_events_mut_for_testing()
                .insert(
                    8,
                    SoraHfSharedLeaseAuditEventV1 {
                        schema_version: SORA_HF_SHARED_LEASE_AUDIT_EVENT_VERSION_V1,
                        sequence: 8,
                        action: SoraHfSharedLeaseActionV1::Join,
                        pool_id,
                        source_id,
                        account_id: BOB_ID.clone(),
                        occurred_at_ms: 11,
                        active_member_count: 2,
                        charged: "0.000005".parse().expect("charged amount"),
                        refunded: Quantity::zero(),
                        lease_expires_at_ms: lease_term_ms + 10,
                        failure_reason: None,
                        service_name: Some("concurrent_portal".to_owned()),
                        apartment_name: None,
                    },
                );
            let app = mk_app_state_for_tests_with_world(world);
            let response = authoritative_hf_shared_lease_status_response(
                &app,
                repo_id,
                resolved_revision,
                storage_class,
                lease_term_ms,
                Some(&ALICE_ID),
            )
            .map_err(|err| eyre::eyre!("authoritative hf status failed: {err:?}"))?;
            assert_eq!(
                response.schema_version,
                HF_SHARED_LEASE_STATUS_SCHEMA_VERSION_V1
            );
            assert_eq!(response.source.source_id, source_id);
            assert_eq!(response.pool.as_ref().expect("pool").pool_id, pool_id);
            assert_eq!(
                response.member.as_ref().expect("member").account_id,
                ALICE_ID.clone()
            );
            assert_eq!(response.audit_event_count, 2);
            assert_eq!(
                response
                    .latest_audit_event
                    .as_ref()
                    .expect("audit event")
                    .account_id,
                ALICE_ID.clone()
            );
            assert_eq!(
                response
                    .latest_audit_event
                    .as_ref()
                    .expect("audit event")
                    .sequence,
                7
            );
            let unscoped_response = authoritative_hf_shared_lease_status_response(
                &app,
                repo_id,
                resolved_revision,
                storage_class,
                lease_term_ms,
                None,
            )
            .map_err(|err| eyre::eyre!("unscoped authoritative hf status failed: {err:?}"))?;
            assert_eq!(
                unscoped_response
                    .latest_audit_event
                    .as_ref()
                    .expect("unscoped latest audit event")
                    .account_id,
                BOB_ID.clone()
            );
            assert_eq!(
                unscoped_response
                    .latest_audit_event
                    .as_ref()
                    .expect("unscoped latest audit event")
                    .sequence,
                8
            );
            assert_eq!(
                response
                    .pool
                    .as_ref()
                    .expect("pool")
                    .queued_next_window
                    .as_ref()
                    .expect("queued next window")
                    .service_name
                    .as_ref(),
                "vision_portal_v2"
            );
            Ok(())
        })
    }
    #[test]
    fn authoritative_hf_shared_lease_status_reads_world_state() -> Result<(), eyre::Report> {
        use iroha_core::state::World;
        let runtime = test_runtime()?;
        runtime.block_on(async move {
            let repo_id = "openai/gpt-oss";
            let resolved_revision = TEST_HF_COMMIT_OID;
            let storage_class = StorageClass::Warm;
            let lease_term_ms = 604_800_000_u64;
            let source_id = hf_source_id(repo_id, resolved_revision)
                .map_err(|err| eyre::eyre!("failed to derive hf source id: {err:?}"))?;
            let pool_id = hf_shared_lease_pool_id(source_id, storage_class, lease_term_ms)
                .map_err(|err| eyre::eyre!("failed to derive hf pool id: {err:?}"))?;
            let asset_definition = hf_shared_lease_asset_definition();
            let mut world = World::default();
            world.soracloud_hf_sources_mut_for_testing().insert(
                source_id,
                SoraHfSourceRecordV1 {
                    schema_version: SORA_HF_SOURCE_RECORD_VERSION_V1,
                    source_id,
                    repo_id: repo_id.to_owned(),
                    resolved_revision: resolved_revision.to_owned(),
                    created_at_ms: 10,
                    updated_at_ms: 30,
                },
            );
            world
                .soracloud_hf_shared_lease_pools_mut_for_testing()
                .insert(
                    pool_id,
                    SoraHfSharedLeasePoolV1 {
                        schema_version: SORA_HF_SHARED_LEASE_POOL_VERSION_V1,
                        pool_id,
                        source_id,
                        storage_class,
                        lease_asset_definition_id: asset_definition.clone(),
                        base_fee: "0.00001".parse().expect("base fee"),
                        lease_term_ms,
                        window_started_at_ms: 10,
                        window_expires_at_ms: lease_term_ms + 10,
                        active_member_count: 2,
                        status: SoraHfSharedLeaseStatusV1::Active,
                        queued_next_window: None,
                    },
                );
            world
                .soracloud_hf_shared_lease_members_mut_for_testing()
                .insert(
                    (pool_id.to_string(), ALICE_ID.to_string()),
                    SoraHfSharedLeaseMemberV1 {
                        schema_version: SORA_HF_SHARED_LEASE_MEMBER_VERSION_V1,
                        pool_id,
                        source_id,
                        account_id: ALICE_ID.clone(),
                        status: SoraHfSharedLeaseMemberStatusV1::Active,
                        joined_at_ms: 30,
                        updated_at_ms: 30,
                        total_paid: "0.000013333".parse().expect("total paid"),
                        total_refunded: Quantity::zero(),
                        last_charge: "0.000003333".parse().expect("last charge"),
                        service_bindings: std::collections::BTreeSet::from([
                            "vision_portal".to_owned()
                        ]),
                        apartment_bindings: std::collections::BTreeSet::from([
                            "ops_agent".to_owned()
                        ]),
                    },
                );
            world
                .soracloud_hf_shared_lease_audit_events_mut_for_testing()
                .insert(
                    5,
                    SoraHfSharedLeaseAuditEventV1 {
                        schema_version: SORA_HF_SHARED_LEASE_AUDIT_EVENT_VERSION_V1,
                        sequence: 5,
                        action: SoraHfSharedLeaseActionV1::Join,
                        pool_id,
                        source_id,
                        account_id: ALICE_ID.clone(),
                        occurred_at_ms: 30,
                        active_member_count: 2,
                        charged: "0.000003333".parse().expect("charged amount"),
                        refunded: Quantity::zero(),
                        lease_expires_at_ms: lease_term_ms + 10,
                        failure_reason: None,
                        service_name: Some("vision_portal".to_owned()),
                        apartment_name: Some("ops_agent".to_owned()),
                    },
                );
            let app = mk_app_state_for_tests_with_world(world);
            let response = authoritative_hf_shared_lease_status_response(
                &app,
                repo_id,
                resolved_revision,
                storage_class,
                lease_term_ms,
                Some(&ALICE_ID),
            )
            .map_err(|err| eyre::eyre!("authoritative hf status failed: {err:?}"))?;
            assert_eq!(response.pool.as_ref().expect("pool").pool_id, pool_id);
            assert_eq!(
                response.member.as_ref().expect("member").account_id,
                ALICE_ID.clone()
            );
            assert_eq!(
                response
                    .latest_audit_event
                    .as_ref()
                    .expect("audit event")
                    .sequence,
                5
            );
            assert_eq!(
                response
                    .latest_audit_event
                    .as_ref()
                    .expect("audit event")
                    .action,
                SoraHfSharedLeaseActionV1::Join
            );
            Ok(())
        })
    }

    #[test]
    fn authoritative_agent_runtime_receipt_for_run_prefers_latest_receipt() {
        use iroha_core::state::World;
        let request_commitment = Hash::new(b"ops-agent-request");
        let run = SoraAgentAutonomyRunRecordV1 {
            run_id: "ops_agent:autonomy:9".to_owned(),
            artifact_hash: "hash:artifact#1".to_owned(),
            provenance_hash: Some("hash:prov#1".to_owned()),
            budget_units: 25,
            run_label: "nightly".to_owned(),
            workflow_input_json: Some("{\"inputs\":\"nightly\"}".to_owned()),
            approved_process_generation: 1,
            request_commitment,
            approved_sequence: 9,
        };
        let service_name: Name = "agent_workflow_service"
            .parse()
            .expect("valid service name");
        let handler_name: Name = "workflow".parse().expect("valid handler name");
        let mut world = World::default();
        world.soracloud_runtime_receipts_mut_for_testing().insert(
            Hash::new(b"ops-agent-receipt-older"),
            SoraRuntimeReceiptV1 {
                schema_version: iroha_data_model::soracloud::SORA_RUNTIME_RECEIPT_VERSION_V1,
                receipt_id: Hash::new(b"ops-agent-receipt-older"),
                service_name: service_name.clone(),
                service_version: "workflow.v1".to_owned(),
                handler_name: handler_name.clone(),
                handler_class: SoraServiceHandlerClassV1::Query,
                request_commitment,
                result_commitment: Hash::new(b"ops-agent-result-older"),
                certified_by: SoraCertifiedResponsePolicyV1::AuditReceipt,
                emitted_sequence: 40,
                mailbox_message_id: None,
                journal_artifact_hash: None,
                checkpoint_artifact_hash: None,
                execution_host: None,
            },
        );
        world.soracloud_runtime_receipts_mut_for_testing().insert(
            Hash::new(b"ops-agent-receipt-newer"),
            SoraRuntimeReceiptV1 {
                schema_version: iroha_data_model::soracloud::SORA_RUNTIME_RECEIPT_VERSION_V1,
                receipt_id: Hash::new(b"ops-agent-receipt-newer"),
                service_name,
                service_version: "workflow.v1".to_owned(),
                handler_name,
                handler_class: SoraServiceHandlerClassV1::Query,
                request_commitment,
                result_commitment: Hash::new(b"ops-agent-result-newer"),
                certified_by: SoraCertifiedResponsePolicyV1::AuditReceipt,
                emitted_sequence: 41,
                mailbox_message_id: None,
                journal_artifact_hash: None,
                checkpoint_artifact_hash: None,
                execution_host: None,
            },
        );
        let world_view = world.view();
        let receipt = authoritative_agent_runtime_receipt_for_run(&world_view, &run)
            .expect("matching receipt should be resolved");
        assert_eq!(receipt.receipt_id, Hash::new(b"ops-agent-receipt-newer"));
        assert_eq!(receipt.emitted_sequence, 41);
        assert_eq!(
            receipt.result_commitment,
            Hash::new(b"ops-agent-result-newer")
        );
    }
    #[test]
    fn mutation_draft_builder_rejects_empty_success() {
        let signer_key = checked_test_keypair(0xB4);
        let signer = SoracloudMutationSigner {
            authority: AccountId::new(signer_key.public_key().clone()),
            request_signer: signer_key.public_key().clone(),
        };
        let error = build_soracloud_mutation_draft(&signer, Vec::new())
            .expect_err("empty successful draft must fail closed");
        assert_eq!(error.kind, SoracloudErrorKind::Conflict);
        assert!(error.message.contains("no transaction instructions"));
    }
    include!("soracloud/tests/agent_runtime_status.rs");
}
