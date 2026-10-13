//! Finalized chain-authoritative SoraFS PDP and PoTR outcome handlers.
use super::*;
use crate::smartcontracts::isi::helpers::instruction_error_as_query_failure as query_failure;
use crate::{
    smartcontracts::ValidSingularQuery,
    state::{StateTransaction, WorldReadOnly},
};
use core::convert::TryFrom;
use iroha_crypto::{Algorithm, PublicKey, ed25519_parse_signature};
use iroha_data_model::{
    account::AccountId,
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::{
            SetSorafsProofOutcomeSignerPolicy, SorafsProofOutcomeSubmissionV1,
            SubmitSorafsProofOutcome,
        },
    },
    permission::Permission,
    query::{
        error::{FindError, QueryExecutionFail, SorafsProofOutcomeFindErrorV1},
        sorafs::prelude::{FindSorafsProofOutcome, FindSorafsProofOutcomeEvents},
    },
    sorafs::{
        capacity::ProviderId,
        pin_registry::ManifestDigest,
        proof_ledger::{
            PROOF_OUTCOME_MAX_POTR_RECEIPT_BYTES_V1, PROOF_OUTCOME_MAX_PROVIDER_KEY_BYTES_V1,
            PROOF_OUTCOME_QUERY_MAX_EVENT_PAGE_BYTES_V1, PROOF_OUTCOME_QUERY_MAX_ITEMS_V1,
            PROOF_OUTCOME_RECORD_VERSION_V1, PROOF_OUTCOME_SIGNER_POLICY_VERSION_V1,
            PdpOutcomeProjectionV1, PdpOutcomeStatusV1, PotrOutcomeProjectionV1,
            PotrOutcomeStatusV1, ProofOutcomeEd25519AttestationV1, ProofOutcomeFinalizedCursorV1,
            ProofOutcomeFinalizedEventPageV1, ProofOutcomeFinalizedEventV1,
            ProofOutcomeFinalizedRecordV1, ProofOutcomeKindV1, ProofOutcomeProjectionV1,
            ProofOutcomeRecordV1, ProofOutcomeSignerPolicyRecordV1, ProofOutcomeSignerPolicyV1,
        },
    },
};
use iroha_executor_data_model::permission::sorafs::{
    CanManageSorafsProofOutcomePolicy, CanRecordSorafsProofOutcome,
};
use iroha_model_base::state_path::StatePath;
use mv::storage::StorageReadOnly;
use norito::{DecodeLimits, decode_from_bytes_with_limits};
use sorafs_manifest::{
    PDP_GOVERNANCE_ARCHIVE_MAX_CANONICAL_BYTES_V1, PDP_PROOF_MAX_CANONICAL_BYTES_V1,
    PDP_PROOF_SIGNATURE_DOMAIN_V1, PdpGovernanceArchiveV1, PdpProofV1, PdpRejectionReasonV1,
    PdpTerminalDecisionV1, PotrReceiptV1, PotrStatus,
};
use std::{str::FromStr, sync::OnceLock};
const POLICY_STATE_KEY_PREFIX: &str = "sorafs_proof_outcome_policy_v1_";
const OUTCOME_STATE_KEY_PREFIX: &str = "sorafs_proof_outcome_v1_";
const EVENT_STATE_KEY_PREFIX: &str = "sorafs_proof_outcome_event_v1_";
const EVENT_JOURNAL_HEAD_STATE_KEY: &str = "sorafs_proof_outcome_event_head_v1";
const POLICY_DIGEST_DOMAIN_V1: &[u8] = b"sorafs.proof-outcome.signer-policy.v1\0";
const STATE_MAX_BYTES: usize = 128 * 1024;
const QUERY_MAX_STATE_READ_BYTES: usize = 16 * 1024 * 1024;
const STATE_LIMITS: DecodeLimits = DecodeLimits::new(
    128 * 1024,
    STATE_MAX_BYTES,
    256 * 1024,
    2 * STATE_MAX_BYTES,
    64,
);
const PDP_ARCHIVE_LIMITS: DecodeLimits = DecodeLimits::new(
    128 * 1024,
    PDP_GOVERNANCE_ARCHIVE_MAX_CANONICAL_BYTES_V1,
    512 * 1024,
    2 * PDP_GOVERNANCE_ARCHIVE_MAX_CANONICAL_BYTES_V1,
    128,
);
const PDP_PROOF_LIMITS: DecodeLimits = DecodeLimits::new(
    128 * 1024,
    PDP_PROOF_MAX_CANONICAL_BYTES_V1,
    512 * 1024,
    2 * PDP_PROOF_MAX_CANONICAL_BYTES_V1,
    128,
);
const POTR_RECEIPT_LIMITS: DecodeLimits = DecodeLimits::new(
    PROOF_OUTCOME_MAX_POTR_RECEIPT_BYTES_V1,
    PROOF_OUTCOME_MAX_POTR_RECEIPT_BYTES_V1,
    2 * PROOF_OUTCOME_MAX_POTR_RECEIPT_BYTES_V1,
    2 * PROOF_OUTCOME_MAX_POTR_RECEIPT_BYTES_V1,
    32,
);
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_proof_outcome::ProofOutcomePersistedEventV1"
)]
struct ProofOutcomePersistedEventV1 {
    sequence: u64,
    target_block_height: u64,
    event_index: u32,
    outcome: ProofOutcomeRecordV1,
}
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_proof_outcome::ProofOutcomeEventJournalHeadV1"
)]
struct ProofOutcomeEventJournalHeadV1 {
    last_sequence: u64,
    last_target_block_height: u64,
    last_event_index: u32,
}
struct PreparedOutcome {
    identity_digest: [u8; 32],
    outcome_digest: [u8; 32],
    provider_id: ProviderId,
    manifest_digest: ManifestDigest,
    admission_envelope_digest: [u8; 32],
    projection: ProofOutcomeProjectionV1,
    has_provider_proof: bool,
}
impl PreparedOutcome {
    fn into_record(
        self,
        submitted_by: AccountId,
        committed_at_unix_ms: u64,
    ) -> ProofOutcomeRecordV1 {
        ProofOutcomeRecordV1 {
            version: PROOF_OUTCOME_RECORD_VERSION_V1,
            identity_digest: self.identity_digest,
            outcome_digest: self.outcome_digest,
            provider_id: self.provider_id,
            manifest_digest: self.manifest_digest,
            admission_envelope_digest: self.admission_envelope_digest,
            submitted_by,
            committed_at_unix_ms,
            projection: self.projection,
        }
    }
}
fn invalid_parameter(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
        message.into(),
    ))
}
fn corrupt_state(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvariantViolation(message.into().into())
}
fn policy_key(provider_id: ProviderId) -> StatePath {
    StatePath::from_str(&format!(
        "{POLICY_STATE_KEY_PREFIX}{}",
        hex::encode(provider_id.as_bytes())
    ))
    .expect("static prefix plus provider hex is a valid state key")
}
fn outcome_key(kind: ProofOutcomeKindV1, identity_digest: [u8; 32]) -> StatePath {
    let kind = match kind {
        ProofOutcomeKindV1::Pdp => "pdp",
        ProofOutcomeKindV1::Potr => "potr",
    };
    StatePath::from_str(&format!(
        "{OUTCOME_STATE_KEY_PREFIX}{kind}_{}",
        hex::encode(identity_digest)
    ))
    .expect("static prefix plus proof kind and digest is a valid state key")
}
fn event_key(sequence: u64) -> StatePath {
    StatePath::from_str(&format!("{EVENT_STATE_KEY_PREFIX}{sequence:016x}"))
        .expect("static prefix plus fixed-width lowercase hex is a valid state key")
}
fn event_journal_head_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| {
        StatePath::from_str(EVENT_JOURNAL_HEAD_STATE_KEY)
            .expect("static proof-outcome event journal head key is valid")
    })
}
fn encode_state<T: norito::core::NoritoSerialize>(
    value: &T,
    label: &str,
) -> Result<Vec<u8>, InstructionExecutionError> {
    let bytes = norito::to_bytes(value)
        .map_err(|error| corrupt_state(format!("failed to encode {label}: {error}")))?;
    if bytes.len() > STATE_MAX_BYTES {
        return Err(corrupt_state(format!(
            "{label} encodes to {} bytes, above {STATE_MAX_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes)
}
fn decode_state<T>(bytes: &[u8], label: &str) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    decode_state_measured(bytes, label).map(|(value, _)| value)
}
fn decode_state_measured<T>(
    bytes: &[u8],
    label: &str,
) -> Result<(T, usize), InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.is_empty() || bytes.len() > STATE_MAX_BYTES {
        return Err(corrupt_state(format!(
            "{label} length {} is outside 1..={STATE_MAX_BYTES}",
            bytes.len()
        )));
    }
    let limits =
        crate::smartcontracts::isi::query::singular_query_decode_limits(bytes.len(), STATE_LIMITS)
            .map_err(InstructionExecutionError::Query)?;
    let (value, usage) = norito::core::with_decode_limits_measured(limits, || {
        decode_from_bytes_with_limits::<T>(bytes, limits)
    });
    let value = value.map_err(|error| {
        if crate::smartcontracts::isi::query::singular_query_limits_active()
            && error.is_decode_resource_limit()
        {
            InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit)
        } else {
            corrupt_state(format!("failed to decode {label}: {error}"))
        }
    })?;
    norito::verify_exact_frame(&value, bytes).map_err(|error| {
        if matches!(error, norito::Error::NonCanonicalEncoding) {
            corrupt_state(format!("{label} is not exact canonical Norito"))
        } else {
            corrupt_state(format!("failed to encode {label}: {error}"))
        }
    })?;
    Ok((value, usage.total_allocated_bytes()))
}
fn decode_state_for_current<T>(
    bytes: &[u8],
    label: &str,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.is_empty() || bytes.len() > STATE_MAX_BYTES {
        return Err(corrupt_state(format!(
            "{label} length {} is outside 1..={STATE_MAX_BYTES}",
            bytes.len()
        )));
    }
    let limits = current
        .decode_limits(bytes.len(), STATE_LIMITS)
        .map_err(InstructionExecutionError::Query)?;
    let (value, usage) = norito::core::with_decode_limits_measured(limits, || {
        decode_from_bytes_with_limits::<T>(bytes, limits)
    });
    let value = value.map_err(|error| {
        if crate::smartcontracts::isi::query::singular_query_limits_active()
            && error.is_decode_resource_limit()
        {
            InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit)
        } else {
            corrupt_state(format!("failed to decode {label}: {error}"))
        }
    })?;
    norito::verify_exact_frame(&value, bytes).map_err(|error| {
        if matches!(error, norito::Error::NonCanonicalEncoding) {
            corrupt_state(format!("{label} is not exact canonical Norito"))
        } else {
            corrupt_state(format!("failed to encode {label}: {error}"))
        }
    })?;
    current
        .add_nested(usage.total_allocated_bytes())
        .map_err(InstructionExecutionError::Query)?;
    Ok(value)
}
fn decode_payload<T>(
    bytes: &[u8],
    maximum: usize,
    limits: DecodeLimits,
    label: &str,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid_parameter(format!(
            "{label} length {} is outside 1..={maximum}",
            bytes.len()
        )));
    }
    let limits =
        crate::smartcontracts::isi::query::singular_query_decode_limits(bytes.len(), limits)
            .map_err(InstructionExecutionError::Query)?;
    let value = decode_from_bytes_with_limits::<T>(bytes, limits).map_err(|error| {
        if crate::smartcontracts::isi::query::singular_query_limits_active()
            && error.is_decode_resource_limit()
        {
            InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit)
        } else {
            invalid_parameter(format!("failed to decode canonical {label}: {error}"))
        }
    })?;
    norito::verify_exact_frame(&value, bytes).map_err(|error| {
        if matches!(error, norito::Error::NonCanonicalEncoding) {
            invalid_parameter(format!("{label} is not exact canonical Norito"))
        } else {
            invalid_parameter(format!("failed to encode canonical {label}: {error}"))
        }
    })?;
    Ok(value)
}
fn block_time_ms(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<u64, InstructionExecutionError> {
    let now = state_transaction.block_unix_timestamp_ms();
    if now == 0 {
        return Err(invalid_parameter(
            "proof-outcome operations require a non-zero block timestamp",
        ));
    }
    Ok(now)
}
fn has_policy_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
) -> bool {
    if state_transaction._curr_block.is_genesis() {
        return true;
    }
    let required = Permission::from(CanManageSorafsProofOutcomePolicy);
    let direct = state_transaction
        .world
        .account_permissions
        .get(authority)
        .is_some_and(|permissions| permissions.contains(&required));
    direct
        || state_transaction
            .world
            .account_roles_iter(authority)
            .filter_map(|role_id| state_transaction.world.roles.get(role_id))
            .any(|role| role.permissions().any(|permission| permission == &required))
}
fn has_scheduler_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    provider_id: ProviderId,
) -> bool {
    if state_transaction._curr_block.is_genesis() {
        return true;
    }
    let required = Permission::from(CanRecordSorafsProofOutcome { provider_id });
    let direct = state_transaction
        .world
        .account_permissions
        .get(authority)
        .is_some_and(|permissions| permissions.contains(&required));
    direct
        || state_transaction
            .world
            .account_roles_iter(authority)
            .filter_map(|role_id| state_transaction.world.roles.get(role_id))
            .any(|role| role.permissions().any(|permission| permission == &required))
}
fn validate_ed25519_public_key(
    bytes: &[u8; 32],
    label: &str,
) -> Result<(), InstructionExecutionError> {
    PublicKey::from_bytes(Algorithm::Ed25519, bytes)
        .map(|_| ())
        .map_err(|error| invalid_parameter(format!("invalid {label}: {error}")))
}
fn validate_mldsa_public_key(bytes: &[u8], label: &str) -> Result<(), InstructionExecutionError> {
    if bytes.is_empty() || bytes.len() > PROOF_OUTCOME_MAX_PROVIDER_KEY_BYTES_V1 {
        return Err(invalid_parameter(format!(
            "{label} length {} is outside 1..={PROOF_OUTCOME_MAX_PROVIDER_KEY_BYTES_V1}",
            bytes.len()
        )));
    }
    PublicKey::from_bytes(Algorithm::MlDsa, bytes)
        .map(|_| ())
        .map_err(|error| invalid_parameter(format!("invalid {label}: {error}")))
}
fn policy_digest(
    policy: &ProofOutcomeSignerPolicyV1,
) -> Result<[u8; 32], InstructionExecutionError> {
    struct Blake3Writer<'a>(&'a mut blake3::Hasher);
    impl std::io::Write for Blake3Writer<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let encoded_len = norito::canonical_frame_len(policy)
        .map_err(|error| invalid_parameter(format!("failed to encode signer policy: {error}")))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(POLICY_DIGEST_DOMAIN_V1);
    hasher.update(
        &u64::try_from(encoded_len)
            .map_err(|_| invalid_parameter("signer policy length does not fit u64"))?
            .to_le_bytes(),
    );
    norito::core::write_canonical_to_writer(policy, &mut Blake3Writer(&mut hasher))
        .map_err(|error| invalid_parameter(format!("failed to encode signer policy: {error}")))?;
    Ok(*hasher.finalize().as_bytes())
}
fn validate_signer_policy(
    policy: &ProofOutcomeSignerPolicyV1,
) -> Result<(), InstructionExecutionError> {
    if policy.version != PROOF_OUTCOME_SIGNER_POLICY_VERSION_V1
        || policy.provider_id.as_bytes() == &[0; 32]
        || policy.revision == 0
        || policy.admission_envelope_digest == [0; 32]
        || policy.valid_from_unix == 0
        || policy.valid_until_unix < policy.valid_from_unix
        || (policy.revision == 1) != policy.predecessor_digest.is_none()
        || policy.predecessor_digest == Some([0; 32])
    {
        return Err(invalid_parameter(
            "proof-outcome signer policy identity, revision, predecessor, or validity window is invalid",
        ));
    }
    validate_ed25519_public_key(&policy.pdp_public_key, "PDP provider public key")?;
    validate_mldsa_public_key(
        &policy.potr_mldsa_public_key,
        "PoTR provider ML-DSA public key",
    )?;
    validate_ed25519_public_key(&policy.gateway_public_key, "PoTR gateway public key")
}
fn read_signer_policy(
    world: &impl WorldReadOnly,
    provider_id: ProviderId,
) -> Result<Option<ProofOutcomeSignerPolicyRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(&policy_key(provider_id)) else {
        return Ok(None);
    };
    let record: ProofOutcomeSignerPolicyRecordV1 =
        decode_state(bytes, "proof-outcome signer policy")?;
    validate_signer_policy(&record.policy)
        .map_err(|error| corrupt_state(format!("stored signer policy is invalid: {error}")))?;
    if record.policy.provider_id != provider_id
        || record.policy_digest == [0; 32]
        || record.policy_digest != policy_digest(&record.policy)?
        || record.activated_at_unix_ms == 0
    {
        return Err(corrupt_state(
            "stored proof-outcome signer policy provenance is inconsistent",
        ));
    }
    Ok(Some(record))
}
fn map_pdp_status(decision: PdpTerminalDecisionV1) -> PdpOutcomeStatusV1 {
    match decision {
        PdpTerminalDecisionV1::Accepted => PdpOutcomeStatusV1::Accepted,
        PdpTerminalDecisionV1::Rejected(reason) => match reason {
            PdpRejectionReasonV1::DeadlineExpired => PdpOutcomeStatusV1::DeadlineExpired,
            PdpRejectionReasonV1::SubmissionLate => PdpOutcomeStatusV1::SubmissionLate,
            PdpRejectionReasonV1::FutureTimestamp => PdpOutcomeStatusV1::FutureTimestamp,
            PdpRejectionReasonV1::InvalidProof => PdpOutcomeStatusV1::InvalidProof,
            PdpRejectionReasonV1::AdmissionRevoked => PdpOutcomeStatusV1::AdmissionRevoked,
            PdpRejectionReasonV1::AdmissionInactive => PdpOutcomeStatusV1::AdmissionInactive,
            PdpRejectionReasonV1::StorageUnavailable => PdpOutcomeStatusV1::StorageUnavailable,
        },
    }
}
fn map_potr_status(status: PotrStatus) -> PotrOutcomeStatusV1 {
    match status {
        PotrStatus::Success => PotrOutcomeStatusV1::Success,
        PotrStatus::MissedDeadline => PotrOutcomeStatusV1::MissedDeadline,
        PotrStatus::ProviderError => PotrOutcomeStatusV1::ProviderError,
        PotrStatus::GatewayError => PotrOutcomeStatusV1::GatewayError,
        PotrStatus::ClientCancelled => PotrOutcomeStatusV1::ClientCancelled,
    }
}
fn prepare_pdp_outcome(
    archive_payload: &[u8],
) -> Result<PreparedOutcome, InstructionExecutionError> {
    let archive: PdpGovernanceArchiveV1 = decode_payload(
        archive_payload,
        PDP_GOVERNANCE_ARCHIVE_MAX_CANONICAL_BYTES_V1,
        PDP_ARCHIVE_LIMITS,
        "PDP governance archive",
    )?;
    archive
        .validate()
        .map_err(|error| invalid_parameter(format!("invalid PDP governance archive: {error}")))?;
    let outcome_digest = archive
        .digest()
        .map_err(|error| invalid_parameter(format!("failed to digest PDP archive: {error}")))?;
    let provider_attestation = archive
        .canonical_proof
        .as_deref()
        .map(|proof_payload| {
            let proof: PdpProofV1 = decode_payload(
                proof_payload,
                PDP_PROOF_MAX_CANONICAL_BYTES_V1,
                PDP_PROOF_LIMITS,
                "PDP proof",
            )?;
            proof.verify_signature().map_err(|error| {
                invalid_parameter(format!("invalid PDP proof signature: {error}"))
            })?;
            if Some(proof.proof_digest().map_err(|error| {
                invalid_parameter(format!("failed to digest PDP proof: {error}"))
            })?) != archive.proof_digest
            {
                return Err(invalid_parameter(
                    "PDP proof digest disagrees with governance archive",
                ));
            }
            Ok(ProofOutcomeEd25519AttestationV1 {
                public_key: proof.signature.public_key,
                signature: proof.signature.signature,
            })
        })
        .transpose()?;
    let status = map_pdp_status(archive.decision);
    let has_provider_attestation = provider_attestation.is_some();
    if (status.requires_proof() && !has_provider_attestation)
        || (!status.allows_proof() && has_provider_attestation)
    {
        return Err(invalid_parameter(
            "PDP terminal classification disagrees with proof presence",
        ));
    }
    Ok(PreparedOutcome {
        identity_digest: archive.challenge_id,
        outcome_digest,
        provider_id: ProviderId::new(archive.provider_id),
        manifest_digest: ManifestDigest::new(archive.manifest_digest),
        admission_envelope_digest: archive.admission_envelope_digest,
        projection: ProofOutcomeProjectionV1::Pdp(PdpOutcomeProjectionV1 {
            source_sequence: archive.sequence,
            epoch_id: archive.epoch_id,
            status,
            proof_digest: archive.proof_digest,
            provider_attestation,
            sampled_segments: archive.sampled_segments,
            sampled_hot_leaves: archive.sampled_hot_leaves,
            sampled_bytes: archive.sampled_bytes,
            issued_at_unix: archive.issued_at_unix,
            response_deadline_unix: archive.response_deadline_unix,
            decided_at_unix: archive.decided_at_unix,
        }),
        has_provider_proof: archive.proof_digest.is_some(),
    })
}
fn prepare_potr_outcome(
    receipt_payload: &[u8],
    admission_envelope_digest: [u8; 32],
) -> Result<PreparedOutcome, InstructionExecutionError> {
    if admission_envelope_digest == [0; 32] {
        return Err(invalid_parameter(
            "PoTR admission envelope digest must be non-zero",
        ));
    }
    let receipt: PotrReceiptV1 = decode_payload(
        receipt_payload,
        PROOF_OUTCOME_MAX_POTR_RECEIPT_BYTES_V1,
        POTR_RECEIPT_LIMITS,
        "PoTR signed receipt",
    )?;
    receipt
        .validate()
        .map_err(|error| invalid_parameter(format!("invalid PoTR signed receipt: {error}")))?;
    let outcome_digest = receipt
        .signed_receipt_digest()
        .map_err(|error| invalid_parameter(format!("failed to digest PoTR receipt: {error}")))?;
    let identity_digest = receipt
        .request_scope_digest()
        .map_err(|error| invalid_parameter(format!("failed to scope PoTR receipt: {error}")))?;
    let gateway_public_key: [u8; 32] = receipt
        .gateway_signature
        .as_ref()
        .ok_or_else(|| invalid_parameter("PoTR receipt has no gateway signature"))?
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| invalid_parameter("PoTR gateway public key is not 32 bytes"))?;
    let governed_provider_public_key = &receipt
        .provider_signature
        .as_ref()
        .ok_or_else(|| invalid_parameter("PoTR receipt has no provider signature"))?
        .public_key;
    let governed_provider_key_digest = *blake3::hash(governed_provider_public_key).as_bytes();
    Ok(PreparedOutcome {
        identity_digest,
        outcome_digest,
        provider_id: ProviderId::new(receipt.provider_id),
        manifest_digest: ManifestDigest::new(receipt.manifest_digest),
        admission_envelope_digest,
        projection: ProofOutcomeProjectionV1::Potr(PotrOutcomeProjectionV1 {
            status: map_potr_status(receipt.status),
            deadline_ms: receipt.deadline_ms,
            latency_ms: receipt.latency_ms,
            requested_at_ms: receipt.requested_at_ms,
            responded_at_ms: receipt.responded_at_ms,
            recorded_at_ms: receipt.recorded_at_ms,
            range_start: receipt.range_start,
            range_end: receipt.range_end,
            gateway_public_key,
            governed_provider_key_digest,
            canonical_signed_receipt: receipt_payload.to_vec(),
        }),
        has_provider_proof: true,
    })
}
fn verify_pdp_attestation(
    proof_digest: [u8; 32],
    attestation: &ProofOutcomeEd25519AttestationV1,
) -> Result<(), InstructionExecutionError> {
    let public_key = PublicKey::from_bytes(Algorithm::Ed25519, &attestation.public_key)
        .map_err(|error| corrupt_state(format!("stored PDP public key is invalid: {error}")))?;
    let signature = ed25519_parse_signature(&attestation.signature)
        .map_err(|error| corrupt_state(format!("stored PDP signature is invalid: {error}")))?;
    let mut message = Vec::with_capacity(PDP_PROOF_SIGNATURE_DOMAIN_V1.len() + proof_digest.len());
    message.extend_from_slice(PDP_PROOF_SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(&proof_digest);
    signature.verify(&public_key, &message).map_err(|error| {
        corrupt_state(format!("stored PDP signature failed verification: {error}"))
    })
}
fn validate_outcome_record(record: &ProofOutcomeRecordV1) -> Result<(), InstructionExecutionError> {
    validate_outcome_record_with_current(record, None)
}
fn validate_outcome_record_with_current(
    record: &ProofOutcomeRecordV1,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<(), InstructionExecutionError> {
    if record.version != PROOF_OUTCOME_RECORD_VERSION_V1
        || record.identity_digest == [0; 32]
        || record.outcome_digest == [0; 32]
        || record.provider_id.as_bytes() == &[0; 32]
        || record.manifest_digest.as_bytes() == &[0; 32]
        || record.admission_envelope_digest == [0; 32]
        || record.committed_at_unix_ms == 0
    {
        return Err(corrupt_state(
            "stored proof-outcome identity or provenance is invalid",
        ));
    }
    match &record.projection {
        ProofOutcomeProjectionV1::Pdp(projection) => {
            let has_proof = projection.proof_digest.is_some();
            if projection.source_sequence == 0
                || projection.epoch_id == 0
                || projection.sampled_segments == 0
                || projection.sampled_hot_leaves == 0
                || projection.issued_at_unix == 0
                || projection.response_deadline_unix <= projection.issued_at_unix
                || projection.decided_at_unix < projection.issued_at_unix
                || projection.proof_digest.is_some() != projection.provider_attestation.is_some()
                || (projection.status.requires_proof() && !has_proof)
                || (!projection.status.allows_proof() && has_proof)
                || (projection.status == PdpOutcomeStatusV1::Accepted)
                    != (projection.sampled_bytes > 0)
            {
                return Err(corrupt_state(
                    "stored PDP outcome projection is inconsistent",
                ));
            }
            if let (Some(proof_digest), Some(attestation)) =
                (projection.proof_digest, projection.provider_attestation)
            {
                if proof_digest == [0; 32] {
                    return Err(corrupt_state("stored PDP proof digest is zero"));
                }
                verify_pdp_attestation(proof_digest, &attestation)?;
            }
            let decided_at_ms = projection
                .decided_at_unix
                .checked_mul(1_000)
                .ok_or_else(|| corrupt_state("stored PDP decision timestamp overflow"))?;
            if decided_at_ms > record.committed_at_unix_ms {
                return Err(corrupt_state(
                    "stored PDP outcome was decided after its committing block",
                ));
            }
        }
        ProofOutcomeProjectionV1::Potr(projection) => {
            if projection.governed_provider_key_digest == [0; 32]
                || projection.gateway_public_key == [0; 32]
                || projection.canonical_signed_receipt.is_empty()
                || projection.canonical_signed_receipt.len()
                    > PROOF_OUTCOME_MAX_POTR_RECEIPT_BYTES_V1
            {
                return Err(corrupt_state(
                    "stored PoTR outcome key or receipt metadata is invalid",
                ));
            }
            let receipt: PotrReceiptV1 = match current {
                Some(current) => decode_state_for_current(
                    &projection.canonical_signed_receipt,
                    "stored canonical PoTR receipt",
                    current,
                )?,
                None => decode_state(
                    &projection.canonical_signed_receipt,
                    "stored canonical PoTR receipt",
                )?,
            };
            receipt.validate().map_err(|error| {
                corrupt_state(format!("stored PoTR receipt is invalid: {error}"))
            })?;
            let receipt_gateway: [u8; 32] = receipt
                .gateway_signature
                .as_ref()
                .ok_or_else(|| corrupt_state("stored PoTR receipt lost its gateway signature"))?
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| corrupt_state("stored PoTR gateway key length is invalid"))?;
            let receipt_provider = &receipt
                .provider_signature
                .as_ref()
                .ok_or_else(|| corrupt_state("stored PoTR receipt lost its provider signature"))?
                .public_key;
            if receipt.request_scope_digest().map_err(|error| {
                corrupt_state(format!("failed to scope stored PoTR receipt: {error}"))
            })? != record.identity_digest
                || receipt.signed_receipt_digest().map_err(|error| {
                    corrupt_state(format!("failed to digest stored PoTR receipt: {error}"))
                })? != record.outcome_digest
                || ProviderId::new(receipt.provider_id) != record.provider_id
                || ManifestDigest::new(receipt.manifest_digest) != record.manifest_digest
                || map_potr_status(receipt.status) != projection.status
                || receipt.deadline_ms != projection.deadline_ms
                || receipt.latency_ms != projection.latency_ms
                || receipt.requested_at_ms != projection.requested_at_ms
                || receipt.responded_at_ms != projection.responded_at_ms
                || receipt.recorded_at_ms != projection.recorded_at_ms
                || receipt.range_start != projection.range_start
                || receipt.range_end != projection.range_end
                || receipt_gateway != projection.gateway_public_key
                || *blake3::hash(receipt_provider).as_bytes()
                    != projection.governed_provider_key_digest
                || receipt.recorded_at_ms > record.committed_at_unix_ms
            {
                return Err(corrupt_state(
                    "stored PoTR outcome disagrees with its canonical signed receipt",
                ));
            }
        }
    }
    Ok(())
}
fn read_outcome(
    world: &impl WorldReadOnly,
    kind: ProofOutcomeKindV1,
    identity_digest: [u8; 32],
) -> Result<Option<ProofOutcomeRecordV1>, InstructionExecutionError> {
    let key = outcome_key(kind, identity_digest);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    let record: ProofOutcomeRecordV1 =
        if crate::smartcontracts::isi::query::singular_query_limits_active() {
            let (record, allocation_bytes) = decode_state_measured(bytes, "proof-outcome record")?;
            let mut current =
                crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
                    allocation_bytes,
                )
                .map_err(InstructionExecutionError::Query)?;
            validate_outcome_record_with_current(&record, Some(&mut current))?;
            record
        } else {
            let record = decode_state(bytes, "proof-outcome record")?;
            validate_outcome_record(&record)?;
            record
        };
    if record.kind() != kind
        || record.identity_digest != identity_digest
        || outcome_key(record.kind(), record.identity_digest) != key
    {
        return Err(corrupt_state(
            "stored proof-outcome record disagrees with its state key",
        ));
    }
    Ok(Some(record))
}
fn same_cryptographic_outcome(
    existing: &ProofOutcomeRecordV1,
    candidate: &ProofOutcomeRecordV1,
) -> bool {
    existing.version == candidate.version
        && existing.identity_digest == candidate.identity_digest
        && existing.outcome_digest == candidate.outcome_digest
        && existing.provider_id == candidate.provider_id
        && existing.manifest_digest == candidate.manifest_digest
        && existing.admission_envelope_digest == candidate.admission_envelope_digest
        && existing.projection == candidate.projection
}
fn validate_outcome_against_current_policy(
    prepared: &PreparedOutcome,
    policy: &ProofOutcomeSignerPolicyV1,
    now_unix: u64,
) -> Result<(), InstructionExecutionError> {
    if policy.provider_id != prepared.provider_id
        || policy.admission_envelope_digest != prepared.admission_envelope_digest
        || now_unix < policy.valid_from_unix
        || now_unix > policy.valid_until_unix
    {
        return Err(invalid_parameter(
            "proof outcome does not bind the current active provider admission policy",
        ));
    }
    match &prepared.projection {
        ProofOutcomeProjectionV1::Pdp(projection) => {
            if projection.issued_at_unix < policy.valid_from_unix
                || projection.response_deadline_unix > policy.valid_until_unix
            {
                return Err(invalid_parameter(
                    "PDP challenge window is outside the current signer policy",
                ));
            }
            if let Some(attestation) = projection.provider_attestation {
                if attestation.public_key != policy.pdp_public_key {
                    return Err(invalid_parameter(
                        "PDP proof signer does not match the current governed provider key",
                    ));
                }
            }
        }
        ProofOutcomeProjectionV1::Potr(projection) => {
            let receipt: PotrReceiptV1 = decode_payload(
                &projection.canonical_signed_receipt,
                PROOF_OUTCOME_MAX_POTR_RECEIPT_BYTES_V1,
                POTR_RECEIPT_LIMITS,
                "PoTR signed receipt",
            )?;
            let provider_key = &receipt
                .provider_signature
                .as_ref()
                .ok_or_else(|| invalid_parameter("PoTR receipt has no provider signature"))?
                .public_key;
            if projection.gateway_public_key != policy.gateway_public_key
                || provider_key != &policy.potr_mldsa_public_key
                || projection.requested_at_ms / 1_000 < policy.valid_from_unix
                || projection.recorded_at_ms / 1_000 > policy.valid_until_unix
            {
                return Err(invalid_parameter(
                    "PoTR receipt signers or timing do not match the current governed policy",
                ));
            }
        }
    }
    Ok(())
}
fn validate_persisted_event(
    event: &ProofOutcomePersistedEventV1,
    expected_sequence: u64,
) -> Result<(), InstructionExecutionError> {
    validate_persisted_event_with_current(event, expected_sequence, None)
}
fn validate_persisted_event_with_current(
    event: &ProofOutcomePersistedEventV1,
    expected_sequence: u64,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<(), InstructionExecutionError> {
    validate_outcome_record_with_current(&event.outcome, current)?;
    if event.sequence == 0
        || event.sequence != expected_sequence
        || event.target_block_height == 0
        || event.outcome.committed_at_unix_ms == 0
    {
        return Err(corrupt_state(
            "stored proof-outcome event cursor metadata is invalid",
        ));
    }
    Ok(())
}
fn validate_event_successor(
    previous: Option<&ProofOutcomePersistedEventV1>,
    current: &ProofOutcomePersistedEventV1,
) -> Result<(), InstructionExecutionError> {
    let Some(previous) = previous else {
        if current.sequence != 1 || current.event_index != 0 {
            return Err(corrupt_state(
                "proof-outcome event journal does not begin at sequence one and block index zero",
            ));
        }
        return Ok(());
    };
    if previous
        .sequence
        .checked_add(1)
        .is_none_or(|next| current.sequence != next)
    {
        return Err(corrupt_state(
            "proof-outcome event journal sequence is not contiguous",
        ));
    }
    match previous
        .target_block_height
        .cmp(&current.target_block_height)
    {
        core::cmp::Ordering::Less if current.event_index == 0 => Ok(()),
        core::cmp::Ordering::Equal
            if previous
                .event_index
                .checked_add(1)
                .is_some_and(|next| current.event_index == next) =>
        {
            Ok(())
        }
        _ => Err(corrupt_state(
            "proof-outcome event journal block height/index ordering is invalid",
        )),
    }
}
fn read_persisted_event(
    world: &impl WorldReadOnly,
    sequence: u64,
) -> Result<Option<ProofOutcomePersistedEventV1>, InstructionExecutionError> {
    if sequence == 0 {
        return Err(corrupt_state(
            "proof-outcome event sequence zero cannot be read",
        ));
    }
    let Some(bytes) = world.smart_contract_state().get(&event_key(sequence)) else {
        return Ok(None);
    };
    let event: ProofOutcomePersistedEventV1 =
        if crate::smartcontracts::isi::query::singular_query_limits_active() {
            let (event, allocation_bytes) =
                decode_state_measured(bytes, "proof-outcome committed event")?;
            let mut current =
                crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
                    allocation_bytes,
                )
                .map_err(InstructionExecutionError::Query)?;
            validate_persisted_event_with_current(&event, sequence, Some(&mut current))?;
            event
        } else {
            let event = decode_state(bytes, "proof-outcome committed event")?;
            validate_persisted_event(&event, sequence)?;
            event
        };
    Ok(Some(event))
}
fn validate_event_outcome_binding(
    world: &impl WorldReadOnly,
    event: &ProofOutcomePersistedEventV1,
) -> Result<usize, InstructionExecutionError> {
    let key = outcome_key(event.outcome.kind(), event.outcome.identity_digest);
    let state_bytes = world.smart_contract_state().get(&key).ok_or_else(|| {
        corrupt_state(format!(
            "proof-outcome event sequence {} references a missing outcome",
            event.sequence
        ))
    })?;
    if state_bytes.is_empty() || state_bytes.len() > STATE_MAX_BYTES {
        return Err(corrupt_state(format!(
            "proof-outcome event sequence {} references an outcome whose length is outside 1..={STATE_MAX_BYTES}",
            event.sequence
        )));
    }
    let maximum = crate::smartcontracts::isi::query::singular_query_frame_limit(STATE_MAX_BYTES);
    if state_bytes.len() > maximum {
        return Err(InstructionExecutionError::Query(
            QueryExecutionFail::CapacityLimit,
        ));
    }
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    norito::verify_exact_frame(&event.outcome, state_bytes).map_err(|_| {
        corrupt_state(format!(
            "proof-outcome event sequence {} disagrees with authoritative state",
            event.sequence
        ))
    })?;
    Ok(state_bytes.len())
}
fn read_event_journal_head(
    world: &impl WorldReadOnly,
) -> Result<Option<ProofOutcomeEventJournalHeadV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(event_journal_head_key()) else {
        return Ok(None);
    };
    let head: ProofOutcomeEventJournalHeadV1 =
        decode_state(bytes, "proof-outcome event journal head")?;
    if head.last_sequence == 0 || head.last_target_block_height == 0 {
        return Err(corrupt_state(
            "stored proof-outcome event journal head is invalid",
        ));
    }
    let terminal = read_persisted_event(world, head.last_sequence)?.ok_or_else(|| {
        corrupt_state("proof-outcome event journal head references a missing event")
    })?;
    if terminal.target_block_height != head.last_target_block_height
        || terminal.event_index != head.last_event_index
    {
        return Err(corrupt_state(
            "proof-outcome event journal head disagrees with its terminal event",
        ));
    }
    let predecessor = if head.last_sequence == 1 {
        None
    } else {
        Some(
            read_persisted_event(world, head.last_sequence - 1)?.ok_or_else(|| {
                corrupt_state("proof-outcome event journal terminal predecessor is missing")
            })?,
        )
    };
    validate_event_successor(predecessor.as_ref(), &terminal)?;
    Ok(Some(head))
}
fn ensure_no_event_after_head(
    world: &impl WorldReadOnly,
    head: Option<ProofOutcomeEventJournalHeadV1>,
) -> Result<(), InstructionExecutionError> {
    let prefix = StatePath::from_str(EVENT_STATE_KEY_PREFIX)
        .expect("static proof-outcome event prefix is valid");
    let first = world
        .smart_contract_state()
        .range(prefix.clone()..)
        .next()
        .and_then(|(key, _)| {
            key.to_string()
                .starts_with(EVENT_STATE_KEY_PREFIX)
                .then_some(key)
        });
    match (head, first) {
        (None, None) => return Ok(()),
        (None, Some(_)) => {
            return Err(corrupt_state(
                "proof-outcome event journal contains records without a head",
            ));
        }
        (Some(_), Some(key)) if *key == event_key(1) => {}
        (Some(_), _) => {
            return Err(corrupt_state(
                "proof-outcome event journal does not begin at sequence one",
            ));
        }
    }
    let start = head.map_or(prefix, |head| event_key(head.last_sequence));
    for (key, _) in world.smart_contract_state().range(start..) {
        if !key.to_string().starts_with(EVENT_STATE_KEY_PREFIX) {
            break;
        }
        if head.is_some_and(|head| *key == event_key(head.last_sequence)) {
            continue;
        }
        return Err(corrupt_state(
            "proof-outcome event journal contains a record beyond its head",
        ));
    }
    Ok(())
}
fn append_event_journal(
    state_transaction: &mut StateTransaction<'_, '_>,
    outcome: &ProofOutcomeRecordV1,
) -> Result<(), InstructionExecutionError> {
    let committed_parent_height =
        u64::try_from(state_transaction.block_hashes().len()).map_err(|_| {
            corrupt_state("committed proof-outcome parent height does not fit into u64")
        })?;
    let target_block_height = committed_parent_height
        .checked_add(1)
        .ok_or_else(|| corrupt_state("proof-outcome event target block height overflow"))?;
    if target_block_height != state_transaction._curr_block.height().get() {
        return Err(corrupt_state(
            "proof-outcome event target height does not match the executing block",
        ));
    }
    let head = read_event_journal_head(state_transaction.world())?;
    ensure_no_event_after_head(state_transaction.world(), head)?;
    let (sequence, event_index, previous) = match head {
        Some(head) => {
            let sequence = head
                .last_sequence
                .checked_add(1)
                .ok_or_else(|| corrupt_state("proof-outcome event sequence overflow"))?;
            let event_index = match head.last_target_block_height.cmp(&target_block_height) {
                core::cmp::Ordering::Less => 0,
                core::cmp::Ordering::Equal => head
                    .last_event_index
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("proof-outcome block event index overflow"))?,
                core::cmp::Ordering::Greater => {
                    return Err(corrupt_state(
                        "proof-outcome event target height regressed behind the journal head",
                    ));
                }
            };
            let previous = read_persisted_event(state_transaction.world(), head.last_sequence)?
                .ok_or_else(|| {
                    corrupt_state("proof-outcome event journal lost its terminal record")
                })?;
            (sequence, event_index, Some(previous))
        }
        None => (1, 0, None),
    };
    let key = event_key(sequence);
    if state_transaction
        .world
        .smart_contract_state
        .get(&key)
        .is_some()
    {
        return Err(corrupt_state(
            "proof-outcome event journal sequence already exists",
        ));
    }
    let event = ProofOutcomePersistedEventV1 {
        sequence,
        target_block_height,
        event_index,
        outcome: outcome.clone(),
    };
    validate_persisted_event(&event, sequence)?;
    validate_event_successor(previous.as_ref(), &event)?;
    validate_event_outcome_binding(state_transaction.world(), &event)?;
    let next_head = ProofOutcomeEventJournalHeadV1 {
        last_sequence: sequence,
        last_target_block_height: target_block_height,
        last_event_index: event_index,
    };
    state_transaction
        .world
        .smart_contract_state
        .insert(key, encode_state(&event, "proof-outcome committed event")?);
    state_transaction.world.smart_contract_state.insert(
        event_journal_head_key().clone(),
        encode_state(&next_head, "proof-outcome event journal head")?,
    );
    Ok(())
}
impl Execute for SetSorafsProofOutcomeSignerPolicy {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        if !has_policy_permission(state_transaction, authority) {
            return Err(invalid_parameter(
                "CanManageSorafsProofOutcomePolicy permission is required",
            ));
        }
        if state_transaction.world.accounts.get(authority).is_none() {
            return Err(invalid_parameter(
                "proof-outcome policy authority is not a registered account",
            ));
        }
        validate_signer_policy(&self.policy)?;
        if state_transaction
            .world
            .provider_owners
            .get(&self.policy.provider_id)
            .is_none()
        {
            return Err(invalid_parameter(
                "proof-outcome signer policy references an unregistered provider",
            ));
        }
        let now = block_time_ms(state_transaction)?;
        if self.policy.valid_until_unix < now / 1_000 {
            return Err(invalid_parameter(
                "proof-outcome signer policy is already expired",
            ));
        }
        let digest = policy_digest(&self.policy)?;
        if let Some(current) =
            read_signer_policy(state_transaction.world(), self.policy.provider_id)?
        {
            if current.policy_digest == digest && current.policy == self.policy {
                return Ok(());
            }
            if self.policy.revision
                != current
                    .policy
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("proof-outcome signer policy revision overflow"))?
                || self.policy.predecessor_digest != Some(current.policy_digest)
            {
                return Err(invalid_parameter(
                    "proof-outcome signer policy revision or predecessor is stale",
                ));
            }
        } else if self.policy.revision != 1 || self.policy.predecessor_digest.is_some() {
            return Err(invalid_parameter(
                "first proof-outcome signer policy must be revision one without a predecessor",
            ));
        }
        let record = ProofOutcomeSignerPolicyRecordV1 {
            policy: self.policy,
            policy_digest: digest,
            activated_by: authority.clone(),
            activated_at_unix_ms: now,
        };
        state_transaction.world.smart_contract_state.insert(
            policy_key(record.policy.provider_id),
            encode_state(&record, "proof-outcome signer policy")?,
        );
        Ok(())
    }
}
impl Execute for SubmitSorafsProofOutcome {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let prepared = match self.submission {
            SorafsProofOutcomeSubmissionV1::Pdp(submission) => {
                prepare_pdp_outcome(&submission.archive_payload)?
            }
            SorafsProofOutcomeSubmissionV1::Potr(submission) => prepare_potr_outcome(
                &submission.receipt_payload,
                submission.admission_envelope_digest,
            )?,
        };
        let now = block_time_ms(state_transaction)?;
        let candidate = PreparedOutcome {
            identity_digest: prepared.identity_digest,
            outcome_digest: prepared.outcome_digest,
            provider_id: prepared.provider_id,
            manifest_digest: prepared.manifest_digest,
            admission_envelope_digest: prepared.admission_envelope_digest,
            projection: prepared.projection.clone(),
            has_provider_proof: prepared.has_provider_proof,
        }
        .into_record(authority.clone(), now);
        if let Some(existing) = read_outcome(
            state_transaction.world(),
            candidate.kind(),
            candidate.identity_digest,
        )? {
            if same_cryptographic_outcome(&existing, &candidate) {
                return Ok(());
            }
            return Err(invalid_parameter(
                "proof-outcome identity was already committed with different cryptographic material",
            ));
        }
        if state_transaction.world.accounts.get(authority).is_none() {
            return Err(invalid_parameter(
                "proof-outcome submitter is not a registered account",
            ));
        }
        let policy = read_signer_policy(state_transaction.world(), prepared.provider_id)?
            .ok_or_else(|| {
                invalid_parameter("proof outcome has no current governed signer policy")
            })?;
        validate_outcome_against_current_policy(&prepared, &policy.policy, now / 1_000)?;
        if !prepared.has_provider_proof
            && !has_scheduler_permission(state_transaction, authority, prepared.provider_id)
        {
            return Err(invalid_parameter(
                "unsigned PDP terminal outcome requires provider-scoped CanRecordSorafsProofOutcome permission",
            ));
        }
        validate_outcome_record(&candidate)?;
        let key = outcome_key(candidate.kind(), candidate.identity_digest);
        state_transaction
            .world
            .smart_contract_state
            .insert(key, encode_state(&candidate, "proof-outcome record")?);
        append_event_journal(state_transaction, &candidate)
    }
}
fn resolve_finalized_cursor(
    state_ro: &impl crate::state::StateReadOnly,
) -> Result<ProofOutcomeFinalizedCursorV1, QueryExecutionFail> {
    let height = u64::try_from(state_ro.block_hashes().len()).map_err(|_| {
        QueryExecutionFail::Conversion(
            "finalized proof-outcome height does not fit into u64".to_owned(),
        )
    })?;
    let block_hash = state_ro
        .block_hashes()
        .last()
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "proof-outcome queries require at least one committed block".to_owned(),
            )
        })?;
    if height == 0 || block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(
            "finalized proof-outcome query anchor is invalid".to_owned(),
        ));
    }
    Ok(ProofOutcomeFinalizedCursorV1 { height, block_hash })
}
/// Read the active provider proof/admission policy from one immutable finalized state view.
///
/// The returned cursor and policy record are resolved from the same borrowed view. Callers must not
/// combine the result with a record read from another view. Stored records are decoded canonically
/// and their policy digest, provider binding, activation provenance, and key material are
/// revalidated before this function returns.
///
/// # Errors
///
/// Returns a query failure when the view has no committed block or the
/// consensus state contains a malformed policy record.
pub fn read_sorafs_proof_outcome_signer_policy_in_finalized_view(
    state_ro: &impl crate::state::StateReadOnly,
    provider_id: iroha_data_model::sorafs::capacity::ProviderId,
) -> Result<
    (
        ProofOutcomeFinalizedCursorV1,
        Option<ProofOutcomeSignerPolicyRecordV1>,
    ),
    QueryExecutionFail,
> {
    let finalized_cursor = resolve_finalized_cursor(state_ro)?;
    let policy = read_signer_policy(state_ro.world(), provider_id).map_err(query_failure)?;
    Ok((finalized_cursor, policy))
}
fn resolve_committed_event(
    state_ro: &impl crate::state::StateReadOnly,
    event: ProofOutcomePersistedEventV1,
) -> Result<ProofOutcomeFinalizedEventV1, QueryExecutionFail> {
    let hash_index = event
        .target_block_height
        .checked_sub(1)
        .and_then(|height| usize::try_from(height).ok())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "proof-outcome target height cannot index finalized block hashes".to_owned(),
            )
        })?;
    let block_hash = state_ro
        .block_hashes()
        .get(hash_index)
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(format!(
                "proof-outcome event sequence {} targets non-finalized block height {}",
                event.sequence, event.target_block_height
            ))
        })?;
    if block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(format!(
            "proof-outcome event sequence {} resolved a zero block hash",
            event.sequence
        )));
    }
    Ok(ProofOutcomeFinalizedEventV1 {
        sequence: event.sequence,
        block_height: event.target_block_height,
        block_hash,
        event_index: event.event_index,
        outcome: event.outcome,
    })
}
fn charge_state_bytes(total: &mut usize, amount: usize) -> Result<(), QueryExecutionFail> {
    *total = total.checked_add(amount).ok_or_else(|| {
        QueryExecutionFail::Conversion(
            "proof-outcome query state-read byte counter overflow".to_owned(),
        )
    })?;
    if *total > QUERY_MAX_STATE_READ_BYTES {
        return Err(QueryExecutionFail::Conversion(format!(
            "proof-outcome query inspected more than {QUERY_MAX_STATE_READ_BYTES} state bytes"
        )));
    }
    Ok(())
}
fn ensure_page_budget<T: norito::core::NoritoSerialize>(
    value: &T,
) -> Result<(), QueryExecutionFail> {
    let maximum = crate::smartcontracts::isi::query::singular_query_frame_limit(
        PROOF_OUTCOME_QUERY_MAX_EVENT_PAGE_BYTES_V1,
    );
    let length = norito::canonical_frame_len(value).map_err(|error| {
        QueryExecutionFail::Conversion(format!("failed to size proof-outcome event page: {error}"))
    })?;
    if length > maximum {
        return Err(QueryExecutionFail::Conversion(format!(
            "proof-outcome event page encodes to {length} bytes, above {maximum}"
        )));
    }
    Ok(())
}
#[derive(Clone, Copy)]
struct ProofOutcomeQueryEventPosition {
    sequence: u64,
    target_block_height: u64,
    event_index: u32,
}
impl From<&ProofOutcomePersistedEventV1> for ProofOutcomeQueryEventPosition {
    fn from(event: &ProofOutcomePersistedEventV1) -> Self {
        Self {
            sequence: event.sequence,
            target_block_height: event.target_block_height,
            event_index: event.event_index,
        }
    }
}
fn validate_query_event_successor(
    previous: Option<ProofOutcomeQueryEventPosition>,
    current: &ProofOutcomePersistedEventV1,
) -> Result<(), QueryExecutionFail> {
    let Some(previous) = previous else {
        return (current.sequence == 1 && current.event_index == 0)
            .then_some(())
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "proof-outcome event journal does not begin at sequence one and block index zero"
                        .to_owned(),
                )
            });
    };
    if previous
        .sequence
        .checked_add(1)
        .is_none_or(|next| current.sequence != next)
    {
        return Err(QueryExecutionFail::Conversion(
            "proof-outcome event journal sequence is not contiguous".to_owned(),
        ));
    }
    match previous
        .target_block_height
        .cmp(&current.target_block_height)
    {
        core::cmp::Ordering::Less if current.event_index == 0 => Ok(()),
        core::cmp::Ordering::Equal
            if previous
                .event_index
                .checked_add(1)
                .is_some_and(|next| current.event_index == next) =>
        {
            Ok(())
        }
        _ => Err(QueryExecutionFail::Conversion(
            "proof-outcome event journal block height/index ordering is invalid".to_owned(),
        )),
    }
}
fn query_event_page(
    query: &FindSorafsProofOutcomeEvents,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: ProofOutcomeFinalizedCursorV1,
) -> Result<ProofOutcomeFinalizedEventPageV1, QueryExecutionFail> {
    let limit = usize::try_from(query.limit).map_err(|_| {
        QueryExecutionFail::Conversion("proof-outcome query limit does not fit usize".to_owned())
    })?;
    if limit == 0 || limit > PROOF_OUTCOME_QUERY_MAX_ITEMS_V1 {
        return Err(QueryExecutionFail::Conversion(format!(
            "proof-outcome query limit {} is outside 1..={PROOF_OUTCOME_QUERY_MAX_ITEMS_V1}",
            query.limit
        )));
    }
    let world = state_ro.world();
    let mut state_read_bytes = world
        .smart_contract_state()
        .get(event_journal_head_key())
        .map_or(0, Vec::len);
    let head = read_event_journal_head(world).map_err(query_failure)?;
    ensure_no_event_after_head(world, head).map_err(query_failure)?;
    let Some(head) = head else {
        let page = ProofOutcomeFinalizedEventPageV1 {
            finalized_cursor,
            events: Vec::new(),
            has_more: false,
            next_after: None,
        };
        ensure_page_budget(&page)?;
        return Ok(page);
    };
    let terminal_state_bytes = world
        .smart_contract_state()
        .get(&event_key(head.last_sequence))
        .map_or(0, Vec::len);
    let terminal = read_persisted_event(world, head.last_sequence)
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "proof-outcome event journal terminal record is missing".to_owned(),
            )
        })?;
    let terminal_binding_bytes =
        validate_event_outcome_binding(world, &terminal).map_err(query_failure)?;
    charge_state_bytes(
        &mut state_read_bytes,
        terminal_state_bytes
            .checked_add(terminal_binding_bytes)
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "proof-outcome terminal read-byte counter overflow".to_owned(),
                )
            })?,
    )?;
    resolve_committed_event(state_ro, terminal)?;
    let mut previous = match query.after {
        Some(after) => {
            if after.sequence == 0 || after.sequence > head.last_sequence {
                return Err(QueryExecutionFail::Expired);
            }
            let event_bytes = world
                .smart_contract_state()
                .get(&event_key(after.sequence))
                .map_or(0, Vec::len);
            let predecessor_record = if after.sequence == 1 {
                None
            } else {
                let sequence = after.sequence - 1;
                let bytes = world
                    .smart_contract_state()
                    .get(&event_key(sequence))
                    .map_or(0, Vec::len);
                charge_state_bytes(&mut state_read_bytes, bytes)?;
                Some(
                    read_persisted_event(world, sequence)
                        .map_err(query_failure)?
                        .ok_or_else(|| {
                            QueryExecutionFail::Conversion(format!(
                                "proof-outcome event journal is missing predecessor sequence {sequence}"
                            ))
                        })?,
                )
            };
            let predecessor = predecessor_record
                .as_ref()
                .map(ProofOutcomeQueryEventPosition::from);
            drop(predecessor_record);
            let event = read_persisted_event(world, after.sequence)
                .map_err(query_failure)?
                .ok_or(QueryExecutionFail::Expired)?;
            let binding_bytes =
                validate_event_outcome_binding(world, &event).map_err(query_failure)?;
            charge_state_bytes(
                &mut state_read_bytes,
                event_bytes.checked_add(binding_bytes).ok_or_else(|| {
                    QueryExecutionFail::Conversion(
                        "proof-outcome cursor read-byte counter overflow".to_owned(),
                    )
                })?,
            )?;
            validate_query_event_successor(predecessor, &event)?;
            let position = ProofOutcomeQueryEventPosition::from(&event);
            if resolve_committed_event(state_ro, event)?.cursor() != after {
                return Err(QueryExecutionFail::Expired);
            }
            Some(position)
        }
        None => None,
    };
    let mut sequence = query
        .after
        .map_or(Some(1), |after| after.sequence.checked_add(1));
    let mut events = crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(limit)?;
    let page_bytes_limit = crate::smartcontracts::isi::query::singular_query_frame_limit(
        PROOF_OUTCOME_QUERY_MAX_EVENT_PAGE_BYTES_V1,
    );
    let payload_budget = page_bytes_limit.saturating_sub(1_024);
    let mut encoded_event_bytes = 0usize;
    let mut inspected_records = 0usize;
    let inspected_budget = limit.saturating_add(4);
    while let Some(current_sequence) = sequence {
        if current_sequence > head.last_sequence || events.len() >= limit {
            break;
        }
        inspected_records = inspected_records.checked_add(1).ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "proof-outcome inspected-record counter overflow".to_owned(),
            )
        })?;
        if inspected_records > inspected_budget {
            return Err(QueryExecutionFail::Conversion(
                "proof-outcome query exceeded its inspected-record budget".to_owned(),
            ));
        }
        let event_state_bytes = world
            .smart_contract_state()
            .get(&event_key(current_sequence))
            .map_or(0, Vec::len);
        let event = read_persisted_event(world, current_sequence)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(format!(
                    "proof-outcome event journal is missing sequence {current_sequence}"
                ))
            })?;
        validate_query_event_successor(previous, &event)?;
        let binding_bytes = validate_event_outcome_binding(world, &event).map_err(query_failure)?;
        charge_state_bytes(
            &mut state_read_bytes,
            event_state_bytes
                .checked_add(binding_bytes)
                .ok_or_else(|| {
                    QueryExecutionFail::Conversion(
                        "proof-outcome event read-byte counter overflow".to_owned(),
                    )
                })?,
        )?;
        let position = ProofOutcomeQueryEventPosition::from(&event);
        let resolved = resolve_committed_event(state_ro, event)?;
        let resolved_bytes = norito::canonical_frame_len(&resolved).map_err(|error| {
            QueryExecutionFail::Conversion(format!(
                "failed to size committed proof-outcome event: {error}"
            ))
        })?;
        let next_bytes = encoded_event_bytes
            .checked_add(resolved_bytes)
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "proof-outcome event-page byte counter overflow".to_owned(),
                )
            })?;
        if next_bytes > payload_budget {
            if events.is_empty() {
                return Err(QueryExecutionFail::Conversion(format!(
                    "one proof-outcome event cannot fit within the {page_bytes_limit}-byte page budget"
                )));
            }
            break;
        }
        encoded_event_bytes = next_bytes;
        previous = Some(position);
        events.try_push(resolved)?;
        sequence = current_sequence.checked_add(1);
    }
    let has_more = events
        .last()
        .is_some_and(|event| event.sequence < head.last_sequence);
    let next_after = has_more.then(|| {
        events
            .last()
            .expect("has_more requires a non-empty proof-outcome page")
            .cursor()
    });
    let page = ProofOutcomeFinalizedEventPageV1 {
        finalized_cursor,
        events: events.into_vec()?,
        has_more,
        next_after,
    };
    ensure_page_budget(&page)?;
    Ok(page)
}
impl ValidSingularQuery for FindSorafsProofOutcome {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ProofOutcomeFinalizedRecordV1, QueryExecutionFail> {
        if self.identity_digest == [0; 32] {
            return Err(QueryExecutionFail::Conversion(
                "proof-outcome identity digest must be non-zero".to_owned(),
            ));
        }
        let finalized_cursor = resolve_finalized_cursor(state_ro)?;
        if self
            .expected_finalized_cursor
            .is_some_and(|expected| expected != finalized_cursor)
        {
            return Err(QueryExecutionFail::Expired);
        }
        let outcome = read_outcome(state_ro.world(), self.kind, self.identity_digest)
            .map_err(query_failure)?
            .ok_or(QueryExecutionFail::Find(FindError::SorafsProofOutcome(
                SorafsProofOutcomeFindErrorV1 {
                    kind: self.kind,
                    identity_digest: self.identity_digest,
                },
            )))?;
        Ok(ProofOutcomeFinalizedRecordV1 {
            finalized_cursor,
            outcome,
        })
    }
}
impl ValidSingularQuery for FindSorafsProofOutcomeEvents {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ProofOutcomeFinalizedEventPageV1, QueryExecutionFail> {
        let actual = resolve_finalized_cursor(state_ro)?;
        if self
            .expected_finalized_cursor
            .is_some_and(|expected| expected != actual)
        {
            return Err(QueryExecutionFail::Expired);
        }
        query_event_page(self, state_ro, actual)
    }
}
#[cfg(test)]
mod tests {
    include!("sorafs_proof_outcome/schema_identity_tests.rs");
    use super::*;
    include!("sorafs/proof_outcome_permission_token_tests.rs");
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_crypto::{KeyPair, PrivateKey, Signature};
    use iroha_data_model::{
        IntoKeyValue, Registrable,
        account::{Account, AccountId},
        block::BlockHeader,
        isi::sorafs::{SorafsPdpProofOutcomeSubmissionV1, SorafsPotrProofOutcomeSubmissionV1},
        permission::{Permission, Permissions},
        sorafs::proof_ledger::{
            PdpOutcomeStatusV1, ProofOutcomeKindV1, ProofOutcomeSignerPolicyV1,
        },
    };
    use sorafs_manifest::{
        ChunkingProfileV1, PDP_GOVERNANCE_ARCHIVE_VERSION_V1, PDP_PROOF_VERSION_V1,
        POTR_RECEIPT_VERSION_V1, PdpChallengeV1, PdpEd25519SignatureV1, PdpGovernanceArchiveV1,
        PdpHotLeafProofV1, PdpProofLeafV1, PdpProofV1, PdpRejectionReasonV1, PdpSampleV1,
        PdpTerminalDecisionV1, PotrReceiptV1, PotrStatus, ProfileId, ProofStreamTier,
        sign_potr_receipt_v1,
    };
    const NOW: u64 = 10_000;
    const PROVIDER_BYTES: [u8; 32] = [0x31; 32];
    const ADMISSION_DIGEST: [u8; 32] = [0x42; 32];
    const MANIFEST_DIGEST: [u8; 32] = [0x53; 32];
    fn ed25519_keypair(seed: u8) -> KeyPair {
        let private = PrivateKey::from_bytes(Algorithm::Ed25519, &[seed; 32])
            .expect("valid deterministic Ed25519 seed");
        KeyPair::from_private_key(private).expect("derive deterministic Ed25519 keypair")
    }
    fn mldsa_keypair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::MlDsa)
            .expect("derive deterministic ML-DSA keypair")
    }
    fn account(keypair: &KeyPair) -> AccountId {
        AccountId::new(keypair.public_key().clone())
    }
    fn ed25519_public_key(keypair: &KeyPair) -> [u8; 32] {
        let (algorithm, bytes) = keypair
            .public_key()
            .try_to_bytes()
            .expect("encode Ed25519 public key");
        assert_eq!(algorithm, Algorithm::Ed25519);
        bytes.try_into().expect("Ed25519 public key length")
    }
    fn mldsa_public_key(keypair: &KeyPair) -> Vec<u8> {
        let (algorithm, bytes) = keypair
            .public_key()
            .try_to_bytes()
            .expect("encode ML-DSA public key");
        assert_eq!(algorithm, Algorithm::MlDsa);
        bytes.to_vec()
    }
    fn provider_id() -> ProviderId {
        ProviderId::new(PROVIDER_BYTES)
    }
    fn block_header_at(height: u64, now_unix: u64) -> BlockHeader {
        BlockHeader::new(
            height.try_into().expect("nonzero fixture block height"),
            None,
            None,
            now_unix * 1_000,
            0,
        )
    }
    fn transact(
        state: &mut State,
        height: u64,
        now_unix: u64,
        operation: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<(), InstructionExecutionError>,
    ) -> Result<(), InstructionExecutionError> {
        let header = block_header_at(height, now_unix);
        let mut block = state.block(header.clone());
        let mut transaction = block.transaction();
        operation(&mut transaction)?;
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit proof-outcome test block");
        state.push_block_hash_for_testing(iroha_crypto::HashOf::new(&header));
        Ok(())
    }
    fn state_with_accounts(
        manager: &KeyPair,
        scheduler: &KeyPair,
        relayer_a: &KeyPair,
        relayer_b: &KeyPair,
    ) -> State {
        let mut world = World::new();
        for keypair in [manager, scheduler, relayer_a, relayer_b] {
            let id = account(keypair);
            let (id, value) = Account::new(id.clone()).build(&id).into_key_value();
            world.accounts.insert(id, value);
        }
        let manager_id = account(manager);
        let mut manager_permissions = Permissions::new();
        manager_permissions.insert(Permission::from(CanManageSorafsProofOutcomePolicy));
        world
            .account_permissions
            .insert(manager_id.clone(), manager_permissions);
        let scheduler_id = account(scheduler);
        let mut scheduler_permissions = Permissions::new();
        scheduler_permissions.insert(Permission::from(CanRecordSorafsProofOutcome {
            provider_id: provider_id(),
        }));
        world
            .account_permissions
            .insert(scheduler_id, scheduler_permissions);
        world.provider_owners.insert(provider_id(), manager_id);
        let mut state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        transact(&mut state, 1, NOW - 1, |_| Ok(())).expect("seed finalized genesis block");
        state
    }
    fn signer_policy(
        revision: u64,
        predecessor_digest: Option<[u8; 32]>,
        pdp_key: &KeyPair,
        potr_key: &KeyPair,
        gateway_key: &KeyPair,
    ) -> ProofOutcomeSignerPolicyV1 {
        ProofOutcomeSignerPolicyV1 {
            version: PROOF_OUTCOME_SIGNER_POLICY_VERSION_V1,
            provider_id: provider_id(),
            revision,
            predecessor_digest,
            admission_envelope_digest: ADMISSION_DIGEST,
            pdp_public_key: ed25519_public_key(pdp_key),
            potr_mldsa_public_key: mldsa_public_key(potr_key),
            gateway_public_key: ed25519_public_key(gateway_key),
            valid_from_unix: NOW - 100,
            valid_until_unix: NOW + 100,
        }
    }
    fn activate_policy(
        state: &mut State,
        height: u64,
        now_unix: u64,
        manager: &KeyPair,
        policy: ProofOutcomeSignerPolicyV1,
    ) {
        transact(state, height, now_unix, |state_transaction| {
            SetSorafsProofOutcomeSignerPolicy::new(policy)
                .execute(&account(manager), state_transaction)
        })
        .expect("activate proof-outcome signer policy");
    }
    fn challenge(unique: u8) -> PdpChallengeV1 {
        PdpChallengeV1::new(
            [unique; 32],
            MANIFEST_DIGEST,
            PROVIDER_BYTES,
            ChunkingProfileV1::from_descriptor(
                sorafs_manifest::chunker_registry::lookup(ProfileId(1))
                    .expect("SF1 chunk profile exists"),
            ),
            [unique.wrapping_add(1); 32],
            u64::from(unique),
            u64::from(unique).saturating_add(100),
            NOW - 50,
            NOW - 20,
            vec![PdpSampleV1 {
                segment_index: 0,
                hot_leaf_indices: vec![0],
            }],
        )
        .expect("valid PDP challenge")
    }
    fn signed_pdp_archive(pdp_key: &KeyPair, sequence: u64, unique: u8) -> Vec<u8> {
        let challenge = challenge(unique);
        let mut proof = PdpProofV1 {
            version: PDP_PROOF_VERSION_V1,
            commitment_digest: challenge.commitment_digest,
            challenge_id: challenge.challenge_id,
            manifest_digest: challenge.manifest_digest,
            provider_id: challenge.provider_id,
            epoch_id: challenge.epoch_id,
            proof_leaves: vec![PdpProofLeafV1 {
                segment_index: 0,
                segment_offset: 0,
                segment_length: 1,
                segment_merkle_path: Vec::new(),
                hot_leaves: vec![PdpHotLeafProofV1 {
                    leaf_index: 0,
                    leaf_offset: 0,
                    leaf_length: 1,
                    leaf_bytes: vec![0xA5],
                    segment_hot_merkle_path: Vec::new(),
                    global_hot_merkle_path: Vec::new(),
                }],
            }],
            issued_at_unix: NOW + 50,
            signature: PdpEd25519SignatureV1 {
                public_key: ed25519_public_key(pdp_key),
                signature: [0; 64],
            },
        };
        let proof_digest = proof.proof_digest().expect("digest PDP proof");
        let mut signing_message =
            Vec::with_capacity(PDP_PROOF_SIGNATURE_DOMAIN_V1.len() + proof_digest.len());
        signing_message.extend_from_slice(PDP_PROOF_SIGNATURE_DOMAIN_V1);
        signing_message.extend_from_slice(&proof_digest);
        proof.signature.signature = Signature::try_new(pdp_key.private_key(), &signing_message)
            .expect("sign PDP proof")
            .payload()
            .try_into()
            .expect("Ed25519 signature length");
        proof.validate().expect("signed PDP proof validates");
        proof
            .verify_signature()
            .expect("signed PDP proof authenticates");
        let archive = PdpGovernanceArchiveV1 {
            version: PDP_GOVERNANCE_ARCHIVE_VERSION_V1,
            sequence,
            challenge_id: challenge.challenge_id,
            commitment_digest: challenge.commitment_digest,
            manifest_digest: challenge.manifest_digest,
            provider_id: challenge.provider_id,
            epoch_id: challenge.epoch_id,
            decision: PdpTerminalDecisionV1::Rejected(PdpRejectionReasonV1::FutureTimestamp),
            proof_digest: Some(proof_digest),
            sampled_segments: 1,
            sampled_hot_leaves: 1,
            sampled_bytes: 0,
            issued_at_unix: challenge.issued_at_unix,
            response_deadline_unix: challenge.response_deadline_unix,
            decided_at_unix: NOW,
            admission_envelope_digest: ADMISSION_DIGEST,
            canonical_challenge: norito::to_bytes(&challenge).expect("encode PDP challenge"),
            canonical_proof: Some(norito::to_bytes(&proof).expect("encode PDP proof")),
        };
        archive.validate().expect("signed PDP archive validates");
        norito::to_bytes(&archive).expect("encode PDP archive")
    }
    fn pdp_archive_without_proof(
        sequence: u64,
        unique: u8,
        reason: PdpRejectionReasonV1,
    ) -> Vec<u8> {
        let challenge = challenge(unique);
        let archive = PdpGovernanceArchiveV1 {
            version: PDP_GOVERNANCE_ARCHIVE_VERSION_V1,
            sequence,
            challenge_id: challenge.challenge_id,
            commitment_digest: challenge.commitment_digest,
            manifest_digest: challenge.manifest_digest,
            provider_id: challenge.provider_id,
            epoch_id: challenge.epoch_id,
            decision: PdpTerminalDecisionV1::Rejected(reason),
            proof_digest: None,
            sampled_segments: 1,
            sampled_hot_leaves: 1,
            sampled_bytes: 0,
            issued_at_unix: challenge.issued_at_unix,
            response_deadline_unix: challenge.response_deadline_unix,
            decided_at_unix: NOW,
            admission_envelope_digest: ADMISSION_DIGEST,
            canonical_challenge: norito::to_bytes(&challenge).expect("encode PDP challenge"),
            canonical_proof: None,
        };
        archive
            .validate()
            .expect("PDP archive without proof validates");
        norito::to_bytes(&archive).expect("encode PDP archive")
    }
    fn unsigned_pdp_archive(sequence: u64, unique: u8) -> Vec<u8> {
        pdp_archive_without_proof(sequence, unique, PdpRejectionReasonV1::DeadlineExpired)
    }
    fn pdp_submission(archive_payload: Vec<u8>) -> SubmitSorafsProofOutcome {
        SubmitSorafsProofOutcome::new(SorafsProofOutcomeSubmissionV1::Pdp(
            SorafsPdpProofOutcomeSubmissionV1 { archive_payload },
        ))
    }
    fn signed_potr_receipt(
        gateway_key: &KeyPair,
        provider_key: &KeyPair,
        request_byte: u8,
        latency_ms: u32,
    ) -> PotrReceiptV1 {
        let requested_at_ms = (NOW - 1) * 1_000;
        sign_potr_receipt_v1(
            PotrReceiptV1 {
                version: POTR_RECEIPT_VERSION_V1,
                manifest_digest: MANIFEST_DIGEST,
                provider_id: PROVIDER_BYTES,
                tier: ProofStreamTier::Hot,
                deadline_ms: 100,
                latency_ms,
                status: PotrStatus::Success,
                requested_at_ms,
                responded_at_ms: requested_at_ms + u64::from(latency_ms),
                recorded_at_ms: requested_at_ms + u64::from(latency_ms) + 1,
                range_start: 0,
                range_end: 31,
                request_id: Some([request_byte; 16]),
                trace_id: None,
                note: None,
                gateway_signature: None,
                provider_signature: None,
            },
            gateway_key,
            provider_key,
        )
        .expect("sign valid PoTR receipt")
    }
    fn potr_submission(receipt: &PotrReceiptV1) -> SubmitSorafsProofOutcome {
        SubmitSorafsProofOutcome::new(SorafsProofOutcomeSubmissionV1::Potr(
            SorafsPotrProofOutcomeSubmissionV1 {
                receipt_payload: receipt
                    .signed_receipt_bytes()
                    .expect("encode signed PoTR receipt"),
                admission_envelope_digest: ADMISSION_DIGEST,
            },
        ))
    }
    fn query_events(
        state: &State,
        expected_finalized_cursor: Option<ProofOutcomeFinalizedCursorV1>,
        after: Option<iroha_data_model::sorafs::proof_ledger::ProofOutcomeFinalizedEventCursorV1>,
        limit: u32,
    ) -> Result<ProofOutcomeFinalizedEventPageV1, QueryExecutionFail> {
        let query = FindSorafsProofOutcomeEvents {
            expected_finalized_cursor,
            after,
            limit,
        };
        ValidSingularQuery::execute(&query, &state.view())
    }
    fn query_outcome(
        state: &State,
        kind: ProofOutcomeKindV1,
        identity_digest: [u8; 32],
        expected_finalized_cursor: Option<ProofOutcomeFinalizedCursorV1>,
    ) -> Result<ProofOutcomeFinalizedRecordV1, QueryExecutionFail> {
        let query = FindSorafsProofOutcome {
            kind,
            identity_digest,
            expected_finalized_cursor,
        };
        ValidSingularQuery::execute(&query, &state.view())
    }
    fn assert_instruction_error_contains(
        result: Result<(), InstructionExecutionError>,
        expected: &str,
    ) {
        let error = result.expect_err("operation must fail closed");
        let InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            error,
        )) = error
        else {
            panic!("unexpected instruction error: {error:?}");
        };
        assert!(
            error.contains(expected),
            "unexpected instruction error: {error}"
        );
    }
    #[test]
    fn signer_policy_digest_is_canonical_under_every_ambient_layout() {
        let policy = signer_policy(
            1,
            None,
            &ed25519_keypair(0x11),
            &mldsa_keypair(0x12),
            &ed25519_keypair(0x13),
        );
        let canonical = norito::encode_canonical(&policy).expect("canonical policy frame");
        let mut expected = blake3::Hasher::new();
        expected.update(POLICY_DIGEST_DOMAIN_V1);
        expected.update(
            &u64::try_from(canonical.len())
                .expect("policy frame length")
                .to_le_bytes(),
        );
        expected.update(&canonical);
        let expected = *expected.finalize().as_bytes();
        for flags in 0..=u8::MAX {
            if norito::core::validate_header_flags(flags).is_err() {
                continue;
            }
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(policy_digest(&policy).expect("policy digest"), expected);
            let mut changed = policy.clone();
            changed.valid_until_unix += 1;
            assert_ne!(
                policy_digest(&changed).expect("changed policy digest"),
                expected
            );
        }
    }
    #[test]
    fn signed_pdp_and_potr_relay_permissionlessly_and_split_peer_replay_is_single_event() {
        let manager = ed25519_keypair(0x01);
        let scheduler = ed25519_keypair(0x02);
        let relayer_a = ed25519_keypair(0x03);
        let relayer_b = ed25519_keypair(0x04);
        let pdp_key = ed25519_keypair(0x11);
        let potr_key = mldsa_keypair(0x12);
        let gateway_key = ed25519_keypair(0x13);
        let mut state = state_with_accounts(&manager, &scheduler, &relayer_a, &relayer_b);
        activate_policy(
            &mut state,
            2,
            NOW,
            &manager,
            signer_policy(1, None, &pdp_key, &potr_key, &gateway_key),
        );
        let pdp = pdp_submission(signed_pdp_archive(&pdp_key, 1, 0x21));
        transact(&mut state, 3, NOW + 1, |state_transaction| {
            pdp.clone().execute(&account(&relayer_a), state_transaction)
        })
        .expect("unprivileged relayer submits governed signed PDP outcome");
        let potr_receipt = signed_potr_receipt(&gateway_key, &potr_key, 0x31, 40);
        let potr = potr_submission(&potr_receipt);
        transact(&mut state, 4, NOW + 2, |state_transaction| {
            potr.clone()
                .execute(&account(&relayer_b), state_transaction)
        })
        .expect("different unprivileged relayer submits governed signed PoTR outcome");
        transact(&mut state, 5, NOW + 3, |state_transaction| {
            pdp.clone().execute(&account(&relayer_b), state_transaction)
        })
        .expect("exact signed PDP replay through another peer is a no-op");
        transact(&mut state, 6, NOW + 4, |state_transaction| {
            potr.clone()
                .execute(&account(&relayer_a), state_transaction)
        })
        .expect("exact signed PoTR replay through another peer is a no-op");
        let page = query_events(
            &state,
            None,
            None,
            u32::try_from(PROOF_OUTCOME_QUERY_MAX_ITEMS_V1).expect("query cap fits u32"),
        )
        .expect("query committed proof outcomes");
        assert_eq!(page.events.len(), 2);
        assert!(!page.has_more);
        assert_eq!(page.events[0].sequence, 1);
        assert_eq!(page.events[0].outcome.kind(), ProofOutcomeKindV1::Pdp);
        assert_eq!(page.events[0].outcome.submitted_by, account(&relayer_a));
        assert_eq!(page.events[1].sequence, 2);
        assert_eq!(page.events[1].outcome.kind(), ProofOutcomeKindV1::Potr);
        assert_eq!(page.events[1].outcome.submitted_by, account(&relayer_b));
        let view = state.view();
        let head = read_event_journal_head(view.world())
            .expect("validated durable journal head")
            .expect("two committed events have a head");
        let event = read_persisted_event(view.world(), head.last_sequence)
            .expect("durable event reader")
            .expect("head references a persisted event");
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &head,
            "iroha_core::smartcontracts::isi::sorafs_proof_outcome::ProofOutcomeEventJournalHeadV1",
        );
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &event,
            "iroha_core::smartcontracts::isi::sorafs_proof_outcome::ProofOutcomePersistedEventV1",
        );
        let head_frame = encode_state(&head, "proof outcome head").expect("production head writer");
        assert!(matches!(
            norito::decode_canonical::<ProofOutcomePersistedEventV1>(&head_frame),
            Err(norito::Error::SchemaMismatch)
        ));
    }
    #[test]
    fn unsigned_pdp_outcome_requires_provider_scoped_scheduler_permission() {
        let manager = ed25519_keypair(0x01);
        let scheduler = ed25519_keypair(0x02);
        let relayer_a = ed25519_keypair(0x03);
        let relayer_b = ed25519_keypair(0x04);
        let pdp_key = ed25519_keypair(0x11);
        let potr_key = mldsa_keypair(0x12);
        let gateway_key = ed25519_keypair(0x13);
        let mut state = state_with_accounts(&manager, &scheduler, &relayer_a, &relayer_b);
        activate_policy(
            &mut state,
            2,
            NOW,
            &manager,
            signer_policy(1, None, &pdp_key, &potr_key, &gateway_key),
        );
        let unsigned = pdp_submission(unsigned_pdp_archive(1, 0x22));
        assert_instruction_error_contains(
            transact(&mut state, 3, NOW + 1, |state_transaction| {
                unsigned
                    .clone()
                    .execute(&account(&relayer_a), state_transaction)
            }),
            "CanRecordSorafsProofOutcome",
        );
        transact(&mut state, 3, NOW + 1, |state_transaction| {
            unsigned.execute(&account(&scheduler), state_transaction)
        })
        .expect("provider-scoped scheduler records unsigned deadline outcome");
        let page = query_events(&state, None, None, 1).expect("query scheduler outcome");
        assert_eq!(page.events.len(), 1);
        let ProofOutcomeProjectionV1::Pdp(projection) = &page.events[0].outcome.projection else {
            panic!("expected PDP projection");
        };
        assert_eq!(projection.status, PdpOutcomeStatusV1::DeadlineExpired);
        assert!(projection.proof_digest.is_none());
        assert!(projection.provider_attestation.is_none());
    }
    #[test]
    fn invalid_pdp_without_canonical_proof_prepares_and_validates() {
        let payload = pdp_archive_without_proof(1, 0x23, PdpRejectionReasonV1::InvalidProof);
        let prepared =
            prepare_pdp_outcome(&payload).expect("prepare invalid PDP without canonical proof");
        assert!(!prepared.has_provider_proof);
        let record = prepared.into_record(account(&ed25519_keypair(0x02)), (NOW + 1) * 1_000);
        validate_outcome_record(&record)
            .expect("invalid PDP without canonical proof is a valid stored projection");
        let ProofOutcomeProjectionV1::Pdp(projection) = record.projection else {
            panic!("expected PDP projection");
        };
        assert_eq!(projection.status, PdpOutcomeStatusV1::InvalidProof);
        assert!(projection.proof_digest.is_none());
        assert!(projection.provider_attestation.is_none());
    }
    #[test]
    fn proof_outcome_rejects_equivocation_non_governed_signers_and_malformed_payloads() {
        let manager = ed25519_keypair(0x01);
        let scheduler = ed25519_keypair(0x02);
        let relayer_a = ed25519_keypair(0x03);
        let relayer_b = ed25519_keypair(0x04);
        let pdp_key = ed25519_keypair(0x11);
        let potr_key = mldsa_keypair(0x12);
        let gateway_key = ed25519_keypair(0x13);
        let wrong_pdp_key = ed25519_keypair(0x21);
        let wrong_potr_key = mldsa_keypair(0x22);
        let wrong_gateway_key = ed25519_keypair(0x23);
        let mut state = state_with_accounts(&manager, &scheduler, &relayer_a, &relayer_b);
        activate_policy(
            &mut state,
            2,
            NOW,
            &manager,
            signer_policy(1, None, &pdp_key, &potr_key, &gateway_key),
        );
        let original = signed_potr_receipt(&gateway_key, &potr_key, 0x41, 40);
        transact(&mut state, 3, NOW + 1, |state_transaction| {
            potr_submission(&original).execute(&account(&relayer_a), state_transaction)
        })
        .expect("commit original PoTR outcome");
        let conflicting = signed_potr_receipt(&gateway_key, &potr_key, 0x41, 41);
        assert_instruction_error_contains(
            transact(&mut state, 4, NOW + 2, |state_transaction| {
                potr_submission(&conflicting).execute(&account(&relayer_b), state_transaction)
            }),
            "different cryptographic material",
        );
        let wrong_gateway = signed_potr_receipt(&wrong_gateway_key, &potr_key, 0x42, 40);
        assert_instruction_error_contains(
            transact(&mut state, 4, NOW + 2, |state_transaction| {
                potr_submission(&wrong_gateway).execute(&account(&relayer_b), state_transaction)
            }),
            "signers or timing",
        );
        let wrong_provider = signed_potr_receipt(&gateway_key, &wrong_potr_key, 0x43, 40);
        assert_instruction_error_contains(
            transact(&mut state, 4, NOW + 2, |state_transaction| {
                potr_submission(&wrong_provider).execute(&account(&relayer_b), state_transaction)
            }),
            "signers or timing",
        );
        let wrong_pdp = pdp_submission(signed_pdp_archive(&wrong_pdp_key, 2, 0x23));
        assert_instruction_error_contains(
            transact(&mut state, 4, NOW + 2, |state_transaction| {
                wrong_pdp.execute(&account(&relayer_b), state_transaction)
            }),
            "PDP proof signer",
        );
        assert_instruction_error_contains(
            prepare_pdp_outcome(&[0xFF]).map(|_| ()),
            "failed to decode canonical PDP governance archive",
        );
        assert_instruction_error_contains(
            prepare_potr_outcome(
                &vec![0; PROOF_OUTCOME_MAX_POTR_RECEIPT_BYTES_V1 + 1],
                ADMISSION_DIGEST,
            )
            .map(|_| ()),
            "outside",
        );
    }
    #[test]
    fn proof_signer_policy_rotates_by_revision_and_preserves_exact_replay() {
        let manager = ed25519_keypair(0x01);
        let scheduler = ed25519_keypair(0x02);
        let relayer_a = ed25519_keypair(0x03);
        let relayer_b = ed25519_keypair(0x04);
        let pdp_key_v1 = ed25519_keypair(0x11);
        let potr_key_v1 = mldsa_keypair(0x12);
        let gateway_key_v1 = ed25519_keypair(0x13);
        let pdp_key_v2 = ed25519_keypair(0x14);
        let potr_key_v2 = mldsa_keypair(0x15);
        let gateway_key_v2 = ed25519_keypair(0x16);
        let mut state = state_with_accounts(&manager, &scheduler, &relayer_a, &relayer_b);
        let first = signer_policy(1, None, &pdp_key_v1, &potr_key_v1, &gateway_key_v1);
        let first_digest = policy_digest(&first).expect("digest first signer policy");
        let historical_bytes = norito::to_bytes(&first).expect("historical signer-policy frame");
        let mut historical = blake3::Hasher::new();
        historical.update(POLICY_DIGEST_DOMAIN_V1);
        historical.update(
            &u64::try_from(historical_bytes.len())
                .expect("test frame length fits u64")
                .to_le_bytes(),
        );
        historical.update(&historical_bytes);
        assert_eq!(first_digest, *historical.finalize().as_bytes());
        assert_instruction_error_contains(
            transact(&mut state, 2, NOW, |state_transaction| {
                SetSorafsProofOutcomeSignerPolicy::new(first.clone())
                    .execute(&account(&relayer_a), state_transaction)
            }),
            "CanManageSorafsProofOutcomePolicy",
        );
        activate_policy(&mut state, 2, NOW, &manager, first);
        let old_receipt = signed_potr_receipt(&gateway_key_v1, &potr_key_v1, 0x51, 40);
        let old_submission = potr_submission(&old_receipt);
        transact(&mut state, 3, NOW + 1, |state_transaction| {
            old_submission
                .clone()
                .execute(&account(&relayer_a), state_transaction)
        })
        .expect("commit v1-key receipt");
        let skipped = signer_policy(
            3,
            Some(first_digest),
            &pdp_key_v2,
            &potr_key_v2,
            &gateway_key_v2,
        );
        assert_instruction_error_contains(
            transact(&mut state, 4, NOW + 2, |state_transaction| {
                SetSorafsProofOutcomeSignerPolicy::new(skipped)
                    .execute(&account(&manager), state_transaction)
            }),
            "revision or predecessor is stale",
        );
        let stale = signer_policy(
            2,
            Some([0xEE; 32]),
            &pdp_key_v2,
            &potr_key_v2,
            &gateway_key_v2,
        );
        assert_instruction_error_contains(
            transact(&mut state, 4, NOW + 2, |state_transaction| {
                SetSorafsProofOutcomeSignerPolicy::new(stale)
                    .execute(&account(&manager), state_transaction)
            }),
            "revision or predecessor is stale",
        );
        activate_policy(
            &mut state,
            4,
            NOW + 2,
            &manager,
            signer_policy(
                2,
                Some(first_digest),
                &pdp_key_v2,
                &potr_key_v2,
                &gateway_key_v2,
            ),
        );
        transact(&mut state, 5, NOW + 3, |state_transaction| {
            old_submission
                .clone()
                .execute(&account(&relayer_b), state_transaction)
        })
        .expect("exact cryptographic replay remains a no-op after signer rotation");
        let stale_new_receipt = signed_potr_receipt(&gateway_key_v1, &potr_key_v1, 0x52, 40);
        assert_instruction_error_contains(
            transact(&mut state, 6, NOW + 4, |state_transaction| {
                potr_submission(&stale_new_receipt).execute(&account(&relayer_b), state_transaction)
            }),
            "signers or timing",
        );
        let current_receipt = signed_potr_receipt(&gateway_key_v2, &potr_key_v2, 0x53, 40);
        transact(&mut state, 6, NOW + 4, |state_transaction| {
            potr_submission(&current_receipt).execute(&account(&relayer_b), state_transaction)
        })
        .expect("new receipt must use rotated governed keys");
        let page = query_events(&state, None, None, 8).expect("query rotated-key outcomes");
        assert_eq!(page.events.len(), 2);
        assert_eq!(page.events[0].outcome.submitted_by, account(&relayer_a));
        assert_eq!(page.events[1].outcome.submitted_by, account(&relayer_b));
    }
    #[test]
    fn proof_outcome_event_query_enforces_cursors_and_resource_budgets() {
        let manager = ed25519_keypair(0x01);
        let scheduler = ed25519_keypair(0x02);
        let relayer_a = ed25519_keypair(0x03);
        let relayer_b = ed25519_keypair(0x04);
        let pdp_key = ed25519_keypair(0x11);
        let potr_key = mldsa_keypair(0x12);
        let gateway_key = ed25519_keypair(0x13);
        let mut state = state_with_accounts(&manager, &scheduler, &relayer_a, &relayer_b);
        activate_policy(
            &mut state,
            2,
            NOW,
            &manager,
            signer_policy(1, None, &pdp_key, &potr_key, &gateway_key),
        );
        for (height, sequence, unique) in [(3, 1, 0x61), (4, 2, 0x62)] {
            let submission = pdp_submission(unsigned_pdp_archive(sequence, unique));
            transact(&mut state, height, NOW + height, |state_transaction| {
                submission.execute(&account(&scheduler), state_transaction)
            })
            .expect("commit scheduler PDP outcome");
        }
        let first = query_events(&state, None, None, 1).expect("query first event page");
        assert_eq!(first.events.len(), 1);
        assert!(first.has_more);
        let after = first.next_after.expect("continuation cursor");
        let second = query_events(&state, Some(first.finalized_cursor), Some(after), 1)
            .expect("query second event page");
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].sequence, 2);
        assert!(!second.has_more);
        assert!(second.next_after.is_none());
        let mut stale_cursor = first.finalized_cursor;
        stale_cursor.block_hash = [0xFF; 32];
        assert_eq!(
            query_events(&state, Some(stale_cursor), None, 1),
            Err(QueryExecutionFail::Expired)
        );
        assert_eq!(
            query_events(
                &state,
                None,
                Some(
                    iroha_data_model::sorafs::proof_ledger::ProofOutcomeFinalizedEventCursorV1 {
                        sequence: 99,
                        block_height: 99,
                        block_hash: [0x99; 32],
                        event_index: 0,
                    },
                ),
                1,
            ),
            Err(QueryExecutionFail::Expired)
        );
        assert!(matches!(
            query_events(&state, None, None, 0),
            Err(QueryExecutionFail::Conversion(_))
        ));
        assert!(matches!(
            query_events(
                &state,
                None,
                None,
                u32::try_from(PROOF_OUTCOME_QUERY_MAX_ITEMS_V1 + 1)
                    .expect("query cap plus one fits u32"),
            ),
            Err(QueryExecutionFail::Conversion(_))
        ));
        let mut charged = QUERY_MAX_STATE_READ_BYTES;
        assert!(charge_state_bytes(&mut charged, 1).is_err());
        let oversized_page = vec![0_u8; PROOF_OUTCOME_QUERY_MAX_EVENT_PAGE_BYTES_V1 + 1];
        assert!(ensure_page_budget(&oversized_page).is_err());
    }
    #[test]
    fn proof_outcome_lookup_is_finalized_constant_time_and_fails_closed() {
        let manager = ed25519_keypair(0x01);
        let scheduler = ed25519_keypair(0x02);
        let relayer_a = ed25519_keypair(0x03);
        let relayer_b = ed25519_keypair(0x04);
        let pdp_key = ed25519_keypair(0x11);
        let potr_key = mldsa_keypair(0x12);
        let gateway_key = ed25519_keypair(0x13);
        let mut state = state_with_accounts(&manager, &scheduler, &relayer_a, &relayer_b);
        activate_policy(
            &mut state,
            2,
            NOW,
            &manager,
            signer_policy(1, None, &pdp_key, &potr_key, &gateway_key),
        );
        let payload = unsigned_pdp_archive(1, 0x6A);
        let prepared = prepare_pdp_outcome(&payload).expect("prepare lookup fixture");
        let identity_digest = prepared.identity_digest;
        transact(&mut state, 3, NOW + 1, |state_transaction| {
            pdp_submission(payload).execute(&account(&scheduler), state_transaction)
        })
        .expect("commit proof outcome before lookup");
        let found = query_outcome(&state, ProofOutcomeKindV1::Pdp, identity_digest, None)
            .expect("lookup committed PDP outcome");
        assert_eq!(found.outcome.identity_digest, identity_digest);
        assert_eq!(found.outcome.kind(), ProofOutcomeKindV1::Pdp);
        assert_eq!(
            found.finalized_cursor,
            resolve_finalized_cursor(&state.view()).expect("resolve lookup cursor")
        );
        assert!(matches!(
            query_outcome(&state, ProofOutcomeKindV1::Pdp, [0; 32], None),
            Err(QueryExecutionFail::Conversion(message))
                if message.contains("must be non-zero")
        ));
        let mut stale_cursor = found.finalized_cursor;
        stale_cursor.block_hash = [0xFF; 32];
        assert_eq!(
            query_outcome(
                &state,
                ProofOutcomeKindV1::Pdp,
                identity_digest,
                Some(stale_cursor),
            ),
            Err(QueryExecutionFail::Expired)
        );
        let missing_identity = [0xEF; 32];
        assert_eq!(
            query_outcome(&state, ProofOutcomeKindV1::Potr, missing_identity, None,),
            Err(QueryExecutionFail::Find(FindError::SorafsProofOutcome(
                SorafsProofOutcomeFindErrorV1 {
                    kind: ProofOutcomeKindV1::Potr,
                    identity_digest: missing_identity,
                },
            )))
        );
        transact(&mut state, 4, NOW + 2, |state_transaction| {
            state_transaction.world.smart_contract_state.insert(
                outcome_key(ProofOutcomeKindV1::Pdp, identity_digest),
                vec![0xFF],
            );
            Ok(())
        })
        .expect("commit corrupt authoritative outcome fixture");
        assert!(matches!(
            query_outcome(&state, ProofOutcomeKindV1::Pdp, identity_digest, None),
            Err(QueryExecutionFail::Conversion(message))
                if message.contains("failed to decode proof-outcome record")
        ));
    }
    #[test]
    fn proof_outcome_event_query_fails_closed_on_corrupt_committed_state() {
        let manager = ed25519_keypair(0x01);
        let scheduler = ed25519_keypair(0x02);
        let relayer_a = ed25519_keypair(0x03);
        let relayer_b = ed25519_keypair(0x04);
        let pdp_key = ed25519_keypair(0x11);
        let potr_key = mldsa_keypair(0x12);
        let gateway_key = ed25519_keypair(0x13);
        let mut state = state_with_accounts(&manager, &scheduler, &relayer_a, &relayer_b);
        activate_policy(
            &mut state,
            2,
            NOW,
            &manager,
            signer_policy(1, None, &pdp_key, &potr_key, &gateway_key),
        );
        let submission = pdp_submission(unsigned_pdp_archive(1, 0x71));
        transact(&mut state, 3, NOW + 1, |state_transaction| {
            submission.execute(&account(&scheduler), state_transaction)
        })
        .expect("commit proof outcome before corruption");
        query_events(&state, None, None, 1).expect("healthy journal is queryable");
        let committed_event = read_persisted_event(state.view().world(), 1)
            .expect("read committed event")
            .expect("committed event exists");
        let committed_outcome_key = outcome_key(
            committed_event.outcome.kind(),
            committed_event.outcome.identity_digest,
        );
        let canonical_outcome = state
            .view()
            .world()
            .smart_contract_state()
            .get(&committed_outcome_key)
            .expect("authoritative outcome exists")
            .clone();
        let mut mismatched_outcome = committed_event.outcome.clone();
        mismatched_outcome.submitted_by = account(&manager);
        let mismatched_outcome = encode_state(&mismatched_outcome, "mismatched outcome fixture")
            .expect("encode valid mismatched outcome fixture");
        transact(&mut state, 4, NOW + 2, |state_transaction| {
            state_transaction
                .world
                .smart_contract_state
                .insert(committed_outcome_key.clone(), mismatched_outcome);
            Ok(())
        })
        .expect("commit mismatched authoritative outcome fixture");
        assert!(matches!(
            query_events(&state, None, None, 1),
            Err(QueryExecutionFail::Conversion(message))
                if message.contains("disagrees with authoritative state")
        ));
        transact(&mut state, 5, NOW + 3, |state_transaction| {
            state_transaction
                .world
                .smart_contract_state
                .insert(committed_outcome_key, canonical_outcome);
            Ok(())
        })
        .expect("restore canonical authoritative outcome fixture");
        transact(&mut state, 6, NOW + 4, |state_transaction| {
            state_transaction
                .world
                .smart_contract_state
                .insert(event_key(1), vec![0xFF]);
            Ok(())
        })
        .expect("commit adversarial corrupt-state fixture");
        let error = query_events(&state, None, None, 1)
            .expect_err("corrupt committed proof-outcome journal must fail closed");
        assert!(
            matches!(&error, QueryExecutionFail::Conversion(_)),
            "unexpected query error: {error}"
        );
    }
}
