//! Authoritative SoraFS proof-of-personhood issuer and registry handlers.
use super::*;
use crate::smartcontracts::isi::helpers::instruction_error_as_query_failure as query_failure;
use crate::{
    smartcontracts::ValidSingularQuery,
    state::{StateTransaction, WorldReadOnly},
};
use iroha_data_model::{
    account::{AccountController, AccountId},
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::{
            CommitSorafsPopCredentialBatch, PublishSorafsPopRevocationList,
            SetSorafsPopIssuerPolicy,
        },
    },
    query::{
        error::{FindError, QueryExecutionFail},
        sorafs::prelude::{
            FindSorafsPopAuditDigestBySequence, FindSorafsPopCommitmentRootByVersion,
            FindSorafsPopCredentialCommitmentByDigest, FindSorafsPopIssuerPolicy,
            FindSorafsPopRegistryStatus, FindSorafsPopRevocationByNonceCommitment,
            FindSorafsPopRevocationPublicationByVersion,
        },
    },
    sorafs::pop_registry::{
        POP_COMMITMENT_ROOT_PAYLOAD_MAX_BYTES_V1, POP_CREDENTIAL_COMMITMENTS_MAX_V1,
        POP_REGISTRY_AUDIT_DIGEST_DOMAIN_V1, POP_REGISTRY_PAYLOAD_DIGEST_DOMAIN_V1,
        POP_REVOCATION_LIST_PAYLOAD_MAX_BYTES_V1, PopCommitmentRootRecordV1,
        PopCredentialCommitmentBatchV1, PopCredentialCommitmentRecordV1, PopIssuerPolicyRecordV1,
        PopRegistryAuditDigestRecordV1, PopRegistryAuditEventKindV1, PopRegistryRevocationReasonV1,
        PopRegistryStatusV1, PopRevocationPublicationRecordV1, PopRevocationRecordV1,
        pop_registry_payload_digest_v1, pop_revocation_nonce_commitment_v1,
    },
};
use iroha_model_base::state_path::StatePath;
use mv::storage::StorageReadOnly;
use norito::{DecodeLimits, decode_canonical_with_limits};
use sorafs_manifest::pop_credentials::{
    POP_REVOCATION_ENTRIES_MAX_V1, PopCommitmentRootV1, PopRevocationEntryV1, PopRevocationListV1,
    PopRevocationReasonV1, verify_pop_commitment_root_signature_v1,
    verify_pop_revocation_list_signature_v1,
};
use std::{collections::BTreeMap, str::FromStr, sync::OnceLock};
const POLICY_STATE_KEY: &str = "sorafs_pop_issuer_policy_v1";
const STATUS_STATE_KEY: &str = "sorafs_pop_registry_status_v1";
const CREDENTIAL_STATE_KEY_PREFIX: &str = "sorafs_pop_credential_commitment_v1_";
const NONCE_BINDING_STATE_KEY_PREFIX: &str = "sorafs_pop_nonce_binding_v1_";
const ROOT_STATE_KEY_PREFIX: &str = "sorafs_pop_commitment_root_v1_";
const REVOCATION_PUBLICATION_STATE_KEY_PREFIX: &str = "sorafs_pop_revocation_publication_v1_";
const REVOCATION_STATE_KEY_PREFIX: &str = "sorafs_pop_revocation_v1_";
const AUDIT_STATE_KEY_PREFIX: &str = "sorafs_pop_registry_audit_v1_";
const MANAGE_PERMISSION: &str = "CanManageSorafsPopRegistry";
const OPERATE_PERMISSION: &str = "CanOperateSorafsPopIssuer";
const STATE_MAX_BYTES: usize = 1024 * 1024;
const BATCH_PAYLOAD_MAX_BYTES: usize = POP_COMMITMENT_ROOT_PAYLOAD_MAX_BYTES_V1
    + POP_REVOCATION_LIST_PAYLOAD_MAX_BYTES_V1
    + POP_CREDENTIAL_COMMITMENTS_MAX_V1 * 256;
const STATE_LIMITS: DecodeLimits = DecodeLimits::new(
    POP_REVOCATION_ENTRIES_MAX_V1,
    STATE_MAX_BYTES,
    POP_REVOCATION_ENTRIES_MAX_V1 * 16,
    STATE_MAX_BYTES * 2,
    64,
);
const BATCH_LIMITS: DecodeLimits = DecodeLimits::new(
    POP_REVOCATION_ENTRIES_MAX_V1,
    BATCH_PAYLOAD_MAX_BYTES,
    POP_REVOCATION_ENTRIES_MAX_V1 * 16,
    BATCH_PAYLOAD_MAX_BYTES * 2,
    64,
);
const ROOT_LIMITS: DecodeLimits = DecodeLimits::new(
    256,
    POP_COMMITMENT_ROOT_PAYLOAD_MAX_BYTES_V1,
    2_048,
    POP_COMMITMENT_ROOT_PAYLOAD_MAX_BYTES_V1 * 2,
    32,
);
const REVOCATION_LIMITS: DecodeLimits = DecodeLimits::new(
    POP_REVOCATION_ENTRIES_MAX_V1,
    POP_REVOCATION_LIST_PAYLOAD_MAX_BYTES_V1,
    POP_REVOCATION_ENTRIES_MAX_V1 * 8,
    POP_REVOCATION_LIST_PAYLOAD_MAX_BYTES_V1 * 2,
    32,
);
#[derive(
    Clone, Debug, norito::NoritoSerialize, norito::NoritoDeserialize, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::smartcontracts::isi::sorafs_pop_registry::NonceBindingStateV1")]
struct NonceBindingStateV1 {
    credential_commitment: [u8; 32],
    revocation_nonce_commitment: [u8; 32],
}
fn invalid_parameter(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
        message.into(),
    ))
}
fn corrupt_state(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvariantViolation(message.into().into())
}
fn has_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &str,
) -> bool {
    if state_transaction._curr_block.is_genesis() {
        return true;
    }
    let required = iroha_data_model::permission::Permission::new(
        permission.to_owned(),
        iroha_primitives::json::Json::new(()),
    );
    let direct = state_transaction
        .world
        .account_permissions
        .get(authority)
        .is_some_and(|permissions| permissions.contains(&required));
    let role = state_transaction
        .world
        .account_roles_iter(authority)
        .filter_map(|role_id| state_transaction.world.roles.get(role_id))
        .any(|role| role.permissions().any(|candidate| candidate == &required));
    direct || role
}
fn require_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &str,
) -> Result<(), InstructionExecutionError> {
    if has_permission(state_transaction, authority, permission) {
        Ok(())
    } else {
        Err(invalid_parameter(format!(
            "permission {permission} required for authoritative SoraFS PoP registry operation"
        )))
    }
}
fn block_time_epoch(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<u64, InstructionExecutionError> {
    let now = state_transaction.block_unix_timestamp_ms() / 1_000;
    if now == 0 {
        return Err(invalid_parameter(
            "authoritative PoP registry operations require a non-zero block timestamp",
        ));
    }
    Ok(now)
}
fn policy_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| {
        StatePath::from_str(POLICY_STATE_KEY).expect("static PoP policy key is valid")
    })
}
fn status_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| {
        StatePath::from_str(STATUS_STATE_KEY).expect("static PoP status key is valid")
    })
}
fn digest_key(prefix: &str, digest: [u8; 32]) -> StatePath {
    StatePath::from_str(&format!("{prefix}{}", hex::encode(digest)))
        .expect("static PoP prefix plus lowercase hex is a valid state key")
}
fn sequence_key(prefix: &str, sequence: u64) -> StatePath {
    StatePath::from_str(&format!("{prefix}{sequence:020}"))
        .expect("static PoP prefix plus decimal sequence is a valid state key")
}
fn credential_key(commitment: [u8; 32]) -> StatePath {
    digest_key(CREDENTIAL_STATE_KEY_PREFIX, commitment)
}
fn nonce_binding_key(commitment: [u8; 32]) -> StatePath {
    digest_key(NONCE_BINDING_STATE_KEY_PREFIX, commitment)
}
fn root_key(version: u64) -> StatePath {
    sequence_key(ROOT_STATE_KEY_PREFIX, version)
}
fn revocation_publication_key(version: u64) -> StatePath {
    sequence_key(REVOCATION_PUBLICATION_STATE_KEY_PREFIX, version)
}
fn revocation_key(commitment: [u8; 32]) -> StatePath {
    digest_key(REVOCATION_STATE_KEY_PREFIX, commitment)
}
fn audit_key(sequence: u64) -> StatePath {
    sequence_key(AUDIT_STATE_KEY_PREFIX, sequence)
}
fn encode_state<T: norito::core::NoritoSerialize>(
    value: &T,
    label: &str,
) -> Result<Vec<u8>, InstructionExecutionError> {
    norito::encode_canonical(value)
        .map_err(|error| corrupt_state(format!("failed to encode {label}: {error}")))
}
fn decode_exact<T>(
    bytes: &[u8],
    limits: DecodeLimits,
    maximum: usize,
    label: &str,
    state: bool,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    decode_exact_with_current(bytes, limits, maximum, label, state, None)
}
fn decode_exact_for_current<T>(
    bytes: &[u8],
    limits: DecodeLimits,
    maximum: usize,
    label: &str,
    state: bool,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    decode_exact_with_current(bytes, limits, maximum, label, state, Some(current))
}
fn decode_exact_with_current<T>(
    bytes: &[u8],
    limits: DecodeLimits,
    maximum: usize,
    label: &str,
    state: bool,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.is_empty() || bytes.len() > maximum {
        let message = format!("{label} size {} is outside 1..={maximum}", bytes.len());
        return Err(if state {
            corrupt_state(message)
        } else {
            invalid_parameter(message)
        });
    }
    let limits = match current.as_deref() {
        Some(current) => current.decode_limits(bytes.len(), limits),
        None => {
            crate::smartcontracts::isi::query::singular_query_decode_limits(bytes.len(), limits)
        }
    }
    .map_err(InstructionExecutionError::Query)?;
    let (value, allocation_bytes) = if current.is_some() {
        let (value, usage) = norito::core::with_decode_limits_measured(limits, || {
            decode_canonical_with_limits::<T>(bytes, limits)
        });
        (value, Some(usage.total_allocated_bytes()))
    } else {
        (decode_canonical_with_limits::<T>(bytes, limits), None)
    };
    let value = value.map_err(|error| {
        if crate::smartcontracts::isi::query::singular_query_limits_active()
            && error.is_decode_resource_limit()
        {
            return InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit);
        }
        let message = if matches!(&error, norito::Error::NonCanonicalEncoding) {
            format!("{label} is not exact canonical Norito")
        } else {
            format!("failed to decode {label}: {error}")
        };
        if state {
            corrupt_state(message)
        } else {
            invalid_parameter(message)
        }
    })?;
    if let (Some(current), Some(allocation_bytes)) = (current, allocation_bytes) {
        current
            .add_nested(allocation_bytes)
            .map_err(InstructionExecutionError::Query)?;
    }
    Ok(value)
}
fn decode_state<T>(bytes: &[u8], label: &str) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    decode_exact(bytes, STATE_LIMITS, STATE_MAX_BYTES, label, true)
}
fn decode_state_for_current<T>(
    bytes: &[u8],
    label: &str,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    decode_exact_for_current(bytes, STATE_LIMITS, STATE_MAX_BYTES, label, true, current)
}
fn decode_root_payload(
    bytes: &[u8],
    state: bool,
) -> Result<PopCommitmentRootV1, InstructionExecutionError> {
    decode_exact(
        bytes,
        ROOT_LIMITS,
        POP_COMMITMENT_ROOT_PAYLOAD_MAX_BYTES_V1,
        "PoP commitment-root payload",
        state,
    )
}
fn decode_root_payload_for_current(
    bytes: &[u8],
    state: bool,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<PopCommitmentRootV1, InstructionExecutionError> {
    decode_exact_for_current(
        bytes,
        ROOT_LIMITS,
        POP_COMMITMENT_ROOT_PAYLOAD_MAX_BYTES_V1,
        "PoP commitment-root payload",
        state,
        current,
    )
}
fn decode_revocation_payload(
    bytes: &[u8],
    state: bool,
) -> Result<PopRevocationListV1, InstructionExecutionError> {
    decode_exact(
        bytes,
        REVOCATION_LIMITS,
        POP_REVOCATION_LIST_PAYLOAD_MAX_BYTES_V1,
        "PoP revocation-list payload",
        state,
    )
}
fn decode_revocation_payload_for_current(
    bytes: &[u8],
    state: bool,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<PopRevocationListV1, InstructionExecutionError> {
    decode_exact_for_current(
        bytes,
        REVOCATION_LIMITS,
        POP_REVOCATION_LIST_PAYLOAD_MAX_BYTES_V1,
        "PoP revocation-list payload",
        state,
        current,
    )
}
fn pop_query_current(
    resident_bytes: usize,
) -> Result<
    crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
    InstructionExecutionError,
> {
    crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(resident_bytes)
        .map_err(InstructionExecutionError::Query)
}
fn reset_pop_query_current(
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
    resident_bytes: usize,
) -> Result<(), InstructionExecutionError> {
    *current = pop_query_current(resident_bytes)?;
    Ok(())
}
struct PopRegistryDigestWriter<'a>(&'a mut blake3::Hasher);
impl std::io::Write for PopRegistryDigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn canonical_registry_payload_digest<T: norito::core::NoritoSerialize>(
    value: &T,
    label: &str,
) -> Result<[u8; 32], InstructionExecutionError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(POP_REGISTRY_PAYLOAD_DIGEST_DOMAIN_V1);
    norito::core::write_canonical_to_writer(value, &mut PopRegistryDigestWriter(&mut hasher))
        .map_err(|error| corrupt_state(format!("failed to encode stored {label}: {error}")))?;
    Ok(*hasher.finalize().as_bytes())
}
fn read_policy(
    world: &impl WorldReadOnly,
) -> Result<Option<PopIssuerPolicyRecordV1>, InstructionExecutionError> {
    read_policy_with_current(world, None)
}
fn read_policy_for_current(
    world: &impl WorldReadOnly,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<PopIssuerPolicyRecordV1>, InstructionExecutionError> {
    read_policy_with_current(world, Some(current))
}
fn read_policy_with_current(
    world: &impl WorldReadOnly,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<PopIssuerPolicyRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(policy_key()) else {
        return Ok(None);
    };
    let record: PopIssuerPolicyRecordV1 = match current.as_deref_mut() {
        Some(current) => decode_state_for_current(bytes, "PoP issuer policy", current)?,
        None => decode_state(bytes, "PoP issuer policy")?,
    };
    record
        .policy
        .validate()
        .map_err(|error| corrupt_state(format!("invalid stored PoP issuer policy: {error}")))?;
    let expected = record
        .policy
        .digest()
        .map_err(|error| corrupt_state(format!("failed to digest stored PoP policy: {error}")))?;
    if expected != record.policy_digest || record.activated_at_epoch == 0 {
        return Err(corrupt_state(
            "stored PoP issuer policy digest or activation timestamp is invalid",
        ));
    }
    let policy_payload_digest = canonical_registry_payload_digest(&record.policy, "PoP policy")?;
    let mut audit_current = current
        .as_deref()
        .map(|current| pop_query_current(current.resident_bytes()))
        .transpose()?;
    validate_audit_binding_with_current(
        world,
        record.audit_sequence,
        record.audit_digest,
        &[PopRegistryAuditEventKindV1::PolicyActivated],
        &record.activated_by,
        record.activated_at_epoch,
        Some(policy_payload_digest),
        audit_current.as_mut(),
    )?;
    Ok(Some(record))
}
pub(super) fn read_status(
    world: &impl WorldReadOnly,
) -> Result<Option<PopRegistryStatusV1>, InstructionExecutionError> {
    read_status_with_current(world, None)
}
fn read_status_for_current(
    world: &impl WorldReadOnly,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<PopRegistryStatusV1>, InstructionExecutionError> {
    read_status_with_current(world, Some(current))
}
fn read_status_with_current(
    world: &impl WorldReadOnly,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<PopRegistryStatusV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(status_key()) else {
        return Ok(None);
    };
    let status: PopRegistryStatusV1 = match current.as_deref_mut() {
        Some(current) => decode_state_for_current(bytes, "PoP registry status", current)?,
        None => decode_state(bytes, "PoP registry status")?,
    };
    let initial = status.active_root_digest.is_none()
        && status.active_tree_version == 0
        && status.active_revocation_list_version == 0
        && status.active_revocation_root.is_none()
        && status.credential_commitment_count == 0
        && status.revoked_credential_count == 0;
    let active = status.active_root_digest.is_some()
        && status.active_tree_version > 0
        && status.active_revocation_list_version > 0
        && status.active_revocation_root.is_some()
        && status.credential_commitment_count > 0
        && status.revoked_credential_count <= status.credential_commitment_count;
    if (!initial && !active)
        || status.audit_sequence == 0
        || status.audit_head.is_none()
        || status.updated_at_epoch == 0
    {
        return Err(corrupt_state("stored PoP registry status is inconsistent"));
    }
    let mut audit_current = current
        .as_deref()
        .map(|current| pop_query_current(current.resident_bytes()))
        .transpose()?;
    let audit = read_audit_with_current(world, status.audit_sequence, audit_current.as_mut())?
        .ok_or_else(|| corrupt_state("PoP registry status audit head record is missing"))?;
    if Some(audit.audit_digest) != status.audit_head
        || audit.recorded_at_epoch != status.updated_at_epoch
    {
        return Err(corrupt_state(
            "PoP registry status does not match its audit head",
        ));
    }
    drop(audit);
    if active {
        let mut root_current = current
            .as_deref()
            .map(|current| pop_query_current(current.resident_bytes()))
            .transpose()?;
        let root =
            read_root_with_current(world, status.active_tree_version, root_current.as_mut())?
                .ok_or_else(|| {
                    corrupt_state("PoP registry status active root record is missing")
                })?;
        let root_digest = root.root_digest;
        if Some(root_digest) != status.active_root_digest {
            return Err(corrupt_state(
                "PoP registry status active root anchor is inconsistent",
            ));
        }
        drop(root);
        let mut publication_current = current
            .as_deref()
            .map(|current| pop_query_current(current.resident_bytes()))
            .transpose()?;
        let revocations = read_revocation_publication_with_current(
            world,
            status.active_revocation_list_version,
            publication_current.as_mut(),
        )?
        .ok_or_else(|| {
            corrupt_state("PoP registry status active revocation publication is missing")
        })?;
        if revocations.commitment_root != root_digest
            || Some(revocations.revocation_root) != status.active_revocation_root
        {
            return Err(corrupt_state(
                "PoP registry status active root/revocation anchors are inconsistent",
            ));
        }
    }
    Ok(Some(status))
}
/// Fully validated active PoP publications used by privacy-preserving consumers.
pub(super) struct ActivePopPublicationsV1 {
    pub(super) status: PopRegistryStatusV1,
    pub(super) issuer_policy_digest: [u8; 32],
    pub(super) root: PopCommitmentRootV1,
    pub(super) revocations: PopRevocationListV1,
}
/// Fully validated historical publications fixed by an admitted moderation appeal.
///
/// Registry advancement must not rewrite the eligibility snapshot of an already-admitted appeal.
/// The audit link and publication records remain consensus-owned, so consumers can validate the
/// exact historical root/list pair without requiring it to remain the active pair.
pub(super) struct PinnedPopPublicationsV1 {
    pub(super) root: PopCommitmentRootV1,
    pub(super) revocations: PopRevocationListV1,
}
/// Load a historical root/list/audit tuple exactly as captured by an appeal.
pub(super) fn read_pinned_publications(
    world: &impl WorldReadOnly,
    issuer_policy_digest: [u8; 32],
    commitment_root: [u8; 32],
    commitment_tree_version: u64,
    revocation_root: [u8; 32],
    revocation_list_version: u64,
    registry_audit_sequence: u64,
    registry_audit_head: [u8; 32],
) -> Result<PinnedPopPublicationsV1, InstructionExecutionError> {
    let current_policy = read_policy(world)?
        .ok_or_else(|| corrupt_state("pinned PoP publications have no issuer policy"))?;
    if current_policy.policy.paused {
        return Err(invalid_parameter(
            "active PoP issuer policy is paused for moderation eligibility",
        ));
    }
    let status = read_status(world)?
        .ok_or_else(|| corrupt_state("pinned PoP publications have no registry status"))?;
    if status.audit_sequence < registry_audit_sequence {
        return Err(corrupt_state(
            "pinned PoP audit sequence is later than the registry head",
        ));
    }
    let audit = read_audit(world, registry_audit_sequence)?
        .ok_or_else(|| corrupt_state("pinned PoP registry audit link is missing"))?;
    if audit.audit_digest != registry_audit_head {
        return Err(corrupt_state(
            "pinned PoP registry audit digest does not match its historical link",
        ));
    }
    let root_record = read_root(world, commitment_tree_version)?
        .ok_or_else(|| corrupt_state("pinned PoP commitment-root record is missing"))?;
    let revocation_record = read_revocation_publication(world, revocation_list_version)?
        .ok_or_else(|| corrupt_state("pinned PoP revocation publication is missing"))?;
    if root_record.root_digest != commitment_root
        || root_record.admitted_policy_digest != issuer_policy_digest
        || revocation_record.commitment_root != commitment_root
        || revocation_record.revocation_root != revocation_root
        || revocation_record.admitted_policy_digest != issuer_policy_digest
        || root_record.audit_sequence > registry_audit_sequence
        || revocation_record.audit_sequence > registry_audit_sequence
    {
        return Err(corrupt_state(
            "pinned PoP root/list records disagree with the admitted snapshot",
        ));
    }
    let root = decode_root_payload(&root_record.canonical_root_payload, true)?;
    let revocations =
        decode_revocation_payload(&revocation_record.canonical_revocation_list_payload, true)?;
    Ok(PinnedPopPublicationsV1 { root, revocations })
}
/// Load the exact signed active PoP root and revocation snapshot.
pub(super) fn read_active_publications(
    world: &impl WorldReadOnly,
) -> Result<Option<ActivePopPublicationsV1>, InstructionExecutionError> {
    let Some(status) = read_status(world)? else {
        return Ok(None);
    };
    let (Some(root_digest), Some(revocation_root)) =
        (status.active_root_digest, status.active_revocation_root)
    else {
        return Ok(None);
    };
    let policy = read_policy(world)?
        .ok_or_else(|| corrupt_state("active PoP publications exist without issuer policy"))?;
    if policy.policy.paused {
        return Err(invalid_parameter(
            "active PoP issuer policy is paused for moderation eligibility",
        ));
    }
    let root_record = read_root(world, status.active_tree_version)?
        .ok_or_else(|| corrupt_state("active PoP commitment-root record is missing"))?;
    let revocation_record =
        read_revocation_publication(world, status.active_revocation_list_version)?
            .ok_or_else(|| corrupt_state("active PoP revocation publication is missing"))?;
    if root_record.root_digest != root_digest
        || revocation_record.commitment_root != root_digest
        || revocation_record.revocation_root != revocation_root
        || root_record.admitted_policy_digest != policy.policy_digest
        || revocation_record.admitted_policy_digest != policy.policy_digest
    {
        return Err(corrupt_state(
            "active PoP publications do not match current registry anchors and issuer policy",
        ));
    }
    let root = decode_root_payload(&root_record.canonical_root_payload, true)?;
    let revocations =
        decode_revocation_payload(&revocation_record.canonical_revocation_list_payload, true)?;
    Ok(Some(ActivePopPublicationsV1 {
        status,
        issuer_policy_digest: policy.policy_digest,
        root,
        revocations,
    }))
}
fn read_credential(
    world: &impl WorldReadOnly,
    commitment: [u8; 32],
) -> Result<Option<PopCredentialCommitmentRecordV1>, InstructionExecutionError> {
    read_credential_with_current(world, commitment, None)
}
fn read_credential_for_current(
    world: &impl WorldReadOnly,
    commitment: [u8; 32],
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<PopCredentialCommitmentRecordV1>, InstructionExecutionError> {
    read_credential_with_current(world, commitment, Some(current))
}
fn read_credential_with_current(
    world: &impl WorldReadOnly,
    commitment: [u8; 32],
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<PopCredentialCommitmentRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&credential_key(commitment))
    else {
        return Ok(None);
    };
    let record: PopCredentialCommitmentRecordV1 = match current.as_deref_mut() {
        Some(current) => decode_state_for_current(bytes, "PoP credential commitment", current)?,
        None => decode_state(bytes, "PoP credential commitment")?,
    };
    record.commitment.validate().map_err(|error| {
        corrupt_state(format!("invalid stored PoP credential commitment: {error}"))
    })?;
    if record.commitment.credential_commitment != commitment
        || record.committed_at_epoch == 0
        || record.admitted_policy_digest == [0; 32]
        || record.audit_sequence == 0
        || record.audit_digest == [0; 32]
    {
        return Err(corrupt_state(
            "stored PoP credential commitment key or provenance is invalid",
        ));
    }
    let mut audit_current = current
        .as_deref()
        .map(|current| pop_query_current(current.resident_bytes()))
        .transpose()?;
    validate_audit_binding_with_current(
        world,
        record.audit_sequence,
        record.audit_digest,
        &[PopRegistryAuditEventKindV1::CredentialBatchCommitted],
        &record.committed_by,
        record.committed_at_epoch,
        None,
        audit_current.as_mut(),
    )?;
    Ok(Some(record))
}
fn read_nonce_binding(
    world: &impl WorldReadOnly,
    nonce_commitment: [u8; 32],
) -> Result<Option<NonceBindingStateV1>, InstructionExecutionError> {
    read_nonce_binding_with_current(world, nonce_commitment, None)
}
fn read_nonce_binding_with_current(
    world: &impl WorldReadOnly,
    nonce_commitment: [u8; 32],
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<NonceBindingStateV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&nonce_binding_key(nonce_commitment))
    else {
        return Ok(None);
    };
    let binding: NonceBindingStateV1 = match current {
        Some(current) => decode_state_for_current(bytes, "PoP nonce binding", current)?,
        None => decode_state(bytes, "PoP nonce binding")?,
    };
    if binding.revocation_nonce_commitment != nonce_commitment
        || binding.credential_commitment == [0; 32]
    {
        return Err(corrupt_state("stored PoP nonce binding is invalid"));
    }
    Ok(Some(binding))
}
fn read_root(
    world: &impl WorldReadOnly,
    version: u64,
) -> Result<Option<PopCommitmentRootRecordV1>, InstructionExecutionError> {
    read_root_with_current(world, version, None)
}
fn read_root_for_current(
    world: &impl WorldReadOnly,
    version: u64,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<PopCommitmentRootRecordV1>, InstructionExecutionError> {
    read_root_with_current(world, version, Some(current))
}
fn read_root_with_current(
    world: &impl WorldReadOnly,
    version: u64,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<PopCommitmentRootRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(&root_key(version)) else {
        return Ok(None);
    };
    let record: PopCommitmentRootRecordV1 = match current.as_deref_mut() {
        Some(current) => decode_state_for_current(bytes, "PoP root publication", current)?,
        None => decode_state(bytes, "PoP root publication")?,
    };
    let record_resident_bytes = current.as_deref().map(|current| current.resident_bytes());
    let root = match current.as_deref_mut() {
        Some(current) => {
            decode_root_payload_for_current(&record.canonical_root_payload, true, current)?
        }
        None => decode_root_payload(&record.canonical_root_payload, true)?,
    };
    verify_pop_commitment_root_signature_v1(&root).map_err(|error| {
        corrupt_state(format!(
            "invalid stored signed PoP commitment root: {error}"
        ))
    })?;
    if record.tree_version != version
        || record.tree_version != root.tree_version
        || record.root_digest != root.root_digest
        || record.tree_size != root.tree_size
        || record.recorded_at_epoch == 0
        || record.admitted_policy_digest == [0; 32]
        || record.audit_sequence == 0
        || record.audit_digest == [0; 32]
    {
        return Err(corrupt_state(
            "stored PoP commitment-root record is inconsistent",
        ));
    }
    drop(root);
    if let (Some(current), Some(record_resident_bytes)) =
        (current.as_deref_mut(), record_resident_bytes)
    {
        reset_pop_query_current(current, record_resident_bytes)?;
    }
    let mut audit_current = current
        .as_deref()
        .map(|current| pop_query_current(current.resident_bytes()))
        .transpose()?;
    validate_audit_binding_with_current(
        world,
        record.audit_sequence,
        record.audit_digest,
        &[PopRegistryAuditEventKindV1::CredentialBatchCommitted],
        &record.recorded_by,
        record.recorded_at_epoch,
        None,
        audit_current.as_mut(),
    )?;
    Ok(Some(record))
}
fn read_revocation_publication(
    world: &impl WorldReadOnly,
    version: u64,
) -> Result<Option<PopRevocationPublicationRecordV1>, InstructionExecutionError> {
    read_revocation_publication_with_current(world, version, None)
}
fn read_revocation_publication_for_current(
    world: &impl WorldReadOnly,
    version: u64,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<PopRevocationPublicationRecordV1>, InstructionExecutionError> {
    read_revocation_publication_with_current(world, version, Some(current))
}
fn read_revocation_publication_with_current(
    world: &impl WorldReadOnly,
    version: u64,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<PopRevocationPublicationRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&revocation_publication_key(version))
    else {
        return Ok(None);
    };
    let record: PopRevocationPublicationRecordV1 = match current.as_deref_mut() {
        Some(current) => decode_state_for_current(bytes, "PoP revocation publication", current)?,
        None => decode_state(bytes, "PoP revocation publication")?,
    };
    let record_resident_bytes = current.as_deref().map(|current| current.resident_bytes());
    let publication = match current.as_deref_mut() {
        Some(current) => decode_revocation_payload_for_current(
            &record.canonical_revocation_list_payload,
            true,
            current,
        )?,
        None => decode_revocation_payload(&record.canonical_revocation_list_payload, true)?,
    };
    verify_pop_revocation_list_signature_v1(&publication).map_err(|error| {
        corrupt_state(format!(
            "invalid stored signed PoP revocation list: {error}"
        ))
    })?;
    if record.list_version != version
        || record.list_version != publication.list_version
        || record.commitment_root != publication.commitment_root
        || record.revocation_root != publication.revocation_root
        || usize::try_from(record.entry_count).ok() != Some(publication.entries.len())
        || record.recorded_at_epoch == 0
        || record.admitted_policy_digest == [0; 32]
        || record.audit_sequence == 0
        || record.audit_digest == [0; 32]
    {
        return Err(corrupt_state(
            "stored PoP revocation publication is inconsistent",
        ));
    }
    drop(publication);
    if let (Some(current), Some(record_resident_bytes)) =
        (current.as_deref_mut(), record_resident_bytes)
    {
        reset_pop_query_current(current, record_resident_bytes)?;
    }
    let mut audit_current = current
        .as_deref()
        .map(|current| pop_query_current(current.resident_bytes()))
        .transpose()?;
    validate_audit_binding_with_current(
        world,
        record.audit_sequence,
        record.audit_digest,
        &[
            PopRegistryAuditEventKindV1::CredentialBatchCommitted,
            PopRegistryAuditEventKindV1::RevocationListPublished,
        ],
        &record.recorded_by,
        record.recorded_at_epoch,
        None,
        audit_current.as_mut(),
    )?;
    Ok(Some(record))
}
fn read_revocation_record_with_current(
    world: &impl WorldReadOnly,
    nonce_commitment: [u8; 32],
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<PopRevocationRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&revocation_key(nonce_commitment))
    else {
        return Ok(None);
    };
    let record: PopRevocationRecordV1 = match current {
        Some(current) => decode_state_for_current(bytes, "PoP revocation record", current)?,
        None => decode_state(bytes, "PoP revocation record")?,
    };
    if record.revocation_nonce_commitment != nonce_commitment
        || record.credential_commitment == [0; 32]
        || record.list_version == 0
        || record.commitment_root == [0; 32]
        || record.revoked_at_epoch == 0
        || record.recorded_at_epoch == 0
        || record.admitted_policy_digest == [0; 32]
        || record.audit_sequence == 0
        || record.audit_digest == [0; 32]
    {
        return Err(corrupt_state("stored PoP revocation record is invalid"));
    }
    Ok(Some(record))
}
fn read_revocation(
    world: &impl WorldReadOnly,
    nonce_commitment: [u8; 32],
) -> Result<Option<PopRevocationRecordV1>, InstructionExecutionError> {
    read_revocation_with_current(world, nonce_commitment, None)
}
fn read_revocation_for_current(
    world: &impl WorldReadOnly,
    nonce_commitment: [u8; 32],
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<PopRevocationRecordV1>, InstructionExecutionError> {
    read_revocation_with_current(world, nonce_commitment, Some(current))
}
fn read_revocation_with_current(
    world: &impl WorldReadOnly,
    nonce_commitment: [u8; 32],
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<PopRevocationRecordV1>, InstructionExecutionError> {
    let retained_base_bytes = current
        .as_deref()
        .map_or(0, |current| current.resident_bytes());
    let Some(record) =
        read_revocation_record_with_current(world, nonce_commitment, current.as_deref_mut())?
    else {
        return Ok(None);
    };
    let mut audit_current = current
        .as_deref()
        .map(|current| pop_query_current(current.resident_bytes()))
        .transpose()?;
    validate_audit_binding_with_current(
        world,
        record.audit_sequence,
        record.audit_digest,
        &[PopRegistryAuditEventKindV1::RevocationListPublished],
        &record.recorded_by,
        record.recorded_at_epoch,
        None,
        audit_current.as_mut(),
    )?;
    let credential_commitment = record.credential_commitment;
    let list_version = record.list_version;
    let commitment_root = record.commitment_root;
    let revoked_at_epoch = record.revoked_at_epoch;
    let reason = record.reason;
    drop(record);
    if let Some(current) = current.as_deref_mut() {
        reset_pop_query_current(current, retained_base_bytes)?;
    }
    let publication =
        read_revocation_publication_with_current(world, list_version, current.as_deref_mut())?
            .ok_or_else(|| corrupt_state("PoP revocation record publication is missing"))?;
    if publication.commitment_root != commitment_root {
        return Err(corrupt_state(
            "PoP revocation record commitment-root binding is invalid",
        ));
    }
    let payload = match current.as_deref_mut() {
        Some(current) => decode_revocation_payload_for_current(
            &publication.canonical_revocation_list_payload,
            true,
            current,
        )?,
        None => decode_revocation_payload(&publication.canonical_revocation_list_payload, true)?,
    };
    let entry_matches = payload
        .entries
        .iter()
        .find(|entry| pop_revocation_nonce_commitment_v1(entry.nonce) == nonce_commitment)
        .map(|entry| {
            entry.revoked_at_epoch == revoked_at_epoch && revocation_reason(entry.reason) == reason
        })
        .ok_or_else(|| {
            corrupt_state("PoP revocation record nonce is absent from its signed publication")
        })?;
    drop(payload);
    drop(publication);
    if let Some(current) = current.as_deref_mut() {
        reset_pop_query_current(current, retained_base_bytes)?;
    }
    if !entry_matches {
        return Err(corrupt_state(
            "PoP revocation record disagrees with its signed publication",
        ));
    }
    let binding = read_nonce_binding_with_current(world, nonce_commitment, current.as_deref_mut())?
        .ok_or_else(|| corrupt_state("PoP revocation record nonce binding is missing"))?;
    if binding.credential_commitment != credential_commitment {
        return Err(corrupt_state(
            "PoP revocation record credential binding is invalid",
        ));
    }
    if let Some(current) = current.as_deref_mut() {
        reset_pop_query_current(current, retained_base_bytes)?;
    }
    let credential =
        read_credential_with_current(world, credential_commitment, current.as_deref_mut())?
            .ok_or_else(|| corrupt_state("PoP revocation record credential is missing"))?;
    if credential.commitment.revocation_nonce_commitment != nonce_commitment {
        return Err(corrupt_state(
            "PoP revocation record disagrees with credential nonce commitment",
        ));
    }
    drop(credential);
    if let Some(current) = current.as_deref_mut() {
        reset_pop_query_current(current, retained_base_bytes)?;
    }
    let record = read_revocation_record_with_current(world, nonce_commitment, current)?
        .ok_or_else(|| corrupt_state("PoP revocation record disappeared during validation"))?;
    if record.credential_commitment != credential_commitment
        || record.list_version != list_version
        || record.commitment_root != commitment_root
        || record.revoked_at_epoch != revoked_at_epoch
        || record.reason != reason
    {
        return Err(corrupt_state(
            "PoP revocation record changed during bounded validation",
        ));
    }
    Ok(Some(record))
}
fn audit_digest(
    sequence: u64,
    kind: PopRegistryAuditEventKindV1,
    payload_digest: [u8; 32],
    previous: Option<[u8; 32]>,
    now: u64,
    authority: &AccountId,
) -> [u8; 32] {
    audit_digest_with_current(
        sequence,
        kind,
        payload_digest,
        previous,
        now,
        authority,
        None,
    )
    .expect("valid PoP audit authorities have a canonical I105 representation")
}
fn audit_digest_for_current(
    sequence: u64,
    kind: PopRegistryAuditEventKindV1,
    payload_digest: [u8; 32],
    previous: Option<[u8; 32]>,
    now: u64,
    authority: &AccountId,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<[u8; 32], InstructionExecutionError> {
    audit_digest_with_current(
        sequence,
        kind,
        payload_digest,
        previous,
        now,
        authority,
        Some(current),
    )
}
fn audit_digest_with_current(
    sequence: u64,
    kind: PopRegistryAuditEventKindV1,
    payload_digest: [u8; 32],
    previous: Option<[u8; 32]>,
    now: u64,
    authority: &AccountId,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<[u8; 32], InstructionExecutionError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(POP_REGISTRY_AUDIT_DIGEST_DOMAIN_V1);
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&[kind.digest_tag()]);
    hasher.update(&[u8::from(previous.is_some())]);
    hasher.update(&previous.unwrap_or([0; 32]));
    hasher.update(&payload_digest);
    hasher.update(&now.to_le_bytes());
    hash_canonical_account_i105(&mut hasher, authority, current)?;
    Ok(*hasher.finalize().as_bytes())
}
fn hash_canonical_account_i105(
    hasher: &mut blake3::Hasher,
    authority: &AccountId,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<(), InstructionExecutionError> {
    let canonical_len = pop_account_address_len(authority)?;
    let maximum_digits = canonical_len
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or_else(|| corrupt_state("PoP audit authority I105 scratch length overflow"))?;
    let scratch_bytes = canonical_len
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(maximum_digits))
        .ok_or_else(|| corrupt_state("PoP audit authority I105 scratch allocation overflow"))?;
    if let Some(current) = current {
        current
            .add_nested(scratch_bytes)
            .map_err(InstructionExecutionError::Query)?;
    }
    let mut canonical = Vec::new();
    canonical
        .try_reserve_exact(canonical_len)
        .map_err(|_| InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit))?;
    encode_pop_account_address(authority, &mut canonical)?;
    if canonical.len() != canonical_len {
        return Err(corrupt_state(
            "PoP audit authority canonical address length changed during encoding",
        ));
    }
    let checksum = iroha_data_model::account::address::i105_checksum_digits(&canonical);
    let digits = pop_encode_base105(&canonical, maximum_digits)?;
    let discriminant = iroha_data_model::account::address::chain_discriminant();
    let mut numeric_sentinel = [0_u8; 6];
    let sentinel = iroha_data_model::account::address::write_i105_sentinel(
        discriminant,
        &mut numeric_sentinel,
    );
    let symbol_bytes = digits.iter().chain(checksum.iter()).try_fold(
        0_usize,
        |bytes, digit| -> Result<usize, InstructionExecutionError> {
            bytes
                .checked_add(pop_i105_symbol(*digit)?.len())
                .ok_or_else(|| corrupt_state("PoP audit authority I105 length overflow"))
        },
    )?;
    let authority_len = sentinel
        .len()
        .checked_add(symbol_bytes)
        .ok_or_else(|| corrupt_state("PoP audit authority I105 length overflow"))?;
    hasher.update(
        &u64::try_from(authority_len)
            .map_err(|_| corrupt_state("PoP audit authority I105 length does not fit u64"))?
            .to_le_bytes(),
    );
    hasher.update(sentinel);
    for digit in digits.iter().chain(checksum.iter()) {
        hasher.update(pop_i105_symbol(*digit)?.as_bytes());
    }
    Ok(())
}
fn pop_account_address_len(authority: &AccountId) -> Result<usize, InstructionExecutionError> {
    let controller_bytes = match authority.controller() {
        AccountController::Single(key) => {
            let (_, payload) = key.try_to_bytes().map_err(|error| {
                corrupt_state(format!("invalid PoP audit authority public key: {error}"))
            })?;
            let length_prefix = if u8::try_from(payload.len()).is_ok() {
                3
            } else {
                u16::try_from(payload.len()).map_err(|_| {
                    corrupt_state("PoP audit authority public-key payload is too long")
                })?;
                4
            };
            length_prefix + payload.len()
        }
        AccountController::Multisig(policy) => {
            u16::try_from(policy.members().len())
                .map_err(|_| corrupt_state("PoP audit authority has too many multisig members"))?;
            policy.members().iter().try_fold(6_usize, |bytes, member| {
                let (_, payload) = member.public_key().try_to_bytes().map_err(|error| {
                    corrupt_state(format!(
                        "invalid PoP audit authority multisig public key: {error}"
                    ))
                })?;
                u16::try_from(payload.len()).map_err(|_| {
                    corrupt_state("PoP audit authority multisig public-key payload is too long")
                })?;
                bytes
                    .checked_add(5)
                    .and_then(|bytes| bytes.checked_add(payload.len()))
                    .ok_or_else(|| corrupt_state("PoP audit authority address length overflow"))
            })?
        }
    };
    controller_bytes
        .checked_add(1)
        .ok_or_else(|| corrupt_state("PoP audit authority address length overflow"))
}
fn encode_pop_account_address(
    authority: &AccountId,
    canonical: &mut Vec<u8>,
) -> Result<(), InstructionExecutionError> {
    match authority.controller() {
        AccountController::Single(key) => {
            canonical.push(0b0000_0010);
            let (algorithm, payload) = key.try_to_bytes().map_err(|error| {
                corrupt_state(format!("invalid PoP audit authority public key: {error}"))
            })?;
            if let Ok(length) = u8::try_from(payload.len()) {
                canonical.extend([0, pop_curve_id(algorithm), length]);
            } else {
                let length = u16::try_from(payload.len()).map_err(|_| {
                    corrupt_state("PoP audit authority public-key payload is too long")
                })?;
                canonical.extend([2, pop_curve_id(algorithm)]);
                canonical.extend_from_slice(&length.to_be_bytes());
            }
            canonical.extend_from_slice(payload);
        }
        AccountController::Multisig(policy) => {
            canonical.extend([0b0000_1010, 1, policy.version()]);
            canonical.extend_from_slice(&policy.threshold().to_be_bytes());
            let member_count = u16::try_from(policy.members().len())
                .map_err(|_| corrupt_state("PoP audit authority has too many multisig members"))?;
            canonical.extend_from_slice(&member_count.to_be_bytes());
            for member in policy.members() {
                let (algorithm, payload) = member.public_key().try_to_bytes().map_err(|error| {
                    corrupt_state(format!(
                        "invalid PoP audit authority multisig public key: {error}"
                    ))
                })?;
                let length = u16::try_from(payload.len()).map_err(|_| {
                    corrupt_state("PoP audit authority multisig public-key payload is too long")
                })?;
                canonical.push(pop_curve_id(algorithm));
                canonical.extend_from_slice(&member.weight().to_be_bytes());
                canonical.extend_from_slice(&length.to_be_bytes());
                canonical.extend_from_slice(payload);
            }
        }
    }
    Ok(())
}
fn pop_curve_id(algorithm: iroha_crypto::Algorithm) -> u8 {
    iroha_data_model::account::curve::CurveId::from_algorithm(algorithm).as_u8()
}
fn pop_encode_base105(
    bytes: &[u8],
    maximum_digits: usize,
) -> Result<Vec<u8>, InstructionExecutionError> {
    if bytes.is_empty() {
        return Err(corrupt_state(
            "PoP audit authority canonical address is empty",
        ));
    }
    let leading_zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
    let mut value = Vec::new();
    value
        .try_reserve_exact(bytes.len())
        .map_err(|_| InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit))?;
    value.extend_from_slice(bytes);
    let mut digits = Vec::new();
    digits
        .try_reserve_exact(maximum_digits)
        .map_err(|_| InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit))?;
    let mut start = leading_zeros;
    while start < value.len() {
        let mut remainder = 0_u32;
        for byte in &mut value[start..] {
            let accumulator = (remainder << 8) | u32::from(*byte);
            *byte = u8::try_from(accumulator / 105)
                .expect("base-105 division quotient fits in one byte");
            remainder = accumulator % 105;
        }
        digits.push(u8::try_from(remainder).expect("base-105 remainder fits in one byte"));
        while start < value.len() && value[start] == 0 {
            start += 1;
        }
    }
    digits.resize(digits.len() + leading_zeros, 0);
    if digits.is_empty() {
        digits.push(0);
    }
    digits.reverse();
    Ok(digits)
}
fn pop_i105_symbol(digit: u8) -> Result<&'static str, InstructionExecutionError> {
    iroha_data_model::account::address::i105_symbol(digit)
        .ok_or_else(|| corrupt_state("PoP audit authority has an invalid I105 digit"))
}
fn read_audit_record_with_current(
    world: &impl WorldReadOnly,
    sequence: u64,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<PopRegistryAuditDigestRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(&audit_key(sequence)) else {
        return Ok(None);
    };
    let record: PopRegistryAuditDigestRecordV1 = match current.as_deref_mut() {
        Some(current) => decode_state_for_current(bytes, "PoP registry audit link", current)?,
        None => decode_state(bytes, "PoP registry audit link")?,
    };
    let record_resident_bytes = current.as_deref().map(|current| current.resident_bytes());
    let expected = match current.as_deref_mut() {
        Some(current) => audit_digest_for_current(
            record.sequence,
            record.kind,
            record.payload_digest,
            record.previous_audit_digest,
            record.recorded_at_epoch,
            &record.recorded_by,
            current,
        )?,
        None => audit_digest(
            record.sequence,
            record.kind,
            record.payload_digest,
            record.previous_audit_digest,
            record.recorded_at_epoch,
            &record.recorded_by,
        ),
    };
    if let (Some(current), Some(record_resident_bytes)) = (current, record_resident_bytes) {
        reset_pop_query_current(current, record_resident_bytes)?;
    }
    if record.sequence != sequence
        || record.sequence == 0
        || (record.sequence == 1) != record.previous_audit_digest.is_none()
        || record.payload_digest == [0; 32]
        || record.audit_digest != expected
        || record.recorded_at_epoch == 0
    {
        return Err(corrupt_state("stored PoP registry audit link is invalid"));
    }
    Ok(Some(record))
}
fn read_audit(
    world: &impl WorldReadOnly,
    sequence: u64,
) -> Result<Option<PopRegistryAuditDigestRecordV1>, InstructionExecutionError> {
    read_audit_with_current(world, sequence, None)
}
fn read_audit_for_current(
    world: &impl WorldReadOnly,
    sequence: u64,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<PopRegistryAuditDigestRecordV1>, InstructionExecutionError> {
    read_audit_with_current(world, sequence, Some(current))
}
fn read_audit_with_current(
    world: &impl WorldReadOnly,
    sequence: u64,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<PopRegistryAuditDigestRecordV1>, InstructionExecutionError> {
    let retained_base_bytes = current
        .as_deref()
        .map_or(0, |current| current.resident_bytes());
    let Some(record) = read_audit_record_with_current(world, sequence, current.as_deref_mut())?
    else {
        return Ok(None);
    };
    if sequence == 1 {
        return Ok(Some(record));
    }
    // Retain only the fixed predecessor digest while validating the adjacent
    // audit record. Re-read the immutable current link afterwards so two
    // independently D-sized decoded records never remain resident together.
    let expected_previous_digest = record.previous_audit_digest;
    drop(record);
    if let Some(current) = current.as_deref_mut() {
        reset_pop_query_current(current, retained_base_bytes)?;
    }
    let previous_sequence = sequence - 1;
    let previous =
        read_audit_record_with_current(world, previous_sequence, current.as_deref_mut())?
            .ok_or_else(|| corrupt_state("preceding PoP registry audit link is missing"))?;
    if expected_previous_digest != Some(previous.audit_digest) {
        return Err(corrupt_state(
            "PoP registry audit chain predecessor is invalid",
        ));
    }
    drop(previous);
    if let Some(current) = current.as_deref_mut() {
        reset_pop_query_current(current, retained_base_bytes)?;
    }
    let record = read_audit_record_with_current(world, sequence, current)?
        .ok_or_else(|| corrupt_state("PoP registry audit link disappeared during validation"))?;
    if record.previous_audit_digest != expected_previous_digest {
        return Err(corrupt_state(
            "PoP registry audit link changed during predecessor validation",
        ));
    }
    Ok(Some(record))
}
#[allow(clippy::too_many_arguments)]
fn validate_audit_binding_with_current(
    world: &impl WorldReadOnly,
    sequence: u64,
    digest: [u8; 32],
    allowed_kinds: &[PopRegistryAuditEventKindV1],
    authority: &AccountId,
    recorded_at_epoch: u64,
    expected_payload_digest: Option<[u8; 32]>,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<(), InstructionExecutionError> {
    let audit = read_audit_with_current(world, sequence, current)?
        .ok_or_else(|| corrupt_state("PoP registry record audit link is missing"))?;
    if audit.audit_digest != digest
        || !allowed_kinds.contains(&audit.kind)
        || &audit.recorded_by != authority
        || audit.recorded_at_epoch != recorded_at_epoch
        || expected_payload_digest.is_some_and(|expected| audit.payload_digest != expected)
    {
        return Err(corrupt_state(
            "PoP registry record audit binding is invalid",
        ));
    }
    Ok(())
}
fn prepare_audit(
    status: &PopRegistryStatusV1,
    kind: PopRegistryAuditEventKindV1,
    payload_digest: [u8; 32],
    now: u64,
    authority: &AccountId,
) -> Result<PopRegistryAuditDigestRecordV1, InstructionExecutionError> {
    let sequence = status
        .audit_sequence
        .checked_add(1)
        .ok_or_else(|| corrupt_state("PoP registry audit sequence overflow"))?;
    let previous_audit_digest = status.audit_head;
    if (sequence == 1) != previous_audit_digest.is_none() {
        return Err(corrupt_state(
            "PoP registry audit head/sequence relationship is invalid",
        ));
    }
    Ok(PopRegistryAuditDigestRecordV1 {
        sequence,
        kind,
        payload_digest,
        previous_audit_digest,
        audit_digest: audit_digest(
            sequence,
            kind,
            payload_digest,
            previous_audit_digest,
            now,
            authority,
        ),
        recorded_at_epoch: now,
        recorded_by: authority.clone(),
    })
}
fn apply_audit(status: &mut PopRegistryStatusV1, audit: &PopRegistryAuditDigestRecordV1) {
    status.audit_sequence = audit.sequence;
    status.audit_head = Some(audit.audit_digest);
    status.updated_at_epoch = audit.recorded_at_epoch;
}
fn active_policy(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
) -> Result<(PopIssuerPolicyRecordV1, PopRegistryStatusV1, u64), InstructionExecutionError> {
    require_permission(state_transaction, authority, OPERATE_PERMISSION)?;
    let now = block_time_epoch(state_transaction)?;
    let record = read_policy(state_transaction.world())?
        .ok_or_else(|| invalid_parameter("SoraFS PoP issuer policy is not configured"))?;
    if record.activated_at_epoch > now {
        return Err(corrupt_state(
            "stored PoP issuer policy activation is later than the current block",
        ));
    }
    if &record.policy.issuer_account != authority {
        return Err(invalid_parameter(
            "transaction authority does not match the active PoP issuer account",
        ));
    }
    if record.policy.paused {
        return Err(invalid_parameter(
            "SoraFS PoP issuer publications are paused by governance",
        ));
    }
    let status = read_status(state_transaction.world())?
        .ok_or_else(|| corrupt_state("active PoP issuer policy has no registry status"))?;
    if status.updated_at_epoch > now {
        return Err(corrupt_state(
            "stored PoP registry status is later than the current block",
        ));
    }
    Ok((record, status, now))
}
fn validate_publication_identity(
    issuer_id: &str,
    public_key: &[u8],
    policy: &PopIssuerPolicyRecordV1,
    label: &str,
) -> Result<(), InstructionExecutionError> {
    if issuer_id != policy.policy.issuer_id {
        return Err(invalid_parameter(format!(
            "{label} issuer id does not match the active PoP issuer policy"
        )));
    }
    if public_key != policy.policy.issuer_public_key.as_slice() {
        return Err(invalid_parameter(format!(
            "{label} publisher key does not match the active PoP issuer policy"
        )));
    }
    Ok(())
}
fn validate_publication_time(
    published: u64,
    previous: Option<u64>,
    now: u64,
    skew: u64,
    label: &str,
) -> Result<(), InstructionExecutionError> {
    let latest = now
        .checked_add(skew)
        .ok_or_else(|| corrupt_state("PoP publication clock bound overflow"))?;
    if published > latest {
        return Err(invalid_parameter(format!(
            "{label} timestamp {published} exceeds current epoch plus policy skew {latest}"
        )));
    }
    if previous.is_some_and(|value| published < value) {
        return Err(invalid_parameter(format!(
            "{label} timestamp rolls back the preceding publication"
        )));
    }
    Ok(())
}
fn revocation_reason(reason: PopRevocationReasonV1) -> PopRegistryRevocationReasonV1 {
    match reason {
        PopRevocationReasonV1::Rotated => PopRegistryRevocationReasonV1::Rotated,
        PopRevocationReasonV1::HolderRequested => PopRegistryRevocationReasonV1::HolderRequested,
        PopRevocationReasonV1::EnrollmentInvalid => {
            PopRegistryRevocationReasonV1::EnrollmentInvalid
        }
        PopRevocationReasonV1::GovernanceSuspension => {
            PopRegistryRevocationReasonV1::GovernanceSuspension
        }
        PopRevocationReasonV1::Expired => PopRegistryRevocationReasonV1::Expired,
    }
}
impl Execute for SetSorafsPopIssuerPolicy {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        require_permission(state_transaction, authority, MANAGE_PERMISSION)?;
        self.policy
            .validate()
            .map_err(|error| invalid_parameter(format!("invalid SoraFS PoP policy: {error}")))?;
        if state_transaction
            .world
            .accounts
            .get(&self.policy.issuer_account)
            .is_none()
        {
            return Err(invalid_parameter(
                "SoraFS PoP issuer policy account is not registered",
            ));
        }
        let now = block_time_epoch(state_transaction)?;
        let digest = self.policy.digest().map_err(|error| {
            invalid_parameter(format!("failed to digest SoraFS PoP policy: {error}"))
        })?;
        let current = read_policy(state_transaction.world())?;
        let mut status = match (current.as_ref(), read_status(state_transaction.world())?) {
            (None, None) => {
                if self.policy.revision != 1 || self.policy.predecessor_policy_digest.is_some() {
                    return Err(invalid_parameter(
                        "first PoP issuer policy must be revision one without a predecessor",
                    ));
                }
                PopRegistryStatusV1::default()
            }
            (Some(current), Some(status)) => {
                let expected = current
                    .policy
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("PoP issuer policy revision overflow"))?;
                if self.policy.revision != expected {
                    return Err(invalid_parameter(format!(
                        "PoP issuer policy revision {} must exactly follow active revision {}",
                        self.policy.revision, current.policy.revision
                    )));
                }
                if self.policy.predecessor_policy_digest != Some(current.policy_digest) {
                    return Err(invalid_parameter(
                        "PoP issuer policy predecessor does not match the active policy digest",
                    ));
                }
                if self.policy.issuer_id != current.policy.issuer_id {
                    return Err(invalid_parameter(
                        "PoP issuer id is immutable after first activation",
                    ));
                }
                status
            }
            _ => {
                return Err(corrupt_state(
                    "PoP issuer policy and registry status state are inconsistent",
                ));
            }
        };
        let policy_payload = norito::encode_canonical(&self.policy).map_err(|error| {
            invalid_parameter(format!("failed to encode SoraFS PoP policy: {error}"))
        })?;
        let audit = prepare_audit(
            &status,
            PopRegistryAuditEventKindV1::PolicyActivated,
            pop_registry_payload_digest_v1(&policy_payload),
            now,
            authority,
        )?;
        apply_audit(&mut status, &audit);
        let record = PopIssuerPolicyRecordV1 {
            policy: self.policy,
            policy_digest: digest,
            activated_at_epoch: now,
            activated_by: authority.clone(),
            audit_sequence: audit.sequence,
            audit_digest: audit.audit_digest,
        };
        let encoded_policy = encode_state(&record, "PoP issuer policy")?;
        let encoded_status = encode_state(&status, "PoP registry status")?;
        let encoded_audit = encode_state(&audit, "PoP registry audit link")?;
        state_transaction
            .world
            .smart_contract_state
            .insert(policy_key().clone(), encoded_policy);
        state_transaction
            .world
            .smart_contract_state
            .insert(audit_key(audit.sequence), encoded_audit);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        Ok(())
    }
}
impl Execute for CommitSorafsPopCredentialBatch {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        if self.batch_payload.len() > BATCH_PAYLOAD_MAX_BYTES {
            return Err(invalid_parameter(format!(
                "PoP credential batch payload exceeds {BATCH_PAYLOAD_MAX_BYTES} bytes"
            )));
        }
        let batch: PopCredentialCommitmentBatchV1 = decode_exact(
            &self.batch_payload,
            BATCH_LIMITS,
            BATCH_PAYLOAD_MAX_BYTES,
            "PoP credential commitment batch",
            false,
        )?;
        batch.validate().map_err(|error| {
            invalid_parameter(format!("invalid PoP credential commitment batch: {error}"))
        })?;
        let (policy, mut status, now) = active_policy(state_transaction, authority)?;
        if batch.issuer_policy_digest != policy.policy_digest {
            return Err(invalid_parameter(
                "PoP credential batch issuer-policy digest does not match the active policy",
            ));
        }
        if batch.commitments.len() > usize::from(policy.policy.max_credentials_per_batch) {
            return Err(invalid_parameter(format!(
                "PoP credential batch contains {} entries but policy allows {}",
                batch.commitments.len(),
                policy.policy.max_credentials_per_batch
            )));
        }
        let root = decode_root_payload(&batch.commitment_root_payload, false)?;
        verify_pop_commitment_root_signature_v1(&root).map_err(|error| {
            invalid_parameter(format!("invalid signed PoP commitment root: {error}"))
        })?;
        let revocations = decode_revocation_payload(&batch.revocation_list_payload, false)?;
        verify_pop_revocation_list_signature_v1(&revocations).map_err(|error| {
            invalid_parameter(format!("invalid signed PoP revocation list: {error}"))
        })?;
        validate_publication_identity(
            &root.issuer_id,
            &root.publisher_signature.public_key,
            &policy,
            "PoP commitment root",
        )?;
        validate_publication_identity(
            &revocations.issuer_id,
            &revocations.publisher_signature.public_key,
            &policy,
            "PoP revocation list",
        )?;
        if root.published_at_epoch != revocations.published_at_epoch {
            return Err(invalid_parameter(
                "atomic PoP root and revocation publications must use the same timestamp",
            ));
        }
        if revocations.commitment_root != root.root_digest {
            return Err(invalid_parameter(
                "PoP revocation publication is not bound to the committed root",
            ));
        }
        let (previous_root_time, previous_revocation_time, previous_entries, expected_tree_size) =
            if status.active_tree_version == 0 {
                if root.tree_version != 1
                    || root.previous_root_digest.is_some()
                    || revocations.list_version != 1
                    || !revocations.entries.is_empty()
                {
                    return Err(invalid_parameter(
                        "initial PoP batch requires root/list version one, no predecessor, and an empty revocation snapshot",
                    ));
                }
                (
                    None,
                    None,
                    Vec::new(),
                    u64::try_from(batch.commitments.len()).map_err(|_| {
                        invalid_parameter("PoP credential batch size conversion failed")
                    })?,
                )
            } else {
                let current_root =
                    read_root(state_transaction.world(), status.active_tree_version)?
                        .ok_or_else(|| corrupt_state("active PoP root record is missing"))?;
                let current_root_payload =
                    decode_root_payload(&current_root.canonical_root_payload, true)?;
                let current_revocations = read_revocation_publication(
                    state_transaction.world(),
                    status.active_revocation_list_version,
                )?
                .ok_or_else(|| corrupt_state("active PoP revocation publication is missing"))?;
                let current_revocation_payload = decode_revocation_payload(
                    &current_revocations.canonical_revocation_list_payload,
                    true,
                )?;
                let expected_root_version = status
                    .active_tree_version
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("PoP tree version overflow"))?;
                let expected_list_version = status
                    .active_revocation_list_version
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("PoP revocation-list version overflow"))?;
                if root.tree_version != expected_root_version
                    || root.previous_root_digest != status.active_root_digest
                    || revocations.list_version != expected_list_version
                {
                    return Err(invalid_parameter(
                        "PoP batch publication rolls back or skips the active root/list version",
                    ));
                }
                if revocations.entries != current_revocation_payload.entries {
                    return Err(invalid_parameter(
                        "credential issuance must rebind the exact active revocation snapshot without adding, removing, or mutating entries",
                    ));
                }
                let added = u64::try_from(batch.commitments.len()).map_err(|_| {
                    invalid_parameter("PoP credential batch size conversion failed")
                })?;
                (
                    Some(current_root_payload.published_at_epoch),
                    Some(current_revocation_payload.published_at_epoch),
                    current_revocation_payload.entries,
                    current_root
                        .tree_size
                        .checked_add(added)
                        .ok_or_else(|| corrupt_state("PoP commitment-tree size overflow"))?,
                )
            };
        if root.tree_size != expected_tree_size {
            return Err(invalid_parameter(format!(
                "PoP commitment-tree size {} does not equal expected size {expected_tree_size}",
                root.tree_size
            )));
        }
        validate_publication_time(
            root.published_at_epoch,
            previous_root_time,
            now,
            policy.policy.max_future_clock_skew_secs,
            "PoP commitment root",
        )?;
        validate_publication_time(
            revocations.published_at_epoch,
            previous_revocation_time,
            now,
            policy.policy.max_future_clock_skew_secs,
            "PoP revocation list",
        )?;
        if previous_entries.len() != revocations.entries.len() {
            return Err(corrupt_state(
                "PoP revocation snapshot changed after equality validation",
            ));
        }
        for commitment in &batch.commitments {
            if commitment.commitment_root != root.root_digest
                || commitment.commitment_tree_version != root.tree_version
                || commitment.revocation_list_version != revocations.list_version
            {
                return Err(invalid_parameter(
                    "PoP credential commitment has the wrong root or publication version binding",
                ));
            }
            let lifetime = commitment
                .expires_at_epoch
                .checked_sub(commitment.issued_at_epoch)
                .ok_or_else(|| invalid_parameter("PoP credential validity window underflow"))?;
            if lifetime > policy.policy.max_credential_lifetime_secs
                || commitment.issued_at_epoch > root.published_at_epoch
                || commitment.expires_at_epoch <= root.published_at_epoch
            {
                return Err(invalid_parameter(
                    "PoP credential commitment violates the active issuance-time policy",
                ));
            }
            if read_credential(state_transaction.world(), commitment.credential_commitment)?
                .is_some()
            {
                return Err(invalid_parameter(format!(
                    "PoP credential commitment {} is already registered",
                    hex::encode(commitment.credential_commitment)
                )));
            }
            if read_nonce_binding(
                state_transaction.world(),
                commitment.revocation_nonce_commitment,
            )?
            .is_some()
            {
                return Err(invalid_parameter(
                    "PoP revocation-nonce commitment is already bound to a credential",
                ));
            }
        }
        let added = u64::try_from(batch.commitments.len())
            .map_err(|_| invalid_parameter("PoP credential batch size conversion failed"))?;
        let next_count = status
            .credential_commitment_count
            .checked_add(added)
            .ok_or_else(|| corrupt_state("PoP credential commitment counter overflow"))?;
        let audit = prepare_audit(
            &status,
            PopRegistryAuditEventKindV1::CredentialBatchCommitted,
            pop_registry_payload_digest_v1(&self.batch_payload),
            now,
            authority,
        )?;
        let mut credential_writes = Vec::with_capacity(batch.commitments.len());
        for commitment in &batch.commitments {
            let record = PopCredentialCommitmentRecordV1 {
                commitment: *commitment,
                committed_at_epoch: now,
                committed_by: authority.clone(),
                admitted_policy_digest: policy.policy_digest,
                audit_sequence: audit.sequence,
                audit_digest: audit.audit_digest,
            };
            let binding = NonceBindingStateV1 {
                credential_commitment: commitment.credential_commitment,
                revocation_nonce_commitment: commitment.revocation_nonce_commitment,
            };
            credential_writes.push((
                credential_key(commitment.credential_commitment),
                encode_state(&record, "PoP credential commitment")?,
                nonce_binding_key(commitment.revocation_nonce_commitment),
                encode_state(&binding, "PoP nonce binding")?,
            ));
        }
        let root_record = PopCommitmentRootRecordV1 {
            root_digest: root.root_digest,
            tree_version: root.tree_version,
            tree_size: root.tree_size,
            canonical_root_payload: batch.commitment_root_payload,
            recorded_at_epoch: now,
            recorded_by: authority.clone(),
            admitted_policy_digest: policy.policy_digest,
            audit_sequence: audit.sequence,
            audit_digest: audit.audit_digest,
        };
        let revocation_record = PopRevocationPublicationRecordV1 {
            list_version: revocations.list_version,
            commitment_root: revocations.commitment_root,
            revocation_root: revocations.revocation_root,
            entry_count: u32::try_from(revocations.entries.len())
                .map_err(|_| corrupt_state("PoP revocation entry count conversion failed"))?,
            canonical_revocation_list_payload: batch.revocation_list_payload,
            recorded_at_epoch: now,
            recorded_by: authority.clone(),
            admitted_policy_digest: policy.policy_digest,
            audit_sequence: audit.sequence,
            audit_digest: audit.audit_digest,
        };
        status.active_root_digest = Some(root.root_digest);
        status.active_tree_version = root.tree_version;
        status.active_revocation_list_version = revocations.list_version;
        status.active_revocation_root = Some(revocations.revocation_root);
        status.credential_commitment_count = next_count;
        apply_audit(&mut status, &audit);
        let encoded_root = encode_state(&root_record, "PoP root publication")?;
        let encoded_revocations = encode_state(&revocation_record, "PoP revocation publication")?;
        let encoded_audit = encode_state(&audit, "PoP registry audit link")?;
        let encoded_status = encode_state(&status, "PoP registry status")?;
        for (credential_key, credential, binding_key, binding) in credential_writes {
            state_transaction
                .world
                .smart_contract_state
                .insert(credential_key, credential);
            state_transaction
                .world
                .smart_contract_state
                .insert(binding_key, binding);
        }
        state_transaction
            .world
            .smart_contract_state
            .insert(root_key(root.tree_version), encoded_root);
        state_transaction.world.smart_contract_state.insert(
            revocation_publication_key(revocations.list_version),
            encoded_revocations,
        );
        state_transaction
            .world
            .smart_contract_state
            .insert(audit_key(audit.sequence), encoded_audit);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        Ok(())
    }
}
impl Execute for PublishSorafsPopRevocationList {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let publication = decode_revocation_payload(&self.revocation_list_payload, false)?;
        verify_pop_revocation_list_signature_v1(&publication).map_err(|error| {
            invalid_parameter(format!("invalid signed PoP revocation list: {error}"))
        })?;
        let operation_payload = norito::encode_canonical(&self).map_err(|error| {
            invalid_parameter(format!(
                "failed to encode PoP revocation publication instruction: {error}"
            ))
        })?;
        let (policy, mut status, now) = active_policy(state_transaction, authority)?;
        if self.issuer_policy_digest != policy.policy_digest {
            return Err(invalid_parameter(
                "PoP revocation publication issuer-policy digest does not match the active policy",
            ));
        }
        if status.active_tree_version == 0 {
            return Err(invalid_parameter(
                "PoP credentials must be committed before publishing revocations",
            ));
        }
        validate_publication_identity(
            &publication.issuer_id,
            &publication.publisher_signature.public_key,
            &policy,
            "PoP revocation list",
        )?;
        if Some(publication.commitment_root) != status.active_root_digest {
            return Err(invalid_parameter(
                "PoP revocation publication is bound to the wrong active commitment root",
            ));
        }
        let expected_version = status
            .active_revocation_list_version
            .checked_add(1)
            .ok_or_else(|| corrupt_state("PoP revocation-list version overflow"))?;
        if publication.list_version != expected_version {
            return Err(invalid_parameter(format!(
                "PoP revocation-list version {} must exactly follow active version {}",
                publication.list_version, status.active_revocation_list_version
            )));
        }
        let previous_record = read_revocation_publication(
            state_transaction.world(),
            status.active_revocation_list_version,
        )?
        .ok_or_else(|| corrupt_state("active PoP revocation publication is missing"))?;
        let previous =
            decode_revocation_payload(&previous_record.canonical_revocation_list_payload, true)?;
        validate_publication_time(
            publication.published_at_epoch,
            Some(previous.published_at_epoch),
            now,
            policy.policy.max_future_clock_skew_secs,
            "PoP revocation list",
        )?;
        let previous_by_nonce: BTreeMap<[u8; 32], PopRevocationEntryV1> = previous
            .entries
            .iter()
            .map(|entry| (entry.nonce, *entry))
            .collect();
        let current_by_nonce: BTreeMap<[u8; 32], PopRevocationEntryV1> = publication
            .entries
            .iter()
            .map(|entry| (entry.nonce, *entry))
            .collect();
        for (nonce, previous_entry) in &previous_by_nonce {
            if current_by_nonce.get(nonce) != Some(previous_entry) {
                return Err(invalid_parameter(
                    "PoP revocation publication rolls back or mutates an existing revocation",
                ));
            }
        }
        let new_entries: Vec<_> = publication
            .entries
            .iter()
            .filter(|entry| !previous_by_nonce.contains_key(&entry.nonce))
            .copied()
            .collect();
        if new_entries.is_empty() {
            return Err(invalid_parameter(
                "PoP revocation publication must add at least one new nonce",
            ));
        }
        if new_entries.len()
            > usize::try_from(policy.policy.max_revocations_per_publication)
                .map_err(|_| corrupt_state("PoP revocation policy limit conversion failed"))?
        {
            return Err(invalid_parameter(format!(
                "PoP revocation publication adds {} entries but policy allows {}",
                new_entries.len(),
                policy.policy.max_revocations_per_publication
            )));
        }
        let audit = prepare_audit(
            &status,
            PopRegistryAuditEventKindV1::RevocationListPublished,
            pop_registry_payload_digest_v1(&operation_payload),
            now,
            authority,
        )?;
        let mut revocation_writes = Vec::with_capacity(new_entries.len());
        for entry in new_entries {
            if entry.revoked_at_epoch > publication.published_at_epoch {
                return Err(invalid_parameter(
                    "PoP revocation timestamp is later than its signed publication",
                ));
            }
            let nonce_commitment = pop_revocation_nonce_commitment_v1(entry.nonce);
            let binding = read_nonce_binding(state_transaction.world(), nonce_commitment)?
                .ok_or_else(|| {
                    invalid_parameter(
                        "PoP revocation nonce is not bound to an authoritative credential commitment",
                    )
                })?;
            let credential =
                read_credential(state_transaction.world(), binding.credential_commitment)?
                    .ok_or_else(|| {
                        corrupt_state("PoP nonce binding target credential is missing")
                    })?;
            if credential.commitment.revocation_nonce_commitment != nonce_commitment {
                return Err(corrupt_state(
                    "PoP nonce binding disagrees with its credential commitment",
                ));
            }
            if entry.revoked_at_epoch < credential.commitment.issued_at_epoch {
                return Err(invalid_parameter(
                    "PoP revocation predates the bound credential issuance",
                ));
            }
            if read_revocation(state_transaction.world(), nonce_commitment)?.is_some() {
                return Err(invalid_parameter(
                    "PoP revocation nonce commitment is already revoked",
                ));
            }
            let record = PopRevocationRecordV1 {
                revocation_nonce_commitment: nonce_commitment,
                credential_commitment: binding.credential_commitment,
                list_version: publication.list_version,
                commitment_root: publication.commitment_root,
                revoked_at_epoch: entry.revoked_at_epoch,
                reason: revocation_reason(entry.reason),
                recorded_at_epoch: now,
                recorded_by: authority.clone(),
                admitted_policy_digest: policy.policy_digest,
                audit_sequence: audit.sequence,
                audit_digest: audit.audit_digest,
            };
            revocation_writes.push((
                revocation_key(nonce_commitment),
                encode_state(&record, "PoP revocation record")?,
            ));
        }
        let added = u64::try_from(revocation_writes.len())
            .map_err(|_| corrupt_state("PoP revocation count conversion failed"))?;
        status.revoked_credential_count = status
            .revoked_credential_count
            .checked_add(added)
            .ok_or_else(|| corrupt_state("PoP revoked-credential counter overflow"))?;
        if status.revoked_credential_count > status.credential_commitment_count {
            return Err(corrupt_state(
                "PoP revoked-credential counter exceeds committed credentials",
            ));
        }
        status.active_revocation_list_version = publication.list_version;
        status.active_revocation_root = Some(publication.revocation_root);
        apply_audit(&mut status, &audit);
        let publication_record = PopRevocationPublicationRecordV1 {
            list_version: publication.list_version,
            commitment_root: publication.commitment_root,
            revocation_root: publication.revocation_root,
            entry_count: u32::try_from(publication.entries.len())
                .map_err(|_| corrupt_state("PoP revocation entry count conversion failed"))?,
            canonical_revocation_list_payload: self.revocation_list_payload,
            recorded_at_epoch: now,
            recorded_by: authority.clone(),
            admitted_policy_digest: policy.policy_digest,
            audit_sequence: audit.sequence,
            audit_digest: audit.audit_digest,
        };
        let encoded_publication = encode_state(&publication_record, "PoP revocation publication")?;
        let encoded_audit = encode_state(&audit, "PoP registry audit link")?;
        let encoded_status = encode_state(&status, "PoP registry status")?;
        for (key, record) in revocation_writes {
            state_transaction
                .world
                .smart_contract_state
                .insert(key, record);
        }
        state_transaction.world.smart_contract_state.insert(
            revocation_publication_key(publication.list_version),
            encoded_publication,
        );
        state_transaction
            .world
            .smart_contract_state
            .insert(audit_key(audit.sequence), encoded_audit);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        Ok(())
    }
}
impl ValidSingularQuery for FindSorafsPopIssuerPolicy {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<PopIssuerPolicyRecordV1, QueryExecutionFail> {
        let mut current = pop_query_current(0).map_err(query_failure)?;
        read_policy_for_current(state_ro.world(), &mut current)
            .map_err(query_failure)?
            .ok_or_else(|| QueryExecutionFail::Find(FindError::SorafsPopIssuerPolicy))
    }
}
impl ValidSingularQuery for FindSorafsPopCredentialCommitmentByDigest {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<PopCredentialCommitmentRecordV1, QueryExecutionFail> {
        let mut current = pop_query_current(0).map_err(query_failure)?;
        read_credential_for_current(state_ro.world(), self.credential_commitment, &mut current)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Find(FindError::SorafsPopCredentialCommitment(
                    self.credential_commitment,
                ))
            })
    }
}
impl ValidSingularQuery for FindSorafsPopCommitmentRootByVersion {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<PopCommitmentRootRecordV1, QueryExecutionFail> {
        let mut current = pop_query_current(0).map_err(query_failure)?;
        read_root_for_current(state_ro.world(), self.tree_version, &mut current)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Find(FindError::SorafsPopCommitmentRoot(self.tree_version))
            })
    }
}
impl ValidSingularQuery for FindSorafsPopRevocationPublicationByVersion {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<PopRevocationPublicationRecordV1, QueryExecutionFail> {
        let mut current = pop_query_current(0).map_err(query_failure)?;
        read_revocation_publication_for_current(state_ro.world(), self.list_version, &mut current)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Find(FindError::SorafsPopRevocationPublication(
                    self.list_version,
                ))
            })
    }
}
impl ValidSingularQuery for FindSorafsPopRevocationByNonceCommitment {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<PopRevocationRecordV1, QueryExecutionFail> {
        let mut current = pop_query_current(0).map_err(query_failure)?;
        read_revocation_for_current(
            state_ro.world(),
            self.revocation_nonce_commitment,
            &mut current,
        )
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Find(FindError::SorafsPopRevocation(
                self.revocation_nonce_commitment,
            ))
        })
    }
}
impl ValidSingularQuery for FindSorafsPopAuditDigestBySequence {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<PopRegistryAuditDigestRecordV1, QueryExecutionFail> {
        let mut current = pop_query_current(0).map_err(query_failure)?;
        read_audit_for_current(state_ro.world(), self.sequence, &mut current)
            .map_err(query_failure)?
            .ok_or_else(|| QueryExecutionFail::Find(FindError::SorafsPopAuditDigest(self.sequence)))
    }
}
impl ValidSingularQuery for FindSorafsPopRegistryStatus {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<PopRegistryStatusV1, QueryExecutionFail> {
        let policy_present = {
            let mut current = pop_query_current(0).map_err(query_failure)?;
            read_policy_for_current(state_ro.world(), &mut current)
                .map_err(query_failure)?
                .is_some()
        };
        let mut current = pop_query_current(0).map_err(query_failure)?;
        let status =
            read_status_for_current(state_ro.world(), &mut current).map_err(query_failure)?;
        match (policy_present, status) {
            (true, Some(status)) => Ok(status),
            (false, None) => Err(QueryExecutionFail::Find(FindError::SorafsPopRegistryStatus)),
            (true, None) | (false, Some(_)) => Err(QueryExecutionFail::Conversion(
                "authoritative SoraFS PoP policy/status state is inconsistent".to_owned(),
            )),
        }
    }
}
#[cfg(test)]
mod tests {
    include!("sorafs_pop_registry/schema_identity_tests.rs");
    use super::*;
    include!("sorafs/pop_permission_token_tests.rs");
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_crypto::{Algorithm, KeyPair, PrivateKey, Signature};
    use iroha_data_model::{
        IntoKeyValue, Registrable,
        account::{Account, AccountId, MultisigMember, MultisigPolicy},
        block::BlockHeader,
        permission::{Permission, Permissions},
        sorafs::pop_registry::{
            POP_CREDENTIAL_COMMITMENT_BATCH_VERSION_V1, POP_ISSUER_POLICY_VERSION_V1,
            PopCredentialCommitmentV1, PopIssuerPolicyV1,
        },
    };
    use iroha_primitives::json::Json;
    use nonzero_ext::nonzero;
    use sorafs_manifest::pop_credentials::{
        POP_COMMITMENT_ROOT_VERSION_V1, POP_CREDENTIAL_TREE_DEPTH_V1,
        POP_REVOCATION_LIST_VERSION_V1, POP_REVOCATION_TREE_DEPTH_V1, PopCommitmentRootV1,
        PopRevocationEntryV1, PopRevocationListV1, PopRevocationReasonV1, PopSignatureAlgorithmV1,
        PopSignatureV1, pop_commitment_root_signature_digest_v1,
        pop_revocation_list_signature_digest_v1, pop_revocation_root_v1,
        verify_pop_commitment_root_signature_v1, verify_pop_revocation_list_signature_v1,
    };
    const NOW: u64 = 10_000;
    fn keypair(seed: u8) -> KeyPair {
        let private = PrivateKey::from_bytes(Algorithm::Ed25519, &[seed; 32])
            .expect("valid deterministic Ed25519 seed");
        KeyPair::from_private_key(private).expect("derive deterministic keypair")
    }
    fn account(keypair: &KeyPair) -> AccountId {
        AccountId::new(keypair.public_key().clone())
    }
    fn public_key_bytes(keypair: &KeyPair) -> [u8; 32] {
        let (_, bytes) = keypair
            .public_key()
            .try_to_bytes()
            .expect("fixture public key");
        bytes.try_into().expect("Ed25519 public key length")
    }
    fn empty_signature(keypair: &KeyPair) -> PopSignatureV1 {
        PopSignatureV1 {
            algorithm: PopSignatureAlgorithmV1::Ed25519,
            public_key: public_key_bytes(keypair).to_vec(),
            signature: Vec::new(),
        }
    }
    fn sign_digest(keypair: &KeyPair, digest: [u8; 32]) -> Vec<u8> {
        Signature::try_new(keypair.private_key(), &digest)
            .expect("sign fixture digest")
            .payload()
            .to_vec()
    }
    fn sign_root(mut root: PopCommitmentRootV1, keypair: &KeyPair) -> PopCommitmentRootV1 {
        root.publisher_signature = empty_signature(keypair);
        let digest = pop_commitment_root_signature_digest_v1(&root).expect("root digest");
        root.publisher_signature.signature = sign_digest(keypair, digest);
        verify_pop_commitment_root_signature_v1(&root).expect("root signature verifies");
        root
    }
    fn sign_revocations(
        mut publication: PopRevocationListV1,
        keypair: &KeyPair,
    ) -> PopRevocationListV1 {
        publication.publisher_signature = empty_signature(keypair);
        let digest =
            pop_revocation_list_signature_digest_v1(&publication).expect("revocation digest");
        publication.publisher_signature.signature = sign_digest(keypair, digest);
        verify_pop_revocation_list_signature_v1(&publication)
            .expect("revocation signature verifies");
        publication
    }
    fn nonce(value: u8) -> [u8; 32] {
        let mut nonce = [0; 32];
        nonce[0] = value;
        nonce
    }
    fn root(
        keypair: &KeyPair,
        root_byte: u8,
        tree_size: u64,
        tree_version: u64,
        previous_root_digest: Option<[u8; 32]>,
        published_at_epoch: u64,
    ) -> PopCommitmentRootV1 {
        sign_root(
            PopCommitmentRootV1 {
                version: POP_COMMITMENT_ROOT_VERSION_V1,
                root_digest: [root_byte; 32],
                tree_size,
                tree_depth: POP_CREDENTIAL_TREE_DEPTH_V1,
                tree_version,
                issuer_id: "pop-issuer-sora-foundation".to_owned(),
                published_at_epoch,
                previous_root_digest,
                governance_event_digest: [0xA5; 32],
                publisher_signature: empty_signature(keypair),
            },
            keypair,
        )
    }
    fn revocations(
        keypair: &KeyPair,
        root_digest: [u8; 32],
        list_version: u64,
        entries: Vec<PopRevocationEntryV1>,
        published_at_epoch: u64,
    ) -> PopRevocationListV1 {
        let revocation_root = pop_revocation_root_v1(&entries).expect("revocation root");
        sign_revocations(
            PopRevocationListV1 {
                version: POP_REVOCATION_LIST_VERSION_V1,
                list_version,
                commitment_root: root_digest,
                revocation_root,
                revocation_tree_depth: POP_REVOCATION_TREE_DEPTH_V1,
                issuer_id: "pop-issuer-sora-foundation".to_owned(),
                published_at_epoch,
                entries,
                publisher_signature: empty_signature(keypair),
            },
            keypair,
        )
    }
    fn commitment(
        credential_byte: u8,
        nonce: [u8; 32],
        root_digest: [u8; 32],
        tree_version: u64,
        list_version: u64,
    ) -> PopCredentialCommitmentV1 {
        PopCredentialCommitmentV1 {
            credential_commitment: [credential_byte; 32],
            revocation_nonce_commitment: pop_revocation_nonce_commitment_v1(nonce),
            commitment_root: root_digest,
            commitment_tree_version: tree_version,
            revocation_list_version: list_version,
            issued_at_epoch: NOW - 100,
            expires_at_epoch: NOW + 1_000,
        }
    }
    fn batch(
        keypair: &KeyPair,
        root_byte: u8,
        tree_size: u64,
        tree_version: u64,
        list_version: u64,
        previous_root_digest: Option<[u8; 32]>,
        commitments: Vec<PopCredentialCommitmentV1>,
        entries: Vec<PopRevocationEntryV1>,
    ) -> PopCredentialCommitmentBatchV1 {
        let root = root(
            keypair,
            root_byte,
            tree_size,
            tree_version,
            previous_root_digest,
            NOW - 1,
        );
        let revocations = revocations(keypair, root.root_digest, list_version, entries, NOW - 1);
        PopCredentialCommitmentBatchV1 {
            version: POP_CREDENTIAL_COMMITMENT_BATCH_VERSION_V1,
            issuer_policy_digest: policy(keypair).digest().expect("policy digest"),
            commitment_root_payload: encode(&root),
            revocation_list_payload: encode(&revocations),
            commitments,
        }
    }
    fn policy(keypair: &KeyPair) -> PopIssuerPolicyV1 {
        PopIssuerPolicyV1 {
            version: POP_ISSUER_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            issuer_id: "pop-issuer-sora-foundation".to_owned(),
            issuer_account: account(keypair),
            issuer_public_key: public_key_bytes(keypair),
            max_credentials_per_batch: 256,
            max_revocations_per_publication: 16,
            max_credential_lifetime_secs: 10_000,
            max_future_clock_skew_secs: 5,
            paused: false,
        }
    }
    fn block_header() -> BlockHeader {
        BlockHeader::new(nonzero!(1_u64), None, None, NOW * 1_000, 0)
    }
    fn non_genesis_block_header() -> BlockHeader {
        BlockHeader::new(nonzero!(2_u64), None, None, NOW * 1_000, 0)
    }
    fn state(operator: &KeyPair, others: &[&KeyPair]) -> State {
        let mut world = World::new();
        for keypair in std::iter::once(operator).chain(others.iter().copied()) {
            let id = account(keypair);
            let (id, value) = Account::new(id.clone()).build(&id).into_key_value();
            world.accounts.insert(id, value);
        }
        let mut permissions = Permissions::new();
        for permission in [MANAGE_PERMISSION, OPERATE_PERMISSION] {
            permissions.insert(Permission::new(permission.to_owned(), Json::new(())));
        }
        world
            .account_permissions
            .insert(account(operator), permissions);
        State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        )
    }
    fn encode<T: norito::core::NoritoSerialize>(value: &T) -> Vec<u8> {
        norito::encode_canonical(value).expect("encode canonical fixture")
    }
    fn encode_with_alternate_norito_layout<T: norito::NoritoSerialize>(value: &T) -> Vec<u8> {
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::to_bytes(value).expect("encode alternate-layout PoP registry fixture")
    }
    fn encode_state_with_alternate_ambient<T: norito::NoritoSerialize>(value: &T) -> Vec<u8> {
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        encode_state(value, "PoP registry fixture").expect("encode canonical PoP registry state")
    }
    #[test]
    fn streamed_policy_audit_payload_digest_matches_canonical_bytes() {
        let operator = keypair(0x0F);
        let policy = policy(&operator);
        let expected = pop_registry_payload_digest_v1(&encode(&policy));
        let actual = canonical_registry_payload_digest(&policy, "PoP policy fixture")
            .expect("stream policy payload digest");
        assert_eq!(actual, expected);
    }
    #[test]
    fn streamed_audit_authority_matches_legacy_i105_preimage() {
        let single = account(&keypair(0x10));
        let multisig = AccountId::new_multisig(
            MultisigPolicy::new(
                1,
                vec![
                    MultisigMember::new(keypair(0x11).public_key().clone(), 1)
                        .expect("valid multisig member"),
                    MultisigMember::new(keypair(0x12).public_key().clone(), 1)
                        .expect("valid multisig member"),
                ],
            )
            .expect("valid multisig policy"),
        );
        let sequence = 7_u64;
        let kind = PopRegistryAuditEventKindV1::CredentialBatchCommitted;
        let payload_digest = [0x31; 32];
        let previous = [0x32; 32];
        let now = NOW;
        for discriminant in [0x02f1, 0x0171, 0, 42] {
            let _guard =
                iroha_data_model::account::address::ChainDiscriminantGuard::enter(discriminant);
            for authority in [&single, &multisig] {
                let authority_text = authority.to_string();
                let mut legacy = blake3::Hasher::new();
                legacy.update(POP_REGISTRY_AUDIT_DIGEST_DOMAIN_V1);
                legacy.update(&sequence.to_le_bytes());
                legacy.update(&[kind.digest_tag()]);
                legacy.update(&[1]);
                legacy.update(&previous);
                legacy.update(&payload_digest);
                legacy.update(&now.to_le_bytes());
                legacy.update(
                    &u64::try_from(authority_text.len())
                        .expect("I105 fixture length fits in u64")
                        .to_le_bytes(),
                );
                legacy.update(authority_text.as_bytes());
                assert_eq!(
                    audit_digest(
                        sequence,
                        kind,
                        payload_digest,
                        Some(previous),
                        now,
                        authority
                    ),
                    *legacy.finalize().as_bytes(),
                );
            }
        }
    }
    fn activate(operator: &KeyPair, state_transaction: &mut StateTransaction<'_, '_>) -> AccountId {
        let authority = account(operator);
        SetSorafsPopIssuerPolicy::new(policy(operator))
            .execute(&authority, state_transaction)
            .expect("activate PoP policy");
        authority
    }
    fn initial_batch(operator: &KeyPair) -> PopCredentialCommitmentBatchV1 {
        let root_digest = [1; 32];
        batch(
            operator,
            1,
            1,
            1,
            1,
            None,
            vec![commitment(1, nonce(1), root_digest, 1, 1)],
            Vec::new(),
        )
    }
    fn commit_initial(
        operator: &KeyPair,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) {
        CommitSorafsPopCredentialBatch::new(encode(&initial_batch(operator)))
            .execute(authority, state_transaction)
            .expect("commit initial credential batch");
    }
    #[test]
    fn policy_batch_queries_and_audit_chain_are_authoritative() {
        let operator = keypair(0x11);
        let state = state(&operator, &[]);
        let mut block = state.block(non_genesis_block_header());
        let mut stx = block.transaction();
        let authority = activate(&operator, &mut stx);
        commit_initial(&operator, &authority, &mut stx);
        let status = FindSorafsPopRegistryStatus.execute(&stx).expect("status");
        assert_eq!(status.active_root_digest, Some([1; 32]));
        assert_eq!(status.active_tree_version, 1);
        assert_eq!(status.active_revocation_list_version, 1);
        assert_eq!(status.credential_commitment_count, 1);
        assert_eq!(status.revoked_credential_count, 0);
        assert_eq!(status.audit_sequence, 2);
        let credential = FindSorafsPopCredentialCommitmentByDigest::new([1; 32])
            .execute(&stx)
            .expect("credential commitment");
        assert_eq!(credential.committed_by, authority);
        assert_eq!(credential.audit_digest, status.audit_head.unwrap());
        let root = FindSorafsPopCommitmentRootByVersion::new(1)
            .execute(&stx)
            .expect("root publication");
        let revocations = FindSorafsPopRevocationPublicationByVersion::new(1)
            .execute(&stx)
            .expect("revocation publication");
        assert_eq!(root.audit_digest, revocations.audit_digest);
        let first_audit = FindSorafsPopAuditDigestBySequence::new(1)
            .execute(&stx)
            .expect("policy audit");
        let second_audit = FindSorafsPopAuditDigestBySequence::new(2)
            .execute(&stx)
            .expect("batch audit");
        assert_eq!(
            second_audit.previous_audit_digest,
            Some(first_audit.audit_digest)
        );
    }
    #[test]
    fn genesis_permission_bypass_matches_executor_but_policy_requires_registered_issuer() {
        let operator = keypair(0x18);
        let genesis_authority = keypair(0x19);
        let configured_state = state(&operator, &[&genesis_authority]);
        let mut block = configured_state.block(block_header());
        let mut stx = block.transaction();
        let genesis_authority_id = account(&genesis_authority);
        SetSorafsPopIssuerPolicy::new(policy(&operator))
            .execute(&genesis_authority_id, &mut stx)
            .expect("genesis policy activation follows executor permission semantics");
        assert_eq!(
            FindSorafsPopIssuerPolicy
                .execute(&stx)
                .expect("genesis policy")
                .activated_by,
            genesis_authority_id
        );
        let unknown_issuer = keypair(0x1A);
        let state = state(&operator, &[]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction();
        let mut invalid_policy = policy(&operator);
        invalid_policy.issuer_account = account(&unknown_issuer);
        assert!(
            SetSorafsPopIssuerPolicy::new(invalid_policy)
                .execute(&account(&operator), &mut stx)
                .is_err()
        );
        assert!(FindSorafsPopIssuerPolicy.execute(&stx).is_err());
    }
    #[test]
    fn unauthorized_governance_and_issuer_accounts_are_rejected() {
        let operator = keypair(0x21);
        let intruder = keypair(0x22);
        let intruder_id = account(&intruder);
        let state = state(&operator, &[&intruder]);
        let mut block = state.block(non_genesis_block_header());
        let mut stx = block.transaction();
        assert!(
            SetSorafsPopIssuerPolicy::new(policy(&operator))
                .execute(&intruder_id, &mut stx)
                .is_err()
        );
        let authority = activate(&operator, &mut stx);
        let mut intruder_permissions = Permissions::new();
        intruder_permissions.insert(Permission::new(
            OPERATE_PERMISSION.to_owned(),
            Json::new(()),
        ));
        stx.world
            .account_permissions
            .insert(intruder_id.clone(), intruder_permissions);
        assert!(
            CommitSorafsPopCredentialBatch::new(encode(&initial_batch(&operator)))
                .execute(&intruder_id, &mut stx)
                .is_err()
        );
        let status = FindSorafsPopRegistryStatus.execute(&stx).expect("status");
        assert_eq!(status.audit_sequence, 1);
        assert_eq!(status.credential_commitment_count, 0);
        assert_eq!(authority, account(&operator));
    }
    #[test]
    fn malformed_noncanonical_and_oversized_batches_fail_without_mutation() {
        let operator = keypair(0x31);
        let state = state(&operator, &[]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction();
        let authority = activate(&operator, &mut stx);
        let mut wrong_policy = initial_batch(&operator);
        wrong_policy.issuer_policy_digest = [0xEE; 32];
        assert!(
            CommitSorafsPopCredentialBatch::new(encode(&wrong_policy))
                .execute(&authority, &mut stx)
                .is_err()
        );
        let canonical_batch = initial_batch(&operator);
        assert_eq!(
            encode_state_with_alternate_ambient(&canonical_batch),
            encode(&canonical_batch)
        );
        let alternate = encode_with_alternate_norito_layout(&canonical_batch);
        let input_error = decode_exact::<PopCredentialCommitmentBatchV1>(
            &alternate,
            BATCH_LIMITS,
            BATCH_PAYLOAD_MAX_BYTES,
            "PoP credential commitment batch",
            false,
        )
        .expect_err("alternate-layout input must be rejected");
        assert!(matches!(
            &input_error,
            InstructionExecutionError::InvalidParameter(_)
        ));
        assert!(
            matches!(&input_error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("not exact canonical Norito"))
        );
        let state_error = decode_exact::<PopCredentialCommitmentBatchV1>(
            &alternate,
            BATCH_LIMITS,
            BATCH_PAYLOAD_MAX_BYTES,
            "PoP credential commitment batch",
            true,
        )
        .expect_err("alternate-layout state must be rejected");
        assert!(matches!(
            &state_error,
            InstructionExecutionError::InvariantViolation(_)
        ));
        assert!(
            state_error
                .to_string()
                .contains("not exact canonical Norito")
        );
        for payload in [
            vec![0xFF, 0x00],
            alternate,
            {
                let mut payload = encode(&initial_batch(&operator));
                payload.push(0);
                payload
            },
            {
                let mut batch = initial_batch(&operator);
                batch.commitment_root_payload.push(0);
                encode(&batch)
            },
        ] {
            assert!(
                CommitSorafsPopCredentialBatch::new(payload)
                    .execute(&authority, &mut stx)
                    .is_err()
            );
        }
        let root_digest = [1; 32];
        let commitments = (1_u16..=257)
            .map(|value| {
                let mut digest = [0; 32];
                digest[..2].copy_from_slice(&value.to_be_bytes());
                let mut candidate = commitment(1, nonce(1), root_digest, 1, 1);
                candidate.credential_commitment = digest;
                candidate.revocation_nonce_commitment = {
                    let mut digest = [0; 32];
                    digest[..2].copy_from_slice(&value.to_le_bytes());
                    digest[31] = 1;
                    digest
                };
                candidate
            })
            .collect();
        let oversized = batch(&operator, 1, 257, 1, 1, None, commitments, Vec::new());
        assert!(
            CommitSorafsPopCredentialBatch::new(encode(&oversized))
                .execute(&authority, &mut stx)
                .is_err()
        );
        let status = FindSorafsPopRegistryStatus.execute(&stx).expect("status");
        assert_eq!(status.audit_sequence, 1);
        assert_eq!(status.credential_commitment_count, 0);
    }
    #[test]
    fn duplicate_commitment_and_stale_root_rollback_are_atomic() {
        let operator = keypair(0x41);
        let state = state(&operator, &[]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction();
        let authority = activate(&operator, &mut stx);
        commit_initial(&operator, &authority, &mut stx);
        let before = FindSorafsPopRegistryStatus.execute(&stx).expect("status");
        let duplicate = batch(
            &operator,
            2,
            2,
            2,
            2,
            Some([1; 32]),
            vec![commitment(1, nonce(2), [2; 32], 2, 2)],
            Vec::new(),
        );
        assert!(
            CommitSorafsPopCredentialBatch::new(encode(&duplicate))
                .execute(&authority, &mut stx)
                .is_err()
        );
        let outdated = batch(
            &operator,
            2,
            2,
            1,
            2,
            Some([1; 32]),
            vec![commitment(2, nonce(2), [2; 32], 1, 2)],
            Vec::new(),
        );
        assert!(
            CommitSorafsPopCredentialBatch::new(encode(&outdated))
                .execute(&authority, &mut stx)
                .is_err()
        );
        assert_eq!(
            FindSorafsPopRegistryStatus.execute(&stx).expect("status"),
            before
        );
        assert!(
            FindSorafsPopCommitmentRootByVersion::new(2)
                .execute(&stx)
                .is_err()
        );
    }
    #[test]
    fn revocation_is_bound_monotonic_and_not_replayable() {
        let operator = keypair(0x51);
        let state = state(&operator, &[]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction();
        let authority = activate(&operator, &mut stx);
        commit_initial(&operator, &authority, &mut stx);
        let unknown = PopRevocationEntryV1 {
            nonce: nonce(9),
            revoked_at_epoch: NOW,
            reason: PopRevocationReasonV1::GovernanceSuspension,
        };
        let wrong_binding = revocations(&operator, [1; 32], 2, vec![unknown], NOW);
        assert!(
            PublishSorafsPopRevocationList::new(
                encode(&wrong_binding),
                policy(&operator).digest().expect("policy digest"),
            )
            .execute(&authority, &mut stx)
            .is_err()
        );
        let entry = PopRevocationEntryV1 {
            nonce: nonce(1),
            revoked_at_epoch: NOW,
            reason: PopRevocationReasonV1::GovernanceSuspension,
        };
        let first = revocations(&operator, [1; 32], 2, vec![entry], NOW);
        PublishSorafsPopRevocationList::new(
            encode(&first),
            policy(&operator).digest().expect("policy digest"),
        )
        .execute(&authority, &mut stx)
        .expect("first revocation");
        let committed = FindSorafsPopRevocationByNonceCommitment::new(
            pop_revocation_nonce_commitment_v1(nonce(1)),
        )
        .execute(&stx)
        .expect("revocation record");
        assert_eq!(committed.credential_commitment, [1; 32]);
        let before = FindSorafsPopRegistryStatus.execute(&stx).expect("status");
        assert!(
            PublishSorafsPopRevocationList::new(
                encode(&first),
                policy(&operator).digest().expect("policy digest"),
            )
            .execute(&authority, &mut stx)
            .is_err()
        );
        let double = revocations(&operator, [1; 32], 3, vec![entry], NOW);
        assert!(
            PublishSorafsPopRevocationList::new(
                encode(&double),
                policy(&operator).digest().expect("policy digest"),
            )
            .execute(&authority, &mut stx)
            .is_err()
        );
        let rollback = revocations(&operator, [1; 32], 3, Vec::new(), NOW);
        assert!(
            PublishSorafsPopRevocationList::new(
                encode(&rollback),
                policy(&operator).digest().expect("policy digest"),
            )
            .execute(&authority, &mut stx)
            .is_err()
        );
        assert_eq!(
            FindSorafsPopRegistryStatus.execute(&stx).expect("status"),
            before
        );
    }
    #[test]
    fn revocation_batch_policy_limit_is_preflighted_atomically() {
        let operator = keypair(0x61);
        let state = state(&operator, &[]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction();
        let authority = activate(&operator, &mut stx);
        let root_digest = [1; 32];
        let commitments = (1_u8..=17)
            .map(|value| commitment(value, nonce(value), root_digest, 1, 1))
            .collect();
        let initial = batch(&operator, 1, 17, 1, 1, None, commitments, Vec::new());
        CommitSorafsPopCredentialBatch::new(encode(&initial))
            .execute(&authority, &mut stx)
            .expect("initial credential batch");
        let before = FindSorafsPopRegistryStatus.execute(&stx).expect("status");
        let entries = (1_u8..=17)
            .map(|value| PopRevocationEntryV1 {
                nonce: nonce(value),
                revoked_at_epoch: NOW,
                reason: PopRevocationReasonV1::GovernanceSuspension,
            })
            .collect();
        let oversized = revocations(&operator, root_digest, 2, entries, NOW);
        assert!(
            PublishSorafsPopRevocationList::new(
                encode(&oversized),
                policy(&operator).digest().expect("policy digest"),
            )
            .execute(&authority, &mut stx)
            .is_err()
        );
        assert_eq!(
            FindSorafsPopRegistryStatus.execute(&stx).expect("status"),
            before
        );
        for value in 1_u8..=17 {
            assert!(
                FindSorafsPopRevocationByNonceCommitment::new(pop_revocation_nonce_commitment_v1(
                    nonce(value)
                ))
                .execute(&stx)
                .is_err()
            );
        }
    }
}

#[cfg(test)]
mod nonce_frame_identity_tests {
    use super::*;

    #[test]
    fn nonce_binding_frame_preserves_both_commitments_and_rejects_substitution() {
        let binding = NonceBindingStateV1 {
            credential_commitment: [0x31; 32],
            revocation_nonce_commitment: [0x42; 32],
        };
        assert_eq!(
            <NonceBindingStateV1 as norito::NoritoSchema>::nominal_name(),
            "iroha_core::smartcontracts::isi::sorafs_pop_registry::NonceBindingStateV1"
        );
        assert_eq!(
            <NonceBindingStateV1 as norito::NoritoSchema>::frame_name(),
            "iroha_core::smartcontracts::isi::sorafs_pop_registry::NonceBindingStateV1"
        );
        let bytes = encode_state(&binding, "nonce binding").expect("production state writer");
        assert_eq!(
            bytes[6..22],
            norito::schema::identity::frame_hash::<NonceBindingStateV1>()
        );
        let read = |bytes: &[u8]| {
            decode_exact::<NonceBindingStateV1>(
                bytes,
                STATE_LIMITS,
                STATE_MAX_BYTES,
                "nonce binding",
                true,
            )
        };
        let decoded = read(&bytes).expect("production bounded state decoder");
        assert_eq!(decoded.credential_commitment, binding.credential_commitment);
        assert_eq!(
            decoded.revocation_nonce_commitment,
            binding.revocation_nonce_commitment
        );
        assert_eq!(
            encode_state(&decoded, "nonce binding").expect("re-encode"),
            bytes
        );
        let mut wrong_owner = bytes.clone();
        wrong_owner[6] ^= 1;
        assert!(matches!(
            norito::decode_canonical::<NonceBindingStateV1>(&wrong_owner),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(read(&wrong_owner).is_err());
        assert!(read(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(read(&trailing).is_err());
    }
}
