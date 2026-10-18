use super::*;
mod publication;
use crate::{
    smartcontracts::ValidSingularQuery,
    state::{StateBlock, StateStorageAdmissionError, StateTransaction},
};
use blake3::hash as blake3_hash;
use core::convert::TryFrom;
use iroha_crypto::{Algorithm, PublicKey, ed25519_parse_signature};
#[cfg(any(test, feature = "iroha-core-tests"))]
use iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1;
use iroha_data_model::{
    asset::AssetId,
    events::data::sorafs::{
        SorafsGatewayEvent, SorafsProofHealthAlert, SorafsRepairLedgerEvent,
        SorafsRepairLedgerEventKind,
    },
    isi::error::{InstructionExecutionError, InvalidParameterError},
    musubi::{
        MUSUBI_MIN_HEALTHY_REPLICAS_V1, MusubiArchiveLocationKeyV1, MusubiProviderLocationKeyV1,
        MusubiReplicationOrderArchiveBindingV1, MusubiReplicationOrderLocationReferenceV1,
    },
    permission::{Permission, Permissions},
    query::{
        error::{FindError, QueryExecutionFail},
        sorafs::prelude::{
            FindSorafsPinManifest, FindSorafsPinManifests, FindSorafsRepairEvents,
            FindSorafsRepairStatus, FindSorafsRepairTask, FindSorafsRepairTasks,
        },
    },
    sorafs::{
        capacity::{
            CapacityAccrual, CapacityDeclarationRecord, CapacityDisputeEvidence, CapacityDisputeId,
            CapacityDisputeRecord, CapacityDisputeStatus, CapacityFeeLedgerEntry,
            CapacityTelemetryRecord, ProviderId,
        },
        moderation_ledger::{
            REPAIR_LEDGER_MAX_APPEAL_REASON_BYTES_V1, REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1,
            REPAIR_LEDGER_MAX_IDEMPOTENCY_KEY_BYTES_V1, REPAIR_LEDGER_MAX_LEASE_MS_V1,
            REPAIR_LEDGER_MAX_RECEIPTS_V1, REPAIR_LEDGER_MIN_LEASE_MS_V1,
            REPAIR_LEDGER_TASK_VERSION_V1, REPAIR_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            REPAIR_QUERY_MAX_ITEMS_V1, REPAIR_QUERY_MAX_TASK_PAGE_BYTES_V1,
            RepairFinalizedCursorV1, RepairFinalizedEventPageV1, RepairFinalizedEventV1,
            RepairFinalizedStatusV1, RepairFinalizedTaskV1, RepairLedgerActionReceiptV1,
            RepairLedgerAppealRecordV1, RepairLedgerCompletedV1, RepairLedgerEscalatedV1,
            RepairLedgerFailedV1, RepairLedgerLeaseV1, RepairLedgerSlashRecordV1,
            RepairLedgerStatusV1, RepairLedgerTaskPageV1, RepairLedgerTaskV1,
            RepairLedgerTerminalKindV1, RepairLedgerTerminalOutcomeV1,
            sorafs_repair_action_digest_v1, sorafs_repair_appeal_id_v1,
            sorafs_repair_idempotency_digest_v1, sorafs_repair_task_id_v1,
        },
        pin_registry::{
            ChunkerProfileHandle, ManifestAliasBinding, ManifestAliasId, ManifestAliasRecord,
            ManifestDigest, ManifestRootCid, PIN_MANIFEST_QUERY_MAX_ITEMS_V1,
            PIN_MANIFEST_QUERY_MAX_PAGE_BYTES_V1, PIN_MANIFEST_QUERY_MIN_PAGE_BYTES_V1,
            PinFeePayment, PinLineageSummaryV1, PinManifestFinalizedCursorV1,
            PinManifestFinalizedRecordV1, PinManifestPageV1, PinManifestRecord,
            PinManifestSummaryV1, PinPolicy, PinResourceUsage, PinStatus, PinStatusKindV1,
            ProviderIngestCompletionAuthorityV1, ProviderIngestFinalizedAnchorV1,
            ReplicationOrderCompletionRecord, ReplicationOrderId, ReplicationOrderRecord,
            ReplicationOrderStatus, SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1,
            StorageClass, derive_sorafs_auto_replication_order_id_v1,
        },
        pricing::{
            PricingComputationError, PricingScheduleRecord, ProviderCreditRecord,
            XOR_QUANTITY_SCALE, checked_mul_div_round_u128,
        },
    },
};
use iroha_executor_data_model::permission::sorafs::CanOperateSorafsRepair;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::{name::Name, state_path::StatePath};
use iroha_primitives::{
    json::Json,
    numeric::{NumericOperationError, Quantity, RoundingMode},
};
use mv::storage::{StorageReadOnly, Transaction as StorageTransaction};
use norito::{
    DecodeLimits, decode_canonical_with_limits,
    json::{self, Value},
};
use sorafs_manifest::{
    BLAKE3_256_MULTIHASH_CODE, ManifestValidationError, PinPolicy as ManifestPinPolicy,
    PinPolicyConstraints as ManifestPinPolicyConstraints, ProfileId,
    StorageClass as ManifestStorageClass,
    alias_cache::decode_alias_proof_untrusted_signers,
    capacity::{
        CapacityDeclarationV1, CapacityDisputeKind, CapacityDisputeV1, CapacityMetadataEntry,
        REPLICATION_ORDER_VERSION_V1, ReplicationAssignmentV1, ReplicationOrderSlaV1,
        ReplicationOrderV1,
    },
    orderbook::BYTES_PER_GIB,
    repair::{RepairReportV1, RepairSlashProposalV1, RepairTicketId},
    validate_chunker_handle, validate_manifest, validate_manifest_root_cid, validate_pin_policy,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::OnceLock,
};
fn next_musubi_location_for_provider(
    provider: ProviderId,
    after: Option<MusubiArchiveLocationKeyV1>,
    state_transaction: &StateTransaction<'_, '_>,
) -> Option<MusubiArchiveLocationKeyV1> {
    let bounds = MusubiProviderLocationKeyV1::provider_range(provider);
    let start = *bounds.start();
    let end = *bounds.end();
    match after {
        None => state_transaction
            .world
            .musubi_locations_by_provider
            .range(start..=end)
            .next()
            .map(|(key, ())| key.location),
        Some(location) => state_transaction
            .world
            .musubi_locations_by_provider
            .range((
                std::ops::Bound::Excluded(MusubiProviderLocationKeyV1::new(provider, location)),
                std::ops::Bound::Included(end),
            ))
            .next()
            .map(|(key, ())| key.location),
    }
}
/// Convert governance configuration into manifest validation constraints.
pub fn manifest_pin_policy_constraints_from_config(
    config: &iroha_config::parameters::actual::SorafsPinPolicyConstraints,
) -> ManifestPinPolicyConstraints {
    let allowed_storage_classes = config.allowed_storage_classes.as_ref().map(|set| {
        set.iter()
            .copied()
            .map(convert_storage_class)
            .collect::<BTreeSet<_>>()
    });
    ManifestPinPolicyConstraints {
        min_replicas_floor: config.min_replicas_floor,
        max_replicas_ceiling: config.max_replicas_ceiling,
        max_retention_epoch: config.max_retention_epoch,
        allowed_storage_classes,
        require_council_signatures: config.require_council_signatures,
    }
}
fn manifest_hex(digest: &ManifestDigest) -> String {
    hex::encode(digest.as_bytes())
}
fn round_xor_quantity_ratio(
    value: &Quantity,
    multiplier: u128,
    divisor: u128,
) -> Result<Quantity, NumericOperationError> {
    let multiplier = Quantity::from(multiplier);
    let divisor = Quantity::from(divisor);
    value.try_mul_div_decimal_round(
        multiplier.as_numeric(),
        divisor.as_numeric(),
        XOR_QUANTITY_SCALE,
        RoundingMode::NearestAway,
    )
}
fn quantity_arithmetic_error(
    context: &str,
    error: NumericOperationError,
) -> InstructionExecutionError {
    InstructionExecutionError::InvariantViolation(
        format!("SoraFS {context} calculation failed: {error}").into(),
    )
}
fn pricing_computation_error(
    context: &str,
    error: PricingComputationError,
) -> InstructionExecutionError {
    InstructionExecutionError::InvariantViolation(
        format!("SoraFS {context} calculation failed: {error}").into(),
    )
}
const STORAGE_CLASS_METADATA_KEY: &str = "sorafs.storage_class";
const PROVIDER_OWNER_METADATA_KEY: &str = "sorafs.owner_account_id";
const MAX_COUNCIL_ENVELOPE_BYTES: usize = 1024 * 1024;
const MAX_COUNCIL_ENVELOPE_SIGNATURES: usize = 64;
const MAX_COUNCIL_ENVELOPE_PROFILE_ALIASES: usize = 16;
const MAX_COUNCIL_ENVELOPE_MANIFEST_NAME_BYTES: usize = 255;
const MAX_RETIREMENT_REASON_BYTES: usize = 1024;
const MAX_ALIAS_PROOF_BYTES: usize = 1024 * 1024;
const MAX_REPLICATION_ORDER_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_CAPACITY_DECLARATION_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_CAPACITY_DISPUTE_PAYLOAD_BYTES: usize = 64 * 1024;
const PIN_ACCOUNTING_STATE_MAX_BYTES: usize = 1024;
const PIN_GLOBAL_USAGE_STATE_KEY_V1: &str = "sorafs_pin_accounting_v1/global";
const PIN_AUTHORITY_USAGE_STATE_KEY_PREFIX_V1: &str = "sorafs_pin_accounting_v1/authority/";
const PIN_LINEAGE_STATE_KEY_PREFIX_V1: &str = "sorafs_pin_accounting_v1/lineage/";
const PIN_EXPIRY_STATE_KEY_PREFIX_V1: &str = "sorafs_pin_accounting_v1/expiry/";
const PIN_STATUS_INDEX_STATE_KEY_PREFIX_V1: &str = "sorafs_pin_accounting_v1/status/";
const PIN_ACCOUNTING_DECODE_LIMITS: DecodeLimits =
    DecodeLimits::new(256, PIN_ACCOUNTING_STATE_MAX_BYTES, 32, 4096, 8);
const REPLICATION_ORDER_DECODE_LIMITS: DecodeLimits = DecodeLimits::new(
    sorafs_manifest::capacity::MAX_CAPACITY_METADATA_VALUE_BYTES,
    MAX_REPLICATION_ORDER_PAYLOAD_BYTES,
    65_536,
    MAX_REPLICATION_ORDER_PAYLOAD_BYTES * 4,
    32,
);
const CAPACITY_DECLARATION_DECODE_LIMITS: DecodeLimits = DecodeLimits::new(
    sorafs_manifest::capacity::MAX_CAPACITY_METADATA_VALUE_BYTES,
    MAX_CAPACITY_DECLARATION_PAYLOAD_BYTES,
    131_072,
    MAX_CAPACITY_DECLARATION_PAYLOAD_BYTES * 4,
    32,
);
const CAPACITY_DISPUTE_DECODE_LIMITS: DecodeLimits = DecodeLimits::new(
    2_048,
    MAX_CAPACITY_DISPUTE_PAYLOAD_BYTES,
    8_192,
    MAX_CAPACITY_DISPUTE_PAYLOAD_BYTES * 4,
    24,
);
fn pin_accounting_corruption(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvariantViolation(
        format!("SoraFS pin accounting is corrupt: {}", message.into()).into(),
    )
}
fn pin_consensus_epoch(state_transaction: &StateTransaction<'_, '_>) -> u64 {
    state_transaction.block_unix_timestamp_ms() / 1_000
}
fn pin_global_usage_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| {
        StatePath::from_str(PIN_GLOBAL_USAGE_STATE_KEY_V1)
            .expect("static pin-accounting key is valid")
    })
}
fn pin_authority_usage_key(authority: &AccountId) -> Result<StatePath, InstructionExecutionError> {
    let authority_bytes = norito::encode_canonical(authority).map_err(|error| {
        pin_accounting_corruption(format!(
            "failed to encode authority for the accounting key: {error}"
        ))
    })?;
    let authority_digest = blake3_hash(&authority_bytes);
    StatePath::from_str(&format!(
        "{PIN_AUTHORITY_USAGE_STATE_KEY_PREFIX_V1}{}",
        hex::encode(authority_digest.as_bytes())
    ))
    .map_err(|error| {
        pin_accounting_corruption(format!("failed to construct authority usage key: {error}"))
    })
}
fn pin_lineage_key(digest: &ManifestDigest) -> StatePath {
    StatePath::from_str(&format!(
        "{PIN_LINEAGE_STATE_KEY_PREFIX_V1}{}",
        manifest_hex(digest)
    ))
    .expect("static prefix plus a manifest digest is a valid state key")
}
fn pin_expiry_key(retention_epoch: u64, digest: &ManifestDigest) -> StatePath {
    StatePath::from_str(&format!(
        "{PIN_EXPIRY_STATE_KEY_PREFIX_V1}{retention_epoch:016x}/{}",
        manifest_hex(digest)
    ))
    .expect("static prefix plus fixed-width epoch and digest is a valid state key")
}
fn pin_status_label(status: &PinStatus) -> &'static str {
    match status {
        PinStatus::Pending => "pending",
        PinStatus::Approved(_) => "approved",
        PinStatus::Retired(_) => "retired",
    }
}
fn pin_status_index_prefix(label: &str) -> Result<StatePath, InstructionExecutionError> {
    if !matches!(label, "pending" | "approved" | "retired") {
        return Err(pin_accounting_corruption(format!(
            "unsupported pin status index label `{label}`"
        )));
    }
    StatePath::from_str(&format!("{PIN_STATUS_INDEX_STATE_KEY_PREFIX_V1}{label}/")).map_err(
        |error| pin_accounting_corruption(format!("failed to construct status prefix: {error}")),
    )
}
fn pin_status_index_key(status: &PinStatus, digest: &ManifestDigest) -> StatePath {
    StatePath::from_str(&format!(
        "{PIN_STATUS_INDEX_STATE_KEY_PREFIX_V1}{}/{}",
        pin_status_label(status),
        manifest_hex(digest)
    ))
    .expect("static status prefix plus a manifest digest is a valid state key")
}
fn prepare_pin_status_transition(
    state_transaction: &StateTransaction<'_, '_>,
    digest: &ManifestDigest,
    previous: &PinStatus,
    next: &PinStatus,
) -> Result<PinAccountingMutation, InstructionExecutionError> {
    if pin_status_label(previous) == pin_status_label(next) {
        return Ok(PinAccountingMutation {
            writes: Vec::new(),
            removals: Vec::new(),
        });
    }
    let previous_key = pin_status_index_key(previous, digest);
    let previous_marker = state_transaction
        .world
        .smart_contract_state
        .get(&previous_key)
        .ok_or_else(|| {
            pin_accounting_corruption(format!(
                "manifest {} has no {} status-index marker",
                manifest_hex(digest),
                pin_status_label(previous)
            ))
        })?;
    if !previous_marker.is_empty() {
        return Err(pin_accounting_corruption(format!(
            "manifest {} status-index marker must be empty",
            manifest_hex(digest)
        )));
    }
    let next_key = pin_status_index_key(next, digest);
    if state_transaction
        .world
        .smart_contract_state
        .get(&next_key)
        .is_some()
    {
        return Err(pin_accounting_corruption(format!(
            "manifest {} already has a {} status-index marker",
            manifest_hex(digest),
            pin_status_label(next)
        )));
    }
    Ok(PinAccountingMutation {
        writes: vec![(next_key, Vec::new())],
        removals: vec![previous_key],
    })
}
fn encode_pin_accounting_state<T: norito::core::NoritoSerialize>(
    value: &T,
    label: &str,
) -> Result<Vec<u8>, InstructionExecutionError> {
    let bytes = norito::encode_canonical(value)
        .map_err(|error| pin_accounting_corruption(format!("failed to encode {label}: {error}")))?;
    if bytes.len() > PIN_ACCOUNTING_STATE_MAX_BYTES {
        return Err(pin_accounting_corruption(format!(
            "encoded {label} exceeds {PIN_ACCOUNTING_STATE_MAX_BYTES} bytes"
        )));
    }
    Ok(bytes)
}
fn decode_pin_accounting_state<T>(bytes: &[u8], label: &str) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.len() > PIN_ACCOUNTING_STATE_MAX_BYTES {
        return Err(pin_accounting_corruption(format!(
            "stored {label} exceeds {PIN_ACCOUNTING_STATE_MAX_BYTES} bytes"
        )));
    }
    decode_canonical_with_limits::<T>(bytes, PIN_ACCOUNTING_DECODE_LIMITS).map_err(|error| {
        if matches!(error, norito::Error::NonCanonicalEncoding) {
            pin_accounting_corruption(format!("stored {label} is not exact canonical Norito"))
        } else {
            pin_accounting_corruption(format!("failed to decode stored {label}: {error}"))
        }
    })
}
fn read_pin_usage(
    world: &impl crate::state::WorldReadOnly,
    key: &StatePath,
    label: &str,
) -> Result<Option<PinResourceUsage>, InstructionExecutionError> {
    world
        .smart_contract_state()
        .get(key)
        .map(|bytes| decode_pin_accounting_state(bytes, label))
        .transpose()
}
fn read_pin_lineage(
    world: &impl crate::state::WorldReadOnly,
    digest: &ManifestDigest,
) -> Result<Option<PinLineageSummaryV1>, InstructionExecutionError> {
    world
        .smart_contract_state()
        .get(&pin_lineage_key(digest))
        .map(|bytes| {
            decode_pin_accounting_state(bytes, &format!("lineage for {}", manifest_hex(digest)))
        })
        .transpose()
}
#[derive(Debug)]
struct PinAccountingMutation {
    writes: Vec<(StatePath, Vec<u8>)>,
    removals: Vec<StatePath>,
}
impl PinAccountingMutation {
    fn apply(self, state_transaction: &mut StateTransaction<'_, '_>) {
        for (key, value) in self.writes {
            state_transaction
                .world
                .smart_contract_state
                .insert(key, value);
        }
        for key in self.removals {
            state_transaction.world.smart_contract_state.remove(key);
        }
    }
}
fn pin_record_has_live_content_charge(record: &PinManifestRecord) -> bool {
    !matches!(record.status, PinStatus::Retired(_))
}
fn prepare_pin_admission_accounting(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    digest: &ManifestDigest,
    successor_of: Option<&ManifestDigest>,
    content_length: u64,
    retention_epoch: u64,
    initial_status: &PinStatus,
) -> Result<PinAccountingMutation, InstructionExecutionError> {
    let policy = &state_transaction.gov.sorafs_pin_policy;
    let world = state_transaction.world();
    let global_key = pin_global_usage_key();
    let global_usage = match read_pin_usage(world, global_key, "global resource usage")? {
        Some(usage) => usage,
        None => {
            if world.pin_manifests().iter().next().is_some() {
                return Err(pin_accounting_corruption(
                    "retained manifests exist without the global resource summary",
                ));
            }
            PinResourceUsage::default()
        }
    };
    let global_usage = global_usage
        .checked_charge(content_length)
        .ok_or_else(|| invalid_parameter("global SoraFS pin resource accounting overflow"))?;
    if global_usage.manifest_count > policy.max_global_manifests
        || global_usage.content_bytes > policy.max_global_bytes
    {
        return Err(invalid_parameter(format!(
            "global SoraFS pin ceiling exceeded: manifests {}/{}, bytes {}/{}",
            global_usage.manifest_count,
            policy.max_global_manifests,
            global_usage.content_bytes,
            policy.max_global_bytes,
        )));
    }
    let authority_key = pin_authority_usage_key(authority)?;
    let authority_usage = match read_pin_usage(world, &authority_key, "authority resource usage")? {
        Some(usage) => usage,
        None => {
            if world
                .pin_manifests()
                .iter()
                .any(|(_, record)| &record.submitted_by == authority)
            {
                return Err(pin_accounting_corruption(format!(
                    "retained manifests for authority {authority} exist without a resource summary"
                )));
            }
            PinResourceUsage::default()
        }
    };
    let authority_usage = authority_usage
        .checked_charge(content_length)
        .ok_or_else(|| {
            invalid_parameter("per-authority SoraFS pin resource accounting overflow")
        })?;
    if authority_usage.manifest_count > policy.max_manifests_per_authority
        || authority_usage.content_bytes > policy.max_bytes_per_authority
    {
        return Err(invalid_parameter(format!(
            "SoraFS pin ceiling for authority {authority} exceeded: manifests {}/{}, bytes {}/{}",
            authority_usage.manifest_count,
            policy.max_manifests_per_authority,
            authority_usage.content_bytes,
            policy.max_bytes_per_authority,
        )));
    }
    let (lineage, parent_update) = if let Some(parent_digest) = successor_of {
        if parent_digest == digest {
            return Err(invalid_parameter(format!(
                "manifest {} cannot declare itself as successor",
                manifest_hex(digest)
            )));
        }
        let parent_record = world.pin_manifests().get(parent_digest).ok_or_else(|| {
            invalid_parameter(format!(
                "predecessor manifest {} referenced by successor {} is not registered",
                manifest_hex(parent_digest),
                manifest_hex(digest)
            ))
        })?;
        if !matches!(parent_record.status, PinStatus::Approved(_)) {
            return Err(invalid_parameter(format!(
                "predecessor manifest {} must be approved and live before registering successor {}",
                manifest_hex(parent_digest),
                manifest_hex(digest)
            )));
        }
        let parent_lineage = read_pin_lineage(world, parent_digest)?.ok_or_else(|| {
            pin_accounting_corruption(format!(
                "manifest {} has no lineage summary",
                manifest_hex(parent_digest)
            ))
        })?;
        let lineage = parent_lineage
            .checked_child()
            .ok_or_else(|| invalid_parameter("SoraFS pin lineage depth overflow"))?;
        if lineage.depth > policy.max_lineage_depth {
            return Err(invalid_parameter(format!(
                "successor chain for manifest {} has depth {}, exceeding configured maximum {}",
                manifest_hex(digest),
                lineage.depth,
                policy.max_lineage_depth,
            )));
        }
        let parent_lineage = parent_lineage
            .checked_add_successor()
            .ok_or_else(|| invalid_parameter("SoraFS pin successor fanout overflow"))?;
        if parent_lineage.direct_successor_count > policy.max_successor_fanout {
            return Err(invalid_parameter(format!(
                "manifest {} successor fanout {} exceeds configured maximum {}",
                manifest_hex(parent_digest),
                parent_lineage.direct_successor_count,
                policy.max_successor_fanout,
            )));
        }
        (lineage, Some((*parent_digest, parent_lineage)))
    } else {
        (PinLineageSummaryV1::root(), None)
    };
    let status_key = pin_status_index_key(initial_status, digest);
    if world.smart_contract_state().get(&status_key).is_some() {
        return Err(pin_accounting_corruption(format!(
            "manifest {} already has a {} status-index marker",
            manifest_hex(digest),
            pin_status_label(initial_status)
        )));
    }
    let mut writes = Vec::with_capacity(if parent_update.is_some() { 6 } else { 5 });
    writes.push((
        global_key.clone(),
        encode_pin_accounting_state(&global_usage, "global resource usage")?,
    ));
    writes.push((
        authority_key,
        encode_pin_accounting_state(&authority_usage, "authority resource usage")?,
    ));
    writes.push((
        pin_lineage_key(digest),
        encode_pin_accounting_state(&lineage, "manifest lineage")?,
    ));
    if let Some((parent_digest, parent_lineage)) = parent_update {
        writes.push((
            pin_lineage_key(&parent_digest),
            encode_pin_accounting_state(&parent_lineage, "parent manifest lineage")?,
        ));
    }
    writes.push((pin_expiry_key(retention_epoch, digest), Vec::new()));
    writes.push((status_key, Vec::new()));
    Ok(PinAccountingMutation {
        writes,
        removals: Vec::new(),
    })
}
fn prepare_pin_retirement_accounting(
    state_transaction: &StateTransaction<'_, '_>,
    record: &PinManifestRecord,
    retired_status: &PinStatus,
) -> Result<PinAccountingMutation, InstructionExecutionError> {
    let world = state_transaction.world();
    let global_usage = read_pin_usage(world, pin_global_usage_key(), "global resource usage")?
        .ok_or_else(|| pin_accounting_corruption("global resource summary is missing"))?
        .checked_release_content(record.content_length)
        .ok_or_else(|| pin_accounting_corruption("global resource summary underflow"))?;
    let authority_key = pin_authority_usage_key(&record.submitted_by)?;
    let authority_usage = read_pin_usage(world, &authority_key, "authority resource usage")?
        .ok_or_else(|| pin_accounting_corruption("authority resource summary is missing"))?
        .checked_release_content(record.content_length)
        .ok_or_else(|| pin_accounting_corruption("authority resource summary underflow"))?;
    read_pin_lineage(world, &record.digest)?.ok_or_else(|| {
        pin_accounting_corruption(format!(
            "manifest {} has no lineage summary",
            manifest_hex(&record.digest)
        ))
    })?;
    let status_transition = prepare_pin_status_transition(
        state_transaction,
        &record.digest,
        &record.status,
        retired_status,
    )?;
    let mut writes = Vec::with_capacity(status_transition.writes.len() + 2);
    writes.push((
        pin_global_usage_key().clone(),
        encode_pin_accounting_state(&global_usage, "global resource usage")?,
    ));
    writes.push((
        authority_key,
        encode_pin_accounting_state(&authority_usage, "authority resource usage")?,
    ));
    if let Some(parent_digest) = record.successor_of {
        let parent_lineage = read_pin_lineage(world, &parent_digest)?.ok_or_else(|| {
            pin_accounting_corruption(format!(
                "parent manifest {} has no lineage summary",
                manifest_hex(&parent_digest)
            ))
        })?;
        if parent_lineage.direct_successor_count == 0 {
            return Err(pin_accounting_corruption(format!(
                "parent manifest {} has no retained successor charge",
                manifest_hex(&parent_digest)
            )));
        }
    }
    writes.extend(status_transition.writes);
    let mut removals = vec![pin_expiry_key(
        record.policy.retention_epoch,
        &record.digest,
    )];
    removals.extend(status_transition.removals);
    Ok(PinAccountingMutation { writes, removals })
}
fn parse_pin_expiry_key(
    key: &StatePath,
) -> Result<(u64, ManifestDigest), InstructionExecutionError> {
    let tail = key
        .as_ref()
        .strip_prefix(PIN_EXPIRY_STATE_KEY_PREFIX_V1)
        .ok_or_else(|| pin_accounting_corruption("expiry key is outside its state namespace"))?;
    let (epoch_hex, digest_hex) = tail
        .split_once('/')
        .ok_or_else(|| pin_accounting_corruption(format!("malformed expiry key `{key}`")))?;
    if epoch_hex.len() != 16
        || !epoch_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || !is_canonical_lower_hex(digest_hex, 32)
    {
        return Err(pin_accounting_corruption(format!(
            "non-canonical expiry key `{key}`"
        )));
    }
    let retention_epoch = u64::from_str_radix(epoch_hex, 16).map_err(|error| {
        pin_accounting_corruption(format!("invalid expiry epoch in `{key}`: {error}"))
    })?;
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(digest_hex, &mut digest).map_err(|error| {
        pin_accounting_corruption(format!("invalid manifest digest in `{key}`: {error}"))
    })?;
    Ok((retention_epoch, ManifestDigest::new(digest)))
}
/// Retire every pin whose prepaid retention window has elapsed at this block's consensus timestamp.
///
/// The expiry index is part of authenticated world state. All due retirements
/// are staged in one state transaction so a corrupt marker or accounting
/// summary rejects the complete block effect without a partial release.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PinExpiryMaintenanceError {
    /// A local World owner or finite pool refused the original transaction.
    #[error(transparent)]
    Storage(#[from] StateStorageAdmissionError),
    /// Authenticated pin accounting or retirement was invalid.
    #[error(transparent)]
    Instruction(#[from] InstructionExecutionError),
}
pub(crate) fn expire_pin_manifests_at_consensus_time(
    state_block: &mut StateBlock<'_>,
) -> Result<usize, PinExpiryMaintenanceError> {
    let mut state_transaction = state_block.try_transaction()?;
    let consensus_epoch = state_transaction.block_unix_timestamp_ms() / 1_000;
    let prefix = StatePath::from_str(PIN_EXPIRY_STATE_KEY_PREFIX_V1)
        .expect("static pin expiry prefix is valid");
    let maximum = usize::try_from(state_transaction.gov.sorafs_pin_policy.max_global_manifests)
        .unwrap_or(usize::MAX);
    let mut due = Vec::new();
    for (key, marker) in state_transaction.world.smart_contract_state.range(prefix..) {
        if !key.as_ref().starts_with(PIN_EXPIRY_STATE_KEY_PREFIX_V1) {
            break;
        }
        if !marker.is_empty() {
            return Err(pin_accounting_corruption(format!(
                "expiry marker `{key}` must have an empty value"
            ))
            .into());
        }
        let (retention_epoch, digest) = parse_pin_expiry_key(key)?;
        if retention_epoch > consensus_epoch {
            break;
        }
        if due.len() >= maximum {
            return Err(pin_accounting_corruption(format!(
                "due expiry marker count exceeds configured global manifest ceiling {maximum}"
            ))
            .into());
        }
        due.push((retention_epoch, digest));
    }
    for (retention_epoch, digest) in &due {
        let record = state_transaction
            .world
            .pin_manifests
            .get(digest)
            .cloned()
            .ok_or_else(|| {
                pin_accounting_corruption(format!(
                    "expiry marker for {} has no manifest record",
                    manifest_hex(digest)
                ))
            })?;
        if record.policy.retention_epoch != *retention_epoch
            || !pin_record_has_live_content_charge(&record)
        {
            return Err(pin_accounting_corruption(format!(
                "expiry marker for {} disagrees with its live manifest record",
                manifest_hex(digest)
            ))
            .into());
        }
        let authority = record.submitted_by.clone();
        iroha_data_model::isi::sorafs::RetirePinManifest {
            digest: *digest,
            reason: Some("consensus retention expired".to_owned()),
        }
        .execute(&authority, &mut state_transaction)?;
    }
    let expired = due.len();
    if expired != 0 {
        state_transaction.apply();
    }
    Ok(expired)
}
pub(super) fn decode_capacity_declaration_payload(
    bytes: &[u8],
) -> Result<CapacityDeclarationV1, String> {
    if bytes.is_empty() || bytes.len() > MAX_CAPACITY_DECLARATION_PAYLOAD_BYTES {
        return Err(format!(
            "payload has {} bytes; expected 1..={MAX_CAPACITY_DECLARATION_PAYLOAD_BYTES}",
            bytes.len()
        ));
    }
    decode_canonical_with_limits::<CapacityDeclarationV1>(bytes, CAPACITY_DECLARATION_DECODE_LIMITS)
        .map_err(|error| {
            if matches!(&error, norito::Error::NonCanonicalEncoding) {
                "payload must use canonical first-release Norito".to_owned()
            } else {
                error.to_string()
            }
        })
}
fn decode_capacity_dispute_payload(bytes: &[u8]) -> Result<CapacityDisputeV1, String> {
    if bytes.is_empty() || bytes.len() > MAX_CAPACITY_DISPUTE_PAYLOAD_BYTES {
        return Err(format!(
            "payload has {} bytes; expected 1..={MAX_CAPACITY_DISPUTE_PAYLOAD_BYTES}",
            bytes.len()
        ));
    }
    decode_canonical_with_limits::<CapacityDisputeV1>(bytes, CAPACITY_DISPUTE_DECODE_LIMITS)
        .map_err(|error| {
            if matches!(&error, norito::Error::NonCanonicalEncoding) {
                "payload must use canonical first-release Norito".to_owned()
            } else {
                error.to_string()
            }
        })
}
fn storage_class_metadata_key() -> &'static Name {
    static KEY: OnceLock<Name> = OnceLock::new();
    KEY.get_or_init(|| {
        STORAGE_CLASS_METADATA_KEY
            .parse()
            .expect("static storage class metadata key must parse")
    })
}
fn parse_storage_class_label(
    provider_id: ProviderId,
    value: &str,
) -> Result<StorageClass, InstructionExecutionError> {
    let provider_hex = hex::encode(provider_id.as_bytes());
    let class = match value {
        "hot" => StorageClass::Hot,
        "warm" => StorageClass::Warm,
        "cold" => StorageClass::Cold,
        _ => {
            return Err(invalid_parameter(format!(
                "capacity declaration metadata `{STORAGE_CLASS_METADATA_KEY}` for provider {provider_hex} must be exactly one of lowercase hot, warm, or cold (found `{value}`)"
            )));
        }
    };
    Ok(class)
}
fn storage_class_from_declaration_metadata(
    provider_id: ProviderId,
    metadata: &Metadata,
) -> Result<StorageClass, InstructionExecutionError> {
    let Some(json_value) = metadata.get(storage_class_metadata_key()) else {
        return Err(invalid_parameter(format!(
            "capacity declaration for provider {} must explicitly declare metadata `{STORAGE_CLASS_METADATA_KEY}`",
            hex::encode(provider_id.as_bytes())
        )));
    };
    let value: String = json_value.try_into_any().map_err(|err| {
        invalid_parameter(format!(
            "capacity declaration metadata `{STORAGE_CLASS_METADATA_KEY}` for provider {} must be a string: {err}",
            hex::encode(provider_id.as_bytes())
        ))
    })?;
    parse_storage_class_label(provider_id, &value)
}
fn storage_class_from_declaration_record(
    record: &CapacityDeclarationRecord,
) -> Result<StorageClass, InstructionExecutionError> {
    storage_class_from_declaration_metadata(record.provider_id, &record.metadata)
}
fn merge_declaration_metadata_into_record(
    provider_id: ProviderId,
    record_metadata: &mut Metadata,
    declaration_metadata: &[CapacityMetadataEntry],
) -> Result<(), InstructionExecutionError> {
    if declaration_metadata.is_empty() {
        return Ok(());
    }
    let provider_hex = hex::encode(provider_id.as_bytes());
    for entry in declaration_metadata {
        let key: Name = entry.key.parse().map_err(|err| {
            invalid_parameter(format!(
                "capacity declaration metadata key `{}` for provider {} is invalid: {err}",
                entry.key, provider_hex
            ))
        })?;
        if let Some(existing) = record_metadata.get(&key) {
            let existing_str: String = existing.try_into_any().map_err(|err| {
                invalid_parameter(format!(
                    "capacity declaration metadata `{}` for provider {} must be a string to match payload: {err}",
                    entry.key, provider_hex
                ))
            })?;
            if existing_str != entry.value {
                return Err(invalid_parameter(format!(
                    "capacity declaration metadata conflict for provider {} on key `{}`: record value `{}`, payload value `{}`",
                    provider_hex, entry.key, existing_str, entry.value
                )));
            }
            continue;
        }
        record_metadata.insert(key, Json::new(entry.value.clone()));
    }
    Ok(())
}
/// Validate the canonical payload and every consensus-trusted summary field of a stored capacity
/// declaration.
pub(crate) fn validate_stored_capacity_declaration(
    record: &CapacityDeclarationRecord,
    record_label: &str,
) -> Result<CapacityDeclarationV1, InstructionExecutionError> {
    let invalid = |reason: String| {
        InstructionExecutionError::InvariantViolation(
            format!("capacity declaration {record_label} is invalid: {reason}").into(),
        )
    };
    let declaration = decode_capacity_declaration_payload(&record.declaration)
        .map_err(|error| invalid(format!("canonical payload could not be decoded: {error}")))?;
    declaration
        .validate()
        .map_err(|error| invalid(format!("payload failed validation: {error}")))?;
    if ProviderId::new(declaration.provider_id) != record.provider_id {
        return Err(invalid(
            "payload provider does not match the stored provider".to_owned(),
        ));
    }
    if declaration.committed_capacity_gib != record.committed_capacity_gib {
        return Err(invalid(
            "payload capacity does not match the stored capacity summary".to_owned(),
        ));
    }
    if declaration.valid_from != record.valid_from_epoch
        || declaration.valid_until != record.valid_until_epoch
    {
        return Err(invalid(
            "payload validity timestamps do not exactly match the stored Unix-second summary"
                .to_owned(),
        ));
    }
    if record.registered_epoch > record.valid_until_epoch {
        return Err(invalid(
            "registration timestamp is later than the declaration validity horizon".to_owned(),
        ));
    }
    let payload_storage_class = declaration
        .metadata
        .iter()
        .find(|entry| entry.key == STORAGE_CLASS_METADATA_KEY)
        .ok_or_else(|| {
            invalid(format!(
                "canonical payload must explicitly declare metadata `{STORAGE_CLASS_METADATA_KEY}`"
            ))
        })
        .and_then(|entry| {
            parse_storage_class_label(record.provider_id, &entry.value)
                .map_err(|error| invalid(error.to_string()))
        })?;
    let payload_owner = declaration
        .metadata
        .iter()
        .find(|entry| entry.key == PROVIDER_OWNER_METADATA_KEY)
        .ok_or_else(|| {
            invalid(format!(
                "canonical payload must explicitly declare metadata `{PROVIDER_OWNER_METADATA_KEY}`"
            ))
        })?;
    let mut merged_metadata = record.metadata.clone();
    merge_declaration_metadata_into_record(
        record.provider_id,
        &mut merged_metadata,
        &declaration.metadata,
    )
    .map_err(|error| {
        // The outer instruction Display is a category; retain its canonical
        // inner parameter reason when explaining invalid stored metadata.
        let reason = std::error::Error::source(&error)
            .map_or_else(|| error.to_string(), |source| source.to_string());
        invalid(reason)
    })?;
    if merged_metadata != record.metadata {
        return Err(invalid(
            "stored metadata does not retain every canonical payload entry".to_owned(),
        ));
    }
    let owner_key: Name = PROVIDER_OWNER_METADATA_KEY
        .parse()
        .expect("static provider owner metadata key must parse");
    let retained_owner: String = record
        .metadata
        .get(&owner_key)
        .ok_or_else(|| {
            invalid(format!(
                "stored metadata must explicitly retain `{PROVIDER_OWNER_METADATA_KEY}`"
            ))
        })?
        .try_into_any()
        .map_err(|error| invalid(format!("stored owner metadata is not a string: {error}")))?;
    if retained_owner != payload_owner.value {
        return Err(invalid(
            "canonical payload owner does not exactly match retained record metadata".to_owned(),
        ));
    }
    let record_storage_class =
        storage_class_from_declaration_metadata(record.provider_id, &record.metadata)
            .map_err(|error| invalid(error.to_string()))?;
    if payload_storage_class != record_storage_class {
        return Err(invalid(
            "canonical payload storage class does not match retained record metadata".to_owned(),
        ));
    }
    Ok(declaration)
}
fn enforce_provider_owner(
    authority: &AccountId,
    metadata: &Metadata,
    provider_hex: &str,
) -> Result<(), InstructionExecutionError> {
    let key = Name::from_str(PROVIDER_OWNER_METADATA_KEY).expect("static metadata key");
    let Some(value) = metadata.get(&key) else {
        return Err(invalid_parameter(format!(
            "capacity declaration metadata `{PROVIDER_OWNER_METADATA_KEY}` for provider {provider_hex} must be present"
        )));
    };
    let owner_str: String = value.try_into_any().map_err(|err| {
        invalid_parameter(format!(
            "capacity declaration metadata `{PROVIDER_OWNER_METADATA_KEY}` for provider {provider_hex} must be a string: {err}"
        ))
    })?;
    if owner_str == authority.to_string() {
        return Ok(());
    }
    Err(invalid_parameter(format!(
        "capacity declaration metadata `{PROVIDER_OWNER_METADATA_KEY}` for provider {provider_hex} must exactly equal the governed owner's canonical I105 account id"
    )))
}
fn ensure_provider_owner_matches_authority(
    authority: &AccountId,
    record: &CapacityDeclarationRecord,
) -> Result<(), InstructionExecutionError> {
    let provider_hex = hex::encode(record.provider_id.as_bytes());
    enforce_provider_owner(authority, &record.metadata, &provider_hex)
}
fn ensure_provider_owner_registered(
    state_transaction: &StateTransaction<'_, '_>,
    provider: &ProviderId,
    authority: &AccountId,
) -> Result<(), InstructionExecutionError> {
    if let Some(owner) = state_transaction.world.provider_owners.get(provider) {
        if owner != authority {
            return Err(invalid_parameter(format!(
                "provider {provider:?} owned by {owner}, but {authority} attempted a SoraFS operation"
            )));
        }
        return Ok(());
    }
    Err(invalid_parameter(format!(
        "provider {provider:?} has no registered owner"
    )))
}
impl Execute for iroha_data_model::isi::sorafs::RegisterProviderOwner {
    fn execute(
        self,
        _authority: &AccountId,
        _state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        Err(invalid_parameter(format!(
            "direct SoraFS provider-owner registration is retired for provider {}; enact a SorafsProviderGovernance proposal",
            hex::encode(self.provider_id.as_bytes())
        )))
    }
}
impl Execute for iroha_data_model::isi::sorafs::UnregisterProviderOwner {
    fn execute(
        self,
        _authority: &AccountId,
        _state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        Err(invalid_parameter(format!(
            "direct SoraFS provider-owner removal is retired for provider {}; enact a SorafsProviderGovernance proposal",
            hex::encode(self.provider_id.as_bytes())
        )))
    }
}
fn refresh_provider_musubi_locations(
    provider_id: ProviderId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let mut cursor = None;
    while let Some(location) =
        next_musubi_location_for_provider(provider_id, cursor, state_transaction)
    {
        super::musubi::refresh_musubi_locations(&[location], state_transaction)?;
        cursor = Some(location);
    }
    Ok(())
}
fn ensure_provider_not_needed_by_pending_replication(
    provider_id: ProviderId,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), InstructionExecutionError> {
    for (order_id, record) in state_transaction.world.replication_orders.iter() {
        if !matches!(record.status, ReplicationOrderStatus::Pending) {
            continue;
        }
        let order_label = order_hex(order_id);
        let payload = validate_stored_replication_order(record, &order_label)?;
        let is_assigned = payload
            .assignments
            .iter()
            .any(|assignment| assignment.provider_id == *provider_id.as_bytes());
        let completion_retained = record
            .provider_completions
            .iter()
            .any(|completion| completion.provider_id == provider_id);
        if is_assigned && !completion_retained {
            return Err(invalid_parameter(format!(
                "provider {} is still required by pending replication order {order_label} without a retained completion",
                hex::encode(provider_id.as_bytes())
            )));
        }
    }
    Ok(())
}
fn ensure_provider_owner_can_change(
    provider_id: ProviderId,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let provider_hex = hex::encode(provider_id.as_bytes());
    ensure_provider_not_needed_by_pending_replication(provider_id, state_transaction)?;
    if state_transaction
        .world
        .capacity_declarations
        .get(&provider_id)
        .is_some()
    {
        return Err(invalid_parameter(format!(
            "provider {provider_hex} has a live capacity declaration; governance cannot change its owner until provider economics are retired"
        )));
    }
    if super::sorafs_reserve::read_provider(state_transaction.world(), provider_id)?.is_some() {
        return Err(invalid_parameter(format!(
            "provider {provider_hex} has an owner-bound reserve account; governance cannot change its owner until reserve custody is retired"
        )));
    }
    Ok(())
}
/// Apply one action-bound provider-owner transition after successful referendum enactment.
///
/// `Ok(false)` means that the compare-and-set precondition is stale. No state
/// is changed in that case, allowing the governance lifecycle to record the
/// proposal as superseded instead of overwriting a newer binding.
pub(super) fn apply_governed_provider_owner_action(
    action: iroha_data_model::isi::sorafs::SorafsProviderGovernanceActionV1,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<bool, Error> {
    use iroha_data_model::isi::sorafs::SorafsProviderGovernanceActionV1;
    action.validate().map_err(|error| {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            error.to_string(),
        ))
    })?;
    match action {
        SorafsProviderGovernanceActionV1::Admission(action) => {
            return super::sorafs_provider_admission::apply(action, state_transaction);
        }
        SorafsProviderGovernanceActionV1::Establish(action) => {
            if state_transaction
                .world
                .provider_owners
                .get(&action.provider_id)
                .is_some()
            {
                return Ok(false);
            }
            state_transaction.world.account(&action.owner)?;
            state_transaction
                .world
                .provider_owners
                .insert(action.provider_id, action.owner.clone());
            grant_repair_worker_permission(state_transaction, &action.owner, action.provider_id);
            refresh_provider_musubi_locations(action.provider_id, state_transaction)?;
        }
        SorafsProviderGovernanceActionV1::Rebind(action) => {
            let Some(current_owner) = state_transaction
                .world
                .provider_owners
                .get(&action.provider_id)
                .cloned()
            else {
                return Ok(false);
            };
            if current_owner != action.expected_owner {
                return Ok(false);
            }
            ensure_provider_owner_can_change(action.provider_id, state_transaction)?;
            state_transaction.world.account(&action.next_owner)?;
            state_transaction
                .world
                .provider_owners
                .insert(action.provider_id, action.next_owner.clone());
            revoke_repair_worker_permission(state_transaction, &current_owner, action.provider_id);
            grant_repair_worker_permission(
                state_transaction,
                &action.next_owner,
                action.provider_id,
            );
            state_transaction
                .world
                .provider_ingest_completion_authorities
                .remove(action.provider_id);
            refresh_provider_musubi_locations(action.provider_id, state_transaction)?;
        }
        SorafsProviderGovernanceActionV1::Remove(action) => {
            let Some(current_owner) = state_transaction
                .world
                .provider_owners
                .get(&action.provider_id)
                .cloned()
            else {
                return Ok(false);
            };
            if current_owner != action.expected_owner {
                return Ok(false);
            }
            ensure_provider_owner_can_change(action.provider_id, state_transaction)?;
            let mut cursor = None;
            while let Some(location) =
                next_musubi_location_for_provider(action.provider_id, cursor, state_transaction)
            {
                super::musubi::ensure_provider_may_be_removed(
                    action.provider_id,
                    &[location],
                    state_transaction.world(),
                )?;
                cursor = Some(location);
            }
            state_transaction
                .world
                .provider_owners
                .remove(action.provider_id);
            revoke_repair_worker_permission(state_transaction, &current_owner, action.provider_id);
            state_transaction
                .world
                .provider_ingest_completion_authorities
                .remove(action.provider_id);
            refresh_provider_musubi_locations(action.provider_id, state_transaction)?;
        }
    }
    Ok(true)
}
fn validate_provider_ingest_completion_authority_successor(
    current: Option<&ProviderIngestCompletionAuthorityV1>,
    next: &ProviderIngestCompletionAuthorityV1,
) -> Result<(), InstructionExecutionError> {
    if !next.is_valid() {
        return Err(invalid_parameter(
            "provider-ingest completion authority has a zero policy identity, revision, or digest",
        ));
    }
    let Some(current) = current else {
        if next.signer_policy.revision != 1 || next.signer_policy.predecessor_digest.is_some() {
            return Err(invalid_parameter(
                "initial provider-ingest completion signer-policy identity must begin at revision 1 without a predecessor",
            ));
        }
        return Ok(());
    };
    if current == next {
        return Ok(());
    }
    let current_policy = current.signer_policy;
    let next_policy = next.signer_policy;
    if current_policy.policy_id == next_policy.policy_id {
        let expected_revision = current_policy.revision.checked_add(1).ok_or_else(|| {
            invalid_parameter("provider-ingest completion signer-policy revision overflow")
        })?;
        if next_policy.revision != expected_revision
            || next_policy.predecessor_digest != Some(current_policy.policy_digest)
            || next_policy.policy_digest == current_policy.policy_digest
        {
            return Err(invalid_parameter(
                "provider-ingest completion signer policy must be an exact predecessor-bound monotonic successor",
            ));
        }
    } else if next_policy.revision != 1 || next_policy.predecessor_digest.is_some() {
        return Err(invalid_parameter(
            "replacement provider-ingest completion signer-policy identity must begin at revision 1 without a predecessor",
        ));
    }
    Ok(())
}
impl Execute for iroha_data_model::isi::sorafs::SetProviderIngestCompletionAuthority {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let provider_owner = state_transaction
            .world
            .provider_owners
            .get(&self.provider_id)
            .ok_or_else(|| {
                invalid_parameter(format!(
                    "provider {} has no registered owner",
                    hex::encode(self.provider_id.as_bytes())
                ))
            })?;
        if provider_owner != authority {
            return Err(invalid_parameter(
                "provider-ingest completion authority may be set only by the exact governed provider owner",
            )
            .into());
        }
        if provider_owner != &self.next.provider_owner {
            return Err(invalid_parameter(
                "provider-ingest completion authority owner does not match the registered provider owner",
            )
            .into());
        }
        state_transaction.world.account(&self.next.provider_owner)?;
        state_transaction
            .world
            .account(&self.next.completion_signer)?;
        let current = state_transaction
            .world
            .provider_ingest_completion_authorities
            .get(&self.provider_id)
            .cloned();
        if current.as_ref() == Some(&self.next) {
            validate_provider_ingest_completion_authority_successor(current.as_ref(), &self.next)?;
            return Ok(());
        }
        if current != self.expected_current {
            return Err(invalid_parameter(
                "provider-ingest completion authority compare-and-set predecessor mismatch",
            )
            .into());
        }
        validate_provider_ingest_completion_authority_successor(current.as_ref(), &self.next)?;
        state_transaction
            .world
            .provider_ingest_completion_authorities
            .insert(self.provider_id, self.next);
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::sorafs::RevokeProviderIngestCompletionAuthority {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if !self.expected_current.is_valid() {
            return Err(invalid_parameter(
                "provider-ingest completion authority revocation is noncanonical",
            )
            .into());
        }
        let provider_owner = state_transaction
            .world
            .provider_owners
            .get(&self.provider_id)
            .ok_or_else(|| {
                invalid_parameter(format!(
                    "provider {} has no registered owner",
                    hex::encode(self.provider_id.as_bytes())
                ))
            })?;
        if provider_owner != authority || &self.expected_current.provider_owner != provider_owner {
            return Err(invalid_parameter(
                "provider-ingest completion authority may be revoked only by the exact governed provider owner",
            )
            .into());
        }
        let current = state_transaction
            .world
            .provider_ingest_completion_authorities
            .get(&self.provider_id);
        if current != Some(&self.expected_current) {
            return Err(invalid_parameter(
                "provider-ingest completion authority compare-and-remove predecessor mismatch",
            )
            .into());
        }
        ensure_provider_not_needed_by_pending_replication(self.provider_id, state_transaction)?;
        state_transaction
            .world
            .provider_ingest_completion_authorities
            .remove(self.provider_id);
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::sorafs::RegisterPinManifest {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Self {
            manifest_payload,
            mut alias,
            successor_of,
        } = self;
        let submitted_epoch = pin_consensus_epoch(state_transaction);
        if manifest_payload.is_empty()
            || manifest_payload.len() > sorafs_manifest::MAX_MANIFEST_ENCODED_BYTES
        {
            return Err(invalid_parameter(format!(
                "manifest payload has {} bytes; expected 1..={}",
                manifest_payload.len(),
                sorafs_manifest::MAX_MANIFEST_ENCODED_BYTES,
            )));
        }
        let manifest =
            sorafs_manifest::decode_manifest_v1_canonical(&manifest_payload).map_err(|error| {
                invalid_parameter(format!("invalid canonical ManifestV1 payload: {error}"))
            })?;
        let mut manifest_constraints =
            manifest_pin_policy_constraints_from_config(&state_transaction.gov.sorafs_pin_policy);
        // The separately submitted approval envelope remains the authoritative
        // council gate. Embedded manifest signatures, when present, are still
        // verified by `validate_manifest`.
        manifest_constraints.require_council_signatures = false;
        validate_manifest(&manifest, &manifest_constraints).map_err(|error| {
            invalid_parameter(format!("manifest payload failed validation: {error}"))
        })?;
        let chunk_digest_sha3_256 = manifest.chunk_digest_sha3_256;
        let por_root = manifest.por_root;
        let digest = ManifestDigest::from_manifest(&manifest).map_err(|error| {
            invalid_parameter(format!("failed to derive manifest digest: {error}"))
        })?;
        let root_cid = ManifestRootCid::try_from_slice(&manifest.root_cid).map_err(|error| {
            invalid_parameter(format!("invalid manifest root CID width: {error}"))
        })?;
        let chunker = ChunkerProfileHandle {
            profile_id: manifest.chunking.profile_id.0,
            namespace: manifest.chunking.namespace.clone(),
            name: manifest.chunking.name.clone(),
            semver: manifest.chunking.semver.clone(),
            multihash_code: manifest.chunking.multihash_code,
        };
        let content_length = manifest.content_length;
        let policy = PinPolicy {
            min_replicas: manifest.pin_policy.min_replicas,
            storage_class: match manifest.pin_policy.storage_class {
                ManifestStorageClass::Hot => StorageClass::Hot,
                ManifestStorageClass::Warm => StorageClass::Warm,
                ManifestStorageClass::Cold => StorageClass::Cold,
            },
            retention_epoch: manifest.pin_policy.retention_epoch,
        };
        if policy.retention_epoch <= submitted_epoch {
            return Err(invalid_parameter(format!(
                "manifest retention epoch {} must be greater than submission epoch {submitted_epoch}",
                policy.retention_epoch,
            )));
        }
        ensure_chunker_handle(&chunker)?;
        ensure_pin_policy(&policy, &state_transaction.gov.sorafs_pin_policy)?;
        if let Some(binding) = alias.as_mut() {
            require_permission(state_transaction, authority, "CanBindSorafsAlias")?;
            let canonical_proof = validate_manifest_alias_binding(
                binding,
                &digest,
                &root_cid,
                Some((submitted_epoch, policy.retention_epoch)),
            )?;
            binding.proof = canonical_proof;
            ensure_alias_unique(
                binding,
                &state_transaction.world.pin_manifests,
                &state_transaction.world.manifest_aliases,
                None,
            )?;
        }
        if let Some(successor_of) = &successor_of {
            if successor_of.as_bytes().iter().all(|byte| *byte == 0) {
                return Err(invalid_parameter(
                    "successor manifest digest must not be zero",
                ));
            }
        }
        if state_transaction.world.pin_manifests.get(&digest).is_some() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("manifest {} already registered", manifest_hex(&digest)).into(),
            ));
        }
        let requires_council_approval = state_transaction
            .gov
            .sorafs_pin_policy
            .require_council_signatures;
        let initial_status = if requires_council_approval {
            PinStatus::Pending
        } else {
            PinStatus::Approved(submitted_epoch)
        };
        let accounting = prepare_pin_admission_accounting(
            state_transaction,
            authority,
            &digest,
            successor_of.as_ref(),
            content_length,
            policy.retention_epoch,
            &initial_status,
        )?;
        let mut record = PinManifestRecord::new(
            digest,
            root_cid,
            chunker,
            chunk_digest_sha3_256,
            por_root,
            content_length,
            policy,
            authority.clone(),
            submitted_epoch,
            alias.clone(),
            successor_of,
            Metadata::default(),
        );
        if !requires_council_approval {
            record.approve(submitted_epoch, None);
        }
        let auto_order = if requires_council_approval {
            // Consensus must retain governed submissions as pending. Torii-side
            // manifest checks are only an early rejection layer and can be
            // bypassed by clients submitting the instruction directly.
            None
        } else {
            ensure_automatic_replication_order_slot_vacant(state_transaction, &record.digest)?;
            let auto_providers =
                select_auto_replication_providers(state_transaction, &record, submitted_epoch)?;
            Some(build_auto_replication_order(
                &record,
                authority,
                submitted_epoch,
                &auto_providers,
            )?)
        };
        // Keep every fallible validation/allocation step ahead of fee movement.
        let pin_fee_payment = collect_public_pin_fee(
            state_transaction,
            authority,
            &policy,
            content_length,
            submitted_epoch,
        )?;
        record.record_pin_fee_payment(pin_fee_payment);
        if !requires_council_approval {
            if let Some(alias) = &record.alias {
                ensure_alias_unique(
                    alias,
                    &state_transaction.world.pin_manifests,
                    &state_transaction.world.manifest_aliases,
                    Some(&digest),
                )?;
                bind_alias_record(
                    state_transaction,
                    alias,
                    &digest,
                    authority,
                    submitted_epoch,
                    record.policy.retention_epoch,
                );
            }
        }
        if let Some(order) = auto_order {
            state_transaction
                .world
                .replication_orders
                .insert(order.order_id, order);
        }
        state_transaction.world.pin_manifests.insert(digest, record);
        accounting.apply(state_transaction);
        Ok(())
    }
}
#[allow(clippy::too_many_lines)]
impl Execute for iroha_data_model::isi::sorafs::ApprovePinManifest {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let approved_epoch = pin_consensus_epoch(state_transaction);
        let Some(mut record) = state_transaction
            .world
            .pin_manifests
            .get(&self.digest)
            .cloned()
        else {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("manifest {} not registered", manifest_hex(&self.digest)).into(),
            ));
        };
        if approved_epoch < record.submitted_epoch {
            return Err(invalid_parameter(format!(
                "manifest {} approval epoch {} predates submission epoch {}",
                manifest_hex(&self.digest),
                approved_epoch,
                record.submitted_epoch,
            )));
        }
        if approved_epoch >= record.policy.retention_epoch {
            return Err(invalid_parameter(format!(
                "manifest {} approval epoch {} must be earlier than retention epoch {}",
                manifest_hex(&self.digest),
                approved_epoch,
                record.policy.retention_epoch,
            )));
        }
        let was_pending = matches!(record.status, PinStatus::Pending);
        let approved_status = PinStatus::Approved(approved_epoch);
        let status_transition = prepare_pin_status_transition(
            state_transaction,
            &self.digest,
            &record.status,
            &approved_status,
        )?;
        let executing_block_height = state_transaction._curr_block.height().get();
        let envelope_digest_from_envelope = self
            .council_envelope
            .as_deref()
            .map(|envelope| {
                verify_council_envelope(
                    &record,
                    envelope,
                    &state_transaction.gov.sorafs_pin_policy,
                    executing_block_height,
                )
            })
            .transpose()?;
        if let (Some(provided), Some(computed)) =
            (self.council_envelope_digest, envelope_digest_from_envelope)
            && provided != computed
        {
            return Err(invalid_parameter(format!(
                "manifest {} approval digest mismatch with provided envelope",
                manifest_hex(&self.digest)
            )));
        }
        let existing_digest = record.council_envelope_digest;
        let digest_to_store = match record.status {
            PinStatus::Pending => envelope_digest_from_envelope.ok_or_else(|| {
                invalid_parameter(format!(
                    "manifest {} approval requires council envelope payload",
                    manifest_hex(&self.digest)
                ))
            })?,
            PinStatus::Approved(existing_epoch) if existing_epoch == approved_epoch => {
                if let Some(existing) = existing_digest {
                    if envelope_digest_from_envelope.is_some_and(|digest| digest != existing)
                        || self
                            .council_envelope_digest
                            .is_some_and(|digest| digest != existing)
                    {
                        return Err(invalid_parameter(format!(
                            "manifest {} re-approval cannot replace its stored council envelope digest",
                            manifest_hex(&self.digest)
                        )));
                    }
                    existing
                } else {
                    envelope_digest_from_envelope.ok_or_else(|| {
                        invalid_parameter(format!(
                            "manifest {} re-approval requires council envelope payload because no digest is stored",
                            manifest_hex(&self.digest)
                        ))
                    })?
                }
            }
            PinStatus::Approved(_) => {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "manifest {} already approved with different epoch",
                        manifest_hex(&self.digest)
                    )
                    .into(),
                ));
            }
            PinStatus::Retired(_) => {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "manifest {} is retired and cannot be approved",
                        manifest_hex(&self.digest)
                    )
                    .into(),
                ));
            }
        };
        record.approve(approved_epoch, Some(digest_to_store));
        if let Some(alias) = &record.alias {
            ensure_alias_unique(
                alias,
                &state_transaction.world.pin_manifests,
                &state_transaction.world.manifest_aliases,
                Some(&self.digest),
            )?;
        }
        let auto_order = if was_pending {
            ensure_automatic_replication_order_slot_vacant(state_transaction, &record.digest)?;
            let auto_providers =
                select_auto_replication_providers(state_transaction, &record, approved_epoch)?;
            Some(build_auto_replication_order(
                &record,
                authority,
                approved_epoch,
                &auto_providers,
            )?)
        } else {
            None
        };
        // Do not publish an alias until every fallible approval step has
        // completed. This keeps a failed automatic-order build from exposing a
        // binding for a manifest that remains pending.
        if let Some(alias) = &record.alias {
            bind_alias_record(
                state_transaction,
                alias,
                &self.digest,
                authority,
                approved_epoch,
                record.policy.retention_epoch,
            );
        }
        if let Some(order) = auto_order {
            state_transaction
                .world
                .replication_orders
                .insert(order.order_id, order);
        }
        state_transaction
            .world
            .pin_manifests
            .insert(self.digest, record);
        status_transition.apply(state_transaction);
        Ok(())
    }
}
fn invalid_parameter(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
        message.into(),
    ))
}
fn has_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &str,
) -> bool {
    let matches = |grant: &Permission| {
        // Borrow canonical JSON so null remains distinct from "null", including
        // when the enclosing instruction has exhausted its decode allocation budget.
        grant.name() == permission && grant.payload().get().as_str() == "null"
    };
    let direct = state_transaction
        .world
        .account_permissions
        .get(authority)
        .is_some_and(|perms| perms.iter().any(matches));
    direct
        || state_transaction
            .world
            .account_roles_iter(authority)
            .filter_map(|role_id| state_transaction.world.roles.get(role_id))
            .any(|role| role.permissions().any(matches))
}
fn require_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &str,
) -> Result<(), Error> {
    if has_permission(state_transaction, authority, permission) {
        Ok(())
    } else {
        Err(invalid_parameter(format!(
            "permission {permission} required for SoraFS operation"
        )))
    }
}
fn grant_repair_worker_permission(
    state_transaction: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    provider_id: ProviderId,
) {
    let permission = Permission::from(CanOperateSorafsRepair { provider_id });
    if let Some(perms) = state_transaction.world.account_permissions.get_mut(owner) {
        perms.insert(permission);
    } else {
        let mut perms = Permissions::new();
        perms.insert(permission);
        state_transaction
            .world
            .account_permissions
            .insert(owner.clone(), perms);
    }
}
fn revoke_repair_worker_permission(
    state_transaction: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    provider_id: ProviderId,
) {
    let permission = Permission::from(CanOperateSorafsRepair { provider_id });
    if let Some(perms) = state_transaction.world.account_permissions.get_mut(owner) {
        perms.remove(&permission);
    }
}
#[allow(clippy::too_many_lines)]
fn verify_council_envelope(
    record: &PinManifestRecord,
    envelope: &[u8],
    approval_policy: &iroha_config::parameters::actual::SorafsPinPolicyConstraints,
    executing_block_height: u64,
) -> Result<[u8; 32], InstructionExecutionError> {
    const ALLOWED_ENVELOPE_FIELDS: &[&str] = &[
        "chunk_digest_sha3_256",
        "manifest",
        "manifest_blake3",
        "profile",
        "profile_aliases",
        "signatures",
    ];

    let manifest_label = manifest_hex(&record.digest);
    validate_council_approval_policy(approval_policy, executing_block_height, &manifest_label)?;
    if envelope.is_empty() || envelope.len() > MAX_COUNCIL_ENVELOPE_BYTES {
        return Err(invalid_parameter(format!(
            "council envelope for manifest {manifest_label} is {} bytes; expected 1..={MAX_COUNCIL_ENVELOPE_BYTES}",
            envelope.len(),
        )));
    }
    let parsed: Value = json::from_slice(envelope).map_err(|err| {
        invalid_parameter(format!(
            "invalid council envelope JSON for manifest {manifest_label}: {err}"
        ))
    })?;
    let obj = parsed.as_object().ok_or_else(|| {
        invalid_parameter(format!(
            "council envelope for manifest {manifest_label} must be a JSON object"
        ))
    })?;
    if let Some(unknown) = obj
        .keys()
        .find(|field| !ALLOWED_ENVELOPE_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid_parameter(format!(
            "council envelope for manifest {manifest_label} contains unknown field `{unknown}`"
        )));
    }
    if let Some(manifest_name) = obj.get("manifest") {
        let manifest_name = manifest_name.as_str().ok_or_else(|| {
            invalid_parameter(format!(
                "council envelope `manifest` field for manifest {manifest_label} must be a string"
            ))
        })?;
        if manifest_name.is_empty()
            || manifest_name.len() > MAX_COUNCIL_ENVELOPE_MANIFEST_NAME_BYTES
            || manifest_name != manifest_name.trim()
            || manifest_name.chars().any(char::is_control)
        {
            return Err(invalid_parameter(format!(
                "council envelope `manifest` field for manifest {manifest_label} is not canonical"
            )));
        }
    }
    let expected_manifest_hex = hex::encode(record.digest.as_bytes());
    let manifest_hex_field = obj
        .get("manifest_blake3")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_parameter(format!(
                "council envelope for manifest {manifest_label} missing `manifest_blake3` field"
            ))
        })?;
    if manifest_hex_field != expected_manifest_hex {
        return Err(invalid_parameter(format!(
            "council envelope manifest digest `{manifest_hex_field}` does not match registered digest `{expected_manifest_hex}` for manifest {manifest_label}"
        )));
    }
    let expected_chunk_hex = hex::encode(record.chunk_digest_sha3_256);
    let chunk_hex_field = obj
        .get("chunk_digest_sha3_256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
                invalid_parameter(format!(
                    "council envelope for manifest {manifest_label} missing `chunk_digest_sha3_256` field"
                ))
        })?;
    if chunk_hex_field != expected_chunk_hex {
        return Err(invalid_parameter(format!(
            "council envelope chunk digest `{chunk_hex_field}` does not match registered digest `{expected_chunk_hex}` for manifest {manifest_label}"
        )));
    }
    let canonical_profile = record.chunker.to_handle();
    let profile_field = obj.get("profile").and_then(Value::as_str).ok_or_else(|| {
        invalid_parameter(format!(
            "council envelope for manifest {manifest_label} missing `profile` field"
        ))
    })?;
    if profile_field != canonical_profile {
        return Err(invalid_parameter(format!(
            "council envelope profile `{profile_field}` does not match registered profile `{canonical_profile}` for manifest {manifest_label}"
        )));
    }
    if let Some(aliases_value) = obj.get("profile_aliases") {
        let aliases = aliases_value.as_array().ok_or_else(|| {
            invalid_parameter(format!(
                "council envelope aliases for manifest {manifest_label} must be an array"
            ))
        })?;
        if aliases.is_empty() || aliases.len() > MAX_COUNCIL_ENVELOPE_PROFILE_ALIASES {
            return Err(invalid_parameter(format!(
                "council envelope aliases for manifest {manifest_label} must contain 1..={MAX_COUNCIL_ENVELOPE_PROFILE_ALIASES} entries"
            )));
        }
        let descriptor = sorafs_manifest::chunker_registry::lookup(ProfileId(
            record.chunker.profile_id,
        ))
        .ok_or_else(|| {
            invalid_parameter(format!(
                "council envelope for manifest {manifest_label} references unknown chunker profile"
            ))
        })?;
        let mut seen = BTreeSet::new();
        for alias in aliases {
            let alias = alias.as_str().ok_or_else(|| {
                invalid_parameter(format!(
                    "council envelope aliases for manifest {manifest_label} must be strings"
                ))
            })?;
            if !descriptor.aliases.contains(&alias) {
                return Err(invalid_parameter(format!(
                    "council envelope for manifest {manifest_label} contains unknown profile alias `{alias}`"
                )));
            }
            if !seen.insert(alias) {
                return Err(invalid_parameter(format!(
                    "council envelope for manifest {manifest_label} repeats profile alias `{alias}`"
                )));
            }
        }
        if !seen.contains(canonical_profile.as_str()) {
            return Err(invalid_parameter(format!(
                "council envelope aliases for manifest {manifest_label} must include canonical profile `{canonical_profile}`"
            )));
        }
    }
    let signatures = obj
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_parameter(format!(
                "council envelope for manifest {manifest_label} missing `signatures` array"
            ))
        })?;
    if signatures.is_empty() {
        return Err(invalid_parameter(format!(
            "council envelope for manifest {manifest_label} must include at least one signature entry"
        )));
    }
    if signatures.len() > MAX_COUNCIL_ENVELOPE_SIGNATURES {
        return Err(invalid_parameter(format!(
            "council envelope for manifest {manifest_label} contains {} signatures; maximum is {MAX_COUNCIL_ENVELOPE_SIGNATURES}",
            signatures.len(),
        )));
    }
    let mut previous_signer: Option<[u8; 32]> = None;
    let mut verified_signatures = 0_usize;
    for entry in signatures {
        const ALLOWED_SIGNATURE_FIELDS: &[&str] =
            &["algorithm", "signature", "signer", "signer_multihash"];

        let entry = entry.as_object().ok_or_else(|| {
            invalid_parameter(format!(
                "council envelope signature entries for manifest {manifest_label} must be objects"
            ))
        })?;
        if let Some(unknown) = entry
            .keys()
            .find(|field| !ALLOWED_SIGNATURE_FIELDS.contains(&field.as_str()))
        {
            return Err(invalid_parameter(format!(
                "council envelope signature for manifest {manifest_label} contains unknown field `{unknown}`"
            )));
        }
        let algorithm = entry
            .get("algorithm")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid_parameter(format!(
                    "council envelope signature entry for manifest {manifest_label} missing `algorithm` field"
                ))
            })?;
        if algorithm != "ed25519" {
            return Err(invalid_parameter(format!(
                "unsupported council signature algorithm `{algorithm}` for manifest {manifest_label}"
            )));
        }
        let signer_hex = entry
            .get("signer")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid_parameter(format!(
                    "council envelope signature entry for manifest {manifest_label} missing `signer` field"
                ))
            })?;
        if !is_canonical_lower_hex(signer_hex, 32) {
            return Err(invalid_parameter(format!(
                "council signer `{signer_hex}` for manifest {manifest_label} must be exactly 32 bytes of lowercase hex"
            )));
        }
        let signer_bytes = hex::decode(signer_hex).map_err(|err| {
            invalid_parameter(format!(
                "invalid signer hex `{signer_hex}` in council envelope for manifest {manifest_label}: {err}"
            ))
        })?;
        let signer_array: [u8; 32] = signer_bytes.as_slice().try_into().map_err(|_| {
            invalid_parameter(format!(
                "council signer `{signer_hex}` for manifest {manifest_label} must be 32 bytes"
            ))
        })?;
        if previous_signer.is_some_and(|previous| previous >= signer_array) {
            return Err(invalid_parameter(format!(
                "council envelope signatures for manifest {manifest_label} must have distinct signer keys in canonical order"
            )));
        }
        previous_signer = Some(signer_array);
        let public_key = PublicKey::from_bytes(Algorithm::Ed25519, &signer_bytes).map_err(|err| {
            invalid_parameter(format!(
                "failed to parse council signer `{signer_hex}` for manifest {manifest_label}: {err}"
            ))
        })?;
        let trusted_signer = approval_policy
            .approval_signers
            .iter()
            .find(|trusted| trusted.public_key == public_key)
            .ok_or_else(|| {
                invalid_parameter(format!(
                    "council signer `{signer_hex}` for manifest {manifest_label} is not present in the governed approval roster"
                ))
            })?;
        if !trusted_signer.is_active_at(executing_block_height) {
            let reason = if executing_block_height < trusted_signer.valid_from_block_height {
                format!(
                    "is not active until block {}",
                    trusted_signer.valid_from_block_height
                )
            } else {
                format!(
                    "was revoked at block {}",
                    trusted_signer
                        .revoked_at_block_height
                        .expect("inactive post-activation signer must be revoked")
                )
            };
            return Err(invalid_parameter(format!(
                "council signer `{signer_hex}` for manifest {manifest_label} {reason}; executing block is {executing_block_height}"
            )));
        }
        let signature_hex = entry
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid_parameter(format!(
                    "council envelope signature entry for manifest {manifest_label} missing `signature` field"
                ))
            })?;
        if !is_canonical_lower_hex(signature_hex, 64) {
            return Err(invalid_parameter(format!(
                "council signature for signer `{signer_hex}` in manifest {manifest_label} must be exactly 64 bytes of lowercase hex"
            )));
        }
        let signature_bytes = hex::decode(signature_hex).map_err(|err| {
            invalid_parameter(format!(
                "invalid signature hex for signer `{signer_hex}` in manifest {manifest_label}: {err}"
            ))
        })?;
        let signature = ed25519_parse_signature(&signature_bytes).map_err(|err| {
            invalid_parameter(format!(
                "invalid council signature material for signer `{signer_hex}` in manifest {manifest_label}: {err}"
            ))
        })?;
        signature.verify(&public_key, record.digest.as_bytes()).map_err(|err| {
            invalid_parameter(format!(
                "failed to verify council signature for signer `{signer_hex}` in manifest {manifest_label}: {err}"
            ))
        })?;
        if let Some(multihash) = entry.get("signer_multihash") {
            let multihash = multihash.as_str().ok_or_else(|| {
                invalid_parameter(format!(
                    "council signature `signer_multihash` for signer `{signer_hex}` in manifest {manifest_label} must be a string"
                ))
            })?;
            let expected_multihash = public_key.to_string();
            if multihash != expected_multihash {
                return Err(invalid_parameter(format!(
                    "council signature for signer `{signer_hex}` in manifest {manifest_label} has multihash `{multihash}` but expected `{expected_multihash}`"
                )));
            }
        }
        verified_signatures = verified_signatures
            .checked_add(1)
            .ok_or_else(|| invalid_parameter("council signature count overflow"))?;
    }
    if verified_signatures < usize::from(approval_policy.approval_quorum) {
        return Err(invalid_parameter(format!(
            "council envelope for manifest {manifest_label} has {verified_signatures} active trusted signatures; approval quorum is {}",
            approval_policy.approval_quorum
        )));
    }
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(blake3::hash(envelope).as_bytes());
    Ok(digest_bytes)
}
fn validate_council_approval_policy(
    policy: &iroha_config::parameters::actual::SorafsPinPolicyConstraints,
    executing_block_height: u64,
    manifest_label: &str,
) -> Result<(), InstructionExecutionError> {
    if policy.approval_signers.is_empty() {
        return Err(invalid_parameter(format!(
            "governed approval signer roster is empty for manifest {manifest_label}"
        )));
    }
    if policy.approval_signers.len() > MAX_COUNCIL_ENVELOPE_SIGNATURES {
        return Err(invalid_parameter(format!(
            "governed approval signer roster for manifest {manifest_label} contains {} entries; maximum is {MAX_COUNCIL_ENVELOPE_SIGNATURES}",
            policy.approval_signers.len()
        )));
    }
    if policy.approval_quorum == 0
        || usize::from(policy.approval_quorum) > policy.approval_signers.len()
    {
        return Err(invalid_parameter(format!(
            "governed approval quorum {} is invalid for {} signers on manifest {manifest_label}",
            policy.approval_quorum,
            policy.approval_signers.len()
        )));
    }
    let mut previous_signer_id: Option<&str> = None;
    let mut public_keys = BTreeSet::new();
    let mut active_signers = 0_usize;
    for signer in &policy.approval_signers {
        let signer_id_is_canonical = !signer.signer_id.is_empty()
            && signer.signer_id.len() <= 128
            && signer.signer_id.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_' | b':')
            });
        if !signer_id_is_canonical
            || previous_signer_id.is_some_and(|previous| previous >= signer.signer_id.as_str())
        {
            return Err(invalid_parameter(format!(
                "governed approval signer ids for manifest {manifest_label} must be canonical and strictly ordered"
            )));
        }
        previous_signer_id = Some(&signer.signer_id);
        if signer.public_key.algorithm() != Algorithm::Ed25519 {
            return Err(invalid_parameter(format!(
                "governed approval signer `{}` for manifest {manifest_label} is not Ed25519",
                signer.signer_id
            )));
        }
        if !public_keys.insert(signer.public_key.clone()) {
            return Err(invalid_parameter(format!(
                "governed approval roster for manifest {manifest_label} contains duplicate public keys"
            )));
        }
        if signer
            .revoked_at_block_height
            .is_some_and(|revoked_at| revoked_at <= signer.valid_from_block_height)
        {
            return Err(invalid_parameter(format!(
                "governed approval signer `{}` for manifest {manifest_label} has an invalid activation/revocation window",
                signer.signer_id
            )));
        }
        if signer.is_active_at(executing_block_height) {
            active_signers = active_signers
                .checked_add(1)
                .ok_or_else(|| invalid_parameter("active approval signer count overflow"))?;
        }
    }
    if active_signers < usize::from(policy.approval_quorum) {
        return Err(invalid_parameter(format!(
            "governed approval roster for manifest {manifest_label} has {active_signers} active signers at executing block {executing_block_height}; quorum is {}",
            policy.approval_quorum
        )));
    }
    Ok(())
}
fn is_canonical_lower_hex(value: &str, decoded_len: usize) -> bool {
    decoded_len.checked_mul(2) == Some(value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn ensure_chunker_handle(
    chunker: &iroha_data_model::sorafs::pin_registry::ChunkerProfileHandle,
) -> Result<(), InstructionExecutionError> {
    validate_chunker_handle(
        ProfileId(chunker.profile_id),
        &chunker.namespace,
        &chunker.name,
        &chunker.semver,
        chunker.multihash_code,
        None,
    )
    .map(|_| ())
    .map_err(|err| manifest_error(&err))
}
fn ensure_pin_policy(
    policy: &iroha_data_model::sorafs::pin_registry::PinPolicy,
    constraints: &iroha_config::parameters::actual::SorafsPinPolicyConstraints,
) -> Result<(), InstructionExecutionError> {
    let manifest_policy = ManifestPinPolicy {
        min_replicas: policy.min_replicas,
        storage_class: convert_storage_class(policy.storage_class),
        retention_epoch: policy.retention_epoch,
    };
    let manifest_constraints = manifest_pin_policy_constraints_from_config(constraints);
    validate_pin_policy(&manifest_policy, &manifest_constraints).map_err(|err| manifest_error(&err))
}
fn convert_storage_class(
    storage_class: iroha_data_model::sorafs::pin_registry::StorageClass,
) -> ManifestStorageClass {
    match storage_class {
        iroha_data_model::sorafs::pin_registry::StorageClass::Hot => ManifestStorageClass::Hot,
        iroha_data_model::sorafs::pin_registry::StorageClass::Warm => ManifestStorageClass::Warm,
        iroha_data_model::sorafs::pin_registry::StorageClass::Cold => ManifestStorageClass::Cold,
    }
}
fn order_hex(order_id: &ReplicationOrderId) -> String {
    hex::encode(order_id.as_bytes())
}
const AUTO_REPLICATION_ORDER_AVAILABILITY_PERCENT_MILLI: u32 = 99_500;
const AUTO_REPLICATION_ORDER_POR_SUCCESS_PERCENT_MILLI: u32 = 98_000;
fn automatic_replication_slice_gib(content_length: u64) -> Result<u64, InstructionExecutionError> {
    let whole_gib = content_length / BYTES_PER_GIB;
    let partial_gib = u64::from(!content_length.is_multiple_of(BYTES_PER_GIB));
    whole_gib
        .checked_add(partial_gib)
        .map(|slice_gib| slice_gib.max(1))
        .ok_or_else(|| invalid_parameter("automatic replication slice size overflow"))
}
fn automatic_replication_deadline_epoch(
    issued_epoch: u64,
) -> Result<u64, InstructionExecutionError> {
    issued_epoch
        .checked_add(u64::from(
            SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1,
        ))
        .ok_or_else(|| invalid_parameter("automatic replication deadline epoch overflow"))
}
fn ensure_automatic_replication_order_slot_vacant(
    state_transaction: &StateTransaction<'_, '_>,
    digest: &ManifestDigest,
) -> Result<(), InstructionExecutionError> {
    let order_id = derive_sorafs_auto_replication_order_id_v1(digest);
    if state_transaction
        .world
        .replication_orders
        .get(&order_id)
        .is_some()
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "automatic replication order {} already exists for manifest {}",
                order_hex(&order_id),
                manifest_hex(digest)
            )
            .into(),
        ));
    }
    Ok(())
}
/// Return the exact-profile capacity available to a pin throughout an automatic order window.
pub(crate) fn automatic_replication_profile_capacity_gib(
    declaration_record: &CapacityDeclarationRecord,
    pin: &PinManifestRecord,
    issued_epoch: u64,
    deadline_epoch: u64,
) -> Result<Option<u64>, InstructionExecutionError> {
    let provider_label = hex::encode(declaration_record.provider_id.as_bytes());
    let declaration = validate_stored_capacity_declaration(declaration_record, &provider_label)?;
    if issued_epoch < declaration_record.valid_from_epoch
        || deadline_epoch > declaration_record.valid_until_epoch
        || storage_class_from_declaration_metadata(
            declaration_record.provider_id,
            &declaration_record.metadata,
        )? != pin.policy.storage_class
    {
        return Ok(None);
    }
    let canonical_profile = pin.chunker.to_handle();
    Ok(declaration
        .chunker_commitments
        .iter()
        .find(|commitment| commitment.profile_id == canonical_profile)
        .map(|commitment| commitment.committed_gib)
        .filter(|committed_gib| *committed_gib <= declaration.committed_capacity_gib))
}
fn active_automatic_allocations(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<BTreeMap<(ProviderId, String), u64>, InstructionExecutionError> {
    let mut allocations = BTreeMap::<(ProviderId, String), u64>::new();
    for (order_id, record) in state_transaction.world.replication_orders.iter() {
        if !order_id.is_auto() {
            continue;
        }
        if record.order_id != *order_id {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "automatic replication order key {} does not match its stored identifier",
                    order_hex(order_id)
                )
                .into(),
            ));
        }
        let pin = state_transaction
            .world
            .pin_manifests
            .get(&record.manifest_digest)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "automatic replication order {} references a missing pin",
                        order_hex(order_id)
                    )
                    .into(),
                )
            })?;
        let payload =
            validate_stored_automatic_replication_order(pin, record, &order_hex(order_id))?;
        if !matches!(pin.status, PinStatus::Approved(_))
            || !matches!(
                record.status,
                ReplicationOrderStatus::Pending | ReplicationOrderStatus::Completed(_)
            )
        {
            continue;
        }
        for assignment in &payload.assignments {
            let provider_id = ProviderId::new(assignment.provider_id);
            let allocated = allocations
                .entry((provider_id, payload.chunking_profile.clone()))
                .or_default();
            *allocated = allocated.checked_add(assignment.slice_gib).ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "automatic replication capacity allocation overflowed for provider {}",
                        hex::encode(provider_id.as_bytes())
                    )
                    .into(),
                )
            })?;
        }
    }
    Ok(allocations)
}
fn ensure_capacity_covers_active_automatic_allocations(
    state_transaction: &StateTransaction<'_, '_>,
    provider_id: ProviderId,
    declaration_record: &CapacityDeclarationRecord,
    declaration: &CapacityDeclarationV1,
) -> Result<(), InstructionExecutionError> {
    for (order_id, order) in state_transaction.world.replication_orders.iter() {
        if !order_id.is_auto()
            || !matches!(
                order.status,
                ReplicationOrderStatus::Pending | ReplicationOrderStatus::Completed(_)
            )
        {
            continue;
        }
        let pin = state_transaction
            .world
            .pin_manifests
            .get(&order.manifest_digest)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "automatic replication order {} references a missing pin",
                        order_hex(order_id)
                    )
                    .into(),
                )
            })?;
        if !matches!(pin.status, PinStatus::Approved(_)) {
            continue;
        }
        let payload =
            validate_stored_automatic_replication_order(pin, order, &order_hex(order_id))?;
        if payload
            .assignments
            .iter()
            .any(|assignment| assignment.provider_id == *provider_id.as_bytes())
            && automatic_replication_profile_capacity_gib(
                declaration_record,
                pin,
                order.issued_epoch,
                order.deadline_epoch,
            )?
            .is_none()
        {
            return Err(invalid_parameter(format!(
                "capacity declaration for provider {} no longer covers the profile, storage class, and deadline of active automatic order {}",
                hex::encode(provider_id.as_bytes()),
                order_hex(order_id)
            )));
        }
    }
    for ((allocated_provider, profile), allocated_gib) in
        active_automatic_allocations(state_transaction)?
    {
        if allocated_provider != provider_id {
            continue;
        }
        let committed_gib = declaration
            .chunker_commitments
            .iter()
            .find(|commitment| commitment.profile_id == profile)
            .map_or(0, |commitment| commitment.committed_gib);
        if allocated_gib > committed_gib {
            return Err(invalid_parameter(format!(
                "capacity declaration for provider {} commits {committed_gib} GiB to profile `{profile}`, below its active automatic allocation of {allocated_gib} GiB",
                hex::encode(provider_id.as_bytes())
            )));
        }
    }
    Ok(())
}
fn select_auto_replication_providers(
    state_transaction: &StateTransaction<'_, '_>,
    pin: &PinManifestRecord,
    issued_epoch: u64,
) -> Result<Vec<ProviderId>, InstructionExecutionError> {
    let required_replicas = usize::from(pin.policy.min_replicas);
    if required_replicas == 0 {
        return Ok(Vec::new());
    }
    let canonical_profile = pin.chunker.to_handle();
    let deadline_epoch = automatic_replication_deadline_epoch(issued_epoch)?;
    let slice_gib = automatic_replication_slice_gib(pin.content_length)?;
    let active_allocations = active_automatic_allocations(state_transaction)?;
    let mut providers = Vec::new();
    providers.try_reserve_exact(required_replicas).map_err(|_| {
        invalid_parameter(format!(
            "failed to reserve automatic replication provider set of {required_replicas} entries"
        ))
    })?;
    for (provider_id, declaration_record) in state_transaction.world.capacity_declarations.iter() {
        if providers.len() == required_replicas {
            break;
        }
        if declaration_record.provider_id != *provider_id {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "capacity declaration key {} contains a record for {}",
                    hex::encode(provider_id.as_bytes()),
                    hex::encode(declaration_record.provider_id.as_bytes())
                )
                .into(),
            ));
        }
        let Some(provider_owner) = state_transaction.world.provider_owners.get(provider_id) else {
            continue;
        };
        let Some(completion_authority) = state_transaction
            .world
            .provider_ingest_completion_authorities
            .get(provider_id)
        else {
            continue;
        };
        if !completion_authority.is_valid()
            || &completion_authority.provider_owner != provider_owner
        {
            continue;
        }
        let Some(profile_capacity) = automatic_replication_profile_capacity_gib(
            declaration_record,
            pin,
            issued_epoch,
            deadline_epoch,
        )?
        else {
            continue;
        };
        let already_allocated = active_allocations
            .get(&(*provider_id, canonical_profile.clone()))
            .copied()
            .unwrap_or(0);
        let required_capacity = already_allocated.checked_add(slice_gib).ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                format!(
                    "automatic replication capacity allocation overflowed for provider {}",
                    hex::encode(provider_id.as_bytes())
                )
                .into(),
            )
        })?;
        if required_capacity > profile_capacity {
            continue;
        }
        providers.push(*provider_id);
    }
    if providers.len() != required_replicas {
        return Err(invalid_parameter(format!(
            "automatic replication requires {required_replicas} eligible providers but found {}",
            providers.len()
        )));
    }
    Ok(providers)
}
/// Install canonical capacity and completion-authority fixtures for automatic replication tests.
///
/// This fixture supplies the prerequisites of pin selection. It does not exercise
/// governed provider admission, bond custody, or finalized network execution.
///
/// # Errors
/// Returns an error for invalid capacity, overflowing validity, or a malformed declaration.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn seed_eligible_auto_replication_providers_for_test(
    state_transaction: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    count: u16,
    storage_class: StorageClass,
    profile: &ChunkerProfileHandle,
    consensus_epoch: u64,
    deadline_horizon_secs: u64,
    per_provider_gib: u64,
) -> Result<Vec<ProviderId>, InstructionExecutionError> {
    use sorafs_manifest::{
        capacity::{CAPACITY_DECLARATION_VERSION_V1, ChunkerCommitmentV1},
        provider_advert::StakePointer,
    };

    if per_provider_gib == 0 {
        return Err(invalid_parameter(
            "automatic replication test providers require positive profile capacity",
        ));
    }
    let valid_until = consensus_epoch
        .checked_add(deadline_horizon_secs)
        .ok_or_else(|| invalid_parameter("automatic replication test validity overflow"))?;
    if valid_until == consensus_epoch {
        return Err(invalid_parameter(
            "automatic replication test providers require a positive deadline horizon",
        ));
    }
    let profile_handle = profile.to_handle();
    let owner_literal = owner.to_string();
    let mut providers = Vec::new();
    providers
        .try_reserve_exact(usize::from(count))
        .map_err(|_| invalid_parameter("failed to reserve automatic replication test providers"))?;
    for index in 0..count {
        let mut provider_hasher = blake3::Hasher::new();
        provider_hasher.update(b"iroha.sorafs.auto-replication.test-provider.v1\0");
        provider_hasher.update(owner_literal.as_bytes());
        provider_hasher.update(&index.to_le_bytes());
        let mut provider_bytes = *provider_hasher.finalize().as_bytes();
        provider_bytes[31] |= 1;
        let provider_id = ProviderId::new(provider_bytes);

        let mut pool_id = provider_bytes;
        pool_id[0] ^= 0x5A;
        pool_id[31] |= 1;
        let declaration = CapacityDeclarationV1 {
            version: CAPACITY_DECLARATION_VERSION_V1,
            provider_id: provider_bytes,
            stake: StakePointer {
                pool_id,
                stake_amount: "1".parse().expect("static positive XOR stake must parse"),
            },
            committed_capacity_gib: per_provider_gib,
            chunker_commitments: vec![ChunkerCommitmentV1 {
                profile_id: profile_handle.clone(),
                profile_aliases: None,
                committed_gib: per_provider_gib,
                capability_refs: Vec::new(),
            }],
            lane_commitments: Vec::new(),
            pricing: None,
            valid_from: consensus_epoch,
            valid_until,
            metadata: vec![
                CapacityMetadataEntry {
                    key: PROVIDER_OWNER_METADATA_KEY.to_owned(),
                    value: owner_literal.clone(),
                },
                CapacityMetadataEntry {
                    key: STORAGE_CLASS_METADATA_KEY.to_owned(),
                    value: match storage_class {
                        StorageClass::Hot => "hot",
                        StorageClass::Warm => "warm",
                        StorageClass::Cold => "cold",
                    }
                    .to_owned(),
                },
            ],
        };
        declaration.validate().map_err(|error| {
            invalid_parameter(format!(
                "automatic replication test capacity declaration failed validation: {error}"
            ))
        })?;
        let mut metadata = Metadata::default();
        merge_declaration_metadata_into_record(provider_id, &mut metadata, &declaration.metadata)?;
        let record = CapacityDeclarationRecord::new(
            provider_id,
            norito::encode_canonical(&declaration).map_err(|error| {
                invalid_parameter(format!(
                    "failed to encode automatic replication test capacity declaration: {error}"
                ))
            })?,
            per_provider_gib,
            consensus_epoch,
            consensus_epoch,
            valid_until,
            metadata,
        );
        validate_stored_capacity_declaration(&record, &hex::encode(provider_id.as_bytes()))?;
        state_transaction
            .world
            .provider_owners
            .insert(provider_id, owner.clone());
        state_transaction.world.add_account_permission(
            owner,
            Permission::from(
                iroha_executor_data_model::permission::sorafs::CanCompleteSorafsReplicationOrder {
                    provider_id,
                },
            ),
        );
        state_transaction
            .world
            .provider_ingest_completion_authorities
            .insert(
                provider_id,
                ProviderIngestCompletionAuthorityV1::new(
                    owner.clone(),
                    owner.clone(),
                    ProviderIngestCompletionSignerPolicyV1 {
                        policy_id: provider_bytes,
                        revision: 1,
                        predecessor_digest: None,
                        policy_digest: pool_id,
                    },
                ),
            );
        state_transaction
            .world
            .capacity_declarations
            .insert(provider_id, record);
        providers.push(provider_id);
    }
    Ok(providers)
}
fn build_auto_replication_order(
    record: &PinManifestRecord,
    issued_by: &AccountId,
    issued_epoch: u64,
    assignments: &[ProviderId],
) -> Result<ReplicationOrderRecord, InstructionExecutionError> {
    let assignment_count = usize::from(record.policy.min_replicas);
    if assignments.len() != assignment_count {
        return Err(invalid_parameter(format!(
            "automatic replication requires exactly {assignment_count} assignments but received {}",
            assignments.len()
        )));
    }
    let mut canonical_assignments = Vec::new();
    canonical_assignments
        .try_reserve_exact(assignment_count)
        .map_err(|_| {
            invalid_parameter(format!(
                "failed to reserve automatic replication assignment set of {assignment_count} entries"
            ))
        })?;
    let slice_gib = automatic_replication_slice_gib(record.content_length)?;
    canonical_assignments.extend(assignments.iter().take(assignment_count).map(|provider| {
        ReplicationAssignmentV1 {
            provider_id: *provider.as_bytes(),
            slice_gib,
            lane: None,
        }
    }));
    let order_id = derive_sorafs_auto_replication_order_id_v1(&record.digest);
    // Pin-registry epochs and replication-order timestamps are both Unix seconds. Keep the
    // authoritative record and provider-facing payload on that one time base so completion
    // checks enforce the same 24-hour SLA that providers receive.
    let deadline_epoch = automatic_replication_deadline_epoch(issued_epoch)?;
    if deadline_epoch >= record.policy.retention_epoch {
        return Err(invalid_parameter(format!(
            "automatic replication deadline epoch {deadline_epoch} must be earlier than manifest retention epoch {}",
            record.policy.retention_epoch
        )));
    }
    let issued_at = issued_epoch;
    let deadline_at = deadline_epoch;
    let order = ReplicationOrderV1 {
        version: REPLICATION_ORDER_VERSION_V1,
        order_id: *order_id.as_bytes(),
        manifest_cid: record.root_cid.as_bytes().to_vec(),
        manifest_digest: *record.digest.as_bytes(),
        chunking_profile: record.chunker.to_handle(),
        target_replicas: record.policy.min_replicas,
        assignments: canonical_assignments,
        issued_at,
        deadline_at,
        sla: ReplicationOrderSlaV1 {
            ingest_deadline_secs: SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1,
            min_availability_percent_milli: AUTO_REPLICATION_ORDER_AVAILABILITY_PERCENT_MILLI,
            min_por_success_percent_milli: AUTO_REPLICATION_ORDER_POR_SUCCESS_PERCENT_MILLI,
        },
        metadata: Vec::new(),
    };
    order.validate().map_err(|error| {
        InstructionExecutionError::InvariantViolation(
            format!("automatic replication order failed validation: {error}").into(),
        )
    })?;
    let canonical_order = norito::encode_canonical(&order).map_err(|error| {
        InstructionExecutionError::InvariantViolation(
            format!("failed to encode automatic replication order: {error}").into(),
        )
    })?;
    let stored_order = ReplicationOrderRecord {
        order_id,
        manifest_digest: record.digest,
        manifest_root_cid: record.root_cid,
        musubi_archive: None,
        issued_by: issued_by.clone(),
        issued_epoch,
        deadline_epoch,
        canonical_order,
        assignment_revision: 1,
        provider_completions: Vec::new(),
        status: ReplicationOrderStatus::Pending,
    };
    validate_stored_automatic_replication_order(
        record,
        &stored_order,
        &order_hex(&stored_order.order_id),
    )?;
    Ok(stored_order)
}
#[cfg(test)]
pub(crate) fn completed_auto_replication_order_for_test(
    pin: &PinManifestRecord,
    issued_by: &AccountId,
) -> Result<ReplicationOrderRecord, InstructionExecutionError> {
    let provider_id = ProviderId::new([0xD5; 32]);
    let issued_epoch = match pin.status {
        PinStatus::Approved(epoch) => epoch,
        PinStatus::Pending | PinStatus::Retired(_) => pin.submitted_epoch,
    };
    let mut order = build_auto_replication_order(pin, issued_by, issued_epoch, &[provider_id])?;
    let completion_authority = ProviderIngestCompletionAuthorityV1::new(
        issued_by.clone(),
        issued_by.clone(),
        ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [0xD6; 32],
            revision: 1,
            predecessor_digest: None,
            policy_digest: [0xD7; 32],
        },
    );
    order
        .provider_completions
        .push(ReplicationOrderCompletionRecord {
            provider_id,
            completed_by: issued_by.clone(),
            completion_epoch: issued_epoch,
            assignment_revision: order.assignment_revision,
            completion_authority,
            finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                height: 1,
                block_hash: *iroha_crypto::Hash::new(
                    b"completed automatic replication order fixture block",
                )
                .as_ref(),
            },
        });
    order.status = ReplicationOrderStatus::Completed(issued_epoch);
    Ok(order)
}
fn collect_public_pin_fee(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    policy: &PinPolicy,
    content_length: u64,
    submitted_epoch: u64,
) -> Result<PinFeePayment, InstructionExecutionError> {
    let amount = state_transaction
        .world
        .sorafs_pricing
        .get()
        .public_pin_fee(
            policy.storage_class,
            content_length,
            policy.min_replicas,
            submitted_epoch,
            policy.retention_epoch,
        )
        .map_err(|error| pricing_computation_error("public pin fee", error))?;
    let fee_asset_id = state_transaction.gov.sorafs_pin_fee_asset_id.clone();
    let treasury_account_id = state_transaction
        .gov
        .sorafs_pin_fee_treasury_account
        .clone();
    let source_id = AssetId::new(fee_asset_id.clone(), authority.clone());
    crate::smartcontracts::isi::asset::isi::execute_user_numeric_asset_transfer(
        state_transaction,
        authority,
        source_id,
        treasury_account_id.clone(),
        amount.clone(),
    )?;
    Ok(PinFeePayment {
        paid_by: authority.clone(),
        fee_asset_id,
        treasury_account_id,
        amount,
    })
}
fn manifest_error(err: &ManifestValidationError) -> InstructionExecutionError {
    invalid_parameter(format!("manifest validation failed: {err}"))
}
fn validate_manifest_alias_binding(
    alias: &ManifestAliasBinding,
    expected_manifest: &ManifestDigest,
    expected_root_cid: &ManifestRootCid,
    expected_epoch_bounds: Option<(u64, u64)>,
) -> Result<Vec<u8>, InstructionExecutionError> {
    validate_alias_segment(&alias.namespace, "namespace")?;
    validate_alias_segment(&alias.name, "name")?;
    if alias.proof.is_empty() {
        return Err(invalid_parameter(
            "alias proof must not be empty; provide AliasBindingV1 Norito payload".to_string(),
        ));
    }
    if alias.proof.len() > MAX_ALIAS_PROOF_BYTES {
        return Err(invalid_parameter(format!(
            "alias proof is {} bytes; maximum is {MAX_ALIAS_PROOF_BYTES}",
            alias.proof.len(),
        )));
    }
    let bundle = {
        // The manifest helper validates canonicality and recomputes the
        // Norito-derived binding leaf internally. Scope the complete verified
        // decode to the fixed V1 layout so caller ambient state cannot affect
        // proof admission or identity.
        let _canonical_flags =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        decode_alias_proof_untrusted_signers(&alias.proof)
    }
    .map_err(|err| invalid_parameter(format!("alias proof failed verification: {err}")))?;
    let expected_alias = format!("{}/{}", alias.namespace, alias.name);
    if bundle.binding.alias != expected_alias {
        return Err(invalid_parameter(format!(
            "alias proof alias `{}` does not match requested alias `{expected_alias}`",
            bundle.binding.alias
        )));
    }
    if bundle.binding.manifest_cid.as_slice() != expected_root_cid.as_bytes() {
        return Err(invalid_parameter(format!(
            "alias proof manifest CID does not match content root registered for manifest {}",
            manifest_hex(expected_manifest)
        )));
    }
    if let Some((bound_epoch, expiry_epoch)) = expected_epoch_bounds {
        if bundle.binding.bound_at != bound_epoch {
            return Err(invalid_parameter(format!(
                "alias proof bound_at {} does not match requested bound_epoch {}",
                bundle.binding.bound_at, bound_epoch
            )));
        }
        if bundle.binding.expiry_epoch != expiry_epoch {
            return Err(invalid_parameter(format!(
                "alias proof expiry_epoch {} does not match requested expiry_epoch {}",
                bundle.binding.expiry_epoch, expiry_epoch
            )));
        }
    }
    norito::encode_canonical(&bundle).map_err(|err| {
        invalid_parameter(format!("failed to canonicalize alias proof bundle: {err}"))
    })
}
fn validate_alias_segment(value: &str, field: &str) -> Result<(), InstructionExecutionError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid_parameter(format!(
            "alias {field} must not be empty"
        )));
    }
    if trimmed.len() > 128 {
        return Err(invalid_parameter(format!(
            "alias {field} `{trimmed}` exceeds 128 characters"
        )));
    }
    if trimmed != value {
        return Err(invalid_parameter(format!(
            "alias {field} must not include surrounding whitespace"
        )));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_'))
    {
        return Err(invalid_parameter(format!(
            "alias {field} `{trimmed}` contains invalid characters; expected lowercase ASCII, digits, '.', '-', '_'"
        )));
    }
    Ok(())
}
fn alias_label(alias: &ManifestAliasBinding) -> String {
    format!("{}/{}", alias.namespace, alias.name)
}
fn ensure_alias_unique(
    alias: &ManifestAliasBinding,
    manifests: &impl StorageReadOnly<ManifestDigest, PinManifestRecord>,
    alias_records: &impl StorageReadOnly<ManifestAliasId, ManifestAliasRecord>,
    current_manifest: Option<&ManifestDigest>,
) -> Result<(), InstructionExecutionError> {
    let requested = alias_label(alias);
    let alias_id = ManifestAliasId::from(alias);
    for (digest, record) in manifests.iter() {
        if record.alias.as_ref().is_some_and(|existing| {
            existing.namespace == alias.namespace && existing.name == alias.name
        }) && (current_manifest != Some(digest))
        {
            return Err(invalid_parameter(format!(
                "alias `{requested}` is already bound to manifest {}",
                manifest_hex(digest)
            )));
        }
    }
    if let Some(existing) = alias_records.get(&alias_id)
        && current_manifest.is_none_or(|current| !existing.targets_manifest(current))
    {
        return Err(invalid_parameter(format!(
            "alias `{requested}` is already associated with manifest {}",
            manifest_hex(&existing.manifest)
        )));
    }
    Ok(())
}
fn bind_alias_record(
    state_transaction: &mut StateTransaction<'_, '_>,
    alias: &ManifestAliasBinding,
    manifest: &ManifestDigest,
    authority: &AccountId,
    bound_epoch: u64,
    expiry_epoch: u64,
) {
    let alias_id = ManifestAliasId::from(alias);
    drop_alias_binding_if_matches(
        &mut state_transaction.world.manifest_aliases,
        alias,
        manifest,
    );
    let record = ManifestAliasRecord::new(
        alias.clone(),
        *manifest,
        authority.clone(),
        bound_epoch,
        expiry_epoch,
    );
    state_transaction
        .world
        .manifest_aliases
        .insert(alias_id, record);
}
fn drop_alias_binding_if_matches(
    aliases: &mut StorageTransaction<'_, ManifestAliasId, ManifestAliasRecord>,
    alias: &ManifestAliasBinding,
    manifest: &ManifestDigest,
) {
    let alias_id = ManifestAliasId::from(alias);
    if let Some(existing) = aliases.get(&alias_id)
        && existing.targets_manifest(manifest)
    {
        aliases.remove(alias_id);
    }
}
#[cfg(test)]
mod pin_policy_tests {
    use super::*;
    #[test]
    fn manifest_constraints_reflect_config() {
        use iroha_config::parameters::actual::SorafsPinPolicyConstraints as ConfigConstraints;
        use iroha_data_model::sorafs::pin_registry::StorageClass as DmStorageClass;
        let mut allowed = BTreeSet::new();
        allowed.insert(DmStorageClass::Hot);
        allowed.insert(DmStorageClass::Cold);
        let config = ConfigConstraints {
            min_replicas_floor: 2,
            max_replicas_ceiling: Some(4),
            max_retention_epoch: Some(10),
            allowed_storage_classes: Some(allowed.clone()),
            require_council_signatures: true,
            approval_quorum: 1,
            approval_signers: Vec::new(),
            ..ConfigConstraints::default()
        };
        let constraints = manifest_pin_policy_constraints_from_config(&config);
        assert_eq!(constraints.min_replicas_floor, 2);
        assert_eq!(constraints.max_replicas_ceiling, Some(4));
        assert_eq!(constraints.max_retention_epoch, Some(10));
        assert!(constraints.require_council_signatures);
        let produced = constraints
            .allowed_storage_classes
            .expect("allowed storage classes propagated");
        assert_eq!(
            produced,
            allowed
                .into_iter()
                .map(super::convert_storage_class)
                .collect::<BTreeSet<_>>()
        );
    }
}
impl Execute for iroha_data_model::isi::sorafs::RetirePinManifest {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let retired_epoch = pin_consensus_epoch(state_transaction);
        let Some(mut record) = state_transaction
            .world
            .pin_manifests
            .get(&self.digest)
            .cloned()
        else {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("manifest {} not registered", manifest_hex(&self.digest)).into(),
            ));
        };
        if &record.submitted_by != authority {
            return Err(invalid_parameter(format!(
                "only the authenticated submitter {} may retire manifest {}",
                record.submitted_by,
                manifest_hex(&self.digest),
            )));
        }
        let musubi_location = state_transaction
            .world
            .musubi_locations_by_pin
            .get(&self.digest)
            .filter(|reference| reference.active)
            .map(|reference| reference.location);
        if retired_epoch < record.submitted_epoch {
            return Err(invalid_parameter(format!(
                "manifest {} retirement epoch {} predates submission epoch {}",
                manifest_hex(&self.digest),
                retired_epoch,
                record.submitted_epoch,
            )));
        }
        if let PinStatus::Approved(approved_epoch) = record.status
            && retired_epoch < approved_epoch
        {
            return Err(invalid_parameter(format!(
                "manifest {} retirement epoch {} predates approval epoch {}",
                manifest_hex(&self.digest),
                retired_epoch,
                approved_epoch,
            )));
        }
        if let Some(reason) = self.reason.as_deref()
            && (reason.is_empty()
                || reason.len() > MAX_RETIREMENT_REASON_BYTES
                || reason != reason.trim()
                || reason.chars().any(char::is_control))
        {
            return Err(invalid_parameter(format!(
                "manifest {} retirement reason must be canonical, non-empty, control-free UTF-8 of at most {MAX_RETIREMENT_REASON_BYTES} bytes",
                manifest_hex(&self.digest),
            )));
        }
        if matches!(record.status, PinStatus::Retired(existing) if existing == retired_epoch)
            && record.retirement_reason.as_deref() == self.reason.as_deref()
        {
            return Ok(());
        }
        if let PinStatus::Retired(existing_epoch) = record.status {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "manifest {} already retired at epoch {}",
                    manifest_hex(&self.digest),
                    existing_epoch
                )
                .into(),
            ));
        }
        let automatic_order_id = derive_sorafs_auto_replication_order_id_v1(&self.digest);
        if retired_epoch < record.policy.retention_epoch
            && state_transaction
                .world
                .replication_orders
                .get(&automatic_order_id)
                .is_some_and(|order| {
                    order.manifest_digest == self.digest
                        && matches!(order.status, ReplicationOrderStatus::Completed(_))
                })
        {
            return Err(invalid_parameter(format!(
                "replicated manifest {} cannot retire before its promised retention epoch {}",
                manifest_hex(&self.digest),
                record.policy.retention_epoch,
            )));
        }
        let retired_status = PinStatus::Retired(retired_epoch);
        let accounting =
            prepare_pin_retirement_accounting(state_transaction, &record, &retired_status)?;
        if let Some(location) = musubi_location {
            super::musubi::ensure_locations_may_be_invalidated(
                &[location],
                state_transaction.world(),
            )?;
        }
        let pending_order_count = state_transaction
            .world
            .replication_orders
            .iter()
            .filter(|(_, order)| {
                order.manifest_digest == self.digest
                    && matches!(order.status, ReplicationOrderStatus::Pending)
            })
            .count();
        let mut pending_order_ids = Vec::new();
        pending_order_ids
            .try_reserve_exact(pending_order_count)
            .map_err(|_| {
                invalid_parameter(format!(
                    "failed to reserve {pending_order_count} replication-order retirements for manifest {}",
                    manifest_hex(&self.digest),
                ))
            })?;
        pending_order_ids.extend(
            state_transaction
                .world
                .replication_orders
                .iter()
                .filter(|(_, order)| {
                    order.manifest_digest == self.digest
                        && matches!(order.status, ReplicationOrderStatus::Pending)
                })
                .map(|(order_id, _)| *order_id),
        );
        for order_id in &pending_order_ids {
            let Some(order) = state_transaction.world.replication_orders.get(order_id) else {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "replication order {} disappeared while validating manifest {} retirement",
                        order_hex(order_id),
                        manifest_hex(&self.digest),
                    )
                    .into(),
                ));
            };
            if retired_epoch < order.issued_epoch {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "replication order {} issued at {} after manifest {} retirement epoch {retired_epoch}",
                        order_hex(order_id),
                        order.issued_epoch,
                        manifest_hex(&self.digest),
                    )
                    .into(),
                ));
            }
        }
        for order_id in pending_order_ids {
            let Some(mut order) = state_transaction
                .world
                .replication_orders
                .get(&order_id)
                .cloned()
            else {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "replication order {} disappeared while retiring manifest {}",
                        order_hex(&order_id),
                        manifest_hex(&self.digest),
                    )
                    .into(),
                ));
            };
            order.status = if retired_epoch <= order.deadline_epoch {
                ReplicationOrderStatus::Cancelled(retired_epoch)
            } else {
                ReplicationOrderStatus::Expired(retired_epoch)
            };
            state_transaction
                .world
                .replication_orders
                .insert(order_id, order);
        }
        if let Some(alias) = &record.alias {
            drop_alias_binding_if_matches(
                &mut state_transaction.world.manifest_aliases,
                alias,
                &self.digest,
            );
        }
        record.retire(retired_epoch, self.reason.clone());
        state_transaction
            .world
            .pin_manifests
            .insert(self.digest, record);
        accounting.apply(state_transaction);
        if let Some(location) = musubi_location {
            super::musubi::refresh_musubi_locations(&[location], state_transaction)?;
        }
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::sorafs::BindManifestAlias {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(state_transaction, authority, "CanBindSorafsAlias")?;
        let Self {
            digest,
            mut binding,
            bound_epoch,
            expiry_epoch,
        } = self;
        if expiry_epoch < bound_epoch {
            return Err(invalid_parameter(
                "alias expiry epoch must be greater than or equal to bound epoch",
            ));
        }
        let manifest_label = manifest_hex(&digest);
        let mut record = state_transaction
            .world
            .pin_manifests
            .get(&digest)
            .cloned()
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!("manifest {manifest_label} not registered").into(),
                )
            })?;
        let canonical_proof = validate_manifest_alias_binding(
            &binding,
            &digest,
            &record.root_cid,
            Some((bound_epoch, expiry_epoch)),
        )?;
        binding.proof = canonical_proof;
        if !matches!(record.status, PinStatus::Approved(_)) {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("manifest {manifest_label} must be approved before binding an alias")
                    .into(),
            ));
        }
        let approved_epoch = match record.status {
            PinStatus::Approved(epoch) => epoch,
            _ => unreachable!("checked above"),
        };
        if bound_epoch < approved_epoch {
            return Err(invalid_parameter(format!(
                "alias bound_epoch {bound_epoch} precedes manifest approval epoch {approved_epoch} \
                 for {manifest_label}"
            )));
        }
        if expiry_epoch > record.policy.retention_epoch {
            return Err(invalid_parameter(format!(
                "alias expiry epoch {expiry_epoch} exceeds manifest retention epoch \
                 {retention_epoch} for {manifest_label}",
                retention_epoch = record.policy.retention_epoch,
            )));
        }
        ensure_alias_unique(
            &binding,
            &state_transaction.world.pin_manifests,
            &state_transaction.world.manifest_aliases,
            Some(&digest),
        )?;
        if let Some(existing) = &record.alias
            && ManifestAliasId::from(existing) != ManifestAliasId::from(&binding)
        {
            drop_alias_binding_if_matches(
                &mut state_transaction.world.manifest_aliases,
                existing,
                &digest,
            );
        }
        bind_alias_record(
            state_transaction,
            &binding,
            &digest,
            authority,
            bound_epoch,
            expiry_epoch,
        );
        record.alias = Some(binding);
        state_transaction.world.pin_manifests.insert(digest, record);
        Ok(())
    }
}
fn provider_credit_locked_custody(
    record: &ProviderCreditRecord,
) -> Result<Quantity, InstructionExecutionError> {
    record.bonded.checked_add(&record.slashed).map_err(|error| {
        InstructionExecutionError::InvariantViolation(
            format!(
                "SoraFS provider credit bonded-plus-slashed custody commitment overflow: {error}"
            )
            .into(),
        )
    })
}
impl Execute for iroha_data_model::isi::sorafs::RegisterCapacityDeclaration {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let declaration =
            decode_capacity_declaration_payload(&self.declaration).map_err(|err| {
                invalid_parameter(format!("invalid capacity declaration payload: {err}"))
            })?;
        let provider_id = ProviderId::new(declaration.provider_id);
        let provider_hex = hex::encode(provider_id.as_bytes());
        declaration.validate().map_err(|err| {
            invalid_parameter(format!(
                "capacity declaration validation failed for provider {provider_hex}: {err}"
            ))
        })?;
        let payload_storage_class = declaration
            .metadata
            .iter()
            .find(|entry| entry.key == STORAGE_CLASS_METADATA_KEY)
            .ok_or_else(|| {
                invalid_parameter(format!(
                    "capacity declaration for provider {provider_hex} must explicitly declare metadata `{STORAGE_CLASS_METADATA_KEY}` in its canonical payload"
                ))
            })?;
        parse_storage_class_label(provider_id, &payload_storage_class.value)?;
        if !declaration
            .metadata
            .iter()
            .any(|entry| entry.key == PROVIDER_OWNER_METADATA_KEY)
        {
            return Err(invalid_parameter(format!(
                "capacity declaration for provider {provider_hex} must explicitly declare metadata `{PROVIDER_OWNER_METADATA_KEY}` in its canonical payload"
            )));
        }
        let consensus_epoch = pin_consensus_epoch(state_transaction);
        let mut record = CapacityDeclarationRecord::new(
            provider_id,
            self.declaration,
            declaration.committed_capacity_gib,
            consensus_epoch,
            declaration.valid_from,
            declaration.valid_until,
            Metadata::default(),
        );
        if consensus_epoch > record.valid_until_epoch {
            return Err(invalid_parameter(format!(
                "capacity declaration for provider {provider_hex} expired at Unix second {} before registration at {consensus_epoch}",
                record.valid_until_epoch
            )));
        }
        merge_declaration_metadata_into_record(
            provider_id,
            &mut record.metadata,
            &declaration.metadata,
        )?;
        validate_stored_capacity_declaration(&record, &provider_hex)?;
        ensure_capacity_covers_active_automatic_allocations(
            state_transaction,
            provider_id,
            &record,
            &declaration,
        )?;
        let registered_owner = state_transaction
            .world
            .provider_owners
            .get(&provider_id)
            .cloned()
            .ok_or_else(|| {
                invalid_parameter(format!(
                    "provider {provider_hex} has no governance-established owner"
                ))
            })?;
        if &registered_owner != authority {
            return Err(invalid_parameter(format!(
                "provider {provider_hex} is owned by {registered_owner}; capacity declarations require the exact registered owner authority {authority}"
            )));
        }
        enforce_provider_owner(&registered_owner, &record.metadata, &provider_hex)?;
        let verified_bond = super::sorafs_reserve::verified_provider_bond(
            state_transaction.world(),
            provider_id,
            &registered_owner,
            declaration.committed_capacity_gib,
        )?;
        let credit_record = state_transaction
            .world
            .provider_credit_ledger
            .get(&provider_id)
            .ok_or_else(|| {
                invalid_parameter(format!(
                    "provider {provider_hex} has no governance-established credit and bond record"
                ))
            })?;
        if credit_record.provider_id != provider_id {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "SoraFS provider credit key {provider_hex} contains a record for {}",
                    hex::encode(credit_record.provider_id.as_bytes())
                )
                .into(),
            ));
        }
        let locked_custody = provider_credit_locked_custody(credit_record)?;
        if &locked_custody != verified_bond.as_quantity() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "provider {provider_hex} credit projection commits bonded {} plus slashed {}, but owner-funded native reserve holds {}",
                    credit_record.bonded,
                    credit_record.slashed,
                    verified_bond.as_quantity()
                )
                .into(),
            ));
        }
        let declared_stake = declaration.stake.stake_amount.as_quantity();
        if credit_record.bonded.is_zero() || &credit_record.bonded < declared_stake {
            return Err(invalid_parameter(format!(
                "provider {provider_hex} declares stake {declared_stake}, but its unslashed custody-backed bond holds {}",
                credit_record.bonded
            )));
        }
        if credit_record.bonded < credit_record.required_bond {
            return Err(invalid_parameter(format!(
                "provider {provider_hex} unslashed custody-backed bond {} is below its governed requirement {}",
                credit_record.bonded, credit_record.required_bond
            )));
        }
        state_transaction
            .world
            .capacity_declarations
            .insert(provider_id, record.clone());
        let mut ledger = state_transaction
            .world
            .capacity_fee_ledger
            .get(&provider_id)
            .cloned()
            .unwrap_or_else(|| CapacityFeeLedgerEntry {
                provider_id,
                ..Default::default()
            });
        ledger.provider_id = provider_id;
        ledger.total_declared_gib = u128::from(declaration.committed_capacity_gib);
        ledger.last_updated_epoch = record.registered_epoch;
        state_transaction
            .world
            .capacity_fee_ledger
            .insert(provider_id, ledger);
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::sorafs::RecordCapacityTelemetry {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let record: CapacityTelemetryRecord = self.record;
        let provider_id = record.provider_id;
        let policy = &state_transaction.gov.sorafs_telemetry;
        let reject = |reason: &str| {
            #[cfg(feature = "telemetry")]
            {
                state_transaction
                    .telemetry
                    .record_sorafs_capacity_telemetry_reject(
                        &hex::encode(provider_id.as_bytes()),
                        reason,
                    );
            }
            Err(invalid_parameter(format!(
                "capacity telemetry rejected: {reason}"
            )))
        };
        if policy.require_submitter {
            if let Some(overrides) = policy.per_provider_submitters.get(&provider_id) {
                if !overrides.iter().any(|allowed| allowed == authority) {
                    return reject("unauthorised_submitter_provider");
                }
            } else if !policy.submitters.iter().any(|allowed| allowed == authority) {
                return reject("unauthorised_submitter");
            }
        }
        if policy.require_nonce && record.nonce == 0 {
            return reject("missing_nonce");
        }
        let declaration_record = state_transaction
            .world
            .capacity_declarations
            .get(&provider_id)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!("capacity telemetry received for unknown provider {provider_id:?}")
                        .into(),
                )
            })?;
        ensure_provider_owner_matches_authority(authority, declaration_record)?;
        if let Some(owner) = state_transaction.world.provider_owners.get(&provider_id)
            && owner != authority
        {
            return reject("provider_owner_mismatch");
        }
        let mut ledger = state_transaction
            .world
            .capacity_fee_ledger
            .get(&provider_id)
            .cloned()
            .unwrap_or_else(|| CapacityFeeLedgerEntry {
                provider_id,
                ..Default::default()
            });
        ledger.provider_id = provider_id;
        if policy.reject_zero_capacity
            && (record.declared_gib == 0 || record.effective_gib == 0 || record.utilised_gib == 0)
        {
            return reject("zero_capacity_window");
        }
        let committed_capacity = declaration_record.committed_capacity_gib;
        if record.declared_gib > committed_capacity
            || record.effective_gib > committed_capacity
            || record.utilised_gib > committed_capacity
        {
            return reject("capacity_exceeds_commitment");
        }
        if record.effective_gib > record.declared_gib || record.utilised_gib > record.declared_gib {
            return reject("capacity_exceeds_declaration");
        }
        if record.window_end_epoch <= record.window_start_epoch {
            return reject("invalid_window_bounds");
        }
        let Some(window_secs) = record
            .window_end_epoch
            .checked_sub(record.window_start_epoch)
        else {
            return reject("invalid_window_bounds");
        };
        if record.nonce != 0 && ledger.last_nonce == record.nonce {
            if record.window_start_epoch == ledger.last_window_start_epoch
                && record.window_end_epoch == ledger.last_window_end_epoch
            {
                // Idempotent submission: already applied.
                return Ok(());
            }
            return reject("replayed_nonce");
        }
        if ledger.last_window_end_epoch > 0 {
            if record.window_start_epoch < ledger.last_window_end_epoch {
                return reject("overlapping_window");
            }
            if record.window_end_epoch <= ledger.last_window_end_epoch {
                return reject("stale_window");
            }
            let Some(gap) = record
                .window_start_epoch
                .checked_sub(ledger.last_window_end_epoch)
            else {
                return reject("overlapping_window");
            };
            if gap > policy.max_window_gap.as_secs() {
                return reject("window_gap_exceeded");
            }
        }
        let pricing_schedule = state_transaction.world.sorafs_pricing.get();
        let storage_class = storage_class_from_declaration_record(declaration_record)?;
        let storage_fee = pricing_schedule
            .storage_charge(storage_class, record.utilised_gib, window_secs)
            .map_err(|error| pricing_computation_error("storage fee", error))?;
        let uptime_bps = u128::from(record.uptime_bps.min(10_000));
        let por_bps = u128::from(record.por_success_bps.min(10_000));
        let health_multiplier = uptime_bps.checked_mul(por_bps).ok_or_else(|| {
            pricing_computation_error(
                "health multiplier",
                PricingComputationError::ArithmeticOverflow("health multiplier"),
            )
        })?;
        let storage_fee =
            round_xor_quantity_ratio(&storage_fee, health_multiplier, 10_000_u128 * 10_000_u128)
                .map_err(|error| quantity_arithmetic_error("health-adjusted storage fee", error))?;
        let egress_fee = pricing_schedule
            .egress_charge_bytes(storage_class, record.egress_bytes)
            .map_err(|error| pricing_computation_error("egress fee", error))?;
        let expected_storage = pricing_schedule
            .expected_settlement_storage_charge(storage_class, record.utilised_gib)
            .map_err(|error| pricing_computation_error("expected settlement", error))?;
        let expected_settlement = expected_storage
            .checked_add(&egress_fee)
            .map_err(|error| quantity_arithmetic_error("expected settlement", error))?;
        ledger
            .accrue(&CapacityAccrual {
                declared_delta_gib: u128::from(record.declared_gib),
                utilised_delta_gib: u128::from(record.utilised_gib),
                storage_fee_delta: storage_fee.clone(),
                egress_fee_delta: egress_fee.clone(),
                expected_settlement: expected_settlement.clone(),
                window_start_epoch: record.window_start_epoch,
                window_end_epoch: record.window_end_epoch,
                nonce: record.nonce,
            })
            .map_err(|error| {
                InstructionExecutionError::InvariantViolation(
                    format!("SoraFS capacity fee ledger accrual failed: {error}").into(),
                )
            })?;
        let mut proof_alert: Option<SorafsProofHealthAlert> = None;
        if let Some(mut credit_record) = state_transaction
            .world
            .provider_credit_ledger
            .get(&provider_id)
            .cloned()
        {
            let debit = storage_fee
                .checked_add(&egress_fee)
                .map_err(|error| quantity_arithmetic_error("credit debit", error))?;
            credit_record
                .apply_charge(&debit, record.window_end_epoch)
                .map_err(|error| {
                    InstructionExecutionError::InvariantViolation(
                        format!("SoraFS provider credit charge failed: {error}").into(),
                    )
                })?;
            credit_record.required_bond = pricing_schedule
                .required_collateral(
                    storage_class,
                    record.utilised_gib,
                    credit_record.onboarding_epoch,
                    record.window_end_epoch,
                )
                .map_err(|error| pricing_computation_error("required collateral", error))?;
            credit_record.expected_settlement = expected_settlement.clone();
            let low_balance_threshold = pricing_schedule
                .low_balance_threshold(&expected_settlement)
                .map_err(|error| pricing_computation_error("low-balance threshold", error))?;
            credit_record.track_low_balance(&low_balance_threshold, record.window_end_epoch);
            let penalty_policy = &state_transaction.gov.sorafs_penalty;
            // Treat failure counters as authoritative even when challenge/window counters are
            // missing, so we don't suppress proof-failure penalties and alerts.
            let pdp_fail = record.pdp_failures > penalty_policy.max_pdp_failures;
            let potr_fail = record.potr_breaches > penalty_policy.max_potr_breaches;
            let proof_failure = pdp_fail || potr_fail;
            let penalties_enabled =
                penalty_policy.penalty_bond_bps > 0 && penalty_policy.strike_threshold > 0;
            if penalties_enabled {
                let utilisation_ratio_bps = if record.declared_gib == 0 {
                    10_000_u128
                } else {
                    checked_mul_div_round_u128(
                        u128::from(record.utilised_gib),
                        10_000,
                        u128::from(record.declared_gib),
                    )
                    .map_err(|error| pricing_computation_error("utilisation ratio", error))?
                };
                let utilisation_floor =
                    u128::from(penalty_policy.utilisation_floor_bps.min(10_000));
                let uptime_floor = u32::from(penalty_policy.uptime_floor_bps.min(10_000));
                let por_floor = u32::from(penalty_policy.por_success_floor_bps.min(10_000));
                let utilisation_fail = utilisation_ratio_bps < utilisation_floor;
                let uptime_fail = record.uptime_bps < uptime_floor;
                let por_success_below_floor = record.por_success_bps < por_floor;
                if proof_failure {
                    let previous_strikes = credit_record.under_delivery_strikes;
                    credit_record.under_delivery_strikes = penalty_policy.strike_threshold;
                    proof_alert = Some(SorafsProofHealthAlert {
                        provider_id,
                        window_start_epoch: record.window_start_epoch,
                        window_end_epoch: record.window_end_epoch,
                        prior_strikes: previous_strikes,
                        strike_threshold: penalty_policy.strike_threshold,
                        pdp_challenges: record.pdp_challenges,
                        pdp_failures: record.pdp_failures,
                        potr_windows: record.potr_windows,
                        potr_breaches: record.potr_breaches,
                        triggered_by_pdp: pdp_fail,
                        triggered_by_potr: potr_fail,
                        max_pdp_failures: penalty_policy.max_pdp_failures,
                        max_potr_breaches: penalty_policy.max_potr_breaches,
                        penalty_bond_bps: penalty_policy.penalty_bond_bps,
                        penalty_applied: Quantity::zero(),
                        cooldown_active: false,
                    });
                    iroha_logger::warn!(
                        provider_id = %hex::encode(provider_id.as_bytes()),
                        pdp_challenges = record.pdp_challenges,
                        pdp_failures = record.pdp_failures,
                        potr_windows = record.potr_windows,
                        potr_breaches = record.potr_breaches,
                        "capacity telemetry reported PDP/PoTR failures; forcing immediate strike"
                    );
                } else if utilisation_fail || uptime_fail || por_success_below_floor {
                    credit_record.add_strike().map_err(|error| {
                        InstructionExecutionError::InvariantViolation(
                            format!("SoraFS provider strike update failed: {error}").into(),
                        )
                    })?;
                } else {
                    credit_record.reset_strikes();
                }
                let strikes_met =
                    credit_record.under_delivery_strikes >= penalty_policy.strike_threshold;
                let cooldown_secs = penalty_policy
                    .cooldown_window_secs(pricing_schedule.credit.settlement_window_secs);
                let within_cooldown = if let Some(epoch) = credit_record.last_penalty_epoch {
                    let Some(elapsed) = record.window_end_epoch.checked_sub(epoch) else {
                        return reject("penalty_epoch_in_future");
                    };
                    cooldown_secs > 0 && elapsed < cooldown_secs
                } else {
                    false
                };
                if let Some(alert) = proof_alert.as_mut() {
                    alert.cooldown_active = within_cooldown;
                }
                if strikes_met && !within_cooldown {
                    let calculated_penalty = round_xor_quantity_ratio(
                        &credit_record.bonded,
                        u128::from(penalty_policy.penalty_bond_bps),
                        10_000,
                    )
                    .map_err(|error| quantity_arithmetic_error("provider penalty", error))?;
                    let penalty_amount = if calculated_penalty > credit_record.bonded {
                        credit_record.bonded.clone()
                    } else {
                        calculated_penalty
                    };
                    if let Some(alert) = proof_alert.as_mut() {
                        alert.penalty_applied = penalty_amount.clone();
                    }
                    if !penalty_amount.is_zero() {
                        credit_record
                            .apply_penalty(&penalty_amount, record.window_end_epoch)
                            .map_err(|error| {
                                InstructionExecutionError::InvariantViolation(
                                    format!("SoraFS provider penalty failed: {error}").into(),
                                )
                            })?;
                        ledger
                            .apply_penalty(&penalty_amount, record.window_end_epoch)
                            .map_err(|error| {
                                InstructionExecutionError::InvariantViolation(
                                    format!("SoraFS capacity penalty ledger failed: {error}")
                                        .into(),
                                )
                            })?;
                    } else {
                        credit_record.reset_strikes();
                    }
                }
            }
            state_transaction
                .world
                .provider_credit_ledger
                .insert(provider_id, credit_record);
        }
        state_transaction
            .world
            .capacity_fee_ledger
            .insert(provider_id, ledger);
        if let Some(alert) = proof_alert {
            #[cfg(feature = "telemetry")]
            {
                state_transaction
                    .telemetry
                    .record_sorafs_proof_health_alert(&alert);
            }
            state_transaction
                .world
                .emit_events(Some(SorafsGatewayEvent::ProofHealth(alert)));
        }
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::sorafs::RegisterCapacityDispute {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(state_transaction, authority, "CanFileSorafsCapacityDispute")?;
        let mut record: CapacityDisputeRecord = self.record;
        let dispute = decode_capacity_dispute_payload(&record.dispute_payload)
            .map_err(|err| invalid_parameter(format!("invalid capacity dispute payload: {err}")))?;
        dispute.validate().map_err(|err| {
            invalid_parameter(format!("capacity dispute validation failed: {err}"))
        })?;
        let dispute_id = CapacityDisputeId::new(*blake3_hash(&record.dispute_payload).as_bytes());
        if record.dispute_id != dispute_id {
            return Err(invalid_parameter(
                "capacity dispute identifier mismatch with payload digest",
            ));
        }
        let provider_id = ProviderId::new(dispute.provider_id);
        if record.provider_id != provider_id {
            return Err(invalid_parameter(
                "capacity dispute provider identifier mismatch",
            ));
        }
        if record.complainant_id != dispute.complainant_id {
            return Err(invalid_parameter(
                "capacity dispute complainant identifier mismatch",
            ));
        }
        if record.replication_order_id != dispute.replication_order_id {
            return Err(invalid_parameter(
                "capacity dispute replication order identifier mismatch",
            ));
        }
        if matches!(dispute.kind, CapacityDisputeKind::ReplicationShortfall)
            && dispute.replication_order_id.is_none()
        {
            return Err(invalid_parameter(
                "capacity dispute replication order identifier is required for replication shortfall",
            ));
        }
        if let Some(replication_order_id) = dispute.replication_order_id {
            let order_id = ReplicationOrderId::new(replication_order_id);
            if state_transaction
                .world
                .replication_orders
                .get(&order_id)
                .is_none()
            {
                return Err(invalid_parameter(
                    "capacity dispute references unknown replication order",
                ));
            }
        }
        record.kind = dispute.kind as u8;
        record.replication_order_id = dispute.replication_order_id;
        record.submitted_epoch = dispute.submitted_epoch;
        record.description.clone_from(&dispute.description);
        record
            .requested_remedy
            .clone_from(&dispute.requested_remedy);
        record.evidence = CapacityDisputeEvidence {
            digest: dispute.evidence.evidence_digest,
            media_type: dispute.evidence.media_type.clone(),
            uri: dispute.evidence.uri.clone(),
            size_bytes: dispute.evidence.size_bytes,
        };
        record.status = CapacityDisputeStatus::Pending;
        if state_transaction
            .world
            .capacity_declarations
            .get(&provider_id)
            .is_none()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("capacity dispute received for unknown provider {provider_id:?}").into(),
            ));
        }
        if let Some(existing) = state_transaction
            .world
            .capacity_disputes
            .get(&dispute_id)
            .cloned()
        {
            if !capacity_dispute_immutable_fields_match(&existing, &record) {
                return Err(InstructionExecutionError::InvariantViolation(
                    "capacity dispute id aliases different immutable content".into(),
                ));
            }
            super::sorafs_reputation::validate_capacity_dispute_opened_replay(
                state_transaction,
                authority,
                &existing,
            )?;
            return Ok(());
        }
        super::sorafs_reputation::append_capacity_dispute_opened(
            state_transaction,
            authority,
            &record,
        )?;
        state_transaction
            .world
            .capacity_disputes
            .insert(dispute_id, record);
        Ok(())
    }
}
fn capacity_dispute_immutable_fields_match(
    existing: &CapacityDisputeRecord,
    candidate: &CapacityDisputeRecord,
) -> bool {
    // Lifecycle status is intentionally excluded: replaying the canonical
    // intake remains idempotent after the separate governed resolution.
    existing.dispute_id == candidate.dispute_id
        && existing.provider_id == candidate.provider_id
        && existing.complainant_id == candidate.complainant_id
        && existing.replication_order_id == candidate.replication_order_id
        && existing.kind == candidate.kind
        && existing.submitted_epoch == candidate.submitted_epoch
        && existing.description == candidate.description
        && existing.requested_remedy == candidate.requested_remedy
        && existing.evidence == candidate.evidence
        && existing.dispute_payload == candidate.dispute_payload
}
impl Execute for iroha_data_model::isi::sorafs::IssueReplicationOrder {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(
            state_transaction,
            authority,
            "CanIssueSorafsReplicationOrder",
        )?;
        let order_label = order_hex(&self.order_id);
        if self.order_id.is_auto() {
            return Err(invalid_parameter(format!(
                "replication order {order_label} uses the reserved automatic-order identifier namespace"
            )));
        }
        if self.deadline_epoch <= self.issued_epoch {
            return Err(invalid_parameter(format!(
                "replication order {order_label} deadline {} must be greater than issued_epoch {}",
                self.deadline_epoch, self.issued_epoch
            )));
        }
        if self.order_payload.is_empty()
            || self.order_payload.len() > MAX_REPLICATION_ORDER_PAYLOAD_BYTES
        {
            return Err(invalid_parameter(format!(
                "replication order {order_label} payload has {} bytes; expected 1..={MAX_REPLICATION_ORDER_PAYLOAD_BYTES}",
                self.order_payload.len(),
            )));
        }
        if state_transaction
            .world
            .replication_orders
            .get(&self.order_id)
            .is_some()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("replication order {order_label} already exists").into(),
            ));
        }
        if state_transaction
            .world
            .musubi_locations_by_replication_order
            .get(&self.order_id)
            .is_some()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} already has an immutable Musubi archive binding"
                )
                .into(),
            ));
        }
        let order_payload = decode_canonical_with_limits::<ReplicationOrderV1>(
            &self.order_payload,
            REPLICATION_ORDER_DECODE_LIMITS,
        )
        .map_err(|err| {
            if matches!(&err, norito::Error::NonCanonicalEncoding) {
                invalid_parameter(format!(
                    "replication order {order_label} payload must use canonical first-release Norito"
                ))
            } else {
                invalid_parameter(format!(
                    "invalid replication order payload for {order_label}: {err}"
                ))
            }
        })?;
        order_payload.validate().map_err(|err| {
            invalid_parameter(format!(
                "replication order validation failed for {order_label}: {err}"
            ))
        })?;
        if order_payload.order_id != *self.order_id.as_bytes() {
            return Err(invalid_parameter(format!(
                "replication order {order_label} payload uses mismatched identifier"
            )));
        }
        if order_payload.issued_at != self.issued_epoch
            || order_payload.deadline_at != self.deadline_epoch
        {
            return Err(invalid_parameter(format!(
                "replication order {order_label} record epochs must exactly match its canonical Unix-second payload timestamps"
            )));
        }
        let manifest_digest = ManifestDigest::new(order_payload.manifest_digest);
        let manifest_label = manifest_hex(&manifest_digest);
        let manifest_record = state_transaction
            .world
            .pin_manifests
            .get(&manifest_digest)
            .cloned()
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "manifest {manifest_label} not registered for replication order {order_label}"
                    )
                    .into(),
                )
            })?;
        if !manifest_record.status.is_active() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "manifest {manifest_label} must be approved before issuing replication orders"
                )
                .into(),
            ));
        }
        let Some(approved_epoch) =
            validate_stored_pin_approval_history(&manifest_record, &manifest_label)?
        else {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("approved manifest {manifest_label} has no retained approval epoch").into(),
            ));
        };
        if self.issued_epoch < approved_epoch {
            return Err(invalid_parameter(format!(
                "replication order {order_label} issued epoch {} predates manifest approval epoch {approved_epoch}",
                self.issued_epoch
            )));
        }
        if self.deadline_epoch >= manifest_record.policy.retention_epoch {
            return Err(invalid_parameter(format!(
                "replication order {order_label} deadline {} must be earlier than manifest retention epoch {}",
                self.deadline_epoch, manifest_record.policy.retention_epoch
            )));
        }
        if order_payload.manifest_cid.as_slice() != manifest_record.root_cid.as_bytes() {
            return Err(invalid_parameter(format!(
                "replication order {order_label} manifest CID does not match content root registered for manifest {manifest_label}"
            )));
        }
        let canonical_profile = manifest_record.chunker.to_handle();
        if order_payload.chunking_profile != canonical_profile {
            return Err(invalid_parameter(format!(
                "replication order {order_label} chunking profile `{}` does not match manifest profile `{canonical_profile}`",
                order_payload.chunking_profile
            )));
        }
        if order_payload.target_replicas < manifest_record.policy.min_replicas {
            return Err(invalid_parameter(format!(
                "replication order {order_label} target replicas {} below manifest minimum {}",
                order_payload.target_replicas, manifest_record.policy.min_replicas
            )));
        }
        for assignment in &order_payload.assignments {
            let provider = ProviderId::new(assignment.provider_id);
            let provider_owner = state_transaction
                .world
                .provider_owners
                .get(&provider)
                .ok_or_else(|| {
                    invalid_parameter(format!(
                    "replication order {order_label} references provider {} with no registered owner",
                    hex::encode(provider.as_bytes())
                    ))
                })?;
            let completion_authority = state_transaction
                .world
                .provider_ingest_completion_authorities
                .get(&provider)
                .ok_or_else(|| {
                    invalid_parameter(format!(
                        "replication order {order_label} references provider {} with no active completion authority",
                        hex::encode(provider.as_bytes())
                    ))
                })?;
            if !completion_authority.is_valid()
                || &completion_authority.provider_owner != provider_owner
            {
                return Err(invalid_parameter(format!(
                    "replication order {order_label} provider {} has an invalid or owner-mismatched completion authority",
                    hex::encode(provider.as_bytes())
                )));
            }
        }
        let musubi_reference = if let Some(archive_id) = self.musubi_archive {
            let archive = state_transaction
                .world
                .musubi_archives
                .get(&archive_id)
                .cloned()
                .ok_or_else(|| {
                    invalid_parameter(format!(
                        "replication order {order_label} references an unregistered Musubi archive {}",
                        hex::encode(archive_id.as_bytes())
                    ))
                })?;
            archive.validate().map_err(|error| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "replication order {order_label} resolved an invalid Musubi archive: {}",
                        error.reason()
                    )
                    .into(),
                )
            })?;
            if archive.archive_id != archive_id {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "replication order {order_label} resolved a Musubi archive with the wrong embedded identity"
                    )
                    .into(),
                ));
            }
            let commitment = &archive.commitment;
            if manifest_record.root_cid != commitment.root_cid
                || manifest_record.chunker != commitment.chunker
                || manifest_record.chunk_digest_sha3_256 != *commitment.chunk_plan_digest.as_bytes()
                || manifest_record.por_root != *commitment.por_root.as_bytes()
                || manifest_record.content_length != commitment.content_length
            {
                return Err(invalid_parameter(format!(
                    "replication order {order_label} pin manifest does not match the complete Musubi archive commitment"
                )));
            }
            if manifest_record.policy.min_replicas < MUSUBI_MIN_HEALTHY_REPLICAS_V1
                || order_payload.target_replicas < MUSUBI_MIN_HEALTHY_REPLICAS_V1
            {
                return Err(invalid_parameter(format!(
                    "replication order {order_label} does not meet the Musubi minimum of {MUSUBI_MIN_HEALTHY_REPLICAS_V1} replicas"
                )));
            }
            let binding = MusubiReplicationOrderArchiveBindingV1::new(
                self.order_id,
                archive_id,
                commitment.clone(),
            );
            let reference = MusubiReplicationOrderLocationReferenceV1::pre_location(binding);
            reference.validate().map_err(|error| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "replication order {order_label} produced an invalid Musubi archive binding: {}",
                        error.reason()
                    )
                    .into(),
                )
            })?;
            Some(reference)
        } else {
            None
        };
        let record = ReplicationOrderRecord {
            order_id: self.order_id,
            manifest_digest,
            manifest_root_cid: manifest_record.root_cid,
            musubi_archive: self.musubi_archive,
            issued_by: authority.clone(),
            issued_epoch: self.issued_epoch,
            deadline_epoch: self.deadline_epoch,
            canonical_order: self.order_payload,
            assignment_revision: 1,
            provider_completions: Vec::new(),
            status: ReplicationOrderStatus::Pending,
        };
        state_transaction
            .world
            .replication_orders
            .insert(self.order_id, record);
        if let Some(reference) = musubi_reference {
            state_transaction
                .world
                .musubi_locations_by_replication_order
                .insert(self.order_id, reference);
        }
        // Issuance deliberately stops at the immutable pre-location binding. It cannot observe a
        // finalized completion, mint a completed-row claim, read provider bytes, or request an
        // attestation. The daemon-owned finalized capture path performs those post-completion
        // operations under its exact NetworkId and storage-incarnation capabilities.
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::sorafs::ReviseReplicationOrderAssignments {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(
            state_transaction,
            authority,
            "CanIssueSorafsReplicationOrder",
        )?;
        let order_label = order_hex(&self.order_id);
        if self.order_id.is_auto() {
            return Err(invalid_parameter(format!(
                "replication order {order_label} uses the reserved automatic-order identifier namespace and has immutable assignments"
            )));
        }
        let expected_successor = self
            .expected_assignment_revision
            .checked_add(1)
            .ok_or_else(|| invalid_parameter("replication assignment revision overflow"))?;
        if self.expected_assignment_revision == 0
            || self.next_assignment_revision != expected_successor
        {
            return Err(invalid_parameter(
                "replication assignment revision must be an exact nonzero monotonic successor",
            )
            .into());
        }
        let mut record = state_transaction
            .world
            .replication_orders
            .get(&self.order_id)
            .cloned()
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!("replication order {order_label} not found").into(),
                )
            })?;
        if state_transaction
            .world
            .musubi_locations_by_replication_order
            .get(&self.order_id)
            .is_some_and(|reference| reference.active_location().is_some())
        {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} is bound to an immutable Musubi archive location"
                )
                .into(),
            ));
        }
        if record.assignment_revision != self.expected_assignment_revision {
            return Err(invalid_parameter(format!(
                "replication order {order_label} assignment revision compare-and-set mismatch"
            ))
            .into());
        }
        if !matches!(record.status, ReplicationOrderStatus::Pending)
            || !record.provider_completions.is_empty()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} assignments cannot change after completion processing starts"
                )
                .into(),
            ));
        }
        let mut canonical_order = validate_stored_replication_order(&record, &order_label)?;
        if canonical_order.assignments == self.assignments {
            return Err(invalid_parameter(format!(
                "replication order {order_label} assignment revision does not change assignments"
            ))
            .into());
        }
        canonical_order.assignments = self.assignments;
        canonical_order.validate().map_err(|error| {
            invalid_parameter(format!(
                "replication order {order_label} replacement assignments are invalid: {error}"
            ))
        })?;
        for assignment in &canonical_order.assignments {
            let provider = ProviderId::new(assignment.provider_id);
            let provider_owner = state_transaction
                .world
                .provider_owners
                .get(&provider)
                .ok_or_else(|| {
                    invalid_parameter(format!(
                        "replication order {order_label} replacement provider {} has no registered owner",
                        hex::encode(provider.as_bytes())
                    ))
                })?;
            let completion_authority = state_transaction
                .world
                .provider_ingest_completion_authorities
                .get(&provider)
                .ok_or_else(|| {
                    invalid_parameter(format!(
                        "replication order {order_label} replacement provider {} has no active completion authority",
                        hex::encode(provider.as_bytes())
                    ))
                })?;
            if !completion_authority.is_valid()
                || &completion_authority.provider_owner != provider_owner
            {
                return Err(invalid_parameter(format!(
                    "replication order {order_label} replacement provider {} has an invalid or owner-mismatched completion authority",
                    hex::encode(provider.as_bytes())
                ))
                .into());
            }
        }
        record.canonical_order = norito::encode_canonical(&canonical_order).map_err(|error| {
            InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} replacement assignments could not be canonicalized: {error}"
                )
                .into(),
            )
        })?;
        record.assignment_revision = self.next_assignment_revision;
        state_transaction
            .world
            .replication_orders
            .insert(self.order_id, record);
        Ok(())
    }
}
pub(crate) fn validate_stored_replication_order(
    record: &ReplicationOrderRecord,
    order_label: &str,
) -> Result<ReplicationOrderV1, InstructionExecutionError> {
    validate_manifest_root_cid(
        record.manifest_root_cid.as_bytes(),
        sorafs_manifest::chunker_registry::MANIFEST_DAG_CODEC,
        BLAKE3_256_MULTIHASH_CODE,
    )
    .map_err(|error| {
        InstructionExecutionError::InvariantViolation(
            format!("replication order {order_label} stores an invalid manifest root CID: {error}")
                .into(),
        )
    })?;
    let canonical_payload = decode_canonical_with_limits::<ReplicationOrderV1>(
        &record.canonical_order,
        REPLICATION_ORDER_DECODE_LIMITS,
    )
    .map_err(|err| {
        if matches!(&err, norito::Error::NonCanonicalEncoding) {
            InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} stored payload is not canonical or bound to its record"
                )
                .into(),
            )
        } else {
            InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} canonical payload could not be decoded: {err}"
                )
                .into(),
            )
        }
    })?;
    canonical_payload.validate().map_err(|err| {
        InstructionExecutionError::InvariantViolation(
            format!("replication order {order_label} stored payload failed validation: {err}")
                .into(),
        )
    })?;
    if canonical_payload.order_id != *record.order_id.as_bytes()
        || canonical_payload.manifest_digest != *record.manifest_digest.as_bytes()
        || canonical_payload.manifest_cid.as_slice() != record.manifest_root_cid.as_bytes()
        || canonical_payload.issued_at != record.issued_epoch
        || canonical_payload.deadline_at != record.deadline_epoch
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "replication order {order_label} stored payload is not canonical or bound to its record"
            )
            .into(),
        ));
    }
    if record.assignment_revision == 0 {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("replication order {order_label} has a zero assignment revision").into(),
        ));
    }
    if record
        .musubi_archive
        .is_some_and(|archive_id| archive_id.is_zero())
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("replication order {order_label} has an inert Musubi archive purpose").into(),
        ));
    }
    let target_replicas = usize::from(canonical_payload.target_replicas);
    if record.provider_completions.len() > target_replicas {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "replication order {order_label} stores more provider completions than its redundancy target"
            )
            .into(),
        ));
    }
    let mut completed_providers = BTreeSet::new();
    let mut previous_completion_epoch = None;
    for completion in &record.provider_completions {
        if !canonical_payload
            .assignments
            .iter()
            .any(|assignment| assignment.provider_id == *completion.provider_id.as_bytes())
        {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} stores a completion for unassigned provider {}",
                    hex::encode(completion.provider_id.as_bytes())
                )
                .into(),
            ));
        }
        if !completed_providers.insert(*completion.provider_id.as_bytes()) {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} stores duplicate completion records for provider {}",
                    hex::encode(completion.provider_id.as_bytes())
                )
                .into(),
            ));
        }
        if completion.completion_epoch < record.issued_epoch
            || completion.completion_epoch > record.deadline_epoch
            || previous_completion_epoch
                .is_some_and(|previous| completion.completion_epoch < previous)
            || completion.assignment_revision != record.assignment_revision
            || !completion.completion_authority.is_valid()
            || completion.completion_authority.completion_signer != completion.completed_by
            || !completion.finalized_anchor.is_valid()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} stores a completion with invalid epoch, assignment revision, authority, or finalized anchor"
                ).into(),
            ));
        }
        previous_completion_epoch = Some(completion.completion_epoch);
    }
    match record.status {
        ReplicationOrderStatus::Pending if record.provider_completions.len() < target_replicas => {}
        ReplicationOrderStatus::Expired(epoch)
            if epoch > record.deadline_epoch
                && record.provider_completions.len() < target_replicas => {}
        ReplicationOrderStatus::Cancelled(epoch)
            if epoch >= record.issued_epoch
                && epoch <= record.deadline_epoch
                && record.provider_completions.len() < target_replicas => {}
        ReplicationOrderStatus::Completed(epoch)
            if record.provider_completions.len() == target_replicas
                && record
                    .provider_completions
                    .last()
                    .is_some_and(|completion| completion.completion_epoch == epoch) => {}
        _ => {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} lifecycle is inconsistent with its provider completions"
                )
                .into(),
            ));
        }
    }
    Ok(canonical_payload)
}
/// Validate the durable approval history encoded by a pin lifecycle record.
pub(crate) fn validate_stored_pin_approval_history(
    pin: &PinManifestRecord,
    pin_label: &str,
) -> Result<Option<u64>, InstructionExecutionError> {
    let approval_matches_lifecycle = match pin.status {
        PinStatus::Pending => {
            pin.approved_epoch.is_none()
                && pin.council_envelope_digest.is_none()
                && pin.retirement_reason.is_none()
        }
        PinStatus::Approved(status_epoch) => {
            pin.approved_epoch == Some(status_epoch)
                && status_epoch >= pin.submitted_epoch
                && status_epoch < pin.policy.retention_epoch
                && pin.retirement_reason.is_none()
        }
        PinStatus::Retired(retired_epoch) => {
            retired_epoch >= pin.submitted_epoch
                && pin.approved_epoch.is_none_or(|approved_epoch| {
                    approved_epoch >= pin.submitted_epoch
                        && approved_epoch <= retired_epoch
                        && approved_epoch < pin.policy.retention_epoch
                })
                && (pin.approved_epoch.is_some() || pin.council_envelope_digest.is_none())
        }
    };
    if !approval_matches_lifecycle {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "pin manifest {pin_label} lifecycle does not exactly retain its immutable approval epoch"
            )
            .into(),
        ));
    }
    Ok(pin.approved_epoch)
}
/// Validate the complete first-release shape of a registry-issued automatic order.
///
/// This is stricter than generic replication-order validation: the reserved identifier,
/// immutable assignment shape, timestamps, SLA, and pin binding are all derived state.
pub(crate) fn validate_stored_automatic_replication_order(
    pin: &PinManifestRecord,
    record: &ReplicationOrderRecord,
    order_label: &str,
) -> Result<ReplicationOrderV1, InstructionExecutionError> {
    let canonical_order = validate_stored_replication_order(record, order_label)?;
    let pin_label = manifest_hex(&pin.digest);
    let approved_epoch = validate_stored_pin_approval_history(pin, &pin_label)?;
    let expected_order_id = derive_sorafs_auto_replication_order_id_v1(&pin.digest);
    let expected_deadline = record
        .issued_epoch
        .checked_add(u64::from(
            SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1,
        ))
        .ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                format!("automatic replication order {order_label} deadline overflowed").into(),
            )
        })?;
    let issued_epoch_matches_pin = approved_epoch == Some(record.issued_epoch);
    let lifecycle_matches_pin = match (pin.status, record.status) {
        (PinStatus::Approved(_), ReplicationOrderStatus::Cancelled(_))
        | (PinStatus::Pending, _)
        | (PinStatus::Retired(_), ReplicationOrderStatus::Pending) => false,
        (PinStatus::Retired(retired_epoch), ReplicationOrderStatus::Cancelled(cancelled_epoch)) => {
            retired_epoch == cancelled_epoch
        }
        (PinStatus::Retired(retired_epoch), ReplicationOrderStatus::Completed(completed_epoch)) => {
            completed_epoch <= retired_epoch && retired_epoch >= pin.policy.retention_epoch
        }
        (PinStatus::Retired(retired_epoch), ReplicationOrderStatus::Expired(expired_epoch)) => {
            expired_epoch <= retired_epoch
        }
        _ => true,
    };
    let expected_slice_gib = automatic_replication_slice_gib(pin.content_length).map_err(|_| {
        InstructionExecutionError::InvariantViolation(
            format!("automatic replication order {order_label} slice size overflowed").into(),
        )
    })?;
    let exact_assignments = canonical_order.assignments.len()
        == usize::from(pin.policy.min_replicas)
        && canonical_order.assignments.iter().all(|assignment| {
            assignment.slice_gib == expected_slice_gib && assignment.lane.is_none()
        });
    if !record.order_id.is_auto()
        || record.order_id != expected_order_id
        || record.manifest_digest != pin.digest
        || record.manifest_root_cid != pin.root_cid
        || record.musubi_archive.is_some()
        || record.assignment_revision != 1
        || !issued_epoch_matches_pin
        || !lifecycle_matches_pin
        || record.deadline_epoch != expected_deadline
        || record.deadline_epoch >= pin.policy.retention_epoch
        || canonical_order.chunking_profile != pin.chunker.to_handle()
        || canonical_order.target_replicas != pin.policy.min_replicas
        || !exact_assignments
        || canonical_order.sla.ingest_deadline_secs
            != SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1
        || canonical_order.sla.min_availability_percent_milli
            != AUTO_REPLICATION_ORDER_AVAILABILITY_PERCENT_MILLI
        || canonical_order.sla.min_por_success_percent_milli
            != AUTO_REPLICATION_ORDER_POR_SUCCESS_PERCENT_MILLI
        || !canonical_order.metadata.is_empty()
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "automatic replication order {order_label} does not exactly match its derived first-release pin, assignment, epoch, and SLA invariants"
            )
            .into(),
        ));
    }
    Ok(canonical_order)
}
fn provider_ingest_anchor_matches_committed_prefix(
    anchor: ProviderIngestFinalizedAnchorV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> bool {
    if !anchor.is_valid() {
        return false;
    }
    let Some(index) = usize::try_from(anchor.height)
        .ok()
        .and_then(|height| height.checked_sub(1))
    else {
        return false;
    };
    state_transaction
        .block_hashes()
        .get(index)
        .is_some_and(|hash| *hash.as_ref() == anchor.block_hash)
}
impl Execute for iroha_data_model::isi::sorafs::CompleteReplicationOrder {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if !crate::query::provider_ingest_source::has_provider_completion_permission_v1(
            &state_transaction.world,
            authority,
            self.provider_id,
        ) {
            return Err(invalid_parameter(
                "provider-scoped CanCompleteSorafsReplicationOrder permission required",
            ));
        }
        if self.expected_assignment_revision == 0
            || !self.expected_authority.is_valid()
            || !provider_ingest_anchor_matches_committed_prefix(
                self.finalized_anchor,
                state_transaction,
            )
        {
            return Err(invalid_parameter(
                "replication completion authority, assignment revision, or finalized anchor is noncanonical or stale",
            )
            .into());
        }
        let order_label = order_hex(&self.order_id);
        let mut record = state_transaction
            .world
            .replication_orders
            .get(&self.order_id)
            .cloned()
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!("replication order {order_label} not found").into(),
                )
            })?;
        let canonical_order = validate_stored_replication_order(&record, &order_label)?;
        if record.assignment_revision != self.expected_assignment_revision {
            return Err(invalid_parameter(format!(
                "replication order {order_label} assignment revision changed before completion commit"
            ))
            .into());
        }
        if !canonical_order
            .assignments
            .iter()
            .any(|assignment| assignment.provider_id == *self.provider_id.as_bytes())
        {
            return Err(invalid_parameter(format!(
                "provider {} is not assigned to replication order {order_label}",
                hex::encode(self.provider_id.as_bytes())
            )));
        }
        let retained_completion = ReplicationOrderCompletionRecord {
            provider_id: self.provider_id,
            completed_by: authority.clone(),
            completion_epoch: self.completion_epoch,
            assignment_revision: self.expected_assignment_revision,
            completion_authority: self.expected_authority.clone(),
            finalized_anchor: self.finalized_anchor,
        };
        if let Some(completion) = record.provider_completion(self.provider_id) {
            if completion == &retained_completion {
                return Ok(());
            }
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} provider {} already has a different retained completion context",
                    hex::encode(self.provider_id.as_bytes())
                )
                .into(),
            ));
        }
        let provider_owner = state_transaction
            .world
            .provider_owners
            .get(&self.provider_id)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "replication order {order_label} provider {} has no registered owner",
                        hex::encode(self.provider_id.as_bytes())
                    )
                    .into(),
                )
            })?;
        if provider_owner != &self.expected_authority.provider_owner
            || authority != &self.expected_authority.completion_signer
        {
            return Err(invalid_parameter(format!(
                "replication order {order_label} completion for provider {} must be authorized by its exact governed completion signer",
                hex::encode(self.provider_id.as_bytes())
            )));
        }
        let completion_authority = state_transaction
            .world
            .provider_ingest_completion_authorities
            .get(&self.provider_id)
            .ok_or_else(|| {
                invalid_parameter(format!(
                    "replication order {order_label} provider {} has no active completion authority",
                    hex::encode(self.provider_id.as_bytes())
                ))
            })?;
        if completion_authority != &self.expected_authority {
            return Err(invalid_parameter(format!(
                "replication order {order_label} provider {} completion authority changed before commit",
                hex::encode(self.provider_id.as_bytes())
            )));
        }
        match record.status {
            ReplicationOrderStatus::Pending => {}
            ReplicationOrderStatus::Completed(epoch) => {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "replication order {order_label} reached its redundancy target at epoch {epoch}"
                    )
                    .into(),
                ));
            }
            ReplicationOrderStatus::Expired(epoch) => {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!("replication order {order_label} expired at epoch {epoch}").into(),
                ));
            }
            ReplicationOrderStatus::Cancelled(epoch) => {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!("replication order {order_label} was cancelled at epoch {epoch}")
                        .into(),
                ));
            }
        }
        if self.completion_epoch < record.issued_epoch {
            return Err(invalid_parameter(format!(
                "completion_epoch {} must be >= issued_epoch {} for replication order {order_label}",
                self.completion_epoch, record.issued_epoch
            )));
        }
        if self.completion_epoch > record.deadline_epoch {
            return Err(invalid_parameter(format!(
                "completion_epoch {} exceeds deadline_epoch {} for replication order {order_label}",
                self.completion_epoch, record.deadline_epoch
            )));
        }
        let manifest = state_transaction
            .world
            .pin_manifests
            .get(&record.manifest_digest)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!("replication order {order_label} references a missing pin manifest")
                        .into(),
                )
            })?;
        if manifest.root_cid != record.manifest_root_cid {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} content root no longer matches its registered manifest"
                )
                .into(),
            ));
        }
        if !manifest.status.is_active() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} cannot complete after its manifest is inactive"
                )
                .into(),
            ));
        }
        if record.order_id.is_auto() {
            validate_stored_automatic_replication_order(manifest, &record, &order_label)?;
        }
        let current_epoch = pin_consensus_epoch(state_transaction);
        if self.completion_epoch > current_epoch {
            return Err(invalid_parameter(format!(
                "completion_epoch {} is later than current consensus epoch {current_epoch} for replication order {order_label}",
                self.completion_epoch
            )));
        }
        if current_epoch > record.deadline_epoch {
            return Err(invalid_parameter(format!(
                "current consensus epoch {current_epoch} is later than deadline_epoch {} for replication order {order_label}",
                record.deadline_epoch
            )));
        }
        if record
            .provider_completions
            .last()
            .is_some_and(|previous| previous.completion_epoch > self.completion_epoch)
        {
            return Err(invalid_parameter(format!(
                "completion_epoch {} predates the previously retained completion for replication order {order_label}",
                self.completion_epoch
            )));
        }
        record
            .provider_completions
            .try_reserve(1)
            .map_err(|_| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "replication order {order_label} could not reserve bounded provider completion state"
                    )
                    .into(),
                )
            })?;
        record.provider_completions.push(retained_completion);
        if record.provider_completions.len() == usize::from(canonical_order.target_replicas) {
            record.status = ReplicationOrderStatus::Completed(self.completion_epoch);
        }
        state_transaction
            .world
            .replication_orders
            .insert(self.order_id, record);
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::sorafs::ExpireReplicationOrder {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(
            state_transaction,
            authority,
            "CanIssueSorafsReplicationOrder",
        )?;
        let order_label = order_hex(&self.order_id);
        let mut record = state_transaction
            .world
            .replication_orders
            .get(&self.order_id)
            .cloned()
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!("replication order {order_label} not found").into(),
                )
            })?;
        let musubi_location = state_transaction
            .world
            .musubi_locations_by_replication_order
            .get(&self.order_id)
            .and_then(MusubiReplicationOrderLocationReferenceV1::active_location);
        validate_stored_replication_order(&record, &order_label)?;
        let manifest = state_transaction
            .world
            .pin_manifests
            .get(&record.manifest_digest)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!("replication order {order_label} references a missing pin manifest")
                        .into(),
                )
            })?;
        if manifest.root_cid != record.manifest_root_cid {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "replication order {order_label} content root no longer matches its registered manifest"
                )
                .into(),
            ));
        }
        if record.order_id.is_auto() {
            validate_stored_automatic_replication_order(manifest, &record, &order_label)?;
        }
        match record.status {
            ReplicationOrderStatus::Pending => {}
            ReplicationOrderStatus::Expired(epoch) if epoch == self.expiration_epoch => {
                return Ok(());
            }
            ReplicationOrderStatus::Expired(epoch) => {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!("replication order {order_label} already expired at epoch {epoch}")
                        .into(),
                ));
            }
            ReplicationOrderStatus::Completed(epoch) => {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!("replication order {order_label} completed at epoch {epoch}").into(),
                ));
            }
            ReplicationOrderStatus::Cancelled(epoch) => {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!("replication order {order_label} was cancelled at epoch {epoch}")
                        .into(),
                ));
            }
        }
        if self.expiration_epoch <= record.deadline_epoch {
            return Err(invalid_parameter(format!(
                "expiration_epoch {} must be greater than deadline_epoch {} for replication order {order_label}",
                self.expiration_epoch, record.deadline_epoch
            )));
        }
        let consensus_epoch = pin_consensus_epoch(state_transaction);
        if self.expiration_epoch > consensus_epoch {
            return Err(invalid_parameter(format!(
                "expiration_epoch {} cannot exceed consensus Unix-second epoch {consensus_epoch} for replication order {order_label}",
                self.expiration_epoch,
            )));
        }
        if let Some(location) = musubi_location {
            super::musubi::ensure_locations_may_be_invalidated(
                &[location],
                state_transaction.world(),
            )?;
        }
        record.expire(self.expiration_epoch);
        state_transaction
            .world
            .replication_orders
            .insert(self.order_id, record);
        if let Some(location) = musubi_location {
            super::musubi::refresh_musubi_locations(&[location], state_transaction)?;
        }
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::sorafs::SetPricingSchedule {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(state_transaction, authority, "CanSetSorafsPricing")?;
        let schedule: PricingScheduleRecord = self.schedule;
        schedule.validate().map_err(|err| {
            invalid_parameter(format!("pricing schedule validation failed: {err}"))
        })?;
        *state_transaction.world.sorafs_pricing.get_mut() = schedule;
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::sorafs::UpsertProviderCredit {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(
            state_transaction,
            authority,
            "CanUpsertSorafsProviderCredit",
        )?;
        let record: ProviderCreditRecord = self.record;
        if record.provider_id == ProviderId::default() {
            return Err(invalid_parameter(
                "provider credit record must reference a non-zero provider identifier",
            ));
        }
        // Compare the entire canonical native row before reserve scans or mutation.
        // Hash the borrowed record under the inherited attempt allowance. A local
        // serializer refusal remains sticky deferral, never a stale-CAS rejection.
        let current = state_transaction
            .world
            .provider_credit_ledger
            .get(&record.provider_id);
        let matches = match (self.expected_current, current) {
            (None, None) => true,
            (Some(expected), Some(current)) => {
                let hash = iroha_crypto::HashOf::try_new(current).map_err(|error| {
                    state_transaction.world.attempt_error_to_instruction_error(
                        crate::execution_attempt::norito_decode_attempt_error(error, |_| {
                            invalid_parameter(
                                "provider credit current record cannot be canonically hashed",
                            )
                        }),
                    )
                })?;
                hash == expected
            }
            _ => false,
        };
        if !matches {
            return Err(invalid_parameter(
                "provider credit expected current record does not match",
            ));
        }
        let owner = state_transaction
            .world
            .provider_owners
            .get(&record.provider_id)
            .cloned();
        let Some(owner) = owner else {
            return Err(invalid_parameter(format!(
                "provider {:?} has no governance-established owner",
                record.provider_id
            )));
        };
        let committed_capacity_gib = state_transaction
            .world
            .capacity_declarations
            .get(&record.provider_id)
            .map_or(0, |declaration| declaration.committed_capacity_gib);
        let verified_bond = super::sorafs_reserve::verified_provider_bond(
            state_transaction.world(),
            record.provider_id,
            &owner,
            committed_capacity_gib,
        )?;
        if let Some(existing) = state_transaction
            .world
            .provider_credit_ledger
            .get(&record.provider_id)
        {
            if record.slashed != existing.slashed
                || record.last_penalty_epoch != existing.last_penalty_epoch
            {
                return Err(invalid_parameter(format!(
                    "provider {:?} credit upsert cannot reset its custody-backed slash lien or penalty epoch",
                    record.provider_id
                )));
            }
        } else if !record.slashed.is_zero() || record.last_penalty_epoch.is_some() {
            return Err(invalid_parameter(format!(
                "provider {:?} initial credit record cannot author slash history",
                record.provider_id
            )));
        }
        let locked_custody = provider_credit_locked_custody(&record)?;
        if &locked_custody != verified_bond.as_quantity() {
            return Err(invalid_parameter(format!(
                "provider {:?} bonded {} plus slashed {} must equal its owner-funded native reserve {}",
                record.provider_id,
                record.bonded,
                record.slashed,
                verified_bond.as_quantity()
            )));
        }
        state_transaction
            .world
            .provider_credit_ledger
            .insert(record.provider_id, record);
        Ok(())
    }
}
const REPAIR_STATUS_STATE_KEY_V1: &str = "sorafs_repair_status_v1";
const REPAIR_TASK_STATE_KEY_PREFIX_V1: &str = "sorafs_repair_task_v1_";
const REPAIR_SOURCE_STATE_KEY_PREFIX_V1: &str = "sorafs_repair_source_v1_";
const REPAIR_EVENT_STATE_KEY_PREFIX_V1: &str = "sorafs_repair_event_v1_";
const REPAIR_EVENT_JOURNAL_HEAD_STATE_KEY_V1: &str = "sorafs_repair_event_head_v1";
const REPAIR_TICKET_STATE_KEY_DOMAIN_V1: &[u8] = b"sorafs.repair.ticket-state-key.v1";
const REPAIR_STATE_MAX_BYTES_V1: usize = 256 * 1024;
const REPAIR_QUERY_MAX_TASK_STATE_READ_BYTES_V1: usize = 16 * 1024 * 1024;
const REPAIR_QUERY_MAX_EVENT_STATE_READ_BYTES_V1: usize = 32 * 1024 * 1024;
// Owned Norito decoding retains the bounded archive while materializing the
// report's nested strings and evidence. Sixteen bytes of cumulative allocation
// per encoded byte covers that finite object graph while keeping the allocation
// corridor independently bounded by the canonical wire-size limit.
const REPAIR_PAYLOAD_MAX_DECODE_ALLOCATION_BYTES_V1: usize =
    16 * REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1;
const REPAIR_STATE_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 16 * REPAIR_STATE_MAX_BYTES_V1;
const REPAIR_STATE_LIMITS_V1: DecodeLimits = DecodeLimits::new(
    REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1,
    REPAIR_STATE_MAX_BYTES_V1,
    REPAIR_STATE_MAX_BYTES_V1,
    REPAIR_STATE_MAX_DECODE_ALLOCATION_BYTES_V1,
    64,
);
const REPAIR_PAYLOAD_LIMITS_V1: DecodeLimits = DecodeLimits::new(
    256,
    REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1,
    2_048,
    REPAIR_PAYLOAD_MAX_DECODE_ALLOCATION_BYTES_V1,
    64,
);
#[derive(
    Clone, Debug, norito::NoritoSerialize, norito::NoritoDeserialize, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::smartcontracts::isi::sorafs::RepairSourceBindingV1")]
struct RepairSourceBindingV1 {
    source_identity: [u8; 32],
    task_id: [u8; 32],
    ticket_id: String,
    report_digest: [u8; 32],
}
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::smartcontracts::isi::sorafs::RepairPersistedEventV1")]
struct RepairPersistedEventV1 {
    sequence: u64,
    target_block_height: u64,
    event_index: u32,
    event: SorafsRepairLedgerEvent,
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
#[norito_schema(name = "iroha_core::smartcontracts::isi::sorafs::RepairEventJournalHeadV1")]
struct RepairEventJournalHeadV1 {
    last_sequence: u64,
    last_target_block_height: u64,
    last_event_index: u32,
}
fn corrupt_repair_state(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvariantViolation(message.into().into())
}
fn repair_status_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| {
        StatePath::from_str(REPAIR_STATUS_STATE_KEY_V1).expect("static key is valid")
    })
}
fn repair_ticket_digest(ticket_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REPAIR_TICKET_STATE_KEY_DOMAIN_V1);
    hasher.update(
        &u64::try_from(ticket_id.len())
            .expect("string length fits u64")
            .to_le_bytes(),
    );
    hasher.update(ticket_id.as_bytes());
    *hasher.finalize().as_bytes()
}
fn repair_digest_key(prefix: &str, digest: [u8; 32]) -> StatePath {
    StatePath::from_str(&format!("{prefix}{}", hex::encode(digest)))
        .expect("static prefix plus lowercase hex is a valid state key")
}
fn repair_task_key(ticket_id: &str) -> StatePath {
    repair_digest_key(
        REPAIR_TASK_STATE_KEY_PREFIX_V1,
        repair_ticket_digest(ticket_id),
    )
}
fn repair_source_key(source_identity: [u8; 32]) -> StatePath {
    repair_digest_key(
        REPAIR_SOURCE_STATE_KEY_PREFIX_V1,
        sorafs_repair_task_id_v1(source_identity),
    )
}
fn repair_event_key(sequence: u64) -> StatePath {
    StatePath::from_str(&format!(
        "{REPAIR_EVENT_STATE_KEY_PREFIX_V1}{sequence:016x}"
    ))
    .expect("static prefix plus fixed-width lowercase hex is a valid state key")
}
fn repair_event_journal_head_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| {
        StatePath::from_str(REPAIR_EVENT_JOURNAL_HEAD_STATE_KEY_V1)
            .expect("static repair event journal head key is valid")
    })
}
fn encode_repair_state<T: norito::core::NoritoSerialize>(
    value: &T,
    label: &str,
) -> Result<Vec<u8>, InstructionExecutionError> {
    norito::encode_canonical(value).map_err(|error| {
        InstructionExecutionError::InvariantViolation(
            format!("failed to encode {label}: {error}").into(),
        )
    })
}
fn decode_repair_state<T>(bytes: &[u8], label: &str) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    decode_repair_state_measured(bytes, label).map(|(value, _)| value)
}
fn decode_repair_state_measured<T>(
    bytes: &[u8],
    label: &str,
) -> Result<(T, usize), InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.len() > REPAIR_STATE_MAX_BYTES_V1 {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("{label} exceeds {REPAIR_STATE_MAX_BYTES_V1} bytes").into(),
        ));
    }
    let limits = crate::smartcontracts::isi::query::singular_query_decode_limits(
        bytes.len(),
        REPAIR_STATE_LIMITS_V1,
    )
    .map_err(InstructionExecutionError::Query)?;
    let (value, usage) = norito::core::with_decode_limits_measured(limits, || {
        decode_canonical_with_limits::<T>(bytes, limits)
    });
    let value = value.map_err(|error| {
        if crate::smartcontracts::isi::query::singular_query_limits_active()
            && error.is_decode_resource_limit()
        {
            return InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit);
        }
        if matches!(&error, norito::Error::NonCanonicalEncoding) {
            InstructionExecutionError::InvariantViolation(
                format!("{label} is not exact canonical Norito").into(),
            )
        } else {
            InstructionExecutionError::InvariantViolation(
                format!("failed to decode {label}: {error}").into(),
            )
        }
    })?;
    Ok((value, usage.total_allocated_bytes()))
}
fn decode_repair_state_for_current<T>(
    bytes: &[u8],
    label: &str,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.len() > REPAIR_STATE_MAX_BYTES_V1 {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("{label} exceeds {REPAIR_STATE_MAX_BYTES_V1} bytes").into(),
        ));
    }
    let limits = current
        .decode_limits(bytes.len(), REPAIR_STATE_LIMITS_V1)
        .map_err(InstructionExecutionError::Query)?;
    let (value, usage) = norito::core::with_decode_limits_measured(limits, || {
        decode_canonical_with_limits::<T>(bytes, limits)
    });
    let value = value.map_err(|error| {
        if crate::smartcontracts::isi::query::singular_query_limits_active()
            && error.is_decode_resource_limit()
        {
            return InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit);
        }
        if matches!(&error, norito::Error::NonCanonicalEncoding) {
            InstructionExecutionError::InvariantViolation(
                format!("{label} is not exact canonical Norito").into(),
            )
        } else {
            InstructionExecutionError::InvariantViolation(
                format!("failed to decode {label}: {error}").into(),
            )
        }
    })?;
    current
        .add_nested(usage.total_allocated_bytes())
        .map_err(InstructionExecutionError::Query)?;
    Ok(value)
}
fn decode_repair_payload<T>(bytes: &[u8], label: &str) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.is_empty() || bytes.len() > REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1 {
        return Err(invalid_parameter(format!(
            "{label} payload length {} is outside 1..={REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1}",
            bytes.len()
        )));
    }
    decode_canonical_with_limits::<T>(bytes, REPAIR_PAYLOAD_LIMITS_V1).map_err(|error| {
        if matches!(&error, norito::Error::NonCanonicalEncoding) {
            invalid_parameter(format!("{label} is not exact canonical Norito"))
        } else {
            invalid_parameter(format!("invalid canonical {label}: {error}"))
        }
    })
}
fn decode_stored_repair_payload<T>(
    bytes: &[u8],
    label: &str,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.is_empty() || bytes.len() > REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1 {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "{label} payload length {} is outside 1..={REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1}",
                bytes.len()
            )
            .into(),
        ));
    }
    decode_canonical_with_limits::<T>(bytes, REPAIR_PAYLOAD_LIMITS_V1).map_err(|error| {
        if matches!(&error, norito::Error::NonCanonicalEncoding) {
            InstructionExecutionError::InvariantViolation(
                format!("{label} is not exact canonical Norito").into(),
            )
        } else {
            InstructionExecutionError::InvariantViolation(
                format!("failed to decode {label}: {error}").into(),
            )
        }
    })
}
fn decode_stored_repair_payload_for_current<T>(
    bytes: &[u8],
    label: &str,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.is_empty() || bytes.len() > REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1 {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "{label} payload length {} is outside 1..={REPAIR_LEDGER_MAX_CANONICAL_PAYLOAD_BYTES_V1}",
                bytes.len()
            )
            .into(),
        ));
    }
    let limits = current
        .decode_limits(bytes.len(), REPAIR_PAYLOAD_LIMITS_V1)
        .map_err(InstructionExecutionError::Query)?;
    let (value, usage) = norito::core::with_decode_limits_measured(limits, || {
        decode_canonical_with_limits::<T>(bytes, limits)
    });
    let value = value.map_err(|error| {
        if crate::smartcontracts::isi::query::singular_query_limits_active()
            && error.is_decode_resource_limit()
        {
            return InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit);
        }
        if matches!(&error, norito::Error::NonCanonicalEncoding) {
            InstructionExecutionError::InvariantViolation(
                format!("{label} is not exact canonical Norito").into(),
            )
        } else {
            InstructionExecutionError::InvariantViolation(
                format!("failed to decode {label}: {error}").into(),
            )
        }
    })?;
    current
        .add_nested(usage.total_allocated_bytes())
        .map_err(InstructionExecutionError::Query)?;
    Ok(value)
}
fn repair_block_time_ms(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<u64, InstructionExecutionError> {
    let now = state_transaction.block_unix_timestamp_ms();
    if now == 0 {
        return Err(invalid_parameter(
            "authoritative repair operations require a non-zero block timestamp",
        ));
    }
    Ok(now)
}
fn has_repair_worker_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    provider_id: [u8; 32],
) -> bool {
    let required = Permission::from(CanOperateSorafsRepair {
        provider_id: ProviderId::new(provider_id),
    });
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
fn validate_repair_idempotency_key(key: &str) -> Result<(), InstructionExecutionError> {
    if key.is_empty()
        || key != key.trim()
        || key.len() > REPAIR_LEDGER_MAX_IDEMPOTENCY_KEY_BYTES_V1
        || key.chars().any(char::is_control)
    {
        return Err(invalid_parameter(
            "repair idempotency key is empty, padded, contains control characters, or is too long",
        ));
    }
    Ok(())
}
fn validate_repair_appeal_reason(reason: &str) -> Result<(), InstructionExecutionError> {
    if reason.is_empty()
        || reason != reason.trim()
        || reason.len() > REPAIR_LEDGER_MAX_APPEAL_REASON_BYTES_V1
        || reason.chars().any(char::is_control)
    {
        return Err(invalid_parameter(
            "repair appeal reason is empty, padded, contains control characters, or is too long",
        ));
    }
    Ok(())
}
fn validate_repair_lease_duration(duration_ms: u64) -> Result<(), InstructionExecutionError> {
    if !(REPAIR_LEDGER_MIN_LEASE_MS_V1..=REPAIR_LEDGER_MAX_LEASE_MS_V1).contains(&duration_ms) {
        return Err(invalid_parameter(format!(
            "repair lease duration {duration_ms} ms is outside {REPAIR_LEDGER_MIN_LEASE_MS_V1}..={REPAIR_LEDGER_MAX_LEASE_MS_V1}"
        )));
    }
    Ok(())
}
fn checked_repair_inc(value: u64, label: &str) -> Result<u64, InstructionExecutionError> {
    value.checked_add(1).ok_or_else(|| {
        InstructionExecutionError::InvariantViolation(
            format!("repair {label} counter overflow").into(),
        )
    })
}
fn read_repair_source_binding(
    world: &impl crate::state::WorldReadOnly,
    source_identity: [u8; 32],
) -> Result<Option<RepairSourceBindingV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&repair_source_key(source_identity))
    else {
        return Ok(None);
    };
    let binding: RepairSourceBindingV1 = decode_repair_state(bytes, "repair source binding")?;
    let task_id = sorafs_repair_task_id_v1(binding.source_identity);
    if binding.source_identity != source_identity
        || binding.source_identity == [0; 32]
        || binding.task_id != task_id
        || binding.report_digest == [0; 32]
        || !RepairTicketId::is_valid_str(&binding.ticket_id)
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "stored repair source binding is inconsistent".into(),
        ));
    }
    Ok(Some(binding))
}
fn read_repair_source_binding_for_current(
    world: &impl crate::state::WorldReadOnly,
    source_identity: [u8; 32],
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<RepairSourceBindingV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&repair_source_key(source_identity))
    else {
        return Ok(None);
    };
    let binding: RepairSourceBindingV1 =
        decode_repair_state_for_current(bytes, "repair source binding", current)?;
    let task_id = sorafs_repair_task_id_v1(binding.source_identity);
    if binding.source_identity != source_identity
        || binding.source_identity == [0; 32]
        || binding.task_id != task_id
        || binding.report_digest == [0; 32]
        || !RepairTicketId::is_valid_str(&binding.ticket_id)
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "stored repair source binding is inconsistent".into(),
        ));
    }
    Ok(Some(binding))
}
fn read_repair_status(
    world: &impl crate::state::WorldReadOnly,
) -> Result<Option<RepairLedgerStatusV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(repair_status_key()) else {
        return Ok(None);
    };
    let status: RepairLedgerStatusV1 = decode_repair_state(bytes, "repair ledger status")?;
    let terminal_sum = status
        .completed
        .checked_add(status.failed)
        .and_then(|value| value.checked_add(status.escalated));
    let open_tasks = status.tasks.checked_sub(status.terminal_outcomes);
    if status.updated_at_unix_ms == 0
        || terminal_sum != Some(status.terminal_outcomes)
        || open_tasks.is_none()
        || open_tasks.is_some_and(|open_tasks| status.leased_tasks > open_tasks)
        || status.slash_proposals != status.escalated
        || status.appeals > status.slash_proposals
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "stored repair ledger status is inconsistent".into(),
        ));
    }
    Ok(Some(status))
}
fn repair_namespace_has_key(
    world: &impl crate::state::WorldReadOnly,
    prefix: &str,
) -> Result<bool, InstructionExecutionError> {
    let start = StatePath::from_str(prefix).map_err(|error| {
        corrupt_repair_state(format!(
            "repair state namespace prefix `{prefix}` is invalid: {error}"
        ))
    })?;
    Ok(world
        .smart_contract_state()
        .range(start..)
        .next()
        .is_some_and(|(key, _)| key.to_string().starts_with(prefix)))
}
fn read_repair_status_or_prove_empty(
    world: &impl crate::state::WorldReadOnly,
) -> Result<RepairLedgerStatusV1, InstructionExecutionError> {
    if let Some(status) = read_repair_status(world)? {
        return Ok(status);
    }
    if world
        .smart_contract_state()
        .get(repair_event_journal_head_key())
        .is_some()
        || repair_namespace_has_key(world, REPAIR_TASK_STATE_KEY_PREFIX_V1)?
        || repair_namespace_has_key(world, REPAIR_SOURCE_STATE_KEY_PREFIX_V1)?
        || repair_namespace_has_key(world, REPAIR_EVENT_STATE_KEY_PREFIX_V1)?
    {
        return Err(corrupt_repair_state(
            "repair ledger status is absent while orphaned repair state remains",
        ));
    }
    Ok(RepairLedgerStatusV1::default())
}
fn validate_repair_task_record(
    task: &RepairLedgerTaskV1,
    ticket_id: &str,
    task_allocation: usize,
) -> Result<(), InstructionExecutionError> {
    let mut report_current =
        crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(task_allocation)
            .map_err(InstructionExecutionError::Query)?;
    let report: RepairReportV1 = decode_stored_repair_payload_for_current(
        &task.canonical_report,
        "stored repair report",
        &mut report_current,
    )?;
    report.validate().map_err(|error| {
        InstructionExecutionError::InvariantViolation(
            format!("stored repair report is invalid: {error}").into(),
        )
    })?;
    let expected_revision = u64::try_from(task.action_receipts.len())
        .ok()
        .and_then(|count| count.checked_add(1));
    if task.version != REPAIR_LEDGER_TASK_VERSION_V1
        || task.source_identity == [0; 32]
        || task.task_id != sorafs_repair_task_id_v1(task.source_identity)
        || task.ticket_id != ticket_id
        || report.ticket_id.0 != task.ticket_id
        || report.evidence.manifest_digest != task.manifest_digest
        || report.evidence.provider_id != task.provider_id
        || report.auditor_account != task.submitted_by.to_string()
        || task.submitted_at_unix_ms == 0
        || task.updated_at_unix_ms < task.submitted_at_unix_ms
        || task.revision == 0
        || expected_revision != Some(task.revision)
        || task.action_receipts.len() > REPAIR_LEDGER_MAX_RECEIPTS_V1
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "stored repair task metadata is inconsistent".into(),
        ));
    }
    let report_submitted_at_unix = report.submitted_at_unix;
    drop(report);
    let mut last_revision = 1_u64;
    for (index, receipt) in task.action_receipts.iter().enumerate() {
        let expected = last_revision.checked_add(1).ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                "stored repair receipt revision overflow".into(),
            )
        })?;
        if receipt.idempotency_digest == [0; 32]
            || receipt.action_digest == [0; 32]
            || task.action_receipts[..index]
                .iter()
                .any(|prior| prior.idempotency_digest == receipt.idempotency_digest)
            || receipt.resulting_revision != expected
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "stored repair action receipts are inconsistent".into(),
            ));
        }
        last_revision = expected;
    }
    if let Some(lease) = &task.lease {
        if lease.generation == 0
            || lease.acquired_at_unix_ms == 0
            || lease.renewed_at_unix_ms < lease.acquired_at_unix_ms
            || lease.expires_at_unix_ms <= lease.renewed_at_unix_ms
            || task.terminal_outcome.is_some()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "stored repair lease is inconsistent".into(),
            ));
        }
    }
    match (&task.terminal_outcome, &task.slash, &task.appeal) {
        (None, None, None) => {}
        (
            Some(RepairLedgerTerminalOutcomeV1 {
                kind:
                    RepairLedgerTerminalKindV1::Completed(RepairLedgerCompletedV1 { evidence_digest }),
                ..
            }),
            None,
            None,
        ) if *evidence_digest != [0; 32] => {}
        (
            Some(RepairLedgerTerminalOutcomeV1 {
                kind: RepairLedgerTerminalKindV1::Failed(RepairLedgerFailedV1 { failure_digest }),
                ..
            }),
            None,
            None,
        ) if *failure_digest != [0; 32] => {}
        (
            Some(RepairLedgerTerminalOutcomeV1 {
                kind:
                    RepairLedgerTerminalKindV1::Escalated(RepairLedgerEscalatedV1 {
                        slash_proposal_digest,
                    }),
                finalized_by,
                ..
            }),
            Some(slash),
            appeal,
        ) if *slash_proposal_digest != [0; 32]
            && *slash_proposal_digest == slash.proposal_digest
            && slash.proposal_digest == *blake3_hash(&slash.canonical_proposal).as_bytes()
            && &slash.submitted_by == finalized_by
            && slash.submitted_at_unix_ms != 0
            && appeal.as_ref().is_none_or(|appeal| {
                appeal.slash_proposal_digest == slash.proposal_digest
                    && appeal.evidence_digest != [0; 32]
                    && !appeal.reason.is_empty()
                    && appeal.reason == appeal.reason.trim()
                    && appeal.reason.len() <= REPAIR_LEDGER_MAX_APPEAL_REASON_BYTES_V1
                    && !appeal.reason.chars().any(char::is_control)
                    && appeal.submitted_at_unix_ms >= slash.submitted_at_unix_ms
                    && appeal.appeal_id
                        == sorafs_repair_appeal_id_v1(
                            task.task_id,
                            slash.proposal_digest,
                            &appeal.appellant,
                            appeal.evidence_digest,
                            &appeal.reason,
                        )
            }) => {}
        _ => {
            return Err(InstructionExecutionError::InvariantViolation(
                "stored repair terminal, slash, and appeal records are inconsistent".into(),
            ));
        }
    }
    if let Some(slash) = &task.slash {
        let mut proposal_current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(task_allocation)
                .map_err(InstructionExecutionError::Query)?;
        let proposal: RepairSlashProposalV1 = decode_repair_state_for_current(
            &slash.canonical_proposal,
            "stored repair slash proposal",
            &mut proposal_current,
        )?;
        proposal.validate().map_err(|error| {
            InstructionExecutionError::InvariantViolation(
                format!("stored repair slash proposal is invalid: {error}").into(),
            )
        })?;
        if proposal.ticket_id.0 != task.ticket_id
            || proposal.provider_id != task.provider_id
            || proposal.manifest_digest != task.manifest_digest
            || proposal.auditor_account != task.submitted_by.to_string()
            || proposal.approval.is_some()
            || proposal.submitted_at_unix < report_submitted_at_unix
            || proposal.submitted_at_unix > slash.submitted_at_unix_ms / 1_000
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "stored repair slash proposal does not match its task provenance".into(),
            ));
        }
    }
    if let Some(terminal) = &task.terminal_outcome
        && (terminal.lease_generation == 0
            || terminal.finalized_at_unix_ms < task.submitted_at_unix_ms
            || terminal.finalized_at_unix_ms > task.updated_at_unix_ms
            || task.lease.is_some())
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "stored repair terminal provenance is inconsistent".into(),
        ));
    }
    Ok(())
}
fn read_repair_task(
    world: &impl crate::state::WorldReadOnly,
    ticket_id: &str,
) -> Result<Option<RepairLedgerTaskV1>, InstructionExecutionError> {
    let mut current = crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)
        .map_err(InstructionExecutionError::Query)?;
    read_repair_task_for_current(world, ticket_id, &mut current)
}
fn read_repair_task_for_current(
    world: &impl crate::state::WorldReadOnly,
    ticket_id: &str,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<RepairLedgerTaskV1>, InstructionExecutionError> {
    if !RepairTicketId::is_valid_str(ticket_id) {
        return Err(invalid_parameter("invalid repair ticket id"));
    }
    let Some(bytes) = world
        .smart_contract_state()
        .get(&repair_task_key(ticket_id))
    else {
        return Ok(None);
    };
    let task: RepairLedgerTaskV1 = decode_repair_state_for_current(bytes, "repair task", current)?;
    let resident_task_allocation = current.resident_bytes();
    validate_repair_task_record(&task, ticket_id, resident_task_allocation)?;
    let mut binding_current =
        crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
            resident_task_allocation,
        )
        .map_err(InstructionExecutionError::Query)?;
    let binding =
        read_repair_source_binding_for_current(world, task.source_identity, &mut binding_current)?
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "stored repair task is missing its source binding".into(),
                )
            })?;
    if binding.task_id != task.task_id
        || binding.ticket_id != task.ticket_id
        || binding.report_digest != *blake3_hash(&task.canonical_report).as_bytes()
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "stored repair task disagrees with its source binding".into(),
        ));
    }
    Ok(Some(task))
}
fn validate_repair_persisted_event(
    record: &RepairPersistedEventV1,
    expected_sequence: u64,
) -> Result<(), InstructionExecutionError> {
    let event = &record.event;
    let revision_floor = match event.kind {
        SorafsRepairLedgerEventKind::TaskSubmitted => 1,
        SorafsRepairLedgerEventKind::LeaseClaimed
        | SorafsRepairLedgerEventKind::LeaseRenewed
        | SorafsRepairLedgerEventKind::Completed
        | SorafsRepairLedgerEventKind::Failed
        | SorafsRepairLedgerEventKind::Escalated => 2,
        SorafsRepairLedgerEventKind::Appealed => 4,
    };
    if record.sequence == 0
        || record.sequence != expected_sequence
        || record.target_block_height == 0
        || event.task_id == [0; 32]
        || event.provider_id.as_bytes() == &[0; 32]
        || event.manifest_digest.as_bytes() == &[0; 32]
        || event.revision < revision_floor
        || event.occurred_at_unix_ms == 0
        || !RepairTicketId::is_valid_str(&event.ticket_id)
        || (event.kind == SorafsRepairLedgerEventKind::TaskSubmitted && event.revision != 1)
    {
        return Err(corrupt_repair_state(
            "stored repair event cursor metadata or payload is invalid",
        ));
    }
    Ok(())
}
fn validate_repair_event_successor(
    previous: Option<&RepairPersistedEventV1>,
    current: &RepairPersistedEventV1,
) -> Result<(), InstructionExecutionError> {
    let Some(previous) = previous else {
        if current.sequence != 1
            || current.event_index != 0
            || current.event.kind != SorafsRepairLedgerEventKind::TaskSubmitted
            || current.event.revision != 1
        {
            return Err(corrupt_repair_state(
                "repair event journal does not begin with task submission at sequence one and block index zero",
            ));
        }
        return Ok(());
    };
    if previous
        .sequence
        .checked_add(1)
        .is_none_or(|next| current.sequence != next)
    {
        return Err(corrupt_repair_state(
            "repair event journal sequence is not contiguous",
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
        _ => Err(corrupt_repair_state(
            "repair event journal block height/index ordering is invalid",
        )),
    }
}
fn validate_repair_event_successor_position(
    previous: Option<RepairQueryEventPosition>,
    current: &RepairPersistedEventV1,
) -> Result<(), InstructionExecutionError> {
    let Some(previous) = previous else {
        if current.sequence != 1
            || current.event_index != 0
            || current.event.kind != SorafsRepairLedgerEventKind::TaskSubmitted
            || current.event.revision != 1
        {
            return Err(corrupt_repair_state(
                "repair event journal does not begin with task submission at sequence one and block index zero",
            ));
        }
        return Ok(());
    };
    if previous
        .sequence
        .checked_add(1)
        .is_none_or(|next| current.sequence != next)
    {
        return Err(corrupt_repair_state(
            "repair event journal sequence is not contiguous",
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
        _ => Err(corrupt_repair_state(
            "repair event journal block height/index ordering is invalid",
        )),
    }
}
fn read_repair_persisted_event(
    world: &impl crate::state::WorldReadOnly,
    sequence: u64,
) -> Result<Option<RepairPersistedEventV1>, InstructionExecutionError> {
    read_repair_persisted_event_measured(world, sequence)
        .map(|record| record.map(|(record, _)| record))
}
fn read_repair_persisted_event_measured(
    world: &impl crate::state::WorldReadOnly,
    sequence: u64,
) -> Result<Option<(RepairPersistedEventV1, usize)>, InstructionExecutionError> {
    if sequence == 0 {
        return Err(corrupt_repair_state(
            "repair event sequence zero cannot be read",
        ));
    }
    let Some(bytes) = world
        .smart_contract_state()
        .get(&repair_event_key(sequence))
    else {
        return Ok(None);
    };
    let (record, allocation): (RepairPersistedEventV1, usize) =
        decode_repair_state_measured(bytes, "repair committed event")?;
    validate_repair_persisted_event(&record, sequence)?;
    Ok(Some((record, allocation)))
}
fn read_repair_event_journal_head(
    world: &impl crate::state::WorldReadOnly,
) -> Result<Option<RepairEventJournalHeadV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(repair_event_journal_head_key())
    else {
        return Ok(None);
    };
    let head: RepairEventJournalHeadV1 = decode_repair_state(bytes, "repair event journal head")?;
    if head.last_sequence == 0 || head.last_target_block_height == 0 {
        return Err(corrupt_repair_state(
            "stored repair event journal head is invalid",
        ));
    }
    let predecessor = if head.last_sequence == 1 {
        None
    } else {
        let predecessor_sequence = head.last_sequence - 1;
        let predecessor =
            read_repair_persisted_event(world, predecessor_sequence)?.ok_or_else(|| {
                corrupt_repair_state(format!(
                    "repair event journal is missing terminal predecessor sequence {predecessor_sequence}"
                ))
            })?;
        Some(RepairQueryEventPosition::from(&predecessor))
    };
    let record = read_repair_persisted_event(world, head.last_sequence)?.ok_or_else(|| {
        corrupt_repair_state("repair event journal head references a missing event")
    })?;
    if record.target_block_height != head.last_target_block_height
        || record.event_index != head.last_event_index
    {
        return Err(corrupt_repair_state(
            "repair event journal head does not match its terminal event",
        ));
    }
    validate_repair_event_successor_position(predecessor, &record)?;
    Ok(Some(head))
}
fn ensure_no_repair_event_after_head(
    world: &impl crate::state::WorldReadOnly,
    head: Option<RepairEventJournalHeadV1>,
) -> Result<(), InstructionExecutionError> {
    let prefix_start = StatePath::from_str(REPAIR_EVENT_STATE_KEY_PREFIX_V1)
        .expect("static event prefix is valid");
    let first_event_key = world
        .smart_contract_state()
        .range(prefix_start..)
        .next()
        .and_then(|(key, _)| {
            key.to_string()
                .starts_with(REPAIR_EVENT_STATE_KEY_PREFIX_V1)
                .then_some(key)
        });
    match (head, first_event_key) {
        (None, None) => return Ok(()),
        (None, Some(_)) => {
            return Err(corrupt_repair_state(
                "repair event journal contains records without a head",
            ));
        }
        (Some(_), Some(key)) if *key == repair_event_key(1) => {}
        (Some(_), _) => {
            return Err(corrupt_repair_state(
                "repair event journal does not begin at sequence one",
            ));
        }
    }
    let start = head.map_or_else(
        || {
            StatePath::from_str(REPAIR_EVENT_STATE_KEY_PREFIX_V1)
                .expect("static event prefix is valid")
        },
        |head| repair_event_key(head.last_sequence),
    );
    for (key, _) in world.smart_contract_state().range(start..) {
        let rendered = key.to_string();
        if !rendered.starts_with(REPAIR_EVENT_STATE_KEY_PREFIX_V1) {
            break;
        }
        if head.is_some_and(|head| *key == repair_event_key(head.last_sequence)) {
            continue;
        }
        return Err(corrupt_repair_state(
            "repair event journal contains a record beyond its head",
        ));
    }
    Ok(())
}
fn validate_repair_event_task_binding(
    world: &impl crate::state::WorldReadOnly,
    record: &RepairPersistedEventV1,
) -> Result<usize, InstructionExecutionError> {
    let mut current = crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)
        .map_err(InstructionExecutionError::Query)?;
    validate_repair_event_task_binding_for_current(world, record, &mut current)
}
fn validate_repair_event_task_binding_for_current(
    world: &impl crate::state::WorldReadOnly,
    record: &RepairPersistedEventV1,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<usize, InstructionExecutionError> {
    let event = &record.event;
    let task_state_bytes = world
        .smart_contract_state()
        .get(&repair_task_key(&event.ticket_id))
        .map_or(0, Vec::len);
    let task =
        read_repair_task_for_current(world, &event.ticket_id, current)?.ok_or_else(|| {
            corrupt_repair_state(format!(
                "repair event sequence {} references a missing task",
                record.sequence
            ))
        })?;
    let source_state_bytes = world
        .smart_contract_state()
        .get(&repair_source_key(task.source_identity))
        .map_or(0, Vec::len);
    let inspected_state_bytes = task_state_bytes
        .checked_add(source_state_bytes)
        .ok_or_else(|| corrupt_repair_state("repair event binding byte counter overflow"))?;
    if event.task_id != task.task_id
        || event.provider_id.as_bytes() != &task.provider_id
        || event.manifest_digest.as_bytes() != &task.manifest_digest
        || event.revision > task.revision
        || !(task.submitted_at_unix_ms..=task.updated_at_unix_ms)
            .contains(&event.occurred_at_unix_ms)
    {
        return Err(corrupt_repair_state(format!(
            "repair event sequence {} disagrees with its authoritative task",
            record.sequence
        )));
    }
    if event.kind == SorafsRepairLedgerEventKind::TaskSubmitted {
        if event.revision != 1
            || event.authority != task.submitted_by
            || event.occurred_at_unix_ms != task.submitted_at_unix_ms
        {
            return Err(corrupt_repair_state(
                "repair task-submission event provenance is inconsistent",
            ));
        }
        return Ok(inspected_state_bytes);
    }
    let receipt_index = event
        .revision
        .checked_sub(2)
        .and_then(|index| usize::try_from(index).ok())
        .ok_or_else(|| {
            corrupt_repair_state("repair event revision cannot index action receipts")
        })?;
    if task
        .action_receipts
        .get(receipt_index)
        .is_none_or(|receipt| receipt.resulting_revision != event.revision)
    {
        return Err(corrupt_repair_state(
            "repair event revision has no matching authoritative action receipt",
        ));
    }
    match event.kind {
        SorafsRepairLedgerEventKind::TaskSubmitted
        | SorafsRepairLedgerEventKind::LeaseClaimed
        | SorafsRepairLedgerEventKind::LeaseRenewed => {}
        SorafsRepairLedgerEventKind::Completed => {
            let Some(RepairLedgerTerminalOutcomeV1 {
                kind: RepairLedgerTerminalKindV1::Completed(_),
                finalized_by,
                finalized_at_unix_ms,
                ..
            }) = &task.terminal_outcome
            else {
                return Err(corrupt_repair_state(
                    "repair completion event has no matching terminal outcome",
                ));
            };
            if finalized_by != &event.authority
                || *finalized_at_unix_ms != event.occurred_at_unix_ms
            {
                return Err(corrupt_repair_state(
                    "repair completion event provenance is inconsistent",
                ));
            }
        }
        SorafsRepairLedgerEventKind::Failed => {
            let Some(RepairLedgerTerminalOutcomeV1 {
                kind: RepairLedgerTerminalKindV1::Failed(_),
                finalized_by,
                finalized_at_unix_ms,
                ..
            }) = &task.terminal_outcome
            else {
                return Err(corrupt_repair_state(
                    "repair failure event has no matching terminal outcome",
                ));
            };
            if finalized_by != &event.authority
                || *finalized_at_unix_ms != event.occurred_at_unix_ms
            {
                return Err(corrupt_repair_state(
                    "repair failure event provenance is inconsistent",
                ));
            }
        }
        SorafsRepairLedgerEventKind::Escalated => {
            let Some(RepairLedgerTerminalOutcomeV1 {
                kind: RepairLedgerTerminalKindV1::Escalated(_),
                finalized_by,
                finalized_at_unix_ms,
                ..
            }) = &task.terminal_outcome
            else {
                return Err(corrupt_repair_state(
                    "repair escalation event has no matching terminal outcome",
                ));
            };
            if finalized_by != &event.authority
                || *finalized_at_unix_ms != event.occurred_at_unix_ms
                || task.slash.is_none()
            {
                return Err(corrupt_repair_state(
                    "repair escalation event provenance is inconsistent",
                ));
            }
        }
        SorafsRepairLedgerEventKind::Appealed => {
            let Some(appeal) = &task.appeal else {
                return Err(corrupt_repair_state(
                    "repair appeal event has no matching appeal record",
                ));
            };
            if appeal.appellant != event.authority
                || appeal.submitted_at_unix_ms != event.occurred_at_unix_ms
            {
                return Err(corrupt_repair_state(
                    "repair appeal event provenance is inconsistent",
                ));
            }
        }
    }
    Ok(inspected_state_bytes)
}
fn validate_repair_event_current_transition(
    task: &RepairLedgerTaskV1,
    event: &SorafsRepairLedgerEvent,
) -> Result<(), InstructionExecutionError> {
    if (task.revision, task.updated_at_unix_ms) != (event.revision, event.occurred_at_unix_ms) {
        return Err(corrupt_repair_state(
            "repair event does not describe the latest accepted task transition",
        ));
    }
    let valid = match event.kind {
        SorafsRepairLedgerEventKind::TaskSubmitted => {
            task.revision == 1
                && task.action_receipts.is_empty()
                && task.lease.is_none()
                && task.terminal_outcome.is_none()
                && task.slash.is_none()
                && task.appeal.is_none()
        }
        SorafsRepairLedgerEventKind::LeaseClaimed => {
            task.lease.as_ref().is_some_and(|lease| {
                lease.owner == event.authority
                    && lease.acquired_at_unix_ms == event.occurred_at_unix_ms
                    && lease.renewed_at_unix_ms == event.occurred_at_unix_ms
            }) && task.terminal_outcome.is_none()
        }
        SorafsRepairLedgerEventKind::LeaseRenewed => {
            task.lease.as_ref().is_some_and(|lease| {
                lease.owner == event.authority
                    && lease.renewed_at_unix_ms == event.occurred_at_unix_ms
            }) && task.terminal_outcome.is_none()
        }
        SorafsRepairLedgerEventKind::Completed => matches!(
            &task.terminal_outcome,
            Some(RepairLedgerTerminalOutcomeV1 {
                kind: RepairLedgerTerminalKindV1::Completed(_),
                finalized_by,
                finalized_at_unix_ms,
                ..
            }) if finalized_by == &event.authority
                && *finalized_at_unix_ms == event.occurred_at_unix_ms
                && task.lease.is_none()
        ),
        SorafsRepairLedgerEventKind::Failed => matches!(
            &task.terminal_outcome,
            Some(RepairLedgerTerminalOutcomeV1 {
                kind: RepairLedgerTerminalKindV1::Failed(_),
                finalized_by,
                finalized_at_unix_ms,
                ..
            }) if finalized_by == &event.authority
                && *finalized_at_unix_ms == event.occurred_at_unix_ms
                && task.lease.is_none()
        ),
        SorafsRepairLedgerEventKind::Escalated => matches!(
            &task.terminal_outcome,
            Some(RepairLedgerTerminalOutcomeV1 {
                kind: RepairLedgerTerminalKindV1::Escalated(_),
                finalized_by,
                finalized_at_unix_ms,
                ..
            }) if finalized_by == &event.authority
                && *finalized_at_unix_ms == event.occurred_at_unix_ms
                && task.lease.is_none()
                && task.slash.is_some()
        ),
        SorafsRepairLedgerEventKind::Appealed => task.appeal.as_ref().is_some_and(|appeal| {
            appeal.appellant == event.authority
                && appeal.submitted_at_unix_ms == event.occurred_at_unix_ms
        }),
    };
    if !valid {
        return Err(corrupt_repair_state(
            "repair event kind disagrees with the latest task transition",
        ));
    }
    Ok(())
}
fn append_repair_event_journal(
    state_transaction: &mut StateTransaction<'_, '_>,
    task: &RepairLedgerTaskV1,
    event: &SorafsRepairLedgerEvent,
) -> Result<(), InstructionExecutionError> {
    let committed_parent_height =
        u64::try_from(state_transaction.block_hashes().len()).map_err(|_| {
            corrupt_repair_state("committed repair parent height does not fit into u64")
        })?;
    let target_block_height = committed_parent_height
        .checked_add(1)
        .ok_or_else(|| corrupt_repair_state("repair event target block height overflow"))?;
    let executing_block_height = state_transaction._curr_block.height().get();
    if target_block_height != executing_block_height {
        return Err(corrupt_repair_state(format!(
            "repair event target height {target_block_height} does not match executing block height {executing_block_height}"
        )));
    }
    let head = read_repair_event_journal_head(state_transaction.world())?;
    ensure_no_repair_event_after_head(state_transaction.world(), head)?;
    let (sequence, event_index, previous) = match head {
        Some(head) => {
            let sequence = head
                .last_sequence
                .checked_add(1)
                .ok_or_else(|| corrupt_repair_state("repair event sequence overflow"))?;
            let event_index = match head.last_target_block_height.cmp(&target_block_height) {
                core::cmp::Ordering::Less => 0,
                core::cmp::Ordering::Equal => head
                    .last_event_index
                    .checked_add(1)
                    .ok_or_else(|| corrupt_repair_state("repair event block index overflow"))?,
                core::cmp::Ordering::Greater => {
                    return Err(corrupt_repair_state(
                        "repair event target height regressed behind the journal head",
                    ));
                }
            };
            let previous =
                read_repair_persisted_event(state_transaction.world(), head.last_sequence)?
                    .ok_or_else(|| {
                        corrupt_repair_state("repair event journal head lost its terminal record")
                    })?;
            (sequence, event_index, Some(previous))
        }
        None => {
            let status = read_repair_status(state_transaction.world())?
                .ok_or_else(|| corrupt_repair_state("first repair event has no ledger status"))?;
            let initial_status = status.tasks == 1
                && status.leased_tasks == 0
                && status.terminal_outcomes == 0
                && status.completed == 0
                && status.failed == 0
                && status.escalated == 0
                && status.slash_proposals == 0
                && status.appeals == 0
                && status.updated_at_unix_ms == event.occurred_at_unix_ms;
            if event.kind != SorafsRepairLedgerEventKind::TaskSubmitted
                || event.revision != 1
                || !initial_status
            {
                return Err(corrupt_repair_state(
                    "repair event journal must begin with the first task submission",
                ));
            }
            (1, 0, None)
        }
    };
    let key = repair_event_key(sequence);
    if state_transaction
        .world
        .smart_contract_state
        .get(&key)
        .is_some()
    {
        return Err(corrupt_repair_state(
            "repair event journal sequence already exists",
        ));
    }
    let record = RepairPersistedEventV1 {
        sequence,
        target_block_height,
        event_index,
        event: event.clone(),
    };
    validate_repair_persisted_event(&record, sequence)?;
    validate_repair_event_successor(previous.as_ref(), &record)?;
    validate_repair_event_task_binding(state_transaction.world(), &record)?;
    validate_repair_event_current_transition(task, event)?;
    let next_head = RepairEventJournalHeadV1 {
        last_sequence: sequence,
        last_target_block_height: target_block_height,
        last_event_index: event_index,
    };
    let encoded_record = encode_repair_state(&record, "repair committed event")?;
    let encoded_head = encode_repair_state(&next_head, "repair event journal head")?;
    state_transaction
        .world
        .smart_contract_state
        .insert(key, encoded_record);
    state_transaction
        .world
        .smart_contract_state
        .insert(repair_event_journal_head_key().clone(), encoded_head);
    Ok(())
}
fn repair_action_digest<T: norito::core::NoritoSerialize>(
    authority: &AccountId,
    action: &T,
) -> Result<[u8; 32], InstructionExecutionError> {
    // The data-model helper owns the public domain-separated preimage. Pin any
    // internal encoding it performs to the canonical V1 layout as part of this
    // consensus boundary.
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    sorafs_repair_action_digest_v1(authority, action)
        .map_err(|error| invalid_parameter(format!("failed to encode repair action: {error}")))
}
fn repair_action_is_replay(
    task: &RepairLedgerTaskV1,
    idempotency_digest: [u8; 32],
    action_digest: [u8; 32],
) -> Result<bool, InstructionExecutionError> {
    let Some(receipt) = task
        .action_receipts
        .iter()
        .find(|receipt| receipt.idempotency_digest == idempotency_digest)
    else {
        return Ok(false);
    };
    if receipt.action_digest == action_digest {
        return Ok(true);
    }
    Err(invalid_parameter(
        "repair idempotency key was already used for a different action",
    ))
}
fn append_repair_receipt(
    task: &mut RepairLedgerTaskV1,
    idempotency_digest: [u8; 32],
    action_digest: [u8; 32],
    now: u64,
) -> Result<(), InstructionExecutionError> {
    if task.action_receipts.len() >= REPAIR_LEDGER_MAX_RECEIPTS_V1 {
        return Err(invalid_parameter(
            "repair task reached the bounded idempotency receipt limit",
        ));
    }
    let revision = task.revision.checked_add(1).ok_or_else(|| {
        InstructionExecutionError::InvariantViolation("repair task revision overflow".into())
    })?;
    task.action_receipts.push(RepairLedgerActionReceiptV1 {
        idempotency_digest,
        action_digest,
        resulting_revision: revision,
    });
    task.revision = revision;
    task.updated_at_unix_ms = now;
    Ok(())
}
fn ensure_repair_receipt_capacity(
    task: &RepairLedgerTaskV1,
    reserved_after: usize,
    action: &str,
) -> Result<(), InstructionExecutionError> {
    let required = task
        .action_receipts
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_add(reserved_after))
        .ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                "repair receipt-capacity calculation overflow".into(),
            )
        })?;
    if required > REPAIR_LEDGER_MAX_RECEIPTS_V1 {
        return Err(invalid_parameter(format!(
            "repair {action} would consume receipt capacity reserved for terminal outcome and appeal"
        )));
    }
    Ok(())
}
fn repair_active_lease<'a>(
    task: &'a RepairLedgerTaskV1,
    authority: &AccountId,
    generation: u64,
    now: u64,
) -> Result<&'a RepairLedgerLeaseV1, InstructionExecutionError> {
    let lease = task
        .lease
        .as_ref()
        .ok_or_else(|| invalid_parameter("repair task has no active worker lease"))?;
    if &lease.owner != authority {
        return Err(invalid_parameter(
            "repair task lease is owned by a different account",
        ));
    }
    if generation == 0 || lease.generation != generation {
        return Err(invalid_parameter("repair task lease generation mismatch"));
    }
    if now >= lease.expires_at_unix_ms {
        return Err(invalid_parameter("repair task lease is expired"));
    }
    Ok(lease)
}
fn emit_repair_ledger_event(
    state_transaction: &mut StateTransaction<'_, '_>,
    task: &RepairLedgerTaskV1,
    kind: SorafsRepairLedgerEventKind,
    authority: &AccountId,
    now: u64,
) -> Result<(), InstructionExecutionError> {
    let event = SorafsRepairLedgerEvent {
        kind,
        ticket_id: task.ticket_id.clone(),
        task_id: task.task_id,
        provider_id: ProviderId::new(task.provider_id),
        manifest_digest: ManifestDigest::new(task.manifest_digest),
        revision: task.revision,
        authority: authority.clone(),
        occurred_at_unix_ms: now,
    };
    append_repair_event_journal(state_transaction, task, &event)?;
    state_transaction
        .world
        .emit_events(Some(SorafsGatewayEvent::RepairLedger(event)));
    Ok(())
}
impl Execute for iroha_data_model::isi::sorafs::SubmitSorafsRepairTask {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        if self.source_identity == [0; 32] {
            return Err(invalid_parameter("repair source identity must be non-zero"));
        }
        if state_transaction.world.accounts.get(authority).is_none() {
            return Err(invalid_parameter(
                "repair task authority is not a registered account",
            ));
        }
        let report: RepairReportV1 = decode_repair_payload(&self.report_payload, "repair report")?;
        report
            .validate()
            .map_err(|error| invalid_parameter(format!("invalid repair report: {error}")))?;
        if report.auditor_account != authority.to_string() {
            return Err(invalid_parameter(
                "repair report auditor must equal the transaction authority",
            ));
        }
        if !state_transaction._curr_block.is_genesis()
            && !has_repair_worker_permission(
                state_transaction,
                authority,
                report.evidence.provider_id,
            )
        {
            return Err(invalid_parameter(
                "provider-scoped CanOperateSorafsRepair permission required to submit a repair task",
            ));
        }
        let now = repair_block_time_ms(state_transaction)?;
        if report.submitted_at_unix > now / 1_000 {
            return Err(invalid_parameter(
                "repair report submission time is later than the committing block",
            ));
        }
        let task_id = sorafs_repair_task_id_v1(self.source_identity);
        let report_digest = *blake3_hash(&self.report_payload).as_bytes();
        if let Some(binding) =
            read_repair_source_binding(state_transaction.world(), self.source_identity)?
        {
            let task = read_repair_task(state_transaction.world(), &binding.ticket_id)?
                .ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "repair source binding references a missing task".into(),
                    )
                })?;
            if binding.task_id == task_id
                && binding.report_digest == report_digest
                && task.source_identity == self.source_identity
                && task.canonical_report == self.report_payload
            {
                return Ok(());
            }
            return Err(invalid_parameter(
                "repair source identity is already bound to a different canonical report",
            ));
        }
        if let Some(existing) = read_repair_task(state_transaction.world(), &report.ticket_id.0)? {
            if existing.task_id == task_id
                && existing.source_identity == self.source_identity
                && existing.canonical_report == self.report_payload
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "repair task exists without its source binding".into(),
                ));
            }
            return Err(invalid_parameter(
                "repair ticket is already bound to a different task",
            ));
        }
        let task = RepairLedgerTaskV1 {
            version: REPAIR_LEDGER_TASK_VERSION_V1,
            task_id,
            source_identity: self.source_identity,
            ticket_id: report.ticket_id.0.clone(),
            canonical_report: self.report_payload,
            manifest_digest: report.evidence.manifest_digest,
            provider_id: report.evidence.provider_id,
            submitted_by: authority.clone(),
            submitted_at_unix_ms: now,
            revision: 1,
            lease: None,
            terminal_outcome: None,
            slash: None,
            appeal: None,
            action_receipts: Vec::new(),
            updated_at_unix_ms: now,
        };
        validate_repair_task_record(&task, &task.ticket_id, 0)?;
        let binding = RepairSourceBindingV1 {
            source_identity: task.source_identity,
            task_id,
            ticket_id: task.ticket_id.clone(),
            report_digest,
        };
        let mut status = read_repair_status(state_transaction.world())?.unwrap_or_default();
        if status.updated_at_unix_ms != 0 && now < status.updated_at_unix_ms {
            return Err(invalid_parameter(
                "repair ledger block time precedes its latest mutation",
            ));
        }
        status.tasks = checked_repair_inc(status.tasks, "task")?;
        status.updated_at_unix_ms = now;
        let encoded_task = encode_repair_state(&task, "repair task")?;
        let encoded_binding = encode_repair_state(&binding, "repair source binding")?;
        let encoded_status = encode_repair_state(&status, "repair ledger status")?;
        state_transaction
            .world
            .smart_contract_state
            .insert(repair_task_key(&task.ticket_id), encoded_task);
        state_transaction
            .world
            .smart_contract_state
            .insert(repair_source_key(task.source_identity), encoded_binding);
        state_transaction
            .world
            .smart_contract_state
            .insert(repair_status_key().clone(), encoded_status);
        emit_repair_ledger_event(
            state_transaction,
            &task,
            SorafsRepairLedgerEventKind::TaskSubmitted,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::sorafs::ApplySorafsRepairTaskAction {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        use iroha_data_model::isi::sorafs::SorafsRepairTaskActionV1;
        if !RepairTicketId::is_valid_str(&self.ticket_id) {
            return Err(invalid_parameter("invalid repair ticket id"));
        }
        validate_repair_idempotency_key(self.action.idempotency_key())?;
        let now = repair_block_time_ms(state_transaction)?;
        let action_digest = repair_action_digest(authority, &self)?;
        let idempotency_digest =
            sorafs_repair_idempotency_digest_v1(&self.ticket_id, self.action.idempotency_key());
        let mut task = read_repair_task(state_transaction.world(), &self.ticket_id)?
            .ok_or_else(|| invalid_parameter("repair task does not exist"))?;
        if repair_action_is_replay(&task, idempotency_digest, action_digest)? {
            return Ok(());
        }
        if !has_repair_worker_permission(state_transaction, authority, task.provider_id) {
            return Err(invalid_parameter(
                "current provider-scoped CanOperateSorafsRepair permission required to mutate a repair task",
            ));
        }
        if self.expected_revision != task.revision {
            return Err(invalid_parameter(format!(
                "repair task revision mismatch: expected {}, found {}",
                self.expected_revision, task.revision
            )));
        }
        if task.terminal_outcome.is_some() {
            return Err(invalid_parameter(
                "repair task already has its terminal outcome",
            ));
        }
        if now < task.updated_at_unix_ms {
            return Err(invalid_parameter(
                "repair action block time precedes the task's latest mutation",
            ));
        }
        let mut status = read_repair_status(state_transaction.world())?.ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                "repair task exists without ledger status".into(),
            )
        })?;
        if now < status.updated_at_unix_ms {
            return Err(invalid_parameter(
                "repair action block time precedes the ledger's latest mutation",
            ));
        }
        let kind = match self.action {
            SorafsRepairTaskActionV1::Claim(action) => {
                ensure_repair_receipt_capacity(&task, 2, "lease claim")?;
                let lease_duration_ms = action.lease_duration_ms;
                validate_repair_lease_duration(lease_duration_ms)?;
                let generation = if let Some(lease) = &task.lease {
                    let owner_remains_authorized = has_repair_worker_permission(
                        state_transaction,
                        &lease.owner,
                        task.provider_id,
                    );
                    if now < lease.expires_at_unix_ms && owner_remains_authorized {
                        return Err(invalid_parameter(format!(
                            "repair task lease is held by {} until {}",
                            lease.owner, lease.expires_at_unix_ms
                        )));
                    }
                    lease.generation.checked_add(1).ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "repair lease generation overflow".into(),
                        )
                    })?
                } else {
                    status.leased_tasks = checked_repair_inc(status.leased_tasks, "leased-task")?;
                    1
                };
                let expires_at_unix_ms = now
                    .checked_add(lease_duration_ms)
                    .ok_or_else(|| invalid_parameter("repair lease expiry overflows u64"))?;
                task.lease = Some(RepairLedgerLeaseV1 {
                    owner: authority.clone(),
                    generation,
                    acquired_at_unix_ms: now,
                    renewed_at_unix_ms: now,
                    expires_at_unix_ms,
                });
                SorafsRepairLedgerEventKind::LeaseClaimed
            }
            SorafsRepairTaskActionV1::Renew(action) => {
                ensure_repair_receipt_capacity(&task, 2, "lease renewal")?;
                let lease_generation = action.lease_generation;
                let lease_duration_ms = action.lease_duration_ms;
                validate_repair_lease_duration(lease_duration_ms)?;
                repair_active_lease(&task, authority, lease_generation, now)?;
                let expires_at_unix_ms = now
                    .checked_add(lease_duration_ms)
                    .ok_or_else(|| invalid_parameter("repair lease expiry overflows u64"))?;
                let lease = task.lease.as_mut().ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "validated repair lease disappeared".into(),
                    )
                })?;
                lease.renewed_at_unix_ms = now;
                lease.expires_at_unix_ms = expires_at_unix_ms;
                SorafsRepairLedgerEventKind::LeaseRenewed
            }
            SorafsRepairTaskActionV1::Complete(action) => {
                ensure_repair_receipt_capacity(&task, 0, "completion")?;
                let lease_generation = action.lease_generation;
                let evidence_digest = action.evidence_digest;
                if evidence_digest == [0; 32] {
                    return Err(invalid_parameter(
                        "repair completion evidence digest must be non-zero",
                    ));
                }
                repair_active_lease(&task, authority, lease_generation, now)?;
                task.terminal_outcome = Some(RepairLedgerTerminalOutcomeV1 {
                    kind: RepairLedgerTerminalKindV1::Completed(RepairLedgerCompletedV1 {
                        evidence_digest,
                    }),
                    lease_generation,
                    finalized_by: authority.clone(),
                    finalized_at_unix_ms: now,
                });
                task.lease = None;
                status.leased_tasks = status.leased_tasks.checked_sub(1).ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "repair leased-task counter underflow".into(),
                    )
                })?;
                status.terminal_outcomes =
                    checked_repair_inc(status.terminal_outcomes, "terminal-outcome")?;
                status.completed = checked_repair_inc(status.completed, "completed")?;
                SorafsRepairLedgerEventKind::Completed
            }
            SorafsRepairTaskActionV1::Fail(action) => {
                ensure_repair_receipt_capacity(&task, 0, "failure")?;
                let lease_generation = action.lease_generation;
                let failure_digest = action.failure_digest;
                if failure_digest == [0; 32] {
                    return Err(invalid_parameter("repair failure digest must be non-zero"));
                }
                repair_active_lease(&task, authority, lease_generation, now)?;
                task.terminal_outcome = Some(RepairLedgerTerminalOutcomeV1 {
                    kind: RepairLedgerTerminalKindV1::Failed(RepairLedgerFailedV1 {
                        failure_digest,
                    }),
                    lease_generation,
                    finalized_by: authority.clone(),
                    finalized_at_unix_ms: now,
                });
                task.lease = None;
                status.leased_tasks = status.leased_tasks.checked_sub(1).ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "repair leased-task counter underflow".into(),
                    )
                })?;
                status.terminal_outcomes =
                    checked_repair_inc(status.terminal_outcomes, "terminal-outcome")?;
                status.failed = checked_repair_inc(status.failed, "failed")?;
                SorafsRepairLedgerEventKind::Failed
            }
            SorafsRepairTaskActionV1::Escalate(action) => {
                ensure_repair_receipt_capacity(&task, 1, "escalation")?;
                let lease_generation = action.lease_generation;
                let slash_proposal_payload = action.slash_proposal_payload;
                repair_active_lease(&task, authority, lease_generation, now)?;
                let proposal: RepairSlashProposalV1 =
                    decode_repair_payload(&slash_proposal_payload, "repair slash proposal")?;
                proposal.validate().map_err(|error| {
                    invalid_parameter(format!("invalid repair slash proposal: {error}"))
                })?;
                let report: RepairReportV1 =
                    decode_stored_repair_payload(&task.canonical_report, "stored repair report")?;
                if proposal.ticket_id.0 != task.ticket_id
                    || proposal.provider_id != task.provider_id
                    || proposal.manifest_digest != task.manifest_digest
                    || proposal.auditor_account != report.auditor_account
                    || proposal.approval.is_some()
                    || proposal.submitted_at_unix < report.submitted_at_unix
                    || proposal.submitted_at_unix > now / 1_000
                {
                    return Err(invalid_parameter(
                        "repair slash proposal does not match the authoritative task or carries an embedded approval",
                    ));
                }
                let proposal_digest = *blake3_hash(&slash_proposal_payload).as_bytes();
                task.terminal_outcome = Some(RepairLedgerTerminalOutcomeV1 {
                    kind: RepairLedgerTerminalKindV1::Escalated(RepairLedgerEscalatedV1 {
                        slash_proposal_digest: proposal_digest,
                    }),
                    lease_generation,
                    finalized_by: authority.clone(),
                    finalized_at_unix_ms: now,
                });
                task.slash = Some(RepairLedgerSlashRecordV1 {
                    canonical_proposal: slash_proposal_payload,
                    proposal_digest,
                    submitted_by: authority.clone(),
                    submitted_at_unix_ms: now,
                });
                task.lease = None;
                status.leased_tasks = status.leased_tasks.checked_sub(1).ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "repair leased-task counter underflow".into(),
                    )
                })?;
                status.terminal_outcomes =
                    checked_repair_inc(status.terminal_outcomes, "terminal-outcome")?;
                status.escalated = checked_repair_inc(status.escalated, "escalated")?;
                status.slash_proposals =
                    checked_repair_inc(status.slash_proposals, "slash-proposal")?;
                SorafsRepairLedgerEventKind::Escalated
            }
        };
        append_repair_receipt(&mut task, idempotency_digest, action_digest, now)?;
        status.updated_at_unix_ms = now;
        validate_repair_task_record(&task, &task.ticket_id, 0)?;
        let encoded_task = encode_repair_state(&task, "repair task")?;
        let encoded_status = encode_repair_state(&status, "repair ledger status")?;
        state_transaction
            .world
            .smart_contract_state
            .insert(repair_task_key(&task.ticket_id), encoded_task);
        state_transaction
            .world
            .smart_contract_state
            .insert(repair_status_key().clone(), encoded_status);
        emit_repair_ledger_event(state_transaction, &task, kind, authority, now)?;
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::sorafs::SubmitSorafsRepairAppeal {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        if !RepairTicketId::is_valid_str(&self.ticket_id) {
            return Err(invalid_parameter("invalid repair ticket id"));
        }
        validate_repair_idempotency_key(&self.idempotency_key)?;
        validate_repair_appeal_reason(&self.reason)?;
        if self.evidence_digest == [0; 32] {
            return Err(invalid_parameter(
                "repair appeal evidence digest must be non-zero",
            ));
        }
        let now = repair_block_time_ms(state_transaction)?;
        let action_digest = repair_action_digest(authority, &self)?;
        let idempotency_digest =
            sorafs_repair_idempotency_digest_v1(&self.ticket_id, &self.idempotency_key);
        let mut task = read_repair_task(state_transaction.world(), &self.ticket_id)?
            .ok_or_else(|| invalid_parameter("repair task does not exist"))?;
        if repair_action_is_replay(&task, idempotency_digest, action_digest)? {
            return Ok(());
        }
        if task.revision != self.expected_revision {
            return Err(invalid_parameter(format!(
                "repair task revision mismatch: expected {}, found {}",
                self.expected_revision, task.revision
            )));
        }
        let provider_id = ProviderId::new(task.provider_id);
        ensure_provider_owner_registered(state_transaction, &provider_id, authority)?;
        let slash = task
            .slash
            .as_ref()
            .ok_or_else(|| invalid_parameter("repair task has no slash proposal to appeal"))?;
        if task.appeal.is_some() {
            return Err(invalid_parameter(
                "repair slash proposal already has its single appeal",
            ));
        }
        if !matches!(
            task.terminal_outcome,
            Some(RepairLedgerTerminalOutcomeV1 {
                kind: RepairLedgerTerminalKindV1::Escalated(_),
                ..
            })
        ) {
            return Err(InstructionExecutionError::InvariantViolation(
                "repair slash exists without escalated terminal outcome".into(),
            ));
        }
        if now < slash.submitted_at_unix_ms || now < task.updated_at_unix_ms {
            return Err(invalid_parameter(
                "repair appeal block time precedes the slash or latest task mutation",
            ));
        }
        let slash_proposal_digest = slash.proposal_digest;
        task.appeal = Some(RepairLedgerAppealRecordV1 {
            appeal_id: sorafs_repair_appeal_id_v1(
                task.task_id,
                slash_proposal_digest,
                authority,
                self.evidence_digest,
                &self.reason,
            ),
            slash_proposal_digest,
            appellant: authority.clone(),
            evidence_digest: self.evidence_digest,
            reason: self.reason,
            submitted_at_unix_ms: now,
        });
        append_repair_receipt(&mut task, idempotency_digest, action_digest, now)?;
        let mut status = read_repair_status(state_transaction.world())?.ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                "repair task exists without ledger status".into(),
            )
        })?;
        if now < status.updated_at_unix_ms {
            return Err(invalid_parameter(
                "repair appeal block time precedes the ledger's latest mutation",
            ));
        }
        status.appeals = checked_repair_inc(status.appeals, "appeal")?;
        status.updated_at_unix_ms = now;
        validate_repair_task_record(&task, &task.ticket_id, 0)?;
        let encoded_task = encode_repair_state(&task, "repair task")?;
        let encoded_status = encode_repair_state(&status, "repair ledger status")?;
        state_transaction
            .world
            .smart_contract_state
            .insert(repair_task_key(&task.ticket_id), encoded_task);
        state_transaction
            .world
            .smart_contract_state
            .insert(repair_status_key().clone(), encoded_status);
        emit_repair_ledger_event(
            state_transaction,
            &task,
            SorafsRepairLedgerEventKind::Appealed,
            authority,
            now,
        )?;
        Ok(())
    }
}
fn repair_query_failure(error: InstructionExecutionError) -> QueryExecutionFail {
    match error {
        InstructionExecutionError::Query(error) => error,
        error => QueryExecutionFail::Conversion(error.to_string()),
    }
}
fn checked_repair_query_limit(limit: u32) -> Result<usize, QueryExecutionFail> {
    if !(1..=REPAIR_QUERY_MAX_ITEMS_V1).contains(&limit) {
        return Err(QueryExecutionFail::Conversion(format!(
            "SoraFS repair query limit {limit} is outside 1..={REPAIR_QUERY_MAX_ITEMS_V1}"
        )));
    }
    usize::try_from(limit).map_err(|_| {
        QueryExecutionFail::Conversion("SoraFS repair query limit conversion failed".to_owned())
    })
}
fn charge_repair_query_state_bytes(
    total: &mut usize,
    additional: usize,
    maximum: usize,
    label: &str,
) -> Result<(), QueryExecutionFail> {
    *total = (*total).checked_add(additional).ok_or_else(|| {
        QueryExecutionFail::Conversion(format!("{label} state-read byte counter overflow"))
    })?;
    if *total > maximum {
        return Err(QueryExecutionFail::Conversion(format!(
            "{label} inspected more than {maximum} state bytes"
        )));
    }
    Ok(())
}
fn charge_repair_query_inspected_records(
    total: &mut usize,
    additional: usize,
    maximum: usize,
    label: &str,
) -> Result<(), QueryExecutionFail> {
    *total = (*total).checked_add(additional).ok_or_else(|| {
        QueryExecutionFail::Conversion(format!("{label} inspected-record counter overflow"))
    })?;
    if *total > maximum {
        return Err(QueryExecutionFail::Conversion(format!(
            "{label} inspected more than {maximum} records"
        )));
    }
    Ok(())
}
fn ensure_repair_query_encoded_budget<T: norito::core::NoritoSerialize>(
    value: &T,
    maximum: usize,
    label: &str,
) -> Result<(), QueryExecutionFail> {
    let maximum = crate::smartcontracts::isi::query::singular_query_frame_limit(maximum);
    let encoded_len = norito::canonical_frame_len(value).map_err(|error| {
        QueryExecutionFail::Conversion(format!("failed to size {label}: {error}"))
    })?;
    if encoded_len > maximum {
        return Err(QueryExecutionFail::Conversion(format!(
            "{label} encodes to {encoded_len} bytes, above {maximum}"
        )));
    }
    Ok(())
}
fn resolve_pin_manifest_finalized_cursor(
    state_ro: &impl crate::state::StateReadOnly,
) -> Result<PinManifestFinalizedCursorV1, QueryExecutionFail> {
    let height = u64::try_from(state_ro.block_hashes().len()).map_err(|_| {
        QueryExecutionFail::Conversion(
            "finalized pin-manifest height does not fit into u64".to_owned(),
        )
    })?;
    let block_hash = state_ro
        .block_hashes()
        .last()
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "pin-manifest queries require at least one committed block".to_owned(),
            )
        })?;
    if height == 0 || block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(
            "finalized pin-manifest query anchor is invalid".to_owned(),
        ));
    }
    Ok(PinManifestFinalizedCursorV1 { height, block_hash })
}
fn pin_query_failure(error: InstructionExecutionError) -> QueryExecutionFail {
    match error {
        InstructionExecutionError::Query(error) => error,
        error => QueryExecutionFail::Conversion(error.to_string()),
    }
}
fn pin_status_kind_label(status: PinStatusKindV1) -> &'static str {
    match status {
        PinStatusKindV1::Pending => "pending",
        PinStatusKindV1::Approved => "approved",
        PinStatusKindV1::Retired => "retired",
    }
}
fn parse_pin_status_index_digest(
    key: &StatePath,
    expected_status: PinStatusKindV1,
) -> Result<ManifestDigest, QueryExecutionFail> {
    let prefix = format!(
        "{PIN_STATUS_INDEX_STATE_KEY_PREFIX_V1}{}/",
        pin_status_kind_label(expected_status)
    );
    let digest_hex = key.as_ref().strip_prefix(&prefix).ok_or_else(|| {
        QueryExecutionFail::Conversion(format!(
            "pin status-index key `{key}` is outside `{prefix}`"
        ))
    })?;
    if !is_canonical_lower_hex(digest_hex, 32) {
        return Err(QueryExecutionFail::Conversion(format!(
            "pin status-index key `{key}` has a non-canonical digest"
        )));
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(digest_hex, &mut digest).map_err(|error| {
        QueryExecutionFail::Conversion(format!(
            "pin status-index key `{key}` has an invalid digest: {error}"
        ))
    })?;
    if digest == [0; 32] {
        return Err(QueryExecutionFail::Conversion(format!(
            "pin status-index key `{key}` uses the zero digest"
        )));
    }
    Ok(ManifestDigest::new(digest))
}
fn validate_pin_status_index_marker(
    world: &impl crate::state::WorldReadOnly,
    digest: &ManifestDigest,
    status: &PinStatus,
) -> Result<(), QueryExecutionFail> {
    let key = pin_status_index_key(status, digest);
    let marker = world.smart_contract_state().get(&key).ok_or_else(|| {
        QueryExecutionFail::Conversion(format!(
            "manifest {} has no {} status-index marker",
            manifest_hex(digest),
            pin_status_label(status)
        ))
    })?;
    if !marker.is_empty() {
        return Err(QueryExecutionFail::Conversion(format!(
            "manifest {} status-index marker is not empty",
            manifest_hex(digest)
        )));
    }
    Ok(())
}
fn bounded_pin_manifest_summary(
    record: &PinManifestRecord,
) -> Result<PinManifestSummaryV1, QueryExecutionFail> {
    crate::smartcontracts::isi::query::own_singular_query_struct::<PinManifestSummaryV1, 8>(
        [
            &record.digest,
            &record.submitted_by,
            &record.submitted_epoch,
            &record.approved_epoch,
            &record.content_length,
            &record.policy.retention_epoch,
            &record.status,
            &record.successor_of,
        ],
        || PinManifestSummaryV1::from(record),
    )
}
fn finalize_pin_manifest_page(
    finalized_cursor: PinManifestFinalizedCursorV1,
    charged_usage: PinResourceUsage,
    mut manifests: Vec<PinManifestSummaryV1>,
    mut has_more: bool,
    maximum_bytes: usize,
) -> Result<PinManifestPageV1, QueryExecutionFail> {
    let maximum_bytes =
        crate::smartcontracts::isi::query::singular_query_frame_limit(maximum_bytes);
    loop {
        let next_after_digest = has_more
            .then(|| manifests.last().map(|entry| entry.digest))
            .flatten();
        let page = PinManifestPageV1 {
            finalized_cursor,
            charged_usage,
            manifests,
            has_more,
            next_after_digest,
        };
        let encoded_len = norito::canonical_frame_len(&page).map_err(|error| {
            QueryExecutionFail::Conversion(format!(
                "failed to size finalized pin-manifest page: {error}"
            ))
        })?;
        if encoded_len <= maximum_bytes {
            if page.has_more && page.next_after_digest.is_none() {
                return Err(QueryExecutionFail::Conversion(
                    "pin-manifest byte limit cannot fit one summary row".to_owned(),
                ));
            }
            return Ok(page);
        }
        manifests = page.manifests;
        if manifests.pop().is_none() {
            return Err(QueryExecutionFail::Conversion(format!(
                "pin-manifest page envelope exceeds requested {maximum_bytes}-byte limit"
            )));
        }
        has_more = true;
    }
}
fn query_pin_manifest_page(
    query: &FindSorafsPinManifests,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: PinManifestFinalizedCursorV1,
) -> Result<PinManifestPageV1, QueryExecutionFail> {
    if query.limit == 0 || query.limit > PIN_MANIFEST_QUERY_MAX_ITEMS_V1 {
        return Err(QueryExecutionFail::Conversion(format!(
            "pin-manifest page limit must be 1..={PIN_MANIFEST_QUERY_MAX_ITEMS_V1}"
        )));
    }
    if query.max_bytes < PIN_MANIFEST_QUERY_MIN_PAGE_BYTES_V1
        || query.max_bytes > PIN_MANIFEST_QUERY_MAX_PAGE_BYTES_V1
    {
        return Err(QueryExecutionFail::Conversion(format!(
            "pin-manifest page byte limit must be {PIN_MANIFEST_QUERY_MIN_PAGE_BYTES_V1}..={PIN_MANIFEST_QUERY_MAX_PAGE_BYTES_V1}"
        )));
    }
    if query
        .after_digest
        .is_some_and(|digest| digest.as_bytes() == &[0; 32])
    {
        return Err(QueryExecutionFail::Conversion(
            "pin-manifest page cursor must be non-zero".to_owned(),
        ));
    }
    let world = state_ro.world();
    let charged_usage = match read_pin_usage(world, pin_global_usage_key(), "global resource usage")
        .map_err(pin_query_failure)?
    {
        Some(usage) => usage,
        None if world.pin_manifests().iter().next().is_some() => {
            return Err(QueryExecutionFail::Conversion(
                "retained pin manifests exist without the global resource summary".to_owned(),
            ));
        }
        None => PinResourceUsage::default(),
    };
    let limit = usize::try_from(query.limit).expect("u32 page limit fits usize");
    let mut manifests = crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(limit)?;
    let mut has_more = false;
    if let Some(status) = query.status {
        let prefix =
            pin_status_index_prefix(pin_status_kind_label(status)).map_err(pin_query_failure)?;
        let start = query.after_digest.map_or_else(
            || prefix.clone(),
            |digest| {
                let status = match status {
                    PinStatusKindV1::Pending => PinStatus::Pending,
                    PinStatusKindV1::Approved => PinStatus::Approved(0),
                    PinStatusKindV1::Retired => PinStatus::Retired(0),
                };
                pin_status_index_key(&status, &digest)
            },
        );
        for (key, marker) in world.smart_contract_state().range(start..) {
            if !key.as_ref().starts_with(prefix.as_ref()) {
                break;
            }
            let digest = parse_pin_status_index_digest(key, status)?;
            if query.after_digest.is_some_and(|after| digest <= after) {
                continue;
            }
            if !marker.is_empty() {
                return Err(QueryExecutionFail::Conversion(format!(
                    "manifest {} status-index marker is not empty",
                    manifest_hex(&digest)
                )));
            }
            let record = world.pin_manifests().get(&digest).ok_or_else(|| {
                QueryExecutionFail::Conversion(format!(
                    "status index references missing pin manifest {}",
                    manifest_hex(&digest)
                ))
            })?;
            if !status.matches(&record.status) || record.digest != digest {
                return Err(QueryExecutionFail::Conversion(format!(
                    "status index disagrees with pin manifest {}",
                    manifest_hex(&digest)
                )));
            }
            if manifests.len() == limit {
                has_more = true;
                break;
            }
            manifests.try_push(bounded_pin_manifest_summary(record)?)?;
        }
    } else {
        let mut visit = |digest: &ManifestDigest,
                         record: &PinManifestRecord|
         -> Result<bool, QueryExecutionFail> {
            if query.after_digest.is_some_and(|after| *digest <= after) {
                return Ok(true);
            }
            if record.digest != *digest {
                return Err(QueryExecutionFail::Conversion(format!(
                    "pin-manifest map key disagrees with record {}",
                    manifest_hex(digest)
                )));
            }
            validate_pin_status_index_marker(world, digest, &record.status)?;
            if manifests.len() == limit {
                has_more = true;
                return Ok(false);
            }
            manifests.try_push(bounded_pin_manifest_summary(record)?)?;
            Ok(true)
        };
        if let Some(after) = query.after_digest {
            use std::ops::Bound::{Excluded, Unbounded};
            for (digest, record) in world.pin_manifests().range((Excluded(after), Unbounded)) {
                if !visit(digest, record)? {
                    break;
                }
            }
        } else {
            for (digest, record) in world.pin_manifests().iter() {
                if !visit(digest, record)? {
                    break;
                }
            }
        }
    }
    finalize_pin_manifest_page(
        finalized_cursor,
        charged_usage,
        manifests.into_vec()?,
        has_more,
        usize::try_from(query.max_bytes).expect("u32 byte limit fits usize"),
    )
}
fn resolve_repair_finalized_cursor(
    state_ro: &impl crate::state::StateReadOnly,
) -> Result<RepairFinalizedCursorV1, QueryExecutionFail> {
    let height = u64::try_from(state_ro.block_hashes().len()).map_err(|_| {
        QueryExecutionFail::Conversion("finalized repair height does not fit into u64".to_owned())
    })?;
    let block_hash = state_ro
        .block_hashes()
        .last()
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "finalized repair queries require at least one committed block".to_owned(),
            )
        })?;
    if height == 0 || block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(
            "finalized repair query anchor is invalid".to_owned(),
        ));
    }
    Ok(RepairFinalizedCursorV1 { height, block_hash })
}
fn resolve_repair_query_finalized_cursor(
    expected: Option<RepairFinalizedCursorV1>,
    state_ro: &impl crate::state::StateReadOnly,
) -> Result<RepairFinalizedCursorV1, QueryExecutionFail> {
    let actual = resolve_repair_finalized_cursor(state_ro)?;
    if expected.is_some_and(|expected| expected != actual) {
        return Err(QueryExecutionFail::Expired);
    }
    Ok(actual)
}
fn resolve_repair_committed_event(
    state_ro: &impl crate::state::StateReadOnly,
    record: RepairPersistedEventV1,
) -> Result<RepairFinalizedEventV1, QueryExecutionFail> {
    let hash_index = record
        .target_block_height
        .checked_sub(1)
        .and_then(|height| usize::try_from(height).ok())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "repair event target height cannot index finalized block hashes".to_owned(),
            )
        })?;
    let block_hash = state_ro
        .block_hashes()
        .get(hash_index)
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(format!(
                "repair event sequence {} targets non-finalized block height {}",
                record.sequence, record.target_block_height
            ))
        })?;
    if block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(format!(
            "repair event sequence {} resolved a zero block hash",
            record.sequence
        )));
    }
    Ok(RepairFinalizedEventV1 {
        sequence: record.sequence,
        block_height: record.target_block_height,
        block_hash,
        event_index: record.event_index,
        event: record.event,
    })
}
#[derive(Clone, Copy)]
struct RepairQueryEventPosition {
    sequence: u64,
    target_block_height: u64,
    event_index: u32,
}
impl From<&RepairPersistedEventV1> for RepairQueryEventPosition {
    fn from(record: &RepairPersistedEventV1) -> Self {
        Self {
            sequence: record.sequence,
            target_block_height: record.target_block_height,
            event_index: record.event_index,
        }
    }
}
fn validate_repair_query_event_successor(
    previous: Option<RepairQueryEventPosition>,
    current: &RepairPersistedEventV1,
) -> Result<(), QueryExecutionFail> {
    let Some(previous) = previous else {
        return (current.sequence == 1
            && current.event_index == 0
            && current.event.kind == SorafsRepairLedgerEventKind::TaskSubmitted
            && current.event.revision == 1)
            .then_some(())
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "repair event journal does not begin with task submission at sequence one and block index zero"
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
            "repair event journal sequence is not contiguous".to_owned(),
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
            "repair event journal block height/index ordering is invalid".to_owned(),
        )),
    }
}
fn read_repair_event_sequence(
    state_ro: &impl crate::state::StateReadOnly,
    sequence: u64,
    previous: Option<RepairQueryEventPosition>,
) -> Result<(RepairQueryEventPosition, RepairFinalizedEventV1, usize), QueryExecutionFail> {
    let event_state_bytes = state_ro
        .world()
        .smart_contract_state()
        .get(&repair_event_key(sequence))
        .map_or(0, Vec::len);
    let (record, record_allocation) =
        read_repair_persisted_event_measured(state_ro.world(), sequence)
            .map_err(repair_query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(format!(
                    "repair event journal is missing sequence {sequence}"
                ))
            })?;
    validate_repair_query_event_successor(previous, &record)?;
    let mut current =
        crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(record_allocation)?;
    let binding_state_bytes =
        validate_repair_event_task_binding_for_current(state_ro.world(), &record, &mut current)
            .map_err(repair_query_failure)?;
    let inspected_state_bytes = event_state_bytes
        .checked_add(binding_state_bytes)
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "repair event state-read byte counter overflow".to_owned(),
            )
        })?;
    let position = RepairQueryEventPosition::from(&record);
    let resolved = resolve_repair_committed_event(state_ro, record)?;
    Ok((position, resolved, inspected_state_bytes))
}
fn read_repair_indexed_task(
    world: &impl crate::state::WorldReadOnly,
    key: &StatePath,
    payload: &[u8],
    after_task_id: Option<[u8; 32]>,
) -> Result<Option<([u8; 32], RepairLedgerTaskV1)>, QueryExecutionFail> {
    let (binding, binding_allocation): (RepairSourceBindingV1, usize) =
        decode_repair_state_measured(payload, "repair source binding")
            .map_err(repair_query_failure)?;
    let RepairSourceBindingV1 {
        source_identity,
        task_id,
        ticket_id,
        report_digest,
    } = binding;
    let ticket_id = RepairTicketId(ticket_id);
    if source_identity == [0; 32]
        || task_id == [0; 32]
        || task_id != sorafs_repair_task_id_v1(source_identity)
        || report_digest == [0; 32]
        || repair_source_key(source_identity) != *key
        || ticket_id.validate().is_err()
    {
        return Err(QueryExecutionFail::Conversion(
            "authoritative repair source-binding key or record is inconsistent".to_owned(),
        ));
    }
    if after_task_id.is_some_and(|cursor| task_id <= cursor) {
        return Ok(None);
    }
    let mut current =
        crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(binding_allocation)?;
    let task = read_repair_task_for_current(world, &ticket_id.0, &mut current)
        .map_err(repair_query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "authoritative repair task disappeared during page read".to_owned(),
            )
        })?;
    if task.task_id != task_id {
        return Err(QueryExecutionFail::Conversion(
            "authoritative repair task disagrees with its page index".to_owned(),
        ));
    }
    Ok(Some((task_id, task)))
}
fn query_repair_task_page(
    query: &FindSorafsRepairTasks,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: RepairFinalizedCursorV1,
) -> Result<RepairLedgerTaskPageV1, QueryExecutionFail> {
    let limit = checked_repair_query_limit(query.limit)?;
    let world = state_ro.world();
    let start = repair_digest_key(
        REPAIR_SOURCE_STATE_KEY_PREFIX_V1,
        query.after_task_id.unwrap_or([0; 32]),
    );
    let read_budget = limit.saturating_add(2);
    let task_payload_budget = crate::smartcontracts::isi::query::singular_query_frame_limit(
        REPAIR_QUERY_MAX_TASK_PAGE_BYTES_V1,
    )
    .saturating_sub(1_024);
    let mut reads = 0usize;
    let mut state_read_bytes = 0usize;
    let mut encoded_task_bytes = 0usize;
    let mut selected_count = 0usize;
    let mut last_selected_task_id = None;
    let mut has_more = false;
    for (key, payload) in world.smart_contract_state().range(start.clone()..) {
        if !key.as_ref().starts_with(REPAIR_SOURCE_STATE_KEY_PREFIX_V1) {
            break;
        }
        charge_repair_query_inspected_records(&mut reads, 1, read_budget, "repair task page")?;
        state_read_bytes = state_read_bytes.checked_add(payload.len()).ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "repair task-page state-read byte counter overflow".to_owned(),
            )
        })?;
        if state_read_bytes > REPAIR_QUERY_MAX_TASK_STATE_READ_BYTES_V1 {
            return Err(QueryExecutionFail::Conversion(format!(
                "repair task page inspected more than {REPAIR_QUERY_MAX_TASK_STATE_READ_BYTES_V1} state bytes"
            )));
        }
        let Some((task_id, task)) =
            read_repair_indexed_task(world, key, payload, query.after_task_id)?
        else {
            continue;
        };
        let indexed_state_bytes = world
            .smart_contract_state()
            .get(&repair_task_key(&task.ticket_id))
            .map_or(0, Vec::len)
            .checked_add(payload.len())
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "repair task-page indexed-read byte counter overflow".to_owned(),
                )
            })?;
        state_read_bytes = state_read_bytes
            .checked_add(indexed_state_bytes)
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "repair task-page state-read byte counter overflow".to_owned(),
                )
            })?;
        if state_read_bytes > REPAIR_QUERY_MAX_TASK_STATE_READ_BYTES_V1 {
            return Err(QueryExecutionFail::Conversion(format!(
                "repair task page inspected more than {REPAIR_QUERY_MAX_TASK_STATE_READ_BYTES_V1} state bytes"
            )));
        }
        let task_len = norito::canonical_frame_len(&task).map_err(|error| {
            QueryExecutionFail::Conversion(format!(
                "failed to size authoritative repair task: {error}"
            ))
        })?;
        let next_encoded_task_bytes =
            encoded_task_bytes.checked_add(task_len).ok_or_else(|| {
                QueryExecutionFail::Conversion("repair task-page byte counter overflow".to_owned())
            })?;
        if selected_count >= limit || next_encoded_task_bytes > task_payload_budget {
            if selected_count == 0 {
                return Err(QueryExecutionFail::Conversion(format!(
                    "one repair task cannot fit within the {REPAIR_QUERY_MAX_TASK_PAGE_BYTES_V1}-byte page budget"
                )));
            }
            has_more = true;
            break;
        }
        encoded_task_bytes = next_encoded_task_bytes;
        selected_count = selected_count.checked_add(1).ok_or_else(|| {
            QueryExecutionFail::Conversion("repair task-page item counter overflow".to_owned())
        })?;
        last_selected_task_id = Some(task_id);
    }
    let next_after_task_id = if has_more {
        Some(last_selected_task_id.ok_or_else(|| {
            QueryExecutionFail::Conversion("repair task-page cursor invariant failed".to_owned())
        })?)
    } else {
        None
    };
    let mut tasks =
        crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(selected_count)?;
    if selected_count != 0 {
        for (key, payload) in world.smart_contract_state().range(start..) {
            if tasks.len() == selected_count {
                break;
            }
            if !key.as_ref().starts_with(REPAIR_SOURCE_STATE_KEY_PREFIX_V1) {
                break;
            }
            let Some((_, task)) =
                read_repair_indexed_task(world, key, payload, query.after_task_id)?
            else {
                continue;
            };
            tasks.try_push(task)?;
        }
    }
    if tasks.len() != selected_count {
        return Err(QueryExecutionFail::Conversion(
            "repair task-page materialization count changed during immutable read".to_owned(),
        ));
    }
    let page = RepairLedgerTaskPageV1 {
        finalized_cursor,
        tasks: tasks.into_vec()?,
        has_more,
        next_after_task_id,
    };
    ensure_repair_query_encoded_budget(
        &page,
        REPAIR_QUERY_MAX_TASK_PAGE_BYTES_V1,
        "authoritative repair task page",
    )?;
    Ok(page)
}
fn query_repair_event_page(
    query: &FindSorafsRepairEvents,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: RepairFinalizedCursorV1,
) -> Result<RepairFinalizedEventPageV1, QueryExecutionFail> {
    let limit = checked_repair_query_limit(query.limit)?;
    let world = state_ro.world();
    let head_state_bytes = world
        .smart_contract_state()
        .get(repair_event_journal_head_key())
        .map_or(0, Vec::len);
    let head = read_repair_event_journal_head(world)
        .map_err(repair_query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "active repair state has no committed-event journal".to_owned(),
            )
        })?;
    let terminal_event_state_bytes = world
        .smart_contract_state()
        .get(&repair_event_key(head.last_sequence))
        .map_or(0, Vec::len);
    let head_predecessor_state_bytes = head
        .last_sequence
        .checked_sub(1)
        .filter(|sequence| *sequence != 0)
        .and_then(|sequence| {
            world
                .smart_contract_state()
                .get(&repair_event_key(sequence))
                .map(Vec::len)
        })
        .unwrap_or(0);
    let (terminal, terminal_allocation) =
        read_repair_persisted_event_measured(world, head.last_sequence)
            .map_err(repair_query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "repair event journal terminal record disappeared during read".to_owned(),
                )
            })?;
    let mut terminal_current =
        crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
            terminal_allocation,
        )?;
    let terminal_binding_state_bytes =
        validate_repair_event_task_binding_for_current(world, &terminal, &mut terminal_current)
            .map_err(repair_query_failure)?;
    let inspected_record_budget = limit.saturating_add(6);
    let mut inspected_records = 2usize + usize::from(head.last_sequence > 1);
    let mut state_read_bytes = 0usize;
    charge_repair_query_state_bytes(
        &mut state_read_bytes,
        head_state_bytes,
        REPAIR_QUERY_MAX_EVENT_STATE_READ_BYTES_V1,
        "repair event page",
    )?;
    charge_repair_query_state_bytes(
        &mut state_read_bytes,
        terminal_event_state_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(head_predecessor_state_bytes))
            .and_then(|bytes| bytes.checked_add(terminal_binding_state_bytes))
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "repair event-page initial read-byte counter overflow".to_owned(),
                )
            })?,
        REPAIR_QUERY_MAX_EVENT_STATE_READ_BYTES_V1,
        "repair event page",
    )?;
    resolve_repair_committed_event(state_ro, terminal)?;
    ensure_no_repair_event_after_head(world, Some(head)).map_err(repair_query_failure)?;
    let mut previous = match query.after {
        Some(after) => {
            if after.sequence == 0 || after.sequence > head.last_sequence {
                return Err(QueryExecutionFail::Expired);
            }
            let cursor_event_state_bytes = world
                .smart_contract_state()
                .get(&repair_event_key(after.sequence))
                .map_or(0, Vec::len);
            let predecessor_record = if after.sequence == 1 {
                None
            } else {
                let predecessor_sequence = after.sequence - 1;
                let predecessor_state_bytes = world
                    .smart_contract_state()
                    .get(&repair_event_key(predecessor_sequence))
                    .map_or(0, Vec::len);
                charge_repair_query_state_bytes(
                    &mut state_read_bytes,
                    predecessor_state_bytes,
                    REPAIR_QUERY_MAX_EVENT_STATE_READ_BYTES_V1,
                    "repair event page",
                )?;
                charge_repair_query_inspected_records(
                    &mut inspected_records,
                    1,
                    inspected_record_budget,
                    "repair event page",
                )?;
                Some(
                    read_repair_persisted_event(world, predecessor_sequence)
                        .map_err(repair_query_failure)?
                        .ok_or_else(|| {
                            QueryExecutionFail::Conversion(format!(
                                "repair event journal is missing predecessor sequence {predecessor_sequence}"
                            ))
                        })?,
                )
            };
            let predecessor = predecessor_record
                .as_ref()
                .map(RepairQueryEventPosition::from);
            drop(predecessor_record);
            let (record, record_allocation) =
                read_repair_persisted_event_measured(world, after.sequence)
                    .map_err(repair_query_failure)?
                    .ok_or(QueryExecutionFail::Expired)?;
            let mut current =
                crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
                    record_allocation,
                )?;
            let cursor_binding_state_bytes =
                validate_repair_event_task_binding_for_current(world, &record, &mut current)
                    .map_err(repair_query_failure)?;
            charge_repair_query_state_bytes(
                &mut state_read_bytes,
                cursor_event_state_bytes
                    .checked_add(cursor_binding_state_bytes)
                    .ok_or_else(|| {
                        QueryExecutionFail::Conversion(
                            "repair event cursor read-byte counter overflow".to_owned(),
                        )
                    })?,
                REPAIR_QUERY_MAX_EVENT_STATE_READ_BYTES_V1,
                "repair event page",
            )?;
            charge_repair_query_inspected_records(
                &mut inspected_records,
                1,
                inspected_record_budget,
                "repair event page",
            )?;
            validate_repair_query_event_successor(predecessor, &record)?;
            let position = RepairQueryEventPosition::from(&record);
            let resolved = resolve_repair_committed_event(state_ro, record)?;
            if resolved.cursor() != after {
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
    let mut encoded_event_bytes = 0usize;
    while let Some(current_sequence) = sequence {
        if current_sequence > head.last_sequence || events.len() >= limit {
            break;
        }
        charge_repair_query_inspected_records(
            &mut inspected_records,
            1,
            inspected_record_budget,
            "repair event page",
        )?;
        let (position, resolved, inspected_state_bytes) =
            read_repair_event_sequence(state_ro, current_sequence, previous)?;
        charge_repair_query_state_bytes(
            &mut state_read_bytes,
            inspected_state_bytes,
            REPAIR_QUERY_MAX_EVENT_STATE_READ_BYTES_V1,
            "repair event page",
        )?;
        encoded_event_bytes = encoded_event_bytes
            .checked_add(norito::canonical_frame_len(&resolved).map_err(|error| {
                QueryExecutionFail::Conversion(format!(
                    "failed to size committed repair event: {error}"
                ))
            })?)
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "committed repair event-page byte counter overflow".to_owned(),
                )
            })?;
        if encoded_event_bytes > REPAIR_QUERY_MAX_EVENT_PAGE_BYTES_V1 {
            return Err(QueryExecutionFail::Conversion(format!(
                "committed repair event page exceeds {REPAIR_QUERY_MAX_EVENT_PAGE_BYTES_V1} bytes"
            )));
        }
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
            .expect("has_more requires a non-empty repair event page")
            .cursor()
    });
    let page = RepairFinalizedEventPageV1 {
        finalized_cursor,
        events: events.into_vec()?,
        has_more,
        next_after,
    };
    ensure_repair_query_encoded_budget(
        &page,
        REPAIR_QUERY_MAX_EVENT_PAGE_BYTES_V1,
        "committed repair event page",
    )?;
    Ok(page)
}
impl ValidSingularQuery for FindSorafsPinManifest {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<PinManifestFinalizedRecordV1, QueryExecutionFail> {
        if self.digest.as_bytes() == &[0; 32] {
            return Err(QueryExecutionFail::Conversion(
                "pin-manifest digest must be non-zero".to_owned(),
            ));
        }
        let finalized_cursor = resolve_pin_manifest_finalized_cursor(state_ro)?;
        if self
            .expected_finalized_cursor
            .is_some_and(|expected| expected != finalized_cursor)
        {
            return Err(QueryExecutionFail::Expired);
        }
        let manifest =
            state_ro
                .world()
                .pin_manifests()
                .get(&self.digest)
                .ok_or(QueryExecutionFail::Find(FindError::SorafsPinManifest(
                    self.digest,
                )))?;
        crate::smartcontracts::isi::query::own_singular_query_struct::<
            PinManifestFinalizedRecordV1,
            2,
        >([&finalized_cursor, manifest], || {
            PinManifestFinalizedRecordV1 {
                finalized_cursor,
                manifest: manifest.clone(),
            }
        })
    }
}
impl ValidSingularQuery for FindSorafsPinManifests {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<PinManifestPageV1, QueryExecutionFail> {
        let finalized_cursor = resolve_pin_manifest_finalized_cursor(state_ro)?;
        if self
            .expected_finalized_cursor
            .is_some_and(|expected| expected != finalized_cursor)
        {
            return Err(QueryExecutionFail::Expired);
        }
        query_pin_manifest_page(self, state_ro, finalized_cursor)
    }
}
impl ValidSingularQuery for FindSorafsRepairTask {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<RepairFinalizedTaskV1, QueryExecutionFail> {
        let finalized_cursor =
            resolve_repair_query_finalized_cursor(self.expected_finalized_cursor, state_ro)?;
        let task = read_repair_task(state_ro.world(), &self.ticket_id)
            .map_err(repair_query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Find(FindError::SorafsRepairTask(self.ticket_id.clone()))
            })?;
        Ok(RepairFinalizedTaskV1 {
            finalized_cursor,
            task,
        })
    }
}
impl ValidSingularQuery for FindSorafsRepairTasks {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<RepairLedgerTaskPageV1, QueryExecutionFail> {
        read_repair_status_or_prove_empty(state_ro.world()).map_err(repair_query_failure)?;
        let finalized_cursor =
            resolve_repair_query_finalized_cursor(self.expected_finalized_cursor, state_ro)?;
        query_repair_task_page(self, state_ro, finalized_cursor)
    }
}
impl ValidSingularQuery for FindSorafsRepairStatus {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<RepairFinalizedStatusV1, QueryExecutionFail> {
        let finalized_cursor =
            resolve_repair_query_finalized_cursor(self.expected_finalized_cursor, state_ro)?;
        let status =
            read_repair_status_or_prove_empty(state_ro.world()).map_err(repair_query_failure)?;
        Ok(RepairFinalizedStatusV1 {
            finalized_cursor,
            status,
        })
    }
}
impl ValidSingularQuery for FindSorafsRepairEvents {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<RepairFinalizedEventPageV1, QueryExecutionFail> {
        let status =
            read_repair_status_or_prove_empty(state_ro.world()).map_err(repair_query_failure)?;
        let finalized_cursor =
            resolve_repair_query_finalized_cursor(self.expected_finalized_cursor, state_ro)?;
        if status.tasks == 0 {
            checked_repair_query_limit(self.limit)?;
            if self.after.is_some() {
                return Err(QueryExecutionFail::Expired);
            }
            let page = RepairFinalizedEventPageV1 {
                finalized_cursor,
                events: Vec::new(),
                has_more: false,
                next_after: None,
            };
            ensure_repair_query_encoded_budget(
                &page,
                REPAIR_QUERY_MAX_EVENT_PAGE_BYTES_V1,
                "committed repair event page",
            )?;
            return Ok(page);
        }
        query_repair_event_page(self, state_ro, finalized_cursor)
    }
}
#[cfg(test)]
mod sorafs_tests {
    include!("sorafs_fixture_and_admission_tests.rs");
    include!("sorafs/initial_executor_tests.rs");
    include!("sorafs/pin_lifecycle_fixture.rs");
    include!("sorafs/publication_tests.rs");
    fn insert_pin_record_with_accounting(
        stx: &mut crate::state::StateTransaction<'_, '_>,
        record: PinManifestRecord,
    ) {
        let has_live_content_charge = pin_record_has_live_content_charge(&record);
        let accounting = prepare_pin_admission_accounting(
            stx,
            &record.submitted_by,
            &record.digest,
            record.successor_of.as_ref(),
            if has_live_content_charge {
                record.content_length
            } else {
                0
            },
            record.policy.retention_epoch,
            &record.status,
        )
        .expect("coherent pin fixture accounting");
        accounting.apply(stx);
        if !has_live_content_charge {
            stx.world.smart_contract_state.remove(pin_expiry_key(
                record.policy.retention_epoch,
                &record.digest,
            ));
        }
        stx.world.pin_manifests.insert(record.digest, record);
    }
    fn insert_pending_manifest(
        stx: &mut crate::state::StateTransaction<'_, '_>,
        digest: ManifestDigest,
        chunk_digest: [u8; 32],
    ) {
        insert_manifest_with_status(stx, digest, chunk_digest, None, PinStatus::Pending);
    }
    fn insert_pending_manifest_with_alias(
        stx: &mut crate::state::StateTransaction<'_, '_>,
        digest: ManifestDigest,
        chunk_digest: [u8; 32],
        alias: ManifestAliasBinding,
    ) -> PinManifestRecord {
        let record = PinManifestRecord::new(
            digest,
            root_cid_for_manifest(digest),
            default_chunker(),
            chunk_digest,
            por_root_for_manifest(digest),
            default_content_length(),
            default_policy(),
            alice(),
            5,
            Some(alias),
            None,
            Metadata::default(),
        );
        insert_pin_record_with_accounting(stx, record.clone());
        record
    }
    fn default_alias_binding() -> ManifestAliasBinding {
        alias_binding_for(
            default_digest(),
            "sora",
            "docs",
            5,
            default_policy().retention_epoch,
        )
    }
    fn assert_alias_registration_rejected_without_fee(
        alias: ManifestAliasBinding,
        expected_message: &str,
    ) {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let instruction = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: Some(alias),
            successor_of: None,
        };
        let err = instruction
            .execute(&alice(), &mut stx)
            .expect_err("registration must reject adversarial alias");
        match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => assert!(
                message.contains(expected_message),
                "expected error containing `{expected_message}`, got: {message}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            stx.world.pin_manifests.get(&default_digest()).is_none(),
            "rejected alias registration must not store a pin manifest"
        );
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    pub(super) fn replication_order_struct(
        order_id: ReplicationOrderId,
        manifest: ManifestDigest,
        providers: &[ProviderId],
        target_replicas: u16,
    ) -> ReplicationOrderV1 {
        let assignments = providers
            .iter()
            .map(|provider| ReplicationAssignmentV1 {
                provider_id: *provider.as_bytes(),
                slice_gib: 512,
                lane: None,
            })
            .collect();
        ReplicationOrderV1 {
            version: REPLICATION_ORDER_VERSION_V1,
            order_id: *order_id.as_bytes(),
            manifest_cid: root_cid_for_manifest(manifest).as_bytes().to_vec(),
            manifest_digest: *manifest.as_bytes(),
            chunking_profile: canonical_profile(&default_chunker()),
            target_replicas,
            assignments,
            issued_at: 1_700_000_000,
            deadline_at: 1_700_086_400,
            sla: ReplicationOrderSlaV1 {
                ingest_deadline_secs: 86_400,
                min_availability_percent_milli: 99_500,
                min_por_success_percent_milli: 98_000,
            },
            metadata: Vec::new(),
        }
    }
    pub(super) fn encode_replication_order(order: &ReplicationOrderV1) -> Vec<u8> {
        norito::encode_canonical(order).expect("serialize canonical replication order")
    }
    pub(super) fn encode_replication_order_for_epoch_window(
        mut order: ReplicationOrderV1,
        issued_epoch: u64,
        deadline_epoch: u64,
    ) -> Vec<u8> {
        let window = deadline_epoch
            .checked_sub(issued_epoch)
            .and_then(|seconds| u32::try_from(seconds).ok())
            .filter(|seconds| *seconds != 0)
            .expect("replication-order fixture window fits the V1 SLA field");
        order.issued_at = issued_epoch;
        order.deadline_at = deadline_epoch;
        order.sla.ingest_deadline_secs = window;
        encode_replication_order(&order)
    }
    fn sample_capacity_declaration() -> CapacityDeclarationV1 {
        CapacityDeclarationV1 {
            version: CAPACITY_DECLARATION_VERSION_V1,
            provider_id: [0x11; 32],
            stake: StakePointer {
                pool_id: [0x22; 32],
                stake_amount: "1".parse().expect("canonical XOR stake"),
            },
            committed_capacity_gib: 1_024,
            chunker_commitments: vec![ChunkerCommitmentV1 {
                profile_id: "sorafs.sf1@1.0.0".to_string(),
                profile_aliases: None,
                committed_gib: 1_024,
                capability_refs: vec![CapabilityType::ToriiGateway],
            }],
            lane_commitments: Vec::new(),
            pricing: None,
            valid_from: 0,
            valid_until: 2_000_000_000,
            metadata: vec![
                CapacityMetadataEntry {
                    key: PROVIDER_OWNER_METADATA_KEY.to_owned(),
                    value: account_literal(&alice()),
                },
                CapacityMetadataEntry {
                    key: STORAGE_CLASS_METADATA_KEY.to_owned(),
                    value: "hot".to_owned(),
                },
            ],
        }
    }
    fn set_capacity_storage_class(declaration: &mut CapacityDeclarationV1, value: &str) {
        declaration
            .metadata
            .iter_mut()
            .find(|entry| entry.key == STORAGE_CLASS_METADATA_KEY)
            .expect("capacity fixture explicitly declares its storage class")
            .value = value.to_owned();
    }
    fn sample_capacity_record() -> (ProviderId, CapacityDeclarationRecord) {
        let declaration = sample_capacity_declaration();
        let canonical_bytes =
            norito::encode_canonical(&declaration).expect("serialize canonical declaration");
        let provider = ProviderId::new(declaration.provider_id);
        let mut metadata = Metadata::default();
        merge_declaration_metadata_into_record(provider, &mut metadata, &declaration.metadata)
            .expect("merge canonical capacity metadata");
        let record = CapacityDeclarationRecord::new(
            provider,
            canonical_bytes,
            declaration.committed_capacity_gib,
            5,
            declaration.valid_from,
            declaration.valid_until,
            metadata,
        );
        (provider, record)
    }
    fn capacity_record_with_owner(owner: &AccountId) -> (ProviderId, CapacityDeclarationRecord) {
        let mut declaration = sample_capacity_declaration();
        declaration.metadata = vec![
            CapacityMetadataEntry {
                key: PROVIDER_OWNER_METADATA_KEY.to_owned(),
                value: account_literal(owner),
            },
            CapacityMetadataEntry {
                key: STORAGE_CLASS_METADATA_KEY.to_owned(),
                value: "hot".to_owned(),
            },
        ];
        let canonical_bytes =
            norito::encode_canonical(&declaration).expect("serialize canonical declaration");
        let provider = ProviderId::new(declaration.provider_id);
        let mut metadata = Metadata::default();
        merge_declaration_metadata_into_record(provider, &mut metadata, &declaration.metadata)
            .expect("merge canonical capacity metadata");
        let record = CapacityDeclarationRecord::new(
            provider,
            canonical_bytes,
            declaration.committed_capacity_gib,
            5,
            declaration.valid_from,
            declaration.valid_until,
            metadata,
        );
        (provider, record)
    }
    #[derive(Clone, Copy, Default)]
    struct ProofWindowCounters {
        pdp_challenges: u32,
        pdp_failures: u32,
        potr_windows: u32,
        potr_breaches: u32,
    }
    #[derive(Clone, Copy)]
    struct ProofHealthFixture {
        strike_threshold: u32,
        penalty_bond_bps: u16,
        cooldown_windows: u32,
        max_pdp_failures: u32,
        max_potr_breaches: u32,
    }
    impl ProofHealthFixture {
        fn all_proofs(strike_threshold: u32, penalty_bond_bps: u16, cooldown_windows: u32) -> Self {
            Self {
                strike_threshold,
                penalty_bond_bps,
                cooldown_windows,
                max_pdp_failures: 0,
                max_potr_breaches: 0,
            }
        }
        fn pdp(strike_threshold: u32, penalty_bond_bps: u16, cooldown_windows: u32) -> Self {
            Self {
                max_potr_breaches: u32::MAX,
                ..Self::all_proofs(strike_threshold, penalty_bond_bps, cooldown_windows)
            }
        }
        fn potr(strike_threshold: u32, penalty_bond_bps: u16, cooldown_windows: u32) -> Self {
            Self {
                max_pdp_failures: u32::MAX,
                ..Self::all_proofs(strike_threshold, penalty_bond_bps, cooldown_windows)
            }
        }
        fn policy(self) -> iroha_config::parameters::actual::SorafsPenaltyPolicy {
            iroha_config::parameters::actual::SorafsPenaltyPolicy {
                utilisation_floor_bps: 7_500,
                uptime_floor_bps: 9_000,
                por_success_floor_bps: 9_000,
                strike_threshold: self.strike_threshold,
                penalty_bond_bps: self.penalty_bond_bps,
                cooldown_windows: self.cooldown_windows,
                max_pdp_failures: self.max_pdp_failures,
                max_potr_breaches: self.max_potr_breaches,
            }
        }
        fn configure(self, state: &mut State) {
            state.gov.sorafs_penalty = self.policy();
        }
        fn install(self, stx: &mut StateTransaction<'_, '_>, bonded_nanos: u128) -> ProviderId {
            assert_eq!(
                stx.gov.sorafs_penalty,
                self.policy(),
                "capture the exact fixture policy before opening its scope"
            );
            let (provider, record) = sample_capacity_record();
            register_governed_capacity_declaration(stx, &alice(), record)
                .expect("register capacity declaration");
            let mut schedule = PricingScheduleRecord::launch_default();
            schedule.credit = CreditPolicy {
                settlement_window_secs: SECONDS_PER_BILLING_MONTH,
                settlement_grace_secs: 0,
                low_balance_alert_bps: 1_000,
            };
            schedule.collateral = CollateralPolicy {
                multiplier_bps: 20_000,
                onboarding_discount_bps: 1,
                onboarding_period_secs: 1,
            };
            SetPricingSchedule { schedule }
                .execute(&alice(), stx)
                .expect("set pricing schedule");
            let credit = provider_credit_nanos(provider, 1_000_000_000_000, bonded_nanos);
            upsert_provider_credit_with_reserve_fixture(stx, &alice(), credit)
                .expect("seed provider credit");
            provider
        }
    }
    fn proof_health_alerts(stx: &StateTransaction<'_, '_>) -> Vec<SorafsProofHealthAlert> {
        stx.world
            .internal_event_buf
            .iter()
            .filter_map(|entry| match entry.as_ref() {
                DataEvent::Sorafs(SorafsGatewayEvent::ProofHealth(alert)) => Some(alert.clone()),
                _ => None,
            })
            .collect()
    }
    #[allow(clippy::too_many_arguments)]
    fn record_capacity_window(
        stx: &mut StateTransaction<'_, '_>,
        provider: ProviderId,
        start_epoch: u64,
        end_epoch: u64,
        declared_gib: u64,
        effective_gib: u64,
        utilised_gib: u64,
        uptime_bps: u32,
        por_success_bps: u32,
        egress_bytes: u64,
    ) {
        record_capacity_window_with_proofs(
            stx,
            provider,
            start_epoch,
            end_epoch,
            declared_gib,
            effective_gib,
            utilised_gib,
            uptime_bps,
            por_success_bps,
            egress_bytes,
            ProofWindowCounters::default(),
        );
    }
    #[allow(clippy::too_many_arguments)]
    fn record_capacity_window_with_proofs(
        stx: &mut StateTransaction<'_, '_>,
        provider: ProviderId,
        start_epoch: u64,
        end_epoch: u64,
        declared_gib: u64,
        effective_gib: u64,
        utilised_gib: u64,
        uptime_bps: u32,
        por_success_bps: u32,
        egress_bytes: u64,
        proof: ProofWindowCounters,
    ) {
        let telemetry = CapacityTelemetryRecord::new(
            provider,
            start_epoch,
            end_epoch,
            declared_gib,
            effective_gib,
            utilised_gib,
            1,
            1,
            uptime_bps,
            por_success_bps,
            egress_bytes,
            proof.pdp_challenges,
            proof.pdp_failures,
            proof.potr_windows,
            proof.potr_breaches,
        )
        .with_nonce(end_epoch);
        RecordCapacityTelemetry { record: telemetry }
            .execute(&alice(), stx)
            .expect("record telemetry");
    }
    fn sample_capacity_dispute(provider: ProviderId) -> (CapacityDisputeRecord, CapacityDisputeId) {
        let dispute = CapacityDisputeV1 {
            version: CAPACITY_DISPUTE_VERSION_V1,
            provider_id: provider.as_bytes().to_owned(),
            complainant_id: [0x44; 32],
            replication_order_id: None,
            kind: CapacityDisputeKind::UptimeBreach,
            evidence: sorafs_manifest::capacity::CapacityDisputeEvidenceV1 {
                evidence_digest: [0xAA; 32],
                media_type: Some("application/zip".into()),
                uri: Some("https://evidence.example/dispute.zip".into()),
                size_bytes: Some(1_024),
            },
            submitted_epoch: 1_700_000_128,
            description: "provider uptime dipped below SLA".into(),
            requested_remedy: Some("slash stake".into()),
        };
        let payload = norito::encode_canonical(&dispute).expect("encode canonical dispute payload");
        let dispute_id = CapacityDisputeId::new(*blake3_hash(&payload).as_bytes());
        let evidence = CapacityDisputeEvidence {
            digest: dispute.evidence.evidence_digest,
            media_type: dispute.evidence.media_type.clone(),
            uri: dispute.evidence.uri.clone(),
            size_bytes: dispute.evidence.size_bytes,
        };
        let record = CapacityDisputeRecord::new_pending(
            dispute_id,
            provider,
            dispute.complainant_id,
            dispute.replication_order_id,
            dispute.kind as u8,
            dispute.submitted_epoch,
            dispute.description.clone(),
            dispute.requested_remedy.clone(),
            evidence,
            payload,
        );
        (record, dispute_id)
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn v1_norito_boundaries_ignore_ambient_layout() {
        let declaration = sample_capacity_declaration();
        let declaration_bytes =
            norito::encode_canonical(&declaration).expect("encode canonical declaration");
        let provider = ProviderId::new(declaration.provider_id);
        let (dispute_record, _) = sample_capacity_dispute(provider);
        let dispute = decode_capacity_dispute_payload(&dispute_record.dispute_payload)
            .expect("decode canonical dispute fixture");
        let report = repair_report(
            "REP-CANONICAL-AMBIENT",
            provider,
            [0x45; 32],
            &alice(),
            4_000,
        );
        let report_bytes =
            norito::encode_canonical(&report).expect("encode canonical repair report");
        let action_digest =
            repair_action_digest(&alice(), &report).expect("derive canonical action digest");
        let digest = default_digest();
        let mut manifest_record = PinManifestRecord::new(
            digest,
            default_root_cid(),
            default_chunker(),
            default_chunk_digest(),
            por_root_for_manifest(digest),
            default_content_length(),
            default_policy(),
            alice(),
            5,
            None,
            None,
            Metadata::default(),
        );
        manifest_record.policy.retention_epoch =
            8 + u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1);
        manifest_record.approve(7, None);
        let providers = [
            ProviderId::new([0x46; 32]),
            ProviderId::new([0x47; 32]),
            ProviderId::new([0x48; 32]),
        ];
        let automatic = build_auto_replication_order(&manifest_record, &alice(), 7, &providers)
            .expect("build canonical automatic order");
        let alias = default_alias_binding();
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_report =
            norito::to_bytes(&report).expect("encode alternate-layout ambient report");
        assert_ne!(ambient_report, report_bytes);
        assert_eq!(
            decode_capacity_declaration_payload(&declaration_bytes)
                .expect("decode declaration under alternate ambient layout"),
            declaration
        );
        assert_eq!(
            decode_capacity_dispute_payload(&dispute_record.dispute_payload)
                .expect("decode dispute under alternate ambient layout"),
            dispute
        );
        assert_eq!(
            encode_repair_state(&report, "ambient repair report")
                .expect("encode repair state under alternate ambient layout"),
            report_bytes
        );
        assert_eq!(
            decode_repair_state::<RepairReportV1>(&report_bytes, "ambient repair report")
                .expect("decode repair state under alternate ambient layout"),
            report
        );
        assert_eq!(
            decode_repair_payload::<RepairReportV1>(&report_bytes, "ambient repair report")
                .expect("decode repair payload under alternate ambient layout"),
            report
        );
        assert_eq!(
            repair_action_digest(&alice(), &report)
                .expect("derive action digest under alternate ambient layout"),
            action_digest
        );
        ensure_repair_query_encoded_budget(&report, report_bytes.len(), "ambient repair report")
            .expect("canonical query budget ignores alternate ambient layout");
        let automatic_under_ambient =
            build_auto_replication_order(&manifest_record, &alice(), 7, &providers)
                .expect("build automatic order under alternate ambient layout");
        assert_eq!(automatic_under_ambient, automatic);
        let validated_order =
            validate_stored_replication_order(&automatic, "canonical-ambient-order")
                .expect("validate stored order under alternate ambient layout");
        assert_eq!(
            norito::encode_canonical(&validated_order).expect("encode validated order"),
            automatic.canonical_order
        );
        assert_eq!(
            validate_manifest_alias_binding(
                &alias,
                &digest,
                &default_root_cid(),
                Some((5, default_policy().retention_epoch)),
            )
            .expect("validate alias under alternate ambient layout"),
            alias.proof
        );
        assert_eq!(
            norito::to_bytes(&report).expect("encode ambient report after canonical operations"),
            ambient_report,
            "canonical helpers must restore the caller's ambient layout"
        );
    }
    pub(super) fn alice() -> AccountId {
        AccountId::new(
            "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
                .parse()
                .expect("public key"),
        )
    }
    fn account_literal(account: &AccountId) -> String {
        account.to_string()
    }
    pub(super) fn bob() -> AccountId {
        iroha_test_samples::BOB_ID.clone()
    }
    #[test]
    fn sorafs_account_fixtures_are_distinct_valid_ed25519_identities() {
        assert_eq!(
            alice().expect_single_signatory().algorithm(),
            Algorithm::Ed25519
        );
        assert_eq!(
            bob().expect_single_signatory().algorithm(),
            Algorithm::Ed25519
        );
        assert_ne!(alice(), bob());
    }
    #[test]
    fn register_capacity_dispute_inserts_record() {
        let state = make_state();
        let mut block = state.block(capacity_dispute_block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), declaration.clone())
            .expect("register declaration");
        activate_reputation_policy(&mut stx, &alice());
        let (record, dispute_id) = sample_capacity_dispute(provider);
        let decoded: CapacityDisputeV1 = norito::decode_from_bytes(&record.dispute_payload)
            .expect("decode stored dispute payload");
        assert_eq!(decoded.provider_id, *record.provider_id.as_bytes());
        RegisterCapacityDispute {
            record: record.clone(),
        }
        .execute(&alice(), &mut stx)
        .expect("register capacity dispute");
        let stored = stx
            .world
            .capacity_disputes
            .get(&dispute_id)
            .expect("dispute stored");
        assert_eq!(stored.description, record.description);
        assert!(matches!(stored.status, CapacityDisputeStatus::Pending));
        let journal_event = stx
            .world
            .internal_event_buf
            .iter()
            .find_map(|event| match event.as_ref() {
                DataEvent::Sorafs(SorafsGatewayEvent::ReputationJournal(
                    iroha_data_model::events::data::sorafs::SorafsReputationJournalEvent::EntryCommitted(
                        committed,
                    ),
                )) => Some(committed),
                _ => None,
            })
            .expect("capacity dispute must append one typed reputation event");
        assert_eq!(journal_event.provider_id, provider);
        assert_eq!(journal_event.source_revision, 1);
        assert_eq!(
            journal_event.source_kind,
            iroha_data_model::sorafs::reputation::ReputationJournalSourceKindV1::ProviderDispute
        );
    }
    #[test]
    fn register_capacity_dispute_rejects_noncanonical_and_resource_bomb_payloads() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), declaration)
            .expect("register declaration");
        let (base_record, _) = sample_capacity_dispute(provider);
        let dispute: CapacityDisputeV1 = norito::decode_from_bytes(&base_record.dispute_payload)
            .expect("decode dispute fixture");
        let alternate = {
            let _guard = norito::core::DecodeFlagsGuard::enter(0);
            norito::to_bytes(&dispute).expect("encode alternate-layout capacity dispute")
        };
        assert_ne!(alternate, base_record.dispute_payload);
        let mut bomb = dispute;
        bomb.description = "x".repeat(2_049);
        let allocation_bomb = norito::to_bytes(&bomb).expect("encode dispute allocation bomb");
        assert!(allocation_bomb.len() <= MAX_CAPACITY_DISPUTE_PAYLOAD_BYTES);
        for (payload, expected) in [
            (Vec::new(), "invalid capacity dispute payload"),
            (vec![0xFF], "invalid capacity dispute payload"),
            (
                vec![0xA5; MAX_CAPACITY_DISPUTE_PAYLOAD_BYTES + 1],
                "invalid capacity dispute payload",
            ),
            (alternate, "invalid capacity dispute payload"),
            (allocation_bomb, "description must be"),
        ] {
            let mut record = base_record.clone();
            record.dispute_payload = payload;
            let dispute_id = record.dispute_id;
            let err = RegisterCapacityDispute { record }
                .execute(&alice(), &mut stx)
                .expect_err("invalid capacity dispute payload must be rejected");
            assert!(matches!(
                err,
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(message)
                ) if message.contains(expected)
            ));
            assert!(stx.world.capacity_disputes.get(&dispute_id).is_none());
        }
    }
    #[test]
    fn capacity_declaration_is_permissionless_for_governed_bonded_provider_owner() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        if let Some(perms) = stx.world.account_permissions.get_mut(&alice()) {
            perms.clear();
        }
        let (provider, declaration) = sample_capacity_record();
        seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::from(1_u32));
        let err = RegisterCapacityDeclaration {
            declaration: declaration.declaration,
        }
        .execute(&alice(), &mut stx);
        assert!(err.is_ok(), "ordinary provider owner should be allowed");
    }
    #[test]
    fn capacity_declaration_derives_registration_time_and_projection_at_execution() {
        let (provider, record) = capacity_record_with_owner(&alice());
        let payload = decode_capacity_declaration_payload(&record.declaration).expect("fixture");
        for consensus_epoch in [5_u64, 17] {
            let state = make_state();
            let header = iroha_data_model::block::BlockHeader::new(
                nonzero!(1_u64),
                None,
                None,
                consensus_epoch * 1000,
                0,
            );
            let mut block = state.block(header);
            let mut stx =
                block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
            seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::from(1_u32));
            RegisterCapacityDeclaration::new(record.declaration.clone())
                .execute(&alice(), &mut stx)
                .expect("submission need not predict commit timestamp");
            let stored = stx
                .world
                .capacity_declarations
                .get(&provider)
                .expect("stored declaration");
            assert_eq!(stored.registered_epoch, consensus_epoch);
            assert_eq!(stored.provider_id, provider);
            assert_eq!(
                stored.committed_capacity_gib,
                payload.committed_capacity_gib
            );
            assert_eq!(stored.valid_from_epoch, payload.valid_from);
            assert_eq!(stored.valid_until_epoch, payload.valid_until);
            assert_eq!(stored.declaration, record.declaration);
            validate_stored_capacity_declaration(stored, "consensus projection")
                .expect("exact projection");
        }
    }
    #[test]
    fn capacity_telemetry_is_permissionless_for_provider_owner() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        remove_permission(&mut stx, "CanSubmitSorafsTelemetry");
        let (provider, declaration) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), declaration)
            .expect("register capacity declaration");
        UpsertProviderCredit {
            expected_current: stx
                .world
                .provider_credit_ledger
                .get(&provider)
                .map(iroha_crypto::HashOf::new),
            record: provider_credit_nanos(provider, 1_000_000_000, 1_000_000_000),
        }
        .execute(&alice(), &mut stx)
        .expect("fund the provider's declared telemetry credit");
        let telemetry = CapacityTelemetryRecord::new(
            provider, 0, 1, 1, 1, 1, 0, 0, 10_000, 10_000, 0, 0, 0, 0, 0,
        )
        .with_nonce(1);
        RecordCapacityTelemetry { record: telemetry }
            .execute(&alice(), &mut stx)
            .expect("ordinary provider owner should be allowed");
    }
    #[test]
    fn capacity_dispute_requires_permission() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        remove_permission(&mut stx, "CanFileSorafsCapacityDispute");
        let record = CapacityDisputeRecord::new_pending(
            CapacityDisputeId::new([0x11; 32]),
            ProviderId::new([0x22; 32]),
            [0x33; 32],
            None,
            0,
            0,
            "dispute".to_string(),
            None,
            CapacityDisputeEvidence {
                digest: [0u8; 32],
                media_type: None,
                uri: None,
                size_bytes: None,
            },
            Vec::new(),
        );
        let err = RegisterCapacityDispute { record }
            .execute(&alice(), &mut stx)
            .expect_err("permissionless dispute must fail");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("CanFileSorafsCapacityDispute")
        ));
    }
    #[test]
    fn capacity_declaration_requires_governed_owner_and_does_not_create_binding() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = capacity_record_with_owner(&alice());
        let error = RegisterCapacityDeclaration {
            declaration: declaration.declaration,
        }
        .execute(&alice(), &mut stx)
        .expect_err("capacity declaration must not self-register an unknown provider");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("no governance-established owner")
        ));
        assert!(stx.world.provider_owners.get(&provider).is_none());
        assert!(stx.world.capacity_declarations.get(&provider).is_none());
        let permission = AccountPermission::from(CanOperateSorafsRepair {
            provider_id: provider,
        });
        assert!(
            !stx.world
                .account_permissions
                .get(&alice())
                .is_some_and(|permissions| permissions.contains(&permission)),
            "rejected declaration must not grant a provider-scoped permission"
        );
    }
    #[test]
    fn instruction_box_dispatches_capacity_declaration() {
        let state = make_initial_sorafs_state();
        let mut block = state.block(initial_sorafs_block_header(&state));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = capacity_record_with_owner(&alice());
        seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::from(1_u32));
        let instruction = InstructionBox::from(RegisterCapacityDeclaration {
            declaration: declaration.declaration,
        });
        instruction
            .execute(&alice(), &mut stx)
            .expect("instruction box should dispatch SoraFS declaration");
        assert_eq!(
            stx.world.provider_owners.get(&provider),
            Some(&alice()),
            "instruction box execution must preserve the governed provider owner"
        );
    }
    #[test]
    fn capacity_declaration_rejects_rebinding_to_new_owner() {
        let mut state = make_state();
        seed_sorafs_permissions(&mut state, &bob());
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, _declaration) = capacity_record_with_owner(&alice());
        seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::from(1_u32));
        let (_provider, second) = capacity_record_with_owner(&bob());
        let err = RegisterCapacityDeclaration {
            declaration: second.declaration,
        }
        .execute(&bob(), &mut stx)
        .expect_err("rebind to different owner must fail");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("exact registered owner authority")
        ));
        assert_eq!(stx.world.provider_owners.get(&provider), Some(&alice()));
        assert!(stx.world.capacity_declarations.get(&provider).is_none());
    }
    #[test]
    fn capacity_declaration_rejects_non_owner_authority() {
        let mut state = make_state();
        seed_sorafs_permissions(&mut state, &bob());
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = capacity_record_with_owner(&alice());
        seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::from(1_u32));
        let error = RegisterCapacityDeclaration {
            declaration: declaration.declaration,
        }
        .execute(&bob(), &mut stx)
        .expect_err("an account other than the exact governed owner must fail");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("exact registered owner authority")
        ));
        assert_eq!(stx.world.provider_owners.get(&provider), Some(&alice()));
        assert!(stx.world.capacity_declarations.get(&provider).is_none());
    }
    #[test]
    fn capacity_declaration_rejects_unbonded_governed_owner() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_governed_capacity_provider(
            &mut stx,
            ProviderId::new([0xE8; 32]),
            &alice(),
            Quantity::from(1_u32),
        );
        let (provider, declaration) = capacity_record_with_owner(&alice());
        seed_provider_owners(&mut stx, &[provider], &alice());
        let missing_record_error = RegisterCapacityDeclaration {
            declaration: declaration.clone().declaration,
        }
        .execute(&alice(), &mut stx)
        .expect_err("a governed owner without an owner-funded reserve must fail");
        assert!(
            matches!(
                &missing_record_error,
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(message)
                ) if message == &format!("provider {provider} has no owner-funded reserve account")
            ),
            "unexpected missing-reserve rejection: {missing_record_error:?}"
        );
        seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::zero());
        let error = RegisterCapacityDeclaration {
            declaration: declaration.declaration,
        }
        .execute(&alice(), &mut stx)
        .expect_err("a governed owner without the declared bonded stake must fail");
        assert!(
            matches!(
                &error,
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(message)
                ) if message.contains("declares stake ")
                    && message.ends_with("but its unslashed custody-backed bond holds 0")
            ),
            "unexpected zero-bond rejection: {error:?}"
        );
        assert_eq!(stx.world.provider_owners.get(&provider), Some(&alice()));
        assert!(stx.world.capacity_declarations.get(&provider).is_none());
    }
    #[test]
    fn capacity_telemetry_enforces_owner_metadata() {
        let mut state = make_state();
        seed_sorafs_permissions(&mut state, &bob());
        state.gov.sorafs_telemetry.require_submitter = true;
        state.gov.sorafs_telemetry.submitters = vec![alice(), bob()];
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), declaration)
            .expect("register declaration");
        UpsertProviderCredit {
            expected_current: stx
                .world
                .provider_credit_ledger
                .get(&provider)
                .map(iroha_crypto::HashOf::new),
            record: provider_credit_nanos(provider, 1_000_000_000, 1_000_000_000),
        }
        .execute(&alice(), &mut stx)
        .expect("fund the provider's declared telemetry credit");
        let telemetry = CapacityTelemetryRecord::new(
            provider, 1, 2, 512, 512, 512, 0, 0, 1_000, 1_000, 0, 0, 0, 0, 0,
        )
        .with_nonce(1);
        let err = RecordCapacityTelemetry { record: telemetry }
            .execute(&bob(), &mut stx)
            .expect_err("non-owner telemetry must fail");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains(PROVIDER_OWNER_METADATA_KEY)
        ));
        RecordCapacityTelemetry { record: telemetry }
            .execute(&alice(), &mut stx)
            .expect("owner telemetry succeeds");
    }
    #[test]
    fn capacity_dispute_requires_governed_recorder_authority() {
        let mut state = make_state();
        seed_sorafs_permissions(&mut state, &bob());
        let mut block = state.block(capacity_dispute_block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), declaration)
            .expect("register declaration");
        activate_reputation_policy(&mut stx, &alice());
        let (record, _dispute_id) = sample_capacity_dispute(provider);
        let err = RegisterCapacityDispute { record }
            .execute(&bob(), &mut stx)
            .expect_err("non-governed dispute recorder must fail");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("governed dispute recorder")
        ));
    }
    #[test]
    fn governed_provider_credit_can_be_established_before_capacity() {
        let mut state = make_state();
        seed_sorafs_permissions(&mut state, &bob());
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, _declaration) = sample_capacity_record();
        seed_provider_owners(&mut stx, &[provider], &alice());
        let credit = ProviderCreditRecord::new(
            provider,
            xor_quantity_nanos(1),
            xor_quantity_nanos(1),
            Quantity::zero(),
            Quantity::zero(),
            1,
            1,
            Metadata::default(),
        );
        upsert_provider_credit_with_reserve_fixture(&mut stx, &bob(), credit)
            .expect("permissioned credit authority may project the pre-declaration native bond");
        assert!(stx.world.capacity_declarations.get(&provider).is_none());
        let stored = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("governed credit record is stored");
        assert_eq!(stored.bonded, xor_quantity_nanos(1));
    }
    #[test]
    fn capacity_declaration_enforces_owner_metadata_when_present() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, mut declaration) = sample_capacity_record();
        seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::from(1_u32));
        let mut payload = decode_capacity_declaration_payload(&declaration.declaration).unwrap();
        let entry = payload
            .metadata
            .iter_mut()
            .find(|entry| entry.key == PROVIDER_OWNER_METADATA_KEY)
            .unwrap();
        entry.value = account_literal(&bob());
        declaration.declaration = norito::encode_canonical(&payload).unwrap();
        let err = RegisterCapacityDeclaration {
            declaration: declaration.clone().declaration,
        }
        .execute(&alice(), &mut stx)
        .expect_err("owner mismatch must fail");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains(PROVIDER_OWNER_METADATA_KEY)
        ));
        payload
            .metadata
            .iter_mut()
            .find(|entry| entry.key == PROVIDER_OWNER_METADATA_KEY)
            .unwrap()
            .value = account_literal(&alice());
        declaration.declaration = norito::encode_canonical(&payload).unwrap();
        RegisterCapacityDeclaration {
            declaration: declaration.declaration,
        }
        .execute(&alice(), &mut stx)
        .expect("owner-aligned declaration must succeed");
        assert!(stx.world.capacity_declarations.get(&provider).is_some());
    }
    #[test]
    fn register_capacity_dispute_exact_replay_is_idempotent() {
        let state = make_state();
        let mut block = state.block(capacity_dispute_block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), declaration.clone())
            .expect("register declaration");
        activate_reputation_policy(&mut stx, &alice());
        let (record, _dispute_id) = sample_capacity_dispute(provider);
        RegisterCapacityDispute {
            record: record.clone(),
        }
        .execute(&alice(), &mut stx)
        .expect("register capacity dispute");
        RegisterCapacityDispute { record }
            .execute(&alice(), &mut stx)
            .expect("exact duplicate dispute must be idempotent");
        assert_eq!(stx.world.capacity_disputes.iter().count(), 1);
    }
    #[test]
    fn register_capacity_dispute_rejects_unknown_replication_order() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), declaration.clone())
            .expect("register declaration");
        let replication_order_id = ReplicationOrderId::new([0x2B; 32]);
        let dispute = CapacityDisputeV1 {
            version: CAPACITY_DISPUTE_VERSION_V1,
            provider_id: provider.as_bytes().to_owned(),
            complainant_id: [0x99; 32],
            replication_order_id: Some(*replication_order_id.as_bytes()),
            kind: CapacityDisputeKind::ReplicationShortfall,
            evidence: sorafs_manifest::capacity::CapacityDisputeEvidenceV1 {
                evidence_digest: [0xCD; 32],
                media_type: Some("application/json".into()),
                uri: Some("https://evidence.example/dispute.json".into()),
                size_bytes: Some(512),
            },
            submitted_epoch: 1_700_000_256,
            description: "replication order not ingested".into(),
            requested_remedy: Some("slash bond".into()),
        };
        let payload = norito::to_bytes(&dispute).expect("encode dispute payload");
        let dispute_id = CapacityDisputeId::new(*blake3_hash(&payload).as_bytes());
        let evidence = CapacityDisputeEvidence {
            digest: dispute.evidence.evidence_digest,
            media_type: dispute.evidence.media_type.clone(),
            uri: dispute.evidence.uri.clone(),
            size_bytes: dispute.evidence.size_bytes,
        };
        let record = CapacityDisputeRecord::new_pending(
            dispute_id,
            provider,
            dispute.complainant_id,
            Some(*replication_order_id.as_bytes()),
            dispute.kind as u8,
            dispute.submitted_epoch,
            dispute.description.clone(),
            dispute.requested_remedy.clone(),
            evidence,
            payload,
        );
        let err = RegisterCapacityDispute { record }
            .execute(&alice(), &mut stx)
            .expect_err("replication order reference must exist");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message
            )) if message.contains("replication order")
        ));
    }
    #[test]
    fn register_manifest_activates_record_immediately() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        let instruction = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        };
        instruction
            .execute(&alice(), &mut stx)
            .expect("register manifest");
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored");
        assert_eq!(stored.status, PinStatus::Approved(5));
        assert_eq!(stored.chunk_digest_sha3_256, default_chunk_digest());
        assert!(stored.council_envelope_digest.is_none());
        assert_eq!(stx.world.replication_orders.iter().count(), 1);
    }
    #[test]
    fn governed_registration_stays_pending_until_verified_approval() {
        let mut state = make_state();
        state.gov.sorafs_pin_policy.require_council_signatures = true;
        let council_key = checked_ed25519_keypair();
        set_council_approval_policy(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = capacity_record_with_owner(&alice());
        seed_provider_owners(&mut stx, &[provider], &alice());
        stx.world
            .capacity_declarations
            .insert(provider, declaration);
        let mut manifest = manifest_fixture(0xAA);
        manifest.pin_policy.min_replicas = 1;
        manifest.pin_policy.retention_epoch =
            6 + u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1);
        assert_eq!(manifest.root_cid, default_root_cid().as_bytes());
        let alias = alias_binding_for(
            default_digest(),
            "sora",
            "docs",
            5,
            manifest.pin_policy.retention_epoch,
        );
        let manifest_digest =
            ManifestDigest::from_manifest(&manifest).expect("derive governed manifest digest");
        RegisterPinManifest {
            manifest_payload: manifest.encode().expect("encode manifest"),
            alias: Some(alias.clone()),
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect("governed registration");
        let pending = stx
            .world
            .pin_manifests
            .get(&manifest_digest)
            .expect("pending manifest stored")
            .clone();
        assert_eq!(pending.status, PinStatus::Pending);
        assert!(
            stx.world
                .smart_contract_state
                .get(&pin_status_index_key(&PinStatus::Pending, &manifest_digest))
                .is_some()
        );
        assert!(pending.pin_fee_payment.is_some());
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&alias))
                .is_none(),
            "pending manifests must not publish aliases"
        );
        assert_eq!(stx.world.replication_orders.iter().count(), 0);
        let (envelope, _) = build_envelope(&pending, &council_key);
        ApprovePinManifest {
            digest: manifest_digest,
            council_envelope: Some(envelope),
            council_envelope_digest: None,
        }
        .execute(&alice(), &mut stx)
        .expect("verified governed approval");
        let approved = stx
            .world
            .pin_manifests
            .get(&manifest_digest)
            .expect("approved manifest stored");
        assert_eq!(approved.status, PinStatus::Approved(5));
        assert!(
            stx.world
                .smart_contract_state
                .get(&pin_status_index_key(&PinStatus::Pending, &manifest_digest))
                .is_none()
        );
        assert!(
            stx.world
                .smart_contract_state
                .get(&pin_status_index_key(&approved.status, &manifest_digest))
                .is_some()
        );
        assert!(approved.council_envelope_digest.is_some());
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&alias))
                .is_some(),
            "approval publishes the reserved alias"
        );
        let (_, order) = stx
            .world
            .replication_orders
            .iter()
            .next()
            .expect("approval issues deferred replication order");
        assert_eq!(order.issued_epoch, 5);
    }
    #[test]
    fn governed_pending_approval_requires_payload_and_nonstale_epoch() {
        {
            let state = make_state();
            let mut block = state.block(block_header());
            let mut stx =
                block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
            insert_pending_manifest(&mut stx, default_digest(), default_chunk_digest());
            let digest_only = ApprovePinManifest {
                digest: default_digest(),
                council_envelope: None,
                council_envelope_digest: Some([0x66; 32]),
            }
            .execute(&alice(), &mut stx)
            .expect_err("first approval must not trust a digest without its envelope");
            assert!(matches!(
                digest_only,
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(message)
                ) if message.contains("requires council envelope payload")
            ));
        }
        for (consensus_epoch, expected) in [
            (4, "predates submission"),
            (
                default_policy().retention_epoch,
                "earlier than retention epoch",
            ),
        ] {
            let state = make_state();
            let mut block = state.block(block_header_at_epoch(consensus_epoch));
            let mut stx =
                block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
            insert_pending_manifest(&mut stx, default_digest(), default_chunk_digest());
            let record = stx
                .world
                .pin_manifests
                .get(&default_digest())
                .expect("pending record")
                .clone();
            let (envelope, _) = build_envelope(&record, &checked_ed25519_keypair());
            let error = ApprovePinManifest {
                digest: default_digest(),
                council_envelope: Some(envelope),
                council_envelope_digest: None,
            }
            .execute(&alice(), &mut stx)
            .expect_err("consensus-time approval boundary must fail closed");
            assert!(matches!(
                error,
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(message)
                ) if message.contains(expected)
            ));
            assert_eq!(
                stx.world
                    .pin_manifests
                    .get(&default_digest())
                    .expect("record remains")
                    .status,
                PinStatus::Pending
            );
        }
    }
    #[test]
    fn register_manifest_rejects_unknown_chunker_profile() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let mut manifest = manifest_fixture(0xAA);
        manifest.chunking.profile_id = ProfileId(u32::MAX);
        let instruction = RegisterPinManifest {
            manifest_payload: manifest.encode().expect("encode invalid manifest fixture"),
            alias: None,
            successor_of: None,
        };
        let err = instruction
            .execute(&alice(), &mut stx)
            .expect_err("registration must reject unknown chunker profile");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message
            )) if message.contains("manifest payload failed validation")
        ));
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_rejects_inert_commitments_and_expired_retention_before_fee() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let base = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        };
        let mut inert_manifest_payload = manifest_fixture(0xAA);
        inert_manifest_payload.root_cid[4..].fill(0);
        let mut zero_manifest = base.clone();
        zero_manifest.manifest_payload = inert_manifest_payload
            .encode()
            .expect("encode inert manifest fixture");
        let mut inert_chunk_digest_manifest = manifest_fixture(0xAA);
        inert_chunk_digest_manifest.chunk_digest_sha3_256 = [0; 32];
        let mut zero_chunks = base.clone();
        zero_chunks.manifest_payload = inert_chunk_digest_manifest
            .encode()
            .expect("encode inert chunk-digest fixture");
        let mut zero_retention_payload = manifest_fixture(0xAA);
        zero_retention_payload.pin_policy.retention_epoch = 0;
        let mut zero_retention = base.clone();
        zero_retention.manifest_payload = zero_retention_payload
            .encode()
            .expect("encode zero-retention fixture");
        let mut zero_successor = base.clone();
        zero_successor.successor_of = Some(ManifestDigest::new([0; 32]));
        for (instruction, expected) in [
            (zero_manifest, "root CID digest must not be all zero"),
            (
                zero_chunks,
                "manifest chunk-plan SHA3-256 digest must not be zero",
            ),
            (zero_retention, "pin retention epoch must be positive"),
            (zero_successor, "successor manifest digest must not be zero"),
        ] {
            let err = instruction
                .execute(&alice(), &mut stx)
                .expect_err("inert manifest commitment must be rejected");
            assert!(matches!(
                err,
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(message)
                ) if message.contains(expected)
            ));
        }
        let expired_state = make_state();
        let mut expired_block =
            expired_state.block(block_header_at_epoch(default_policy().retention_epoch));
        let mut expired_stx =
            expired_block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let error = base
            .execute(&alice(), &mut expired_stx)
            .expect_err("consensus-time submission at retention expiry must fail closed");
        assert!(
            smart_contract_error_message(&error).contains("must be greater than submission epoch")
        );
        assert_eq!(stx.world.pin_manifests.iter().count(), 0);
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_rejects_malformed_noncanonical_and_oversized_payloads_atomically() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let canonical = default_manifest_payload();
        let alternate = {
            let _guard = norito::core::DecodeFlagsGuard::enter(0);
            norito::to_bytes(&manifest_fixture(0xAA)).expect("encode alternate layout")
        };
        assert_ne!(alternate, canonical, "test requires a non-canonical layout");
        let mut trailing = canonical;
        trailing.push(0);
        let mut allocation_bomb = manifest_fixture(0xAA);
        allocation_bomb
            .alias_claims
            .push(sorafs_manifest::AliasClaim {
                name: "bomb".to_owned(),
                namespace: "adversarial".to_owned(),
                proof: vec![0xA5; sorafs_manifest::MAX_MANIFEST_ALIAS_PROOF_BYTES + 1],
            });
        let allocation_bomb = allocation_bomb
            .encode()
            .expect("encode allocation-bomb manifest fixture");
        assert!(
            allocation_bomb.len() <= sorafs_manifest::MAX_MANIFEST_ENCODED_BYTES,
            "resource-limit fixture must pass the outer byte ceiling"
        );
        for (payload, expected) in [
            (Vec::new(), "manifest payload has"),
            (vec![0xFF, 0x00, 0x81], "invalid canonical ManifestV1"),
            (
                vec![0xA5; sorafs_manifest::MAX_MANIFEST_ENCODED_BYTES + 1],
                "manifest payload has",
            ),
            (alternate, "canonical Norito encoding"),
            (trailing, "ManifestV1"),
            (allocation_bomb, "invalid canonical ManifestV1"),
        ] {
            let error = RegisterPinManifest {
                manifest_payload: payload,
                alias: None,
                successor_of: None,
            }
            .execute(&alice(), &mut stx)
            .expect_err("invalid manifest payload must fail");
            assert!(matches!(
                error,
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(message)
                ) if message.contains(expected)
            ));
            assert_eq!(stx.world.pin_manifests.iter().count(), 0);
            assert_eq!(stx.world.replication_orders.iter().count(), 0);
        }
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_rejects_invalid_policy() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let mut manifest = manifest_fixture(0xAA);
        manifest.pin_policy.min_replicas = 0;
        let instruction = RegisterPinManifest {
            manifest_payload: manifest.encode().expect("encode invalid policy fixture"),
            alias: None,
            successor_of: None,
        };
        let err = instruction
            .execute(&alice(), &mut stx)
            .expect_err("registration must reject invalid policy");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message
            )) if message.contains("manifest payload failed validation")
        ));
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_with_alias_persists_binding() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        let alias = default_alias_binding();
        let instruction = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: Some(alias.clone()),
            successor_of: None,
        };
        instruction
            .execute(&alice(), &mut stx)
            .expect("register manifest with alias");
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored");
        let stored_alias = stored.alias.as_ref().expect("alias stored");
        assert_eq!(stored_alias.name, alias.name);
        assert_eq!(stored_alias.namespace, alias.namespace);
        let alias_record = stx
            .world
            .manifest_aliases
            .get(&ManifestAliasId::from(&alias))
            .expect("alias binding stored");
        assert!(alias_record.targets_manifest(&default_digest()));
        assert_eq!(alias_record.bound_epoch, 5);
    }
    #[test]
    fn approve_manifest_with_alias_records_council_digest() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_policy(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        let alias = default_alias_binding();
        let register = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: Some(alias.clone()),
            successor_of: None,
        };
        register
            .execute(&alice(), &mut stx)
            .expect("register manifest");
        let stored_record = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .cloned()
            .expect("manifest stored");
        let (envelope, _) = build_envelope(&stored_record, &council_key);
        ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(envelope),
            council_envelope_digest: None,
        }
        .execute(&alice(), &mut stx)
        .expect("approve manifest");
        let alias_id = ManifestAliasId::from(&alias);
        let alias_record = stx
            .world
            .manifest_aliases
            .get(&alias_id)
            .expect("alias record stored");
        assert!(alias_record.targets_manifest(&default_digest()));
        assert_eq!(alias_record.bound_epoch, 5);
        assert_eq!(alias_record.expiry_epoch, default_policy().retention_epoch);
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored after approval");
        assert!(stored.council_envelope_digest.is_some());
    }
    #[test]
    fn register_manifest_auto_issues_replication_order_for_matching_capacity() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = capacity_record_with_owner(&alice());
        seed_provider_owners(&mut stx, &[provider], &alice());
        stx.world
            .capacity_declarations
            .insert(provider, declaration);
        let mut manifest = manifest_fixture(0xAA);
        manifest.pin_policy.min_replicas = 1;
        manifest.pin_policy.retention_epoch =
            6 + u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1);
        let manifest_digest =
            ManifestDigest::from_manifest(&manifest).expect("derive manifest digest");
        RegisterPinManifest {
            manifest_payload: manifest.encode().expect("encode manifest"),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect("register manifest");
        let (_order_id, order) = stx
            .world
            .replication_orders
            .iter()
            .next()
            .expect("auto replication order stored");
        assert_eq!(order.manifest_digest, manifest_digest);
        assert_eq!(order.issued_epoch, 5);
        assert_eq!(
            order.deadline_epoch,
            5 + u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1)
        );
        let decoded = norito::decode_from_bytes::<ReplicationOrderV1>(&order.canonical_order)
            .expect("decode order");
        assert_eq!(decoded.issued_at, order.issued_epoch);
        assert_eq!(decoded.deadline_at, order.deadline_epoch);
        assert_eq!(decoded.target_replicas, 1);
        assert_eq!(decoded.assignments.len(), 1);
        assert_eq!(decoded.assignments[0].provider_id, *provider.as_bytes());
        assert_eq!(decoded.assignments[0].slice_gib, 1);
    }
    #[test]
    fn automatic_replication_slice_rounds_up_without_overflow() {
        assert_eq!(automatic_replication_slice_gib(0).expect("zero"), 1);
        assert_eq!(
            automatic_replication_slice_gib(BYTES_PER_GIB).expect("one GiB"),
            1
        );
        assert_eq!(
            automatic_replication_slice_gib(BYTES_PER_GIB + 1).expect("partial second GiB"),
            2
        );
        assert_eq!(
            automatic_replication_slice_gib(u64::MAX).expect("maximum byte length"),
            17_179_869_184
        );
    }
    #[test]
    fn automatic_replication_requires_full_deadline_and_exact_profile_capacity() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let mut pin = PinManifestRecord::new(
            default_digest(),
            default_root_cid(),
            default_chunker(),
            default_chunk_digest(),
            por_root_for_manifest(default_digest()),
            BYTES_PER_GIB + 1,
            PinPolicy {
                min_replicas: 1,
                ..default_policy()
            },
            alice(),
            5,
            None,
            None,
            Metadata::default(),
        );
        pin.approve(5, None);
        seed_eligible_auto_replication_providers_for_test(
            &mut stx,
            &alice(),
            1,
            StorageClass::Hot,
            &default_chunker(),
            5,
            u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1),
            1,
        )
        .expect("seed undersized provider");
        select_auto_replication_providers(&stx, &pin, 5)
            .expect_err("one-GiB profile commitment cannot accept a two-GiB slice");

        seed_eligible_auto_replication_providers_for_test(
            &mut stx,
            &alice(),
            1,
            StorageClass::Hot,
            &default_chunker(),
            5,
            u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1) - 1,
            2,
        )
        .expect("seed provider expiring just before the automatic deadline");
        select_auto_replication_providers(&stx, &pin, 5)
            .expect_err("capacity must remain valid through the full automatic deadline");

        seed_eligible_auto_replication_providers_for_test(
            &mut stx,
            &alice(),
            1,
            StorageClass::Hot,
            &default_chunker(),
            5,
            u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1),
            2,
        )
        .expect("seed exact eligible provider");
        let selected = select_auto_replication_providers(&stx, &pin, 5)
            .expect("exact two-GiB profile capacity through the deadline is eligible");
        assert_eq!(selected.len(), 1);
    }
    #[test]
    fn automatic_replication_enforces_aggregate_active_profile_capacity() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_eligible_auto_replication_providers_for_test(
            &mut stx,
            &alice(),
            1,
            StorageClass::Hot,
            &default_chunker(),
            5,
            u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1),
            1,
        )
        .expect("seed one-GiB provider");
        let mut first = manifest_fixture(0xAA);
        first.pin_policy.min_replicas = 1;
        let first_digest =
            ManifestDigest::from_manifest(&first).expect("derive first manifest digest");
        RegisterPinManifest {
            manifest_payload: first.encode().expect("encode first manifest"),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect("first manifest reserves provider capacity");

        let mut second = manifest_fixture(0xAB);
        second.pin_policy.min_replicas = 1;
        let second_digest =
            ManifestDigest::from_manifest(&second).expect("derive second manifest digest");
        let error = RegisterPinManifest {
            manifest_payload: second.encode().expect("encode second manifest"),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("active automatic allocation must prevent oversubscription");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("requires 1 eligible providers but found 0")
        ));
        assert!(stx.world.pin_manifests.get(&second_digest).is_none());

        RetirePinManifest {
            digest: first_digest,
            reason: Some("cancel unfulfilled replication".to_owned()),
        }
        .execute(&alice(), &mut stx)
        .expect("retiring the pending pin releases its capacity reservation");
        RegisterPinManifest {
            manifest_payload: second.encode().expect("encode second manifest again"),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect("cancelled automatic allocation releases profile capacity");
        assert!(stx.world.pin_manifests.get(&second_digest).is_some());
    }
    #[test]
    fn automatic_replication_rejects_deadline_after_manifest_retention() {
        let digest = default_digest();
        let mut record = PinManifestRecord::new(
            digest,
            default_root_cid(),
            default_chunker(),
            default_chunk_digest(),
            por_root_for_manifest(digest),
            default_content_length(),
            default_policy(),
            alice(),
            5,
            None,
            None,
            Metadata::default(),
        );
        record.policy.min_replicas = 1;
        record.policy.retention_epoch =
            5 + u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1);
        record.approve(5, None);
        let error =
            build_auto_replication_order(&record, &alice(), 5, &[ProviderId::new([0xA5; 32])])
                .expect_err("automatic replication must fit inside manifest retention");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("must be earlier than manifest retention epoch")
        ));
    }
    #[test]
    fn automatic_replication_validator_rejects_mutable_or_noncanonical_shape() {
        let digest = default_digest();
        let mut record = PinManifestRecord::new(
            digest,
            default_root_cid(),
            default_chunker(),
            default_chunk_digest(),
            por_root_for_manifest(digest),
            BYTES_PER_GIB + 1,
            default_policy(),
            alice(),
            5,
            None,
            None,
            Metadata::default(),
        );
        record.policy.min_replicas = 1;
        record.policy.retention_epoch =
            6 + u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1);
        record.approve(5, None);
        let automatic =
            build_auto_replication_order(&record, &alice(), 5, &[ProviderId::new([0x66; 32])])
                .expect("build exact automatic order");
        let decoded = norito::decode_from_bytes::<ReplicationOrderV1>(&automatic.canonical_order)
            .expect("decode exact automatic order");
        assert_eq!(decoded.assignments[0].slice_gib, 2);

        let mut revised = automatic.clone();
        revised.assignment_revision = 2;
        validate_stored_automatic_replication_order(&record, &revised, "revised-auto")
            .expect_err("automatic assignment revision is immutable");

        let mut altered = automatic;
        let mut payload = norito::decode_from_bytes::<ReplicationOrderV1>(&altered.canonical_order)
            .expect("decode automatic payload");
        payload.assignments[0].slice_gib = 1;
        altered.canonical_order =
            norito::encode_canonical(&payload).expect("encode altered automatic payload");
        validate_stored_automatic_replication_order(&record, &altered, "altered-auto")
            .expect_err("automatic assignment slice is derived and exact");
    }
    #[test]
    fn automatic_replication_rejects_missing_completion_authority_atomically() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = capacity_record_with_owner(&alice());
        stx.world.provider_owners.insert(provider, alice());
        stx.world
            .capacity_declarations
            .insert(provider, declaration);
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let mut manifest = manifest_fixture(0xAA);
        manifest.pin_policy.min_replicas = 1;
        let error = RegisterPinManifest {
            manifest_payload: manifest.encode().expect("encode manifest"),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("manifest registration must fail without an eligible replication provider");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("requires 1 eligible providers but found 0")
        ));
        assert!(stx.world.pin_manifests.iter().next().is_none());
        assert!(stx.world.replication_orders.iter().next().is_none());
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn automatic_replication_builder_rejects_deadline_overflow() {
        let issued_epoch =
            u64::MAX - u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1) + 1;
        let digest = default_digest();
        let mut policy = default_policy();
        policy.min_replicas = 1;
        policy.retention_epoch = u64::MAX;
        let mut record = PinManifestRecord::new(
            digest,
            default_root_cid(),
            default_chunker(),
            default_chunk_digest(),
            por_root_for_manifest(digest),
            default_content_length(),
            policy,
            alice(),
            issued_epoch,
            None,
            None,
            Metadata::default(),
        );
        record.approve(issued_epoch, None);
        let error = build_auto_replication_order(
            &record,
            &alice(),
            issued_epoch,
            &[ProviderId::new([0x65; 32])],
        )
        .expect_err("automatic replication deadline overflow must fail closed");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("deadline epoch overflow")
        ));
    }
    #[test]
    fn approval_replication_shortfall_does_not_publish_pending_alias() {
        let mut state = make_state();
        let approval_epoch = 5;
        let council_key = checked_ed25519_keypair();
        set_council_approval_policy(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header_at_epoch(approval_epoch));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alias = default_alias_binding();
        let mut policy = default_policy();
        policy.min_replicas = 1;
        let record = PinManifestRecord::new(
            default_digest(),
            default_root_cid(),
            default_chunker(),
            default_chunk_digest(),
            por_root_for_manifest(default_digest()),
            default_content_length(),
            policy,
            alice(),
            approval_epoch,
            Some(alias.clone()),
            None,
            Metadata::default(),
        );
        insert_pin_record_with_accounting(&mut stx, record.clone());
        let (envelope, _) = build_envelope(&record, &council_key);
        let error = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(envelope),
            council_envelope_digest: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("automatic replication shortfall must fail approval atomically");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("requires 1 eligible providers but found 0")
        ));
        assert_eq!(
            stx.world
                .pin_manifests
                .get(&default_digest())
                .expect("pending manifest remains")
                .status,
            PinStatus::Pending
        );
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&alias))
                .is_none(),
            "failed approval must not publish the pending alias"
        );
        assert_eq!(stx.world.replication_orders.iter().count(), 0);
    }
    #[test]
    fn approval_never_overwrites_an_automatic_order_collision() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_policy(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alias = default_alias_binding();
        let mut policy = default_policy();
        policy.min_replicas = 1;
        policy.retention_epoch =
            6 + u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1);
        let record = PinManifestRecord::new(
            default_digest(),
            default_root_cid(),
            default_chunker(),
            default_chunk_digest(),
            por_root_for_manifest(default_digest()),
            default_content_length(),
            policy,
            alice(),
            5,
            Some(alias.clone()),
            None,
            Metadata::default(),
        );
        insert_pin_record_with_accounting(&mut stx, record.clone());
        let mut approved = record.clone();
        approved.approve(5, None);
        let collision =
            build_auto_replication_order(&approved, &alice(), 5, &[ProviderId::new([0x67; 32])])
                .expect("build collision fixture");
        stx.world
            .replication_orders
            .insert(collision.order_id, collision.clone());
        let (envelope, _) = build_envelope(&record, &council_key);
        let error = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(envelope),
            council_envelope_digest: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("automatic-order collision must fail approval");
        assert!(matches!(
            error,
            InstructionExecutionError::InvariantViolation(message)
                if message.contains("automatic replication order")
                    && message.contains("already exists")
        ));
        assert_eq!(
            stx.world
                .pin_manifests
                .get(&default_digest())
                .expect("pending manifest retained")
                .status,
            PinStatus::Pending
        );
        assert_eq!(
            stx.world.replication_orders.get(&collision.order_id),
            Some(&collision)
        );
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&alias))
                .is_none()
        );
    }
    #[test]
    fn register_manifest_rejects_duplicate_alias_binding() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        let alias = default_alias_binding();
        let duplicate_alias = alias_binding_for(
            second_digest(),
            "sora",
            "docs",
            5,
            default_policy().retention_epoch,
        );
        let first = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: Some(alias.clone()),
            successor_of: None,
        };
        first
            .execute(&alice(), &mut stx)
            .expect("first alias registration succeeds");
        let alice_balance_after_first = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_after_first = pin_fee_balance(&stx, &treasury_account);
        let second = RegisterPinManifest {
            manifest_payload: manifest_payload_for_seed(0xBB),
            alias: Some(duplicate_alias),
            successor_of: None,
        };
        let err = second
            .execute(&alice(), &mut stx)
            .expect_err("duplicate alias must be rejected");
        match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => assert!(
                message.contains("alias `sora/docs` is already bound"),
                "unexpected error message: {message}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(
            pin_fee_balance(&stx, &alice()),
            alice_balance_after_first,
            "duplicate alias replay must not charge the submitter again"
        );
        assert_eq!(
            pin_fee_balance(&stx, &treasury_account),
            treasury_balance_after_first,
            "duplicate alias replay must not credit treasury again"
        );
    }
    #[test]
    fn register_manifest_rejects_duplicate_digest() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect("first manifest registration succeeds");
        let alice_balance_after_first = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_after_first = pin_fee_balance(&stx, &treasury_account);
        let err = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("duplicate manifest digest must be rejected");
        let message = match err {
            InstructionExecutionError::InvariantViolation(message) => message.to_string(),
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("already registered"),
            "unexpected error message: {message}"
        );
        assert_eq!(
            pin_fee_balance(&stx, &alice()),
            alice_balance_after_first,
            "duplicate digest replay must not charge the submitter again"
        );
        assert_eq!(
            pin_fee_balance(&stx, &treasury_account),
            treasury_balance_after_first,
            "duplicate digest replay must not credit treasury again"
        );
    }
    #[test]
    fn register_manifest_rejects_empty_alias_proof_without_side_effects() {
        let alias = ManifestAliasBinding {
            name: "docs".into(),
            namespace: "sora".into(),
            proof: Vec::new(),
        };
        assert_alias_registration_rejected_without_fee(alias, "alias proof must not be empty");
    }
    #[test]
    fn register_manifest_rejects_oversized_alias_proof_without_side_effects() {
        let alias = ManifestAliasBinding {
            name: "docs".into(),
            namespace: "sora".into(),
            proof: vec![0xA5; MAX_ALIAS_PROOF_BYTES + 1],
        };
        assert_alias_registration_rejected_without_fee(alias, "maximum is");
    }
    #[test]
    fn register_manifest_rejects_alias_proof_alias_mismatch_without_side_effects() {
        let mut alias = alias_binding_for(
            default_digest(),
            "sora",
            "other",
            5,
            default_policy().retention_epoch,
        );
        alias.name = "docs".to_owned();
        assert_alias_registration_rejected_without_fee(
            alias,
            "does not match requested alias `sora/docs`",
        );
    }
    #[test]
    fn register_manifest_rejects_alias_proof_with_wrong_epoch_commitments() {
        assert_alias_registration_rejected_without_fee(
            alias_binding_for(
                default_digest(),
                "sora",
                "docs",
                4,
                default_policy().retention_epoch,
            ),
            "alias proof bound_at",
        );
        assert_alias_registration_rejected_without_fee(
            alias_binding_for(default_digest(), "sora", "docs", 5, 41),
            "alias proof expiry_epoch",
        );
    }
    #[test]
    fn register_manifest_rejects_alias_whitespace_without_side_effects() {
        let alias = ManifestAliasBinding {
            name: "docs ".into(),
            namespace: "sora".into(),
            proof: Vec::new(),
        };
        assert_alias_registration_rejected_without_fee(alias, "surrounding whitespace");
    }
    #[test]
    fn register_manifest_rejects_malformed_alias_proof_without_side_effects() {
        let alias = ManifestAliasBinding {
            name: "docs".into(),
            namespace: "sora".into(),
            proof: vec![0xFF, 0x00, 0xAA],
        };
        assert_alias_registration_rejected_without_fee(alias, "alias proof failed verification");
    }
    #[test]
    fn register_manifest_rejects_stale_alias_record_without_side_effects() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let requested_alias = default_alias_binding();
        let stale_alias = alias_binding_for(second_digest(), "sora", "docs", 0, 0);
        let stale_record =
            ManifestAliasRecord::new(stale_alias.clone(), second_digest(), bob(), 1, 10);
        stx.world
            .manifest_aliases
            .insert(ManifestAliasId::from(&stale_alias), stale_record);
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let err = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: Some(requested_alias),
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("stale alias record must reject registration");
        match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => assert!(
                message.contains("alias `sora/docs` is already associated"),
                "unexpected error message: {message}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            stx.world.pin_manifests.get(&default_digest()).is_none(),
            "rejected stale-alias registration must not store a pin manifest"
        );
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_rejects_alias_proof_manifest_mismatch() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let mismatched_alias = alias_binding_for(
            second_digest(),
            "sora",
            "docs",
            5,
            default_policy().retention_epoch,
        );
        let instruction = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: Some(mismatched_alias),
            successor_of: None,
        };
        let err = instruction
            .execute(&alice(), &mut stx)
            .expect_err("registration must reject mismatched alias proof");
        match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => assert!(
                message.contains(
                    "alias proof manifest CID does not match content root registered for manifest"
                ),
                "unexpected error message: {message}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_rejects_invalid_alias_characters() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let alias = ManifestAliasBinding {
            name: "Docs".into(),
            namespace: "sora".into(),
            proof: Vec::new(),
        };
        let instruction = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: Some(alias),
            successor_of: None,
        };
        let err = instruction
            .execute(&alice(), &mut stx)
            .expect_err("registration must reject invalid alias");
        match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => assert!(
                message.contains("alias name `Docs`"),
                "unexpected error message: {message}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_with_approved_predecessor_persists_successor_of() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        RegisterPinManifest {
            manifest_payload: manifest_payload_for_seed(0xBB),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect("register predecessor manifest");
        RegisterPinManifest {
            manifest_payload: manifest_payload_for_seed(0xCC),
            alias: None,
            successor_of: Some(second_digest()),
        }
        .execute(&alice(), &mut stx)
        .expect("register successor manifest");
        let stored = stx
            .world
            .pin_manifests
            .get(&third_digest())
            .expect("successor manifest stored");
        assert_eq!(stored.successor_of, Some(second_digest()));
        assert_eq!(stored.status, PinStatus::Approved(5));
    }
    #[test]
    fn register_manifest_rejects_self_successor_reference() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let err = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: Some(default_digest()),
        }
        .execute(&alice(), &mut stx)
        .expect_err("registration must reject self successor");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("cannot declare itself as successor"),
            "unexpected error message: {message}"
        );
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_rejects_unregistered_predecessor() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let err = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: Some(second_digest()),
        }
        .execute(&alice(), &mut stx)
        .expect_err("registration must reject missing predecessor");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert_eq!(
            message,
            format!(
                "predecessor manifest {} referenced by successor {} is not registered",
                manifest_hex(&second_digest()),
                manifest_hex(&default_digest()),
            )
        );
        assert!(stx.world.pin_manifests.get(&default_digest()).is_none());
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_rejects_pending_predecessor() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_pending_manifest(&mut stx, second_digest(), [0xEE; 32]);
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let err = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: Some(second_digest()),
        }
        .execute(&alice(), &mut stx)
        .expect_err("registration must reject pending predecessor");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert_eq!(
            message,
            format!(
                "predecessor manifest {} must be approved and live before registering successor {}",
                manifest_hex(&second_digest()),
                manifest_hex(&default_digest()),
            )
        );
        assert!(stx.world.pin_manifests.get(&default_digest()).is_none());
        assert_eq!(
            stx.world
                .pin_manifests
                .get(&second_digest())
                .unwrap()
                .status,
            PinStatus::Pending
        );
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_rejects_retired_predecessor() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_manifest_with_status(
            &mut stx,
            second_digest(),
            [0xEE; 32],
            None,
            PinStatus::Retired(7),
        );
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let err = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: Some(second_digest()),
        }
        .execute(&alice(), &mut stx)
        .expect_err("registration must reject retired predecessor");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("must be approved and live"),
            "unexpected error message: {message}"
        );
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_rejects_predecessor_without_lineage_summary() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_manifest_with_status(
            &mut stx,
            second_digest(),
            [0xEE; 32],
            None,
            PinStatus::Approved(5),
        );
        stx.world
            .smart_contract_state
            .remove(pin_lineage_key(&second_digest()));
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let err = RegisterPinManifest {
            manifest_payload: manifest_payload_for_seed(0xCC),
            alias: None,
            successor_of: Some(second_digest()),
        }
        .execute(&alice(), &mut stx)
        .expect_err("registration must reject a predecessor without authenticated lineage");
        let message = match &err {
            InstructionExecutionError::InvariantViolation(message) => message.as_ref(),
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("has no lineage summary"),
            "unexpected error message: {message}"
        );
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_rejects_successor_fanout_limit() {
        let mut state = make_state();
        state.gov.sorafs_pin_policy.max_successor_fanout = 1;
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        insert_manifest_with_status(
            &mut stx,
            second_digest(),
            [0xEE; 32],
            None,
            PinStatus::Approved(5),
        );
        RegisterPinManifest {
            manifest_payload: manifest_payload_for_seed(0xCC),
            alias: None,
            successor_of: Some(second_digest()),
        }
        .execute(&alice(), &mut stx)
        .expect("first direct successor remains within the fanout limit");
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let err = RegisterPinManifest {
            manifest_payload: manifest_payload_for_seed(0xDD),
            alias: None,
            successor_of: Some(second_digest()),
        }
        .execute(&alice(), &mut stx)
        .expect_err("registration must reject excess direct successors");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("successor fanout 2 exceeds configured maximum 1"),
            "unexpected error message: {message}"
        );
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn retired_successor_does_not_reopen_the_parent_fanout_ceiling() {
        let mut state = make_state();
        state.gov.sorafs_pin_policy.max_successor_fanout = 1;
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        insert_manifest_with_status(
            &mut stx,
            second_digest(),
            [0xEE; 32],
            None,
            PinStatus::Approved(5),
        );
        RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: Some(second_digest()),
        }
        .execute(&alice(), &mut stx)
        .expect("first direct successor remains within the fanout ceiling");
        RetirePinManifest {
            digest: default_digest(),
            reason: Some("superseded".to_owned()),
        }
        .execute(&alice(), &mut stx)
        .expect("retire the first successor");
        let parent_lineage = read_pin_lineage(stx.world(), &second_digest())
            .expect("valid lineage state")
            .expect("parent lineage exists");
        assert_eq!(
            parent_lineage.direct_successor_count, 1,
            "retained successor history must continue consuming fanout"
        );
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let error = RegisterPinManifest {
            manifest_payload: manifest_payload_for_seed(0xDD),
            alias: None,
            successor_of: Some(second_digest()),
        }
        .execute(&alice(), &mut stx)
        .expect_err("retirement must not recycle the retained lineage slot");
        assert!(
            smart_contract_error_message(&error)
                .contains("successor fanout 2 exceeds configured maximum 1")
        );
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn register_manifest_rejects_lineage_beyond_consensus_depth_limit() {
        let mut state = make_state();
        state.gov.sorafs_pin_policy.max_lineage_depth = 1;
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_manifest_with_status_at_epoch(
            &mut stx,
            second_digest(),
            [0xEE; 32],
            None,
            PinStatus::Approved(4),
            4,
        );
        insert_manifest_with_status(
            &mut stx,
            third_digest(),
            [0xEF; 32],
            Some(second_digest()),
            PinStatus::Approved(5),
        );
        let alice_balance_before = pin_fee_balance(&stx, &alice());
        let treasury_account = stx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_balance_before = pin_fee_balance(&stx, &treasury_account);
        let error = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: Some(third_digest()),
        }
        .execute(&alice(), &mut stx)
        .expect_err("lineage beyond the consensus depth limit must reject");
        assert!(
            smart_contract_error_message(&error).contains("exceeding configured maximum 1"),
            "unexpected error: {error:?}"
        );
        assert_pin_fee_balances_unchanged(
            &stx,
            &alice(),
            alice_balance_before,
            &treasury_account,
            treasury_balance_before,
        );
    }
    #[test]
    fn approve_manifest_records_council_digest_for_auto_approved_manifest() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        let register = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        };
        register
            .execute(&alice(), &mut stx)
            .expect("register manifest");
        let stored_record = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored")
            .clone();
        let (envelope, _) = build_envelope(&stored_record, &council_key);
        let expected_digest = {
            let hash = blake3_hash(&envelope);
            let mut out = [0u8; 32];
            out.copy_from_slice(hash.as_bytes());
            out
        };
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(envelope),
            council_envelope_digest: None,
        };
        approve
            .execute(&alice(), &mut stx)
            .expect("approve manifest");
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored");
        assert!(matches!(stored.status, PinStatus::Approved(5)));
        assert_eq!(stored.council_envelope_digest, Some(expected_digest));
    }
    #[test]
    fn approve_manifest_rejects_mismatched_manifest_digest() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (envelope, _, _) = registered_manifest_approval_envelope(&mut stx, &council_key);
        let mut invalid_json =
            String::from_utf8(envelope.clone()).expect("envelope is valid UTF-8 JSON");
        let manifest_hex = hex::encode(default_digest().as_bytes());
        let bogus_manifest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        invalid_json = invalid_json.replacen(&manifest_hex, bogus_manifest, 1);
        let message = rejected_manifest_approval_message(
            &mut stx,
            invalid_json.into_bytes(),
            None,
            "approval must reject mismatched manifest digest",
        );
        assert!(
            message.contains("manifest digest"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn approve_manifest_rejects_invalid_signature() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (envelope, signature_hex, _) =
            registered_manifest_approval_envelope(&mut stx, &council_key);
        let mut modified_signature =
            hex::decode(&signature_hex).expect("signature hex decodes cleanly");
        modified_signature[0] ^= 0xFF;
        let bad_signature_hex = hex::encode(modified_signature);
        let mut invalid_json =
            String::from_utf8(envelope.clone()).expect("envelope is valid UTF-8 JSON");
        invalid_json = invalid_json.replacen(&signature_hex, &bad_signature_hex, 1);
        let message = rejected_manifest_approval_message(
            &mut stx,
            invalid_json.into_bytes(),
            None,
            "approval must reject invalid signature",
        );
        assert!(
            message.contains("failed to verify council signature")
                || message.contains("invalid council signature material"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn approve_manifest_rejects_all_zero_signature_material() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (envelope, signature_hex, _) =
            registered_manifest_approval_envelope(&mut stx, &council_key);
        let pending = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .unwrap()
            .clone();
        let automatic_order_id = derive_sorafs_auto_replication_order_id_v1(&default_digest());
        let automatic_order = stx
            .world
            .replication_orders
            .get(&automatic_order_id)
            .cloned();
        let inert_signature_hex = hex::encode([0_u8; 64]);
        let mut invalid_json =
            String::from_utf8(envelope.clone()).expect("envelope is valid UTF-8 JSON");
        invalid_json = invalid_json.replacen(&signature_hex, &inert_signature_hex, 1);
        let message = rejected_manifest_approval_message(
            &mut stx,
            invalid_json.into_bytes(),
            None,
            "approval must reject all-zero signature material",
        );
        assert!(
            message.contains("invalid council signature material")
                && message.contains("signature payload must not be empty or all zero"),
            "unexpected error message: {message}"
        );
        assert_eq!(
            stx.world.pin_manifests.get(&default_digest()),
            Some(&pending)
        );
        assert_eq!(
            stx.world.replication_orders.get(&automatic_order_id),
            automatic_order.as_ref()
        );
    }
    #[test]
    fn approve_manifest_rejects_inert_or_malformed_ed25519_signer_key() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (envelope, _, signer_hex) =
            registered_manifest_approval_envelope(&mut stx, &council_key);
        for (label, malformed_signer) in [
            ("all-zero", [0_u8; 32]),
            ("small-order", SMALL_ORDER_ED25519_R),
            ("noncanonical", NONCANONICAL_ED25519_R),
        ] {
            let malformed_signer_hex = hex::encode(malformed_signer);
            let mut invalid_json =
                String::from_utf8(envelope.clone()).expect("envelope is valid UTF-8 JSON");
            invalid_json = invalid_json.replacen(&signer_hex, &malformed_signer_hex, 1);
            let message = rejected_manifest_approval_message(
                &mut stx,
                invalid_json.into_bytes(),
                None,
                "approval must reject malformed signer public key material",
            );
            assert!(
                message.contains("failed to parse council signer"),
                "{label} signer key produced unexpected error message: {message}"
            );
        }
    }
    #[test]
    fn approve_manifest_rejects_malformed_ed25519_signature_r() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (envelope, signature_hex, _) =
            registered_manifest_approval_envelope(&mut stx, &council_key);
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_ED25519_R),
            ("noncanonical", NONCANONICAL_ED25519_R),
        ] {
            let mut modified_signature =
                hex::decode(&signature_hex).expect("signature hex decodes cleanly");
            modified_signature[..replacement_r.len()].copy_from_slice(&replacement_r);
            let bad_signature_hex = hex::encode(modified_signature);
            let mut invalid_json =
                String::from_utf8(envelope.clone()).expect("envelope is valid UTF-8 JSON");
            invalid_json = invalid_json.replacen(&signature_hex, &bad_signature_hex, 1);
            let message = rejected_manifest_approval_message(
                &mut stx,
                invalid_json.into_bytes(),
                None,
                "approval must reject malformed signature R",
            );
            assert!(
                message.contains("invalid council signature material"),
                "{label} signature R produced unexpected error message: {message}"
            );
            assert!(
                !message.contains("failed to verify council signature"),
                "{label} signature R reached backend verification: {message}"
            );
        }
    }
    #[test]
    fn approve_manifest_rejects_self_selected_signer_and_below_quorum() {
        let mut state = make_state();
        let trusted_key = checked_ed25519_keypair();
        set_council_approval_policy(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &trusted_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_pending_manifest(&mut stx, default_digest(), default_chunk_digest());
        let record = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("pending manifest")
            .clone();
        let second_trusted_key = checked_ed25519_keypair();
        let attacker_key = checked_ed25519_keypair();
        let (attacker_envelope, _) = build_envelope(&record, &attacker_key);
        let untrusted_error = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(attacker_envelope),
            council_envelope_digest: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("an envelope must not self-select its approval key");
        assert!(matches!(
            untrusted_error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("not present in the governed approval roster")
        ));
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("retain manifest before approval policy change");
        set_council_approval_policy(
            &mut state,
            2,
            vec![
                council_approval_signer("council-a", &trusted_key, 0, None),
                council_approval_signer("council-b", &second_trusted_key, 0, None),
            ],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (single_signature_envelope, _) = build_envelope(&record, &trusted_key);
        let quorum_error = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(single_signature_envelope),
            council_envelope_digest: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("one trusted signature must not satisfy a two-signer quorum");
        assert!(matches!(
            quorum_error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("has 1 active trusted signatures")
                && message.contains("approval quorum is 2")
        ));
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest remains stored");
        assert_eq!(stored.status, PinStatus::Pending);
        assert!(stored.council_envelope_digest.is_none());
    }
    #[test]
    fn approve_manifest_rejects_not_yet_active_governed_signer() {
        let mut state = make_state();
        let future_key = checked_ed25519_keypair();
        let active_key = checked_ed25519_keypair();
        set_council_approval_policy(
            &mut state,
            1,
            vec![
                council_approval_signer("council-active", &active_key, 0, None),
                council_approval_signer("council-future", &future_key, 2, None),
            ],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_pending_manifest(&mut stx, default_digest(), default_chunk_digest());
        let record = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("pending manifest")
            .clone();
        let (envelope, _) = build_envelope(&record, &future_key);
        let error = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(envelope),
            council_envelope_digest: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("a scheduled future key must not approve early");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("is not active until block 2")
                && message.contains("executing block is 1")
        ));
        assert_eq!(
            stx.world
                .pin_manifests
                .get(&default_digest())
                .expect("manifest remains stored")
                .status,
            PinStatus::Pending
        );
    }
    #[test]
    fn approve_manifest_rejects_revoked_signer_despite_backdated_approval_epoch() {
        let mut state = make_state();
        let revoked_key = checked_ed25519_keypair();
        let current_key = checked_ed25519_keypair();
        set_council_approval_policy(
            &mut state,
            1,
            vec![
                council_approval_signer("council-current", &current_key, 0, None),
                council_approval_signer("council-revoked", &revoked_key, 0, Some(10)),
            ],
        );
        let mut block = state.block(repair_block_header(10, 0));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let record = PinManifestRecord::new(
            default_digest(),
            default_root_cid(),
            default_chunker(),
            default_chunk_digest(),
            por_root_for_manifest(default_digest()),
            default_content_length(),
            default_policy(),
            alice(),
            0,
            None,
            None,
            Metadata::default(),
        );
        insert_pin_record_with_accounting(&mut stx, record.clone());
        let (envelope, _) = build_envelope(&record, &revoked_key);
        let error = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(envelope),
            council_envelope_digest: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("caller-selected approval epoch must not backdate signer authority");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("was revoked at block 10")
                && message.contains("executing block is 10")
        ));
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest remains stored");
        assert_eq!(stored.status, PinStatus::Pending);
        assert!(stored.council_envelope_digest.is_none());
    }
    #[test]
    fn council_envelope_rejects_resource_and_canonicalization_attacks() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_pending_manifest(&mut stx, default_digest(), default_chunk_digest());
        let record = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("pending manifest")
            .clone();
        let council_key = checked_ed25519_keypair();
        let policy = council_approval_policy(
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let (envelope, _) = build_envelope(&record, &council_key);
        verify_council_envelope(&record, &envelope, &policy, 1)
            .expect("baseline envelope verifies");
        let oversized = vec![b' '; MAX_COUNCIL_ENVELOPE_BYTES + 1];
        assert!(council_envelope_error(&record, &oversized, &policy, 1).contains("expected 1..="));
        let baseline: Value = json::from_slice(&envelope).expect("parse baseline envelope");
        let mut unknown_top = baseline.clone();
        unknown_top
            .as_object_mut()
            .expect("envelope object")
            .insert("unexpected".into(), Value::from(true));
        assert!(
            council_envelope_error(
                &record,
                &json::to_vec(&unknown_top).expect("encode unknown-field envelope"),
                &policy,
                1,
            )
            .contains("unknown field")
        );
        let mut unknown_signature_field = baseline.clone();
        unknown_signature_field
            .get_mut("signatures")
            .and_then(Value::as_array_mut)
            .and_then(|signatures| signatures.first_mut())
            .and_then(Value::as_object_mut)
            .expect("signature object")
            .insert("weight".into(), Value::from(1_u64));
        assert!(
            council_envelope_error(
                &record,
                &json::to_vec(&unknown_signature_field)
                    .expect("encode signature unknown-field envelope"),
                &policy,
                1,
            )
            .contains("unknown field")
        );
        let mut invalid_multihash_type = baseline.clone();
        invalid_multihash_type
            .get_mut("signatures")
            .and_then(Value::as_array_mut)
            .and_then(|signatures| signatures.first_mut())
            .and_then(Value::as_object_mut)
            .expect("signature object")
            .insert("signer_multihash".into(), Value::from(7_u64));
        assert!(
            council_envelope_error(
                &record,
                &json::to_vec(&invalid_multihash_type)
                    .expect("encode invalid multihash type envelope"),
                &policy,
                1,
            )
            .contains("must be a string")
        );
        let mut uppercase_signer = baseline.clone();
        let signer = uppercase_signer
            .get_mut("signatures")
            .and_then(Value::as_array_mut)
            .and_then(|signatures| signatures.first_mut())
            .and_then(Value::as_object_mut)
            .expect("signature object")
            .get("signer")
            .and_then(Value::as_str)
            .expect("signer hex")
            .to_ascii_uppercase();
        uppercase_signer
            .get_mut("signatures")
            .and_then(Value::as_array_mut)
            .and_then(|signatures| signatures.first_mut())
            .and_then(Value::as_object_mut)
            .expect("signature object")
            .insert("signer".into(), Value::from(signer));
        assert!(
            council_envelope_error(
                &record,
                &json::to_vec(&uppercase_signer).expect("encode uppercase envelope"),
                &policy,
                1,
            )
            .contains("lowercase hex")
        );
        let mut duplicate_signer = baseline.clone();
        let signatures = duplicate_signer
            .get_mut("signatures")
            .and_then(Value::as_array_mut)
            .expect("signature array");
        let first_signature = signatures[0].clone();
        signatures.push(first_signature);
        assert!(
            council_envelope_error(
                &record,
                &json::to_vec(&duplicate_signer).expect("encode duplicate signer envelope"),
                &policy,
                1,
            )
            .contains("distinct signer keys")
        );
        let mut signature_flood = baseline.clone();
        let signatures = signature_flood
            .get_mut("signatures")
            .and_then(Value::as_array_mut)
            .expect("signature array");
        let first_signature = signatures[0].clone();
        signatures.resize(MAX_COUNCIL_ENVELOPE_SIGNATURES + 1, first_signature);
        assert!(
            council_envelope_error(
                &record,
                &json::to_vec(&signature_flood).expect("encode signature flood"),
                &policy,
                1,
            )
            .contains("maximum")
        );
        for aliases in [
            vec![Value::from("sorafs.sf1@1.0.0"), Value::from("unknown")],
            vec![
                Value::from("sorafs.sf1@1.0.0"),
                Value::from("sorafs.sf1@1.0.0"),
            ],
        ] {
            let mut invalid_aliases = baseline.clone();
            invalid_aliases
                .as_object_mut()
                .expect("envelope object")
                .insert("profile_aliases".into(), Value::Array(aliases));
            let message = council_envelope_error(
                &record,
                &json::to_vec(&invalid_aliases).expect("encode invalid aliases"),
                &policy,
                1,
            );
            assert!(
                message.contains("unknown profile alias")
                    || message.contains("repeats profile alias"),
                "unexpected aliases error: {message}"
            );
        }
    }
    #[test]
    fn approve_manifest_rejects_digest_mismatch() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (envelope, _, _) = registered_manifest_approval_envelope(&mut stx, &council_key);
        let message = rejected_manifest_approval_message(
            &mut stx,
            envelope,
            Some([0x42; 32]),
            "approval must reject digest mismatch",
        );
        assert!(
            message.contains("approval digest mismatch"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn approve_manifest_rejects_provided_digest_mismatch_with_envelope() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (envelope, _, _) = registered_manifest_approval_envelope(&mut stx, &council_key);
        let message = rejected_manifest_approval_message(
            &mut stx,
            envelope,
            Some([0x24; 32]),
            "approval must reject provided digest mismatch with envelope",
        );
        assert!(
            message.contains("approval digest mismatch with provided envelope"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn approve_manifest_rejects_unknown_manifest() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: None,
            council_envelope_digest: None,
        };
        let err = approve
            .execute(&alice(), &mut stx)
            .expect_err("approval must reject unknown manifest");
        let message = match err {
            InstructionExecutionError::InvariantViolation(message) => message.to_string(),
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("not registered"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn approve_manifest_rejects_different_epoch_for_auto_approved_manifest() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        let register = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        };
        register
            .execute(&alice(), &mut stx)
            .expect("register manifest");
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit automatic approval fixture");
        let mut block = state.block(block_header_at_epoch(6));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: None,
            council_envelope_digest: None,
        };
        let err = approve
            .execute(&alice(), &mut stx)
            .expect_err("approval must reject different epoch");
        let message = match err {
            InstructionExecutionError::InvariantViolation(message) => message.to_string(),
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("already approved with different epoch"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn approve_manifest_reapproval_accepts_stored_digest_without_payload() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let expected_digest = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored")
            .council_envelope_digest
            .expect("digest recorded");
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: None,
            council_envelope_digest: None,
        };
        approve
            .execute(&alice(), &mut stx)
            .expect("re-approval should reuse stored digest");
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored");
        assert_eq!(stored.council_envelope_digest, Some(expected_digest));
        assert!(matches!(stored.status, PinStatus::Approved(5)));
    }
    #[test]
    fn approve_manifest_reapproval_accepts_matching_stored_digest() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let expected_digest = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored")
            .council_envelope_digest
            .expect("digest recorded");
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: None,
            council_envelope_digest: Some(expected_digest),
        };
        approve
            .execute(&alice(), &mut stx)
            .expect("re-approval should accept matching stored digest");
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored");
        assert_eq!(stored.council_envelope_digest, Some(expected_digest));
        assert!(matches!(stored.status, PinStatus::Approved(5)));
    }
    #[test]
    fn approve_manifest_reapproval_rejects_valid_replacement_envelope() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let replacement_key = checked_ed25519_keypair();
        state
            .gov
            .sorafs_pin_policy
            .approval_signers
            .push(council_approval_signer(
                "council-b",
                &replacement_key,
                0,
                None,
            ));
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let record = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored")
            .clone();
        let expected_digest = record
            .council_envelope_digest
            .expect("initial approval digest recorded");
        let (replacement, _) = build_envelope(&record, &replacement_key);
        let error = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(replacement),
            council_envelope_digest: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("a valid alternate envelope must not rewrite approval history");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("cannot replace its stored council envelope digest")
        ));
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest remains stored");
        assert_eq!(stored.council_envelope_digest, Some(expected_digest));
        assert_eq!(stored.status, PinStatus::Approved(5));
    }
    #[test]
    fn approve_manifest_reapproval_rejects_mismatched_stored_digest() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: None,
            council_envelope_digest: Some([0x77; 32]),
        };
        let err = approve
            .execute(&alice(), &mut stx)
            .expect_err("re-approval must reject mismatched stored digest");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("stored council envelope digest"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn approve_manifest_reapproval_requires_payload_without_stored_digest() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        let register = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        };
        register
            .execute(&alice(), &mut stx)
            .expect("register manifest");
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: None,
            council_envelope_digest: None,
        };
        let err = approve
            .execute(&alice(), &mut stx)
            .expect_err("re-approval must require payload when no digest is stored");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("re-approval requires council envelope payload"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn approve_pending_manifest_rejects_provided_digest_without_envelope() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_pending_manifest(&mut stx, default_digest(), default_chunk_digest());
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: None,
            council_envelope_digest: Some([0x66; 32]),
        };
        let error = approve
            .execute(&alice(), &mut stx)
            .expect_err("pending approval must require the actual envelope");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("requires council envelope payload")
        ));
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored");
        assert!(matches!(stored.status, PinStatus::Pending));
        assert_eq!(stored.council_envelope_digest, None);
    }
    #[test]
    fn approve_pending_manifest_requires_envelope_or_digest() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_pending_manifest(&mut stx, default_digest(), default_chunk_digest());
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: None,
            council_envelope_digest: None,
        };
        let err = approve
            .execute(&alice(), &mut stx)
            .expect_err("pending approval should require envelope or digest");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("approval requires council envelope payload"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn approve_pending_manifest_rejects_invalid_signature_without_side_effects() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alias = default_alias_binding();
        let record = insert_pending_manifest_with_alias(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            alias.clone(),
        );
        let (envelope, signature_hex) = build_envelope(&record, &council_key);
        let mut modified_signature =
            hex::decode(&signature_hex).expect("signature hex decodes cleanly");
        modified_signature[0] ^= 0xAA;
        let bad_signature_hex = hex::encode(modified_signature);
        let mut invalid_json =
            String::from_utf8(envelope.clone()).expect("envelope is valid UTF-8 JSON");
        invalid_json = invalid_json.replacen(&signature_hex, &bad_signature_hex, 1);
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(invalid_json.into_bytes()),
            council_envelope_digest: None,
        };
        let err = approve
            .execute(&alice(), &mut stx)
            .expect_err("pending approval must reject invalid signature");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("failed to verify council signature")
                || message.contains("invalid council signature material"),
            "unexpected error message: {message}"
        );
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("pending manifest remains stored");
        assert!(matches!(stored.status, PinStatus::Pending));
        assert!(stored.council_envelope_digest.is_none());
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&alias))
                .is_none(),
            "failed approval must not bind the pending alias"
        );
    }
    #[test]
    fn approve_pending_manifest_rejects_alias_collision_without_side_effects() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alias = default_alias_binding();
        let record = insert_pending_manifest_with_alias(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            alias.clone(),
        );
        let stale_alias = alias_binding_for(second_digest(), "sora", "docs", 0, 0);
        let stale_record =
            ManifestAliasRecord::new(stale_alias.clone(), second_digest(), bob(), 1, 10);
        let alias_id = ManifestAliasId::from(&stale_alias);
        stx.world
            .manifest_aliases
            .insert(alias_id.clone(), stale_record);
        let (envelope, _) = build_envelope(&record, &council_key);
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(envelope),
            council_envelope_digest: None,
        };
        let err = approve
            .execute(&alice(), &mut stx)
            .expect_err("pending approval must reject alias collision");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("alias `sora/docs` is already associated"),
            "unexpected error message: {message}"
        );
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("pending manifest remains stored");
        assert!(matches!(stored.status, PinStatus::Pending));
        assert!(stored.council_envelope_digest.is_none());
        let outdated = stx
            .world
            .manifest_aliases
            .get(&alias_id)
            .expect("stale alias record remains");
        assert!(outdated.targets_manifest(&second_digest()));
    }
    #[test]
    fn approve_pending_manifest_rejects_digest_mismatch_with_envelope_without_side_effects() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let alias = default_alias_binding();
        let record = insert_pending_manifest_with_alias(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            alias.clone(),
        );
        let (envelope, _) = build_envelope(&record, &council_key);
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: Some(envelope),
            council_envelope_digest: Some([0x99; 32]),
        };
        let err = approve
            .execute(&alice(), &mut stx)
            .expect_err("pending approval must reject mismatched supplied digest");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("approval digest mismatch with provided envelope"),
            "unexpected error message: {message}"
        );
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("pending manifest remains stored");
        assert!(matches!(stored.status, PinStatus::Pending));
        assert!(stored.council_envelope_digest.is_none());
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&alias))
                .is_none(),
            "failed digest-mismatch approval must not bind the pending alias"
        );
    }
    #[test]
    fn approve_manifest_reapproval_rejects_digest_without_stored_digest() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        let register = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        };
        register
            .execute(&alice(), &mut stx)
            .expect("register manifest");
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: None,
            council_envelope_digest: Some([0x12; 32]),
        };
        let err = approve
            .execute(&alice(), &mut stx)
            .expect_err("re-approval should reject digest-only input without stored digest");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("because no digest is stored"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn approve_manifest_rejects_retired_manifest() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        let register = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        };
        register
            .execute(&alice(), &mut stx)
            .expect("register manifest");
        let retire = RetirePinManifest {
            digest: default_digest(),
            reason: Some("superseded".into()),
        };
        retire.execute(&alice(), &mut stx).expect("retire manifest");
        let approve = ApprovePinManifest {
            digest: default_digest(),
            council_envelope: None,
            council_envelope_digest: None,
        };
        let err = approve
            .execute(&alice(), &mut stx)
            .expect_err("approval must reject retired manifest");
        let message = match err {
            InstructionExecutionError::InvariantViolation(message) => message.to_string(),
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("is retired and cannot be approved"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn retire_manifest_marks_record() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_automatic_replication_capacity(&mut stx, default_policy().min_replicas);
        let register = RegisterPinManifest {
            manifest_payload: default_manifest_payload(),
            alias: None,
            successor_of: None,
        };
        register
            .execute(&alice(), &mut stx)
            .expect("register manifest");
        let retire = RetirePinManifest {
            digest: default_digest(),
            reason: Some("superseded".into()),
        };
        retire.execute(&alice(), &mut stx).expect("retire manifest");
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored");
        assert!(matches!(stored.status, PinStatus::Retired(5)));
        assert!(
            stx.world
                .smart_contract_state
                .get(&pin_status_index_key(
                    &PinStatus::Approved(5),
                    &default_digest()
                ))
                .is_none()
        );
        assert!(
            stx.world
                .smart_contract_state
                .get(&pin_status_index_key(&stored.status, &default_digest()))
                .is_some()
        );
        assert_eq!(stored.retirement_reason.as_deref(), Some("superseded"));
        assert_eq!(
            read_pin_usage(stx.world(), pin_global_usage_key(), "global usage")
                .expect("valid global usage"),
            Some(PinResourceUsage {
                manifest_count: 1,
                content_bytes: 0,
            }),
            "retirement must retain the global record charge and release live content bytes"
        );
        assert_eq!(
            read_pin_usage(
                stx.world(),
                &pin_authority_usage_key(&alice()).expect("authority usage key"),
                "authority usage",
            )
            .expect("valid authority usage"),
            Some(PinResourceUsage {
                manifest_count: 1,
                content_bytes: 0,
            }),
            "retirement must retain the submitter record charge and release live content bytes"
        );
        assert!(
            stx.world
                .smart_contract_state
                .get(&pin_expiry_key(
                    default_policy().retention_epoch,
                    &default_digest()
                ))
                .is_none(),
            "retirement must remove its expiry index entry"
        );
    }
    #[test]
    fn retire_manifest_rejects_nonmonotonic_epochs_and_adversarial_reasons() {
        for (consensus_epoch, expected) in [
            (4, "predates submission epoch"),
            (8, "predates approval epoch"),
        ] {
            let state = make_state();
            let mut block = state.block(block_header_at_epoch(consensus_epoch));
            let mut stx =
                block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
            insert_manifest_with_status(
                &mut stx,
                default_digest(),
                default_chunk_digest(),
                None,
                PinStatus::Approved(9),
            );
            let error = RetirePinManifest {
                digest: default_digest(),
                reason: None,
            }
            .execute(&alice(), &mut stx)
            .expect_err("nonmonotonic retirement epoch must fail");
            assert!(matches!(
                error,
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(message)
                ) if message.contains(expected)
            ));
        }
        let state = make_state();
        let mut block = state.block(block_header_at_epoch(9));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_manifest_with_status(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            None,
            PinStatus::Approved(9),
        );
        for reason in [
            String::new(),
            " padded".to_owned(),
            "line\nbreak".to_owned(),
            "x".repeat(MAX_RETIREMENT_REASON_BYTES + 1),
        ] {
            let error = RetirePinManifest {
                digest: default_digest(),
                reason: Some(reason),
            }
            .execute(&alice(), &mut stx)
            .expect_err("noncanonical retirement reason must fail");
            assert!(matches!(
                error,
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(message)
                ) if message.contains("retirement reason must be canonical")
            ));
        }
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest remains stored");
        assert_eq!(stored.status, PinStatus::Approved(9));
        assert!(stored.retirement_reason.is_none());
    }
    #[test]
    fn retire_manifest_rejects_conflicting_repeat_without_side_effects() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let binding = sample_alias_binding();
        BindManifestAlias {
            digest: default_digest(),
            binding: binding.clone(),
            bound_epoch: 8,
            expiry_epoch: 16,
        }
        .execute(&alice(), &mut stx)
        .expect("bind alias before retirement");
        RetirePinManifest {
            digest: default_digest(),
            reason: Some("superseded".into()),
        }
        .execute(&alice(), &mut stx)
        .expect("first retire succeeds");
        let err = RetirePinManifest {
            digest: default_digest(),
            reason: Some("different".into()),
        }
        .execute(&alice(), &mut stx)
        .expect_err("conflicting second retirement must fail");
        let message = match err {
            InstructionExecutionError::InvariantViolation(message) => message.to_string(),
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("already retired at epoch 5"),
            "unexpected error message: {message}"
        );
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest remains stored");
        assert!(matches!(stored.status, PinStatus::Retired(5)));
        assert_eq!(stored.retirement_reason.as_deref(), Some("superseded"));
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&binding))
                .is_none(),
            "retirement must keep the old alias record removed"
        );
    }
    #[test]
    fn bind_manifest_alias_registers_record() {
        let mut state = make_initial_sorafs_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(initial_sorafs_block_header(&state));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let binding = sample_alias_binding();
        let bind = BindManifestAlias {
            digest: default_digest(),
            binding: binding.clone(),
            bound_epoch: 8,
            expiry_epoch: 16,
        };
        bind.execute_initial(&alice(), &mut stx)
            .expect("bind alias");
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest stored");
        assert_eq!(stored.alias.as_ref(), Some(&binding));
        let alias_id = ManifestAliasId::from(&binding);
        let alias_record = stx
            .world
            .manifest_aliases
            .get(&alias_id)
            .expect("alias record stored");
        assert!(alias_record.targets_manifest(&default_digest()));
        assert_eq!(alias_record.bound_epoch, 8);
        assert_eq!(alias_record.expiry_epoch, 16);
    }
    #[test]
    fn bind_manifest_alias_rejects_duplicates() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        register_and_approve_manifest(
            &mut stx,
            second_digest(),
            chunk_digest_for_seed(0xBB),
            &council_key,
        );
        let binding = sample_alias_binding();
        let first = BindManifestAlias {
            digest: default_digest(),
            binding: binding.clone(),
            bound_epoch: 8,
            expiry_epoch: 16,
        };
        first.execute(&alice(), &mut stx).expect("bind alias");
        let duplicate = BindManifestAlias {
            digest: second_digest(),
            binding: alias_binding_for(second_digest(), "sora", "docs", 9, 18),
            bound_epoch: 9,
            expiry_epoch: 18,
        };
        let err = duplicate
            .execute(&alice(), &mut stx)
            .expect_err("duplicate alias must fail");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(message.contains("alias"), "unexpected message: {message}");
        let first_record = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("first manifest remains stored");
        assert_eq!(first_record.alias.as_ref(), Some(&binding));
        let second_record = stx
            .world
            .pin_manifests
            .get(&second_digest())
            .expect("second manifest remains stored");
        assert!(
            second_record.alias.is_none(),
            "failed duplicate bind must not attach the contested alias to the second manifest"
        );
        let alias_record = stx
            .world
            .manifest_aliases
            .get(&ManifestAliasId::from(&binding))
            .expect("first alias record remains");
        assert!(alias_record.targets_manifest(&default_digest()));
    }
    #[test]
    fn bind_manifest_alias_rejects_expiry_before_bound_without_side_effects() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let binding = alias_binding_for(default_digest(), "sora", "docs", 8, 7);
        let err = BindManifestAlias {
            digest: default_digest(),
            binding: binding.clone(),
            bound_epoch: 8,
            expiry_epoch: 7,
        }
        .execute(&alice(), &mut stx)
        .expect_err("expiry before bound must fail");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("expiry epoch"),
            "unexpected error message: {message}"
        );
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest remains stored");
        assert!(stored.alias.is_none());
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&binding))
                .is_none(),
            "failed bind must not create an alias record"
        );
    }
    #[test]
    fn bind_manifest_alias_rejects_pending_manifest_without_side_effects() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_pending_manifest(&mut stx, default_digest(), default_chunk_digest());
        let binding = sample_alias_binding();
        let err = BindManifestAlias {
            digest: default_digest(),
            binding: binding.clone(),
            bound_epoch: 8,
            expiry_epoch: 16,
        }
        .execute(&alice(), &mut stx)
        .expect_err("pending manifest must not accept alias binding");
        let message = match err {
            InstructionExecutionError::InvariantViolation(message) => message.to_string(),
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("must be approved before binding an alias"),
            "unexpected error message: {message}"
        );
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest remains stored");
        assert!(matches!(stored.status, PinStatus::Pending));
        assert!(stored.alias.is_none());
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&binding))
                .is_none(),
            "failed pending bind must not create an alias record"
        );
    }
    #[test]
    fn bind_manifest_alias_rejects_expiry_past_retention_without_side_effects() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let expiry_epoch = default_policy().retention_epoch + 1;
        let binding = alias_binding_for(default_digest(), "sora", "docs", 8, expiry_epoch);
        let err = BindManifestAlias {
            digest: default_digest(),
            binding: binding.clone(),
            bound_epoch: 8,
            expiry_epoch,
        }
        .execute(&alice(), &mut stx)
        .expect_err("alias expiry beyond retention must fail");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("exceeds manifest retention epoch"),
            "unexpected error message: {message}"
        );
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest remains stored");
        assert!(stored.alias.is_none());
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&binding))
                .is_none(),
            "failed retention bind must not create an alias record"
        );
    }
    #[test]
    fn bind_manifest_alias_rejects_bound_before_approval_without_side_effects() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let binding = alias_binding_for(default_digest(), "sora", "docs", 4, 16);
        let err = BindManifestAlias {
            digest: default_digest(),
            binding: binding.clone(),
            bound_epoch: 4,
            expiry_epoch: 16,
        }
        .execute(&alice(), &mut stx)
        .expect_err("alias bound before approval must fail");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("precedes manifest approval epoch"),
            "unexpected error message: {message}"
        );
        let stored = stx
            .world
            .pin_manifests
            .get(&default_digest())
            .expect("manifest remains stored");
        assert!(matches!(stored.status, PinStatus::Approved(5)));
        assert!(stored.alias.is_none());
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&binding))
                .is_none(),
            "failed early-bound bind must not create an alias record"
        );
    }
    #[test]
    fn bind_manifest_alias_rejects_unknown_manifest_without_side_effects() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let binding = sample_alias_binding();
        let err = BindManifestAlias {
            digest: default_digest(),
            binding: binding.clone(),
            bound_epoch: 8,
            expiry_epoch: 16,
        }
        .execute(&alice(), &mut stx)
        .expect_err("unknown manifest must not accept alias binding");
        let message = match err {
            InstructionExecutionError::InvariantViolation(message) => message.to_string(),
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("not registered"),
            "unexpected error message: {message}"
        );
        assert!(
            stx.world.pin_manifests.get(&default_digest()).is_none(),
            "failed unknown-manifest bind must not create a manifest"
        );
        assert!(
            stx.world
                .manifest_aliases
                .get(&ManifestAliasId::from(&binding))
                .is_none(),
            "failed unknown-manifest bind must not create an alias record"
        );
    }
    #[test]
    fn bind_manifest_alias_rejects_proof_epoch_mismatch() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let mismatched_binding = alias_binding_for(default_digest(), "sora", "docs", 4, 12);
        let bind = BindManifestAlias {
            digest: default_digest(),
            binding: mismatched_binding,
            bound_epoch: 8,
            expiry_epoch: 16,
        };
        let err = bind
            .execute(&alice(), &mut stx)
            .expect_err("binding must reject mismatched alias proof epochs");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("alias proof bound_at"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn issue_replication_order_requires_permission() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        remove_permission(&mut stx, "CanIssueSorafsReplicationOrder");
        let issue = IssueReplicationOrder {
            order_id: ReplicationOrderId::new([0x44; 32]),
            order_payload: Vec::new(),
            issued_epoch: 1,
            deadline_epoch: 2,
            musubi_archive: None,
        };
        let err = issue
            .execute(&alice(), &mut stx)
            .expect_err("permissionless issue must fail");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("CanIssueSorafsReplicationOrder")
        ));
    }
    #[test]
    fn generic_replication_instructions_reject_reserved_automatic_ids() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let order_id = derive_sorafs_auto_replication_order_id_v1(&default_digest());
        let issue_error = IssueReplicationOrder {
            order_id,
            order_payload: Vec::new(),
            issued_epoch: 1,
            deadline_epoch: 2,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("generic issue must not populate the automatic namespace");
        assert!(matches!(
            issue_error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("reserved automatic-order identifier namespace")
        ));
        let revision_error = ReviseReplicationOrderAssignments::new(
            order_id,
            1,
            2,
            vec![ReplicationAssignmentV1 {
                provider_id: [0x21; 32],
                slice_gib: 1,
                lane: None,
            }],
        )
        .execute(&alice(), &mut stx)
        .expect_err("automatic assignments are immutable");
        assert!(matches!(
            revision_error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("immutable assignments")
        ));
        assert!(stx.world.replication_orders.get(&order_id).is_none());
    }
    #[test]
    fn complete_replication_order_requires_permission() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        remove_permission(&mut stx, "CanCompleteSorafsReplicationOrder");
        let complete = completion_instruction(
            ReplicationOrderId::new([0x55; 32]),
            ProviderId::new([0x56; 32]),
            5,
            &alice(),
        );
        let err = complete
            .execute(&alice(), &mut stx)
            .expect_err("permissionless completion must fail");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("CanCompleteSorafsReplicationOrder")
        ));
    }
    #[test]
    fn pricing_schedule_requires_permission() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        remove_permission(&mut stx, "CanSetSorafsPricing");
        let schedule = PricingScheduleRecord::launch_default();
        let err = SetPricingSchedule { schedule }
            .execute(&alice(), &mut stx)
            .expect_err("permissionless pricing must fail");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("CanSetSorafsPricing")
        ));
    }
    #[test]
    fn provider_credit_requires_permission() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        remove_permission(&mut stx, "CanUpsertSorafsProviderCredit");
        let credit = ProviderCreditRecord::new(
            ProviderId::new([0x77; 32]),
            xor_quantity_nanos(1),
            Quantity::zero(),
            Quantity::zero(),
            Quantity::zero(),
            1,
            1,
            Metadata::default(),
        );
        let err = UpsertProviderCredit {
            expected_current: None,
            record: credit,
        }
        .execute(&alice(), &mut stx)
        .expect_err("permissionless credit update must fail");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("CanUpsertSorafsProviderCredit")
        ));
    }
    #[test]
    fn issue_replication_order_stores_record() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let order_id = ReplicationOrderId::new([0x44; 32]);
        let providers = vec![
            ProviderId::new([0x11; 32]),
            ProviderId::new([0x12; 32]),
            ProviderId::new([0x13; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let order_struct = replication_order_struct(order_id, default_digest(), &providers, 3);
        let payload = encode_replication_order_for_epoch_window(order_struct, 12, 32);
        let issue = IssueReplicationOrder {
            order_id,
            order_payload: payload.clone(),
            issued_epoch: 12,
            deadline_epoch: 32,
            musubi_archive: None,
        };
        issue
            .execute(&alice(), &mut stx)
            .expect("issue replication order");
        let record = stx
            .world
            .replication_orders
            .get(&order_id)
            .expect("order stored");
        assert_eq!(record.manifest_digest, default_digest());
        assert_eq!(record.issued_epoch, 12);
        assert_eq!(record.deadline_epoch, 32);
        assert_eq!(record.issued_by, alice());
        assert_eq!(record.canonical_order, payload);
        assert!(matches!(record.status, ReplicationOrderStatus::Pending));
        let decoded = norito::decode_from_bytes::<ReplicationOrderV1>(&record.canonical_order)
            .expect("decode order");
        assert_eq!(decoded.order_id, *order_id.as_bytes());
        assert!(
            stx.world
                .musubi_locations_by_replication_order
                .get(&order_id)
                .is_none(),
            "generic SoraFS orders must not acquire a Musubi binding"
        );
        let mut corrupted = record.clone();
        corrupted.deadline_epoch = 31;
        let error = validate_stored_replication_order(&corrupted, "timestamp-mismatch")
            .expect_err("stored record timestamps must remain bound to the canonical payload");
        assert!(error.to_string().contains("bound to its record"));

        let mut prematurely_expired = record.clone();
        prematurely_expired.status =
            ReplicationOrderStatus::Expired(prematurely_expired.deadline_epoch);
        let error = validate_stored_replication_order(&prematurely_expired, "premature-expiry")
            .expect_err("stored expiry must be strictly later than the order deadline");
        assert!(error.to_string().contains("lifecycle is inconsistent"));

        let mut late_cancellation = record.clone();
        late_cancellation.status = ReplicationOrderStatus::Cancelled(
            late_cancellation
                .deadline_epoch
                .checked_add(1)
                .expect("fixture deadline has room"),
        );
        let error = validate_stored_replication_order(&late_cancellation, "late-cancellation")
            .expect_err("stored cancellation cannot occur after the order deadline");
        assert!(error.to_string().contains("lifecycle is inconsistent"));
    }
    #[test]
    fn issue_replication_order_requires_one_unix_second_window_and_live_pin_horizon() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let providers = vec![
            ProviderId::new([0x91; 32]),
            ProviderId::new([0x92; 32]),
            ProviderId::new([0x93; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());

        let mismatched_id = ReplicationOrderId::new([0x60; 32]);
        let mismatched_payload = encode_replication_order_for_epoch_window(
            replication_order_struct(mismatched_id, default_digest(), &providers, 3),
            12,
            32,
        );
        let mismatch = IssueReplicationOrder::new(mismatched_id, mismatched_payload, 12, 31)
            .execute(&alice(), &mut stx)
            .expect_err("record epochs must match provider-facing Unix timestamps");
        assert!(matches!(
            mismatch,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("must exactly match")
        ));

        let expiring_id = ReplicationOrderId::new([0x64; 32]);
        let expiring_payload = encode_replication_order_for_epoch_window(
            replication_order_struct(expiring_id, default_digest(), &providers, 3),
            12,
            default_policy().retention_epoch,
        );
        let expiring = IssueReplicationOrder::new(
            expiring_id,
            expiring_payload,
            12,
            default_policy().retention_epoch,
        )
        .execute(&alice(), &mut stx)
        .expect_err("pin expiry runs before transactions at the retention second");
        assert!(matches!(
            expiring,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("must be earlier than manifest retention epoch")
        ));
        assert!(stx.world.replication_orders.get(&mismatched_id).is_none());
        assert!(stx.world.replication_orders.get(&expiring_id).is_none());
    }
    include!("sorafs/musubi_replication_order_tests.rs");
    #[test]
    fn issue_replication_order_rejects_musubi_commitment_mismatch_without_partial_state() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let canonical_pin = registry_grade_musubi_pin();
        let archive = musubi_archive_for_pin(&canonical_pin, 0x71);
        let archive_id = archive.archive_id;
        let mut substituted_pin = canonical_pin;
        substituted_pin.content_length = substituted_pin
            .content_length
            .checked_add(1)
            .expect("fixture length remains bounded");
        stx.world
            .pin_manifests
            .insert(substituted_pin.digest, substituted_pin);
        stx.world.musubi_archives.insert(archive_id, archive);
        let order_id = ReplicationOrderId::new([0x72; 32]);
        let providers = vec![
            ProviderId::new([0x73; 32]),
            ProviderId::new([0x74; 32]),
            ProviderId::new([0x75; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let order = replication_order_struct(order_id, default_digest(), &providers, 3);
        let error = IssueReplicationOrder::new(
            order_id,
            encode_replication_order_for_epoch_window(order, 12, 32),
            12,
            32,
        )
        .for_musubi_archive(archive_id)
        .execute(&alice(), &mut stx)
        .expect_err("substituted pin commitment must fail closed");
        assert!(
            smart_contract_error_message(&error).contains("complete Musubi archive commitment"),
            "unexpected Musubi commitment error: {error:?}"
        );
        assert!(stx.world.replication_orders.get(&order_id).is_none());
        assert!(
            stx.world
                .musubi_locations_by_replication_order
                .get(&order_id)
                .is_none()
        );
    }
    #[test]
    fn instruction_box_dispatches_replication_order_issue() {
        let mut state = make_initial_sorafs_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(initial_sorafs_block_header(&state));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let order_id = ReplicationOrderId::new([0x54; 32]);
        let providers = vec![
            ProviderId::new([0x21; 32]),
            ProviderId::new([0x22; 32]),
            ProviderId::new([0x23; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let order_struct = replication_order_struct(order_id, default_digest(), &providers, 3);
        let payload = encode_replication_order_for_epoch_window(order_struct, 12, 32);
        let instruction = InstructionBox::from(IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 12,
            deadline_epoch: 32,
            musubi_archive: None,
        });
        instruction
            .execute(&alice(), &mut stx)
            .expect("instruction box should dispatch SoraFS replication orders");
        assert!(
            stx.world.replication_orders.get(&order_id).is_some(),
            "instruction box execution should store the replication order"
        );
    }
    #[test]
    fn issue_replication_order_rejects_target_below_policy() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let order_id = ReplicationOrderId::new([0x66; 32]);
        let providers = vec![
            ProviderId::new([0x41; 32]),
            ProviderId::new([0x42; 32]),
            ProviderId::new([0x43; 32]),
        ];
        let mut order_struct = replication_order_struct(order_id, default_digest(), &providers, 3);
        order_struct.target_replicas = 2;
        let payload = encode_replication_order_for_epoch_window(order_struct, 10, 20);
        let issue = IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 10,
            deadline_epoch: 20,
            musubi_archive: None,
        };
        let err = issue
            .execute(&alice(), &mut stx)
            .expect_err("target replicas below policy should fail");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("target replicas"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn issue_replication_order_rejects_chunker_mismatch() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let order_id = ReplicationOrderId::new([0x67; 32]);
        let providers = vec![
            ProviderId::new([0x51; 32]),
            ProviderId::new([0x52; 32]),
            ProviderId::new([0x53; 32]),
        ];
        let mut order_struct = replication_order_struct(order_id, default_digest(), &providers, 3);
        order_struct.chunking_profile = "sorafs.sf2@2.0.0".to_owned();
        let payload = encode_replication_order_for_epoch_window(order_struct, 15, 25);
        let issue = IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 15,
            deadline_epoch: 25,
            musubi_archive: None,
        };
        let err = issue
            .execute(&alice(), &mut stx)
            .expect_err("chunking profile mismatch should fail");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("unknown chunker handle"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn issue_replication_order_rejects_noncanonical_unbound_and_oversized_payloads() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let providers = vec![
            ProviderId::new([0x50; 32]),
            ProviderId::new([0x51; 32]),
            ProviderId::new([0x52; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let mismatch_id = ReplicationOrderId::new([0x68; 32]);
        let mut mismatch = replication_order_struct(mismatch_id, default_digest(), &providers, 3);
        mismatch.manifest_cid = manifest_fixture(0xBB).root_cid;
        let error = IssueReplicationOrder {
            order_id: mismatch_id,
            order_payload: encode_replication_order_for_epoch_window(mismatch, 5, 15),
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("manifest CID must be bound to the digest");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("manifest CID does not match content root")
        ));
        let noncanonical_id = ReplicationOrderId::new([0x69; 32]);
        let mut noncanonical =
            replication_order_struct(noncanonical_id, default_digest(), &providers, 3);
        noncanonical.issued_at = 5;
        noncanonical.deadline_at = 15;
        noncanonical.sla.ingest_deadline_secs = 10;
        let noncanonical_bytes = {
            let _guard = norito::core::DecodeFlagsGuard::enter(0);
            norito::to_bytes(&noncanonical).expect("encode alternate-layout fixture")
        };
        let error = IssueReplicationOrder {
            order_id: noncanonical_id,
            order_payload: noncanonical_bytes,
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("alternate Norito layout must fail");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("canonical first-release Norito")
        ));
        let oversized_id = ReplicationOrderId::new([0x6A; 32]);
        let error = IssueReplicationOrder {
            order_id: oversized_id,
            order_payload: vec![0xA5; MAX_REPLICATION_ORDER_PAYLOAD_BYTES + 1],
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("oversized payload must fail before decode");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("expected 1..=")
        ));
        let allocation_bomb_id = ReplicationOrderId::new([0x6C; 32]);
        let mut allocation_bomb =
            replication_order_struct(allocation_bomb_id, default_digest(), &providers, 3);
        allocation_bomb.metadata.push(CapacityMetadataEntry {
            key: "bomb".to_owned(),
            value: "x".repeat(sorafs_manifest::capacity::MAX_CAPACITY_METADATA_VALUE_BYTES + 1),
        });
        let allocation_bomb = encode_replication_order(&allocation_bomb);
        assert!(allocation_bomb.len() <= MAX_REPLICATION_ORDER_PAYLOAD_BYTES);
        let error = IssueReplicationOrder {
            order_id: allocation_bomb_id,
            order_payload: allocation_bomb,
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("sequence allocation bomb must fail before semantic validation");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("replication order validation failed")
        ));
        assert!(
            stx.world
                .replication_orders
                .get(&allocation_bomb_id)
                .is_none()
        );
    }
    #[test]
    fn issue_replication_order_rejects_zero_length_epoch_window() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let error = IssueReplicationOrder {
            order_id: ReplicationOrderId::new([0x6B; 32]),
            order_payload: vec![1],
            issued_epoch: 5,
            deadline_epoch: 5,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect_err("zero-length order epoch window must fail");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("must be greater than issued_epoch")
        ));
    }
    #[test]
    fn issue_replication_order_requires_permission_after_manifest_setup() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        remove_permission(&mut stx, "CanIssueSorafsReplicationOrder");
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let order_id = ReplicationOrderId::new([0x47; 32]);
        let providers = vec![ProviderId::new([0x26; 32])];
        seed_provider_owners(&mut stx, &providers, &alice());
        let order_struct = replication_order_struct(order_id, default_digest(), &providers, 3);
        let payload = encode_replication_order_for_epoch_window(order_struct, 22, 33);
        let issue = IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 22,
            deadline_epoch: 33,
            musubi_archive: None,
        };
        let err = issue
            .execute(&alice(), &mut stx)
            .expect_err("missing permission must reject order issue");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(_))
        ));
    }
    #[test]
    fn issue_replication_order_allows_registered_provider_owned_by_another_account() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let order_id = ReplicationOrderId::new([0x45; 32]);
        let providers = vec![
            ProviderId::new([0x24; 32]),
            ProviderId::new([0x25; 32]),
            ProviderId::new([0x26; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &bob());
        let order_struct = replication_order_struct(order_id, default_digest(), &providers, 3);
        let payload = encode_replication_order_for_epoch_window(order_struct, 22, 33);
        let issue = IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 22,
            deadline_epoch: 33,
            musubi_archive: None,
        };
        issue
            .execute(&alice(), &mut stx)
            .expect("permissioned governance issuer may assign another owner's provider");
        assert!(matches!(
            stx.world
                .replication_orders
                .get(&order_id)
                .expect("order stored")
                .status,
            ReplicationOrderStatus::Pending
        ));
    }
    #[test]
    fn issue_replication_order_rejects_missing_owner() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let order_id = ReplicationOrderId::new([0x46; 32]);
        let providers = vec![ProviderId::new([0x25; 32])];
        let order_struct = replication_order_struct(order_id, default_digest(), &providers, 3);
        let payload = encode_replication_order_for_epoch_window(order_struct, 22, 33);
        let issue = IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 22,
            deadline_epoch: 33,
            musubi_archive: None,
        };
        let err = issue
            .execute(&alice(), &mut stx)
            .expect_err("missing owner must reject order issue");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(_))
        ));
    }
    #[test]
    fn completion_after_deadline_fails_without_changing_pending_order() {
        let state = make_state_with_completion_anchor();
        let mut block = state.block(block_header_at_epoch(16));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_manifest_with_status(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            None,
            PinStatus::Approved(5),
        );
        let order_id = ReplicationOrderId::new([0x76; 32]);
        let providers = vec![
            ProviderId::new([0x30; 32]),
            ProviderId::new([0x31; 32]),
            ProviderId::new([0x32; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let payload = encode_replication_order_for_epoch_window(
            replication_order_struct(order_id, default_digest(), &providers, 3),
            5,
            15,
        );
        IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect("issue order");
        let exact_retry = completion_instruction(order_id, providers[0], 15, &alice());
        let error = exact_retry
            .clone()
            .execute(&alice(), &mut stx)
            .expect_err("a new completion submitted after the deadline must fail");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("current consensus epoch 16 is later than deadline_epoch 15")
        ));
        assert_eq!(
            stx.world
                .replication_orders
                .get(&order_id)
                .expect("order remains")
                .status,
            ReplicationOrderStatus::Pending
        );
        let retained = ReplicationOrderCompletionRecord {
            provider_id: providers[0],
            completed_by: alice(),
            completion_epoch: exact_retry.completion_epoch,
            assignment_revision: exact_retry.expected_assignment_revision,
            completion_authority: exact_retry.expected_authority.clone(),
            finalized_anchor: exact_retry.finalized_anchor,
        };
        stx.world
            .replication_orders
            .get_mut(&order_id)
            .expect("order remains")
            .provider_completions
            .push(retained);
        exact_retry
            .execute(&alice(), &mut stx)
            .expect("an exact retained completion replay remains idempotent after the deadline");
    }
    #[test]
    fn expire_replication_order_is_deadline_bound_and_idempotent() {
        let state = make_state_with_completion_anchor();
        let mut block = state.block(block_header_at_epoch(16));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_manifest_with_status(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            None,
            PinStatus::Approved(5),
        );
        let order_id = ReplicationOrderId::new([0x74; 32]);
        let providers = vec![
            ProviderId::new([0x2E; 32]),
            ProviderId::new([0x2F; 32]),
            ProviderId::new([0x30; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let payload = encode_replication_order_for_epoch_window(
            replication_order_struct(order_id, default_digest(), &providers, 3),
            5,
            15,
        );
        IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect("issue order");
        let early = ExpireReplicationOrder {
            order_id,
            expiration_epoch: 15,
        }
        .execute(&alice(), &mut stx)
        .expect_err("deadline remains completion-eligible");
        assert!(matches!(
            early,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("must be greater than deadline_epoch")
        ));
        assert_eq!(
            stx.world
                .replication_orders
                .get(&order_id)
                .expect("order remains pending")
                .status,
            ReplicationOrderStatus::Pending
        );
        let future = ExpireReplicationOrder {
            order_id,
            expiration_epoch: 17,
        }
        .execute(&alice(), &mut stx)
        .expect_err("expiration cannot claim a future consensus second");
        assert!(matches!(
            future,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("cannot exceed consensus Unix-second epoch")
        ));
        ExpireReplicationOrder {
            order_id,
            expiration_epoch: 16,
        }
        .execute(&alice(), &mut stx)
        .expect("expire after deadline");
        ExpireReplicationOrder {
            order_id,
            expiration_epoch: 16,
        }
        .execute(&alice(), &mut stx)
        .expect("exact expiration replay is idempotent");
        let conflict = ExpireReplicationOrder {
            order_id,
            expiration_epoch: 17,
        }
        .execute(&alice(), &mut stx)
        .expect_err("conflicting expiration replay must fail");
        assert!(matches!(
            conflict,
            InstructionExecutionError::InvariantViolation(message)
                if message.contains("already expired at epoch 16")
        ));
        assert_eq!(
            stx.world
                .replication_orders
                .get(&order_id)
                .expect("expired order retained")
                .status,
            ReplicationOrderStatus::Expired(16)
        );
        let completion = completion_instruction(order_id, providers[0], 15, &alice())
            .execute(&alice(), &mut stx)
            .expect_err("expired order cannot complete");
        assert!(matches!(
            completion,
            InstructionExecutionError::InvariantViolation(message)
                if message.contains("expired at epoch 16")
        ));
    }
    #[test]
    fn expire_replication_order_rejects_completed_order_and_missing_permission() {
        let state = make_state_with_completion_anchor();
        let mut block = state.block(block_header_at_epoch(15));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_manifest_with_status(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            None,
            PinStatus::Approved(5),
        );
        let order_id = ReplicationOrderId::new([0x73; 32]);
        let providers = vec![
            ProviderId::new([0x2D; 32]),
            ProviderId::new([0x2E; 32]),
            ProviderId::new([0x2F; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let payload = encode_replication_order_for_epoch_window(
            replication_order_struct(order_id, default_digest(), &providers, 3),
            5,
            15,
        );
        IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect("issue order");
        remove_permission(&mut stx, "CanIssueSorafsReplicationOrder");
        let denied = ExpireReplicationOrder {
            order_id,
            expiration_epoch: 16,
        }
        .execute(&alice(), &mut stx)
        .expect_err("expiration requires governance issue permission");
        assert!(matches!(
            denied,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(_))
        ));
        grant_permission(&mut stx, "CanIssueSorafsReplicationOrder");
        for provider_id in providers {
            completion_instruction(order_id, provider_id, 15, &alice())
                .execute(&alice(), &mut stx)
                .expect("complete provider assignment at deadline");
        }
        let completed = ExpireReplicationOrder {
            order_id,
            expiration_epoch: 16,
        }
        .execute(&alice(), &mut stx)
        .expect_err("completed order cannot expire");
        assert!(matches!(
            completed,
            InstructionExecutionError::InvariantViolation(message)
                if message.contains("completed at epoch 15")
        ));
    }
    #[test]
    fn retiring_manifest_at_order_deadline_cancels_pending_replication() {
        let state = make_state_with_completion_anchor();
        let mut block = state.block(block_header_at_epoch(15));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_manifest_with_status(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            None,
            PinStatus::Approved(5),
        );
        let order_id = ReplicationOrderId::new([0x75; 32]);
        let providers = vec![
            ProviderId::new([0x2F; 32]),
            ProviderId::new([0x30; 32]),
            ProviderId::new([0x31; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let payload = encode_replication_order_for_epoch_window(
            replication_order_struct(order_id, default_digest(), &providers, 3),
            5,
            15,
        );
        IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect("issue order");
        RetirePinManifest {
            digest: default_digest(),
            reason: Some("superseded".to_owned()),
        }
        .execute(&alice(), &mut stx)
        .expect("retire manifest");
        assert_eq!(
            stx.world
                .replication_orders
                .get(&order_id)
                .expect("order remains auditable")
                .status,
            ReplicationOrderStatus::Cancelled(15)
        );
        let error = completion_instruction(order_id, providers[0], 15, &alice())
            .execute(&alice(), &mut stx)
            .expect_err("cancelled order must not complete");
        assert!(matches!(
            error,
            InstructionExecutionError::InvariantViolation(message)
                if message.contains("cancelled at epoch 15")
        ));
    }
    #[test]
    fn retiring_manifest_after_order_deadline_expires_pending_replication() {
        let state = make_state_with_completion_anchor();
        let mut block = state.block(block_header_at_epoch(16));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_manifest_with_status(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            None,
            PinStatus::Approved(5),
        );
        let order_id = ReplicationOrderId::new([0x76; 32]);
        let providers = vec![
            ProviderId::new([0x32; 32]),
            ProviderId::new([0x33; 32]),
            ProviderId::new([0x34; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let payload = encode_replication_order_for_epoch_window(
            replication_order_struct(order_id, default_digest(), &providers, 3),
            5,
            15,
        );
        IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect("issue order");

        RetirePinManifest {
            digest: default_digest(),
            reason: Some("superseded".to_owned()),
        }
        .execute(&alice(), &mut stx)
        .expect("retire manifest after order deadline");
        assert_eq!(
            stx.world
                .replication_orders
                .get(&order_id)
                .expect("order remains auditable")
                .status,
            ReplicationOrderStatus::Expired(16)
        );
    }
    #[test]
    fn complete_replication_order_requires_permission_after_manifest_setup() {
        let mut state = make_state();
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let order_id = ReplicationOrderId::new([0x7A; 32]);
        let providers = vec![
            ProviderId::new([0x36; 32]),
            ProviderId::new([0x37; 32]),
            ProviderId::new([0x38; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let order_struct = replication_order_struct(order_id, default_digest(), &providers, 3);
        let payload = encode_replication_order_for_epoch_window(order_struct, 20, 40);
        IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 20,
            deadline_epoch: 40,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect("issue replication order");
        remove_permission(&mut stx, "CanCompleteSorafsReplicationOrder");
        let complete = completion_instruction(order_id, providers[0], 25, &alice());
        let err = complete
            .execute(&alice(), &mut stx)
            .expect_err("missing permission should reject completion");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(_))
        ));
    }
    #[test]
    fn complete_replication_order_rejects_permissioned_non_owner_governance() {
        let mut state = make_state_with_completion_anchor();
        seed_sorafs_permissions(&mut state, &bob());
        let council_key = checked_ed25519_keypair();
        set_council_approval_signers(
            &mut state,
            1,
            vec![council_approval_signer("council-a", &council_key, 0, None)],
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_and_approve_manifest(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            &council_key,
        );
        let order_id = ReplicationOrderId::new([0x78; 32]);
        let providers = vec![
            ProviderId::new([0x34; 32]),
            ProviderId::new([0x44; 32]),
            ProviderId::new([0x54; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let order_struct = replication_order_struct(order_id, default_digest(), &providers, 3);
        let payload = encode_replication_order_for_epoch_window(order_struct, 5, 15);
        IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect("issue replication order");
        stx.world.add_account_permission(
            &bob(),
            Permission::from(
                iroha_executor_data_model::permission::sorafs::CanCompleteSorafsReplicationOrder {
                    provider_id: providers[0],
                },
            ),
        );
        let complete = completion_instruction(order_id, providers[0], 10, &alice());
        let error = complete
            .execute(&bob(), &mut stx)
            .expect_err("governance cannot impersonate the assigned provider owner");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("must be authorized by its exact governed completion signer")
        ));
        assert_eq!(
            stx.world
                .replication_orders
                .get(&order_id)
                .expect("order stored")
                .status,
            ReplicationOrderStatus::Pending
        );
    }
    #[test]
    fn provider_owner_transfer_after_retained_completion_cannot_rewrite_evidence() {
        let mut state = make_state_with_completion_anchor();
        seed_sorafs_permissions(&mut state, &bob());
        let mut block = state.block(block_header_at_epoch(12));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        insert_manifest_with_status(
            &mut stx,
            default_digest(),
            default_chunk_digest(),
            None,
            PinStatus::Approved(5),
        );
        let order_id = ReplicationOrderId::new([0x79; 32]);
        let providers = vec![
            ProviderId::new([0x35; 32]),
            ProviderId::new([0x45; 32]),
            ProviderId::new([0x55; 32]),
        ];
        seed_provider_owners(&mut stx, &providers, &alice());
        let order_struct = replication_order_struct(order_id, default_digest(), &providers, 3);
        let payload = encode_replication_order_for_epoch_window(order_struct, 5, 15);
        IssueReplicationOrder {
            order_id,
            order_payload: payload,
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), &mut stx)
        .expect("issue replication order");
        completion_instruction(order_id, providers[0], 10, &alice())
            .execute(&alice(), &mut stx)
            .expect("retain the original owner's completion before transfer");
        assert!(
            apply_governed_provider_owner_action(
                SorafsProviderGovernanceActionV1::Rebind(RebindSorafsProviderOwnerV1 {
                    provider_id: providers[0],
                    expected_owner: alice(),
                    next_owner: bob(),
                }),
                &mut stx,
            )
            .expect("enacted governance replaces the provider owner")
        );
        SetProviderIngestCompletionAuthority::new(
            providers[0],
            None,
            completion_authority(&bob(), 1),
        )
        .execute(&bob(), &mut stx)
        .expect("install the replacement owner's completion authority");
        stx.world.add_account_permission(
            &bob(),
            Permission::from(
                iroha_executor_data_model::permission::sorafs::CanCompleteSorafsReplicationOrder {
                    provider_id: providers[0],
                },
            ),
        );
        let complete = completion_instruction(order_id, providers[0], 12, &alice());
        let error = complete
            .execute(&bob(), &mut stx)
            .expect_err("a successor owner cannot rewrite retained completion evidence");
        assert!(matches!(
            error,
            InstructionExecutionError::InvariantViolation(message)
                if message.contains("different retained completion context")
        ));
    }
    #[test]
    fn register_capacity_declaration_accepts_governed_owner_with_native_reserve_bond() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, record) = sample_capacity_record();
        seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::from(1_u32));
        let instruction = RegisterCapacityDeclaration {
            declaration: record.clone().declaration,
        };
        instruction
            .execute(&alice(), &mut stx)
            .expect("register capacity declaration");
        let stored = stx
            .world
            .capacity_declarations
            .get(&provider)
            .expect("capacity declaration stored");
        assert_eq!(stored.committed_capacity_gib, record.committed_capacity_gib);
        let ledger = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("capacity ledger updated");
        assert_eq!(
            ledger.total_declared_gib,
            u128::from(record.committed_capacity_gib)
        );
        assert_eq!(stx.world.provider_owners.get(&provider), Some(&alice()));
    }
    #[test]
    fn capacity_declaration_accepts_i105_owner_literal_with_governed_registry() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let mut declaration = sample_capacity_declaration();
        declaration.metadata = vec![
            CapacityMetadataEntry {
                key: PROVIDER_OWNER_METADATA_KEY.to_owned(),
                value: alice().to_string(),
            },
            CapacityMetadataEntry {
                key: STORAGE_CLASS_METADATA_KEY.to_owned(),
                value: "hot".to_owned(),
            },
        ];
        let provider = ProviderId::new(declaration.provider_id);
        let record = CapacityDeclarationRecord::new(
            provider,
            norito::to_bytes(&declaration).expect("serialize declaration"),
            declaration.committed_capacity_gib,
            5,
            declaration.valid_from,
            declaration.valid_until,
            Metadata::default(),
        );
        register_governed_capacity_declaration(&mut stx, &alice(), record)
            .expect("register declaration with I105 owner");
        assert!(stx.world.capacity_declarations.get(&provider).is_some());
    }
    #[test]
    fn record_capacity_telemetry_updates_pricing_and_credit() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, record) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), record)
            .expect("register capacity declaration");
        let mut schedule = PricingScheduleRecord::launch_default();
        replace_test_tier(
            &mut schedule,
            TierRate::new(
                StorageClass::Hot,
                xor_quantity_nanos(1_000_000_000),
                xor_quantity_nanos(1_000_000),
            ),
        );
        schedule.credit = CreditPolicy {
            settlement_window_secs: SECONDS_PER_BILLING_MONTH,
            settlement_grace_secs: 0,
            low_balance_alert_bps: 2_000,
        };
        schedule.collateral = CollateralPolicy {
            multiplier_bps: 30_000,
            onboarding_discount_bps: 5_000,
            onboarding_period_secs: SECONDS_PER_BILLING_MONTH,
        };
        SetPricingSchedule { schedule }
            .execute(&alice(), &mut stx)
            .expect("set pricing schedule");
        let credit = ProviderCreditRecord::new(
            provider,
            xor_quantity_nanos(15_000_000_000),
            Quantity::zero(),
            Quantity::zero(),
            Quantity::zero(),
            0,
            0,
            Metadata::default(),
        );
        upsert_provider_credit_with_reserve_fixture(&mut stx, &alice(), credit)
            .expect("seed provider credit");
        let telemetry = CapacityTelemetryRecord::new(
            provider,
            0,
            SECONDS_PER_BILLING_MONTH,
            75,
            75,
            10,
            1,
            1,
            10_000,
            10_000,
            0,
            0,
            0,
            0,
            0,
        )
        .with_nonce(SECONDS_PER_BILLING_MONTH);
        RecordCapacityTelemetry { record: telemetry }
            .execute(&alice(), &mut stx)
            .expect("record capacity telemetry");
        let ledger = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("capacity fee ledger stored");
        assert_eq!(ledger.storage_fee, xor_quantity_nanos(10_000_000_000));
        assert_eq!(ledger.egress_fee, Quantity::zero());
        assert_eq!(ledger.accrued_fee, xor_quantity_nanos(10_000_000_000));
        assert_eq!(
            ledger.expected_settlement,
            xor_quantity_nanos(10_000_000_000)
        );
        let credit_after = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit ledger stored");
        assert_eq!(
            credit_after.available_credit,
            xor_quantity_nanos(5_000_000_000)
        );
        assert_eq!(
            credit_after.expected_settlement,
            xor_quantity_nanos(10_000_000_000)
        );
        assert_eq!(
            credit_after.required_bond,
            xor_quantity_nanos(30_000_000_000)
        );
        assert_eq!(credit_after.low_balance_since_epoch, None);
    }
    #[test]
    fn record_capacity_telemetry_caps_credit_debit_at_zero() {
        // The zero lower bound is enforced fail-closed: an unaffordable debit
        // is rejected atomically rather than clamped into a partial charge.
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, record) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), record)
            .expect("register capacity declaration");
        let mut schedule = PricingScheduleRecord::launch_default();
        replace_test_tier(
            &mut schedule,
            TierRate::new(
                StorageClass::Hot,
                xor_quantity_nanos(1_000_000_000),
                xor_quantity_nanos(1),
            ),
        );
        schedule.credit.settlement_window_secs = SECONDS_PER_BILLING_MONTH;
        SetPricingSchedule { schedule }
            .execute(&alice(), &mut stx)
            .expect("set pricing schedule");
        upsert_provider_credit_with_reserve_fixture(
            &mut stx,
            &alice(),
            provider_credit_nanos(provider, 1, 0),
        )
        .expect("seed one-nano provider credit");
        let ledger_before = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .cloned()
            .expect("capacity ledger exists");
        let telemetry = CapacityTelemetryRecord::new(
            provider,
            0,
            SECONDS_PER_BILLING_MONTH,
            75,
            75,
            1,
            0,
            0,
            10_000,
            10_000,
            0,
            0,
            0,
            0,
            0,
        )
        .with_nonce(SECONDS_PER_BILLING_MONTH);
        let err = RecordCapacityTelemetry { record: telemetry }
            .execute(&alice(), &mut stx)
            .expect_err("debit larger than credit must fail closed");
        assert!(
            matches!(
                err,
                InstructionExecutionError::InvariantViolation(ref message)
                    if message.contains("credit debit")
                        && message.contains("exceeds available balance")
            ),
            "unexpected insufficient-credit error: {err:?}"
        );
        let credit = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("provider credit stored");
        assert_eq!(credit.available_credit, xor_quantity_nanos(1));
        assert_eq!(
            stx.world.capacity_fee_ledger.get(&provider),
            Some(&ledger_before),
            "failed debit must leave the existing capacity ledger unchanged"
        );
    }
    #[test]
    fn record_capacity_telemetry_rejects_quantity_overflow_without_partial_mutation() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, record) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), record)
            .expect("register capacity declaration");
        let mut schedule = PricingScheduleRecord::launch_default();
        replace_test_tier(
            &mut schedule,
            TierRate::new(
                StorageClass::Hot,
                max_positive_quantity(),
                xor_quantity_nanos(1),
            ),
        );
        schedule.credit.settlement_window_secs = SECONDS_PER_BILLING_MONTH;
        SetPricingSchedule { schedule }
            .execute(&alice(), &mut stx)
            .expect("maximum bounded price is structurally valid");
        upsert_provider_credit_with_reserve_fixture(
            &mut stx,
            &alice(),
            provider_credit_nanos(provider, 10_000_000_000, 0),
        )
        .expect("seed provider credit");
        let ledger_before = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .cloned()
            .expect("capacity ledger exists");
        let credit_before = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .cloned()
            .expect("provider credit exists");
        let telemetry = CapacityTelemetryRecord::new(
            provider,
            0,
            SECONDS_PER_BILLING_MONTH,
            75,
            75,
            10,
            0,
            0,
            10_000,
            10_000,
            0,
            0,
            0,
            0,
            0,
        )
        .with_nonce(SECONDS_PER_BILLING_MONTH);
        let error = RecordCapacityTelemetry { record: telemetry }
            .execute(&alice(), &mut stx)
            .expect_err("overflowing storage charge must be rejected");
        assert!(matches!(
            error,
            InstructionExecutionError::InvariantViolation(message)
                if message.contains("SoraFS storage fee calculation failed")
        ));
        assert_eq!(
            stx.world.capacity_fee_ledger.get(&provider),
            Some(&ledger_before),
            "rejected arithmetic must not mutate capacity accounting"
        );
        assert_eq!(
            stx.world.provider_credit_ledger.get(&provider),
            Some(&credit_before),
            "rejected arithmetic must not mutate provider credit"
        );
    }
    #[test]
    fn record_capacity_telemetry_rejects_overcommit_and_zero_capacity() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), declaration)
            .expect("register capacity declaration");
        let oversized = CapacityTelemetryRecord::new(
            provider, 0, 10, 2_048, 2_048, 2_048, 1, 1, 10_000, 10_000, 1, 0, 0, 0, 0,
        )
        .with_nonce(10);
        let err = RecordCapacityTelemetry { record: oversized }
            .execute(&alice(), &mut stx)
            .expect_err("telemetry exceeding committed capacity must be rejected");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message
            )) if message.contains("capacity_exceeds_commitment")
        ));
        let zero_capacity = CapacityTelemetryRecord::new(
            provider, 10, 20, 10, 10, 0, 1, 1, 10_000, 10_000, 1, 0, 0, 0, 0,
        )
        .with_nonce(20);
        let err = RecordCapacityTelemetry {
            record: zero_capacity,
        }
        .execute(&alice(), &mut stx)
        .expect_err("telemetry with zero capacity must be rejected");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message
            )) if message.contains("zero_capacity_window")
        ));
    }
    #[test]
    fn record_capacity_telemetry_rejects_overlap_gap_and_replay() {
        let mut state = make_state();
        state.gov.sorafs_telemetry.max_window_gap = core::time::Duration::from_secs(2);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), declaration)
            .expect("register capacity declaration");
        UpsertProviderCredit {
            expected_current: stx
                .world
                .provider_credit_ledger
                .get(&provider)
                .map(iroha_crypto::HashOf::new),
            record: provider_credit_nanos(provider, 1_000_000_000, 1_000_000_000),
        }
        .execute(&alice(), &mut stx)
        .expect("fund the provider's declared telemetry credit");
        record_capacity_window(&mut stx, provider, 0, 10, 50, 50, 25, 9_500, 9_500, 0);
        let overlap = CapacityTelemetryRecord::new(
            provider, 5, 12, 50, 50, 25, 1, 1, 9_500, 9_500, 0, 0, 0, 0, 0,
        )
        .with_nonce(12);
        let err = RecordCapacityTelemetry { record: overlap }
            .execute(&alice(), &mut stx)
            .expect_err("overlapping telemetry must be rejected");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message
            )) if message.contains("overlapping_window")
        ));
        let replay = CapacityTelemetryRecord::new(
            provider, 11, 18, 50, 50, 25, 1, 1, 9_500, 9_500, 0, 0, 0, 0, 0,
        )
        .with_nonce(10);
        let err = RecordCapacityTelemetry { record: replay }
            .execute(&alice(), &mut stx)
            .expect_err("replayed nonce must be rejected");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message
            )) if message.contains("replayed_nonce")
        ));
        let gap = CapacityTelemetryRecord::new(
            provider, 30, 35, 50, 50, 25, 1, 1, 9_500, 9_500, 0, 0, 0, 0, 0,
        )
        .with_nonce(35);
        let err = RecordCapacityTelemetry { record: gap }
            .execute(&alice(), &mut stx)
            .expect_err("gap beyond policy must be rejected");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message
            )) if message.contains("window_gap_exceeded")
        ));
    }
    #[test]
    fn record_capacity_telemetry_rejects_replay_when_nonce_optional() {
        let mut state = make_state();
        state.gov.sorafs_telemetry.require_nonce = false;
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), declaration)
            .expect("register capacity declaration");
        UpsertProviderCredit {
            expected_current: stx
                .world
                .provider_credit_ledger
                .get(&provider)
                .map(iroha_crypto::HashOf::new),
            record: provider_credit_nanos(provider, 1_000_000_000, 1_000_000_000),
        }
        .execute(&alice(), &mut stx)
        .expect("fund the provider's declared telemetry credit");
        record_capacity_window(&mut stx, provider, 0, 10, 50, 50, 25, 9_500, 9_500, 0);
        let replay = CapacityTelemetryRecord::new(
            provider, 11, 18, 50, 50, 25, 1, 1, 9_500, 9_500, 0, 0, 0, 0, 0,
        )
        .with_nonce(10);
        let err = RecordCapacityTelemetry { record: replay }
            .execute(&alice(), &mut stx)
            .expect_err("replayed nonce must be rejected even when optional");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message
            )) if message.contains("replayed_nonce")
        ));
    }
    #[test]
    fn record_capacity_telemetry_requires_authorised_submitter() {
        let mut state = make_state();
        let bob = bob();
        seed_sorafs_permissions(&mut state, &bob);
        state.gov.sorafs_telemetry.submitters = vec![alice()];
        state.gov.sorafs_telemetry.require_submitter = true;
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, declaration) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), declaration)
            .expect("register capacity declaration");
        let telemetry = CapacityTelemetryRecord::new(
            provider, 0, 10, 50, 50, 25, 1, 1, 10_000, 10_000, 0, 0, 0, 0, 0,
        )
        .with_nonce(10);
        let err = RecordCapacityTelemetry { record: telemetry }
            .execute(&bob, &mut stx)
            .expect_err("unauthorised submitter must be rejected");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("unauthorised_submitter"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn record_capacity_telemetry_provider_override_allows_owner_when_global_rejects() {
        let mut state = make_state();
        seed_sorafs_permissions(&mut state, &bob());
        state.gov.sorafs_telemetry.require_submitter = true;
        state.gov.sorafs_telemetry.submitters = vec![alice()];
        let (provider, declaration) = capacity_record_with_owner(&bob());
        state
            .gov
            .sorafs_telemetry
            .per_provider_submitters
            .insert(provider, vec![bob()]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_governed_capacity_declaration(&mut stx, &bob(), declaration)
            .expect("register capacity declaration");
        UpsertProviderCredit {
            expected_current: stx
                .world
                .provider_credit_ledger
                .get(&provider)
                .map(iroha_crypto::HashOf::new),
            record: provider_credit_nanos(provider, 1_000_000_000, 1_000_000_000),
        }
        .execute(&alice(), &mut stx)
        .expect("fund the provider's declared telemetry credit");
        let telemetry = CapacityTelemetryRecord::new(
            provider, 0, 10, 50, 50, 25, 1, 1, 10_000, 10_000, 0, 0, 0, 0, 0,
        )
        .with_nonce(10);
        RecordCapacityTelemetry { record: telemetry }
            .execute(&bob(), &mut stx)
            .expect("per-provider allow-list should allow owner");
    }
    #[test]
    fn record_capacity_telemetry_provider_override_blocks_owner_not_listed() {
        let mut state = make_state();
        state.gov.sorafs_telemetry.require_submitter = true;
        state.gov.sorafs_telemetry.submitters = vec![alice()];
        let (provider, declaration) = sample_capacity_record();
        state
            .gov
            .sorafs_telemetry
            .per_provider_submitters
            .insert(provider, vec![bob()]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        register_governed_capacity_declaration(&mut stx, &alice(), declaration)
            .expect("register capacity declaration");
        let telemetry = CapacityTelemetryRecord::new(
            provider, 0, 10, 50, 50, 25, 1, 1, 10_000, 10_000, 0, 0, 0, 0, 0,
        )
        .with_nonce(10);
        let err = RecordCapacityTelemetry { record: telemetry }
            .execute(&alice(), &mut stx)
            .expect_err("owner not in provider allow-list must be rejected");
        assert!(matches!(
            err,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message
            )) if message.contains("unauthorised_submitter_provider")
        ));
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn record_capacity_telemetry_penalises_persistent_under_delivery() {
        let mut state = make_state();
        state.gov.sorafs_penalty = iroha_config::parameters::actual::SorafsPenaltyPolicy {
            utilisation_floor_bps: 9_500,
            uptime_floor_bps: 9_500,
            por_success_floor_bps: 9_500,
            strike_threshold: 2,
            penalty_bond_bps: 5_000,
            cooldown_windows: 2,
            max_pdp_failures: 0,
            max_potr_breaches: 0,
        };
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, record) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), record)
            .expect("register capacity declaration");
        let mut schedule = PricingScheduleRecord::launch_default();
        schedule.credit = CreditPolicy {
            settlement_window_secs: SECONDS_PER_BILLING_MONTH,
            settlement_grace_secs: 0,
            low_balance_alert_bps: 2_000,
        };
        schedule.collateral = CollateralPolicy {
            multiplier_bps: 30_000,
            onboarding_discount_bps: 5_000,
            onboarding_period_secs: SECONDS_PER_BILLING_MONTH,
        };
        SetPricingSchedule {
            schedule: schedule.clone(),
        }
        .execute(&alice(), &mut stx)
        .expect("set pricing schedule");
        let credit = ProviderCreditRecord::new(
            provider,
            xor_quantity_nanos(1_000_000_000_000),
            xor_quantity_nanos(8_000_000_000),
            Quantity::zero(),
            Quantity::zero(),
            0,
            0,
            Metadata::default(),
        );
        upsert_provider_credit_with_reserve_fixture(&mut stx, &alice(), credit)
            .expect("seed provider credit");
        let window = SECONDS_PER_BILLING_MONTH;
        record_capacity_window(
            &mut stx, provider, 0, window, 100, 90, 40, 7_500, 7_400, 128,
        );
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        assert_eq!(credit_snapshot.under_delivery_strikes, 1);
        assert_eq!(credit_snapshot.slashed, Quantity::zero());
        assert_eq!(credit_snapshot.last_penalty_epoch, None);
        let ledger_snapshot = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("ledger snapshot");
        assert_eq!(ledger_snapshot.penalty_events, 0);
        assert_eq!(ledger_snapshot.penalty_slashed, Quantity::zero());
        record_capacity_window(
            &mut stx,
            provider,
            window,
            window * 2,
            100,
            90,
            40,
            7_500,
            7_400,
            128,
        );
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        let first_penalty = credit_snapshot.slashed.clone();
        assert!(!first_penalty.is_zero(), "penalty must slash collateral");
        assert_eq!(credit_snapshot.under_delivery_strikes, 0);
        assert_eq!(credit_snapshot.last_penalty_epoch, Some(window * 2));
        assert_eq!(credit_snapshot.bonded, xor_quantity_nanos(4_000_000_000));
        let ledger_snapshot = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("ledger snapshot");
        assert_eq!(ledger_snapshot.penalty_events, 1);
        assert_eq!(ledger_snapshot.penalty_slashed, first_penalty);
        record_capacity_window(
            &mut stx,
            provider,
            window * 2,
            window * 3,
            100,
            90,
            40,
            7_500,
            7_400,
            128,
        );
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        assert_eq!(credit_snapshot.slashed, first_penalty);
        assert_eq!(credit_snapshot.under_delivery_strikes, 1);
        assert_eq!(credit_snapshot.last_penalty_epoch, Some(window * 2));
        let ledger_snapshot = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("ledger snapshot");
        assert_eq!(ledger_snapshot.penalty_events, 1);
        assert_eq!(ledger_snapshot.penalty_slashed, first_penalty);
        record_capacity_window(
            &mut stx,
            provider,
            window * 3,
            window * 4,
            100,
            90,
            40,
            7_500,
            7_400,
            128,
        );
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        assert_eq!(credit_snapshot.bonded, xor_quantity_nanos(2_000_000_000));
        assert_eq!(credit_snapshot.under_delivery_strikes, 0);
        assert_eq!(credit_snapshot.last_penalty_epoch, Some(window * 4));
        let total_slashed = credit_snapshot.slashed.clone();
        assert!(
            total_slashed > first_penalty,
            "penalty total should increase after second slash"
        );
        assert_eq!(total_slashed, xor_quantity_nanos(6_000_000_000));
        let ledger_snapshot = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("ledger snapshot");
        assert_eq!(ledger_snapshot.penalty_events, 2);
        assert_eq!(ledger_snapshot.penalty_slashed, total_slashed);
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn record_capacity_telemetry_respects_cooldown_between_penalties() {
        let mut state = make_state();
        state.gov.sorafs_penalty = iroha_config::parameters::actual::SorafsPenaltyPolicy {
            utilisation_floor_bps: 9_500,
            uptime_floor_bps: 9_500,
            por_success_floor_bps: 9_500,
            strike_threshold: 1,
            penalty_bond_bps: 5_000,
            cooldown_windows: 2,
            max_pdp_failures: u32::MAX,
            max_potr_breaches: u32::MAX,
        };
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, record) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), record)
            .expect("register capacity declaration");
        let mut schedule = PricingScheduleRecord::launch_default();
        schedule.credit = CreditPolicy {
            settlement_window_secs: 10,
            settlement_grace_secs: 0,
            low_balance_alert_bps: 1_000,
        };
        let settlement_window_secs = schedule.credit.settlement_window_secs;
        SetPricingSchedule { schedule }
            .execute(&alice(), &mut stx)
            .expect("set pricing schedule");
        let bonded = xor_quantity_nanos(8_000_000_000);
        let credit = ProviderCreditRecord::new(
            provider,
            xor_quantity_nanos(10_000_000_000),
            bonded.clone(),
            Quantity::zero(),
            Quantity::zero(),
            0,
            0,
            Metadata::default(),
        );
        upsert_provider_credit_with_reserve_fixture(&mut stx, &alice(), credit)
            .expect("seed provider credit");
        let penalty_policy = stx.gov.sorafs_penalty;
        let cooldown_secs = penalty_policy.cooldown_window_secs(settlement_window_secs);
        let expected_first_penalty =
            round_xor_quantity_ratio(&bonded, u128::from(penalty_policy.penalty_bond_bps), 10_000)
                .expect("expected first penalty");
        record_capacity_window(
            &mut stx,
            provider,
            0,
            settlement_window_secs,
            100,
            90,
            40,
            7_500,
            7_400,
            0,
        );
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        let ledger_snapshot = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("ledger snapshot");
        assert_eq!(ledger_snapshot.penalty_events, 1);
        assert_eq!(ledger_snapshot.penalty_slashed, expected_first_penalty);
        assert_eq!(credit_snapshot.slashed, expected_first_penalty);
        assert_eq!(
            credit_snapshot.last_penalty_epoch,
            Some(settlement_window_secs)
        );
        let bonded_after_first = bonded
            .checked_sub(&expected_first_penalty)
            .expect("bond covers first penalty");
        record_capacity_window(
            &mut stx,
            provider,
            settlement_window_secs,
            settlement_window_secs * 2,
            100,
            90,
            40,
            7_500,
            7_400,
            0,
        );
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        let ledger_snapshot = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("ledger snapshot");
        assert_eq!(ledger_snapshot.penalty_events, 1);
        assert_eq!(ledger_snapshot.penalty_slashed, expected_first_penalty);
        assert_eq!(credit_snapshot.slashed, expected_first_penalty);
        assert_eq!(
            credit_snapshot.last_penalty_epoch,
            Some(settlement_window_secs)
        );
        assert_eq!(credit_snapshot.under_delivery_strikes, 1);
        record_capacity_window(
            &mut stx,
            provider,
            settlement_window_secs * 2,
            settlement_window_secs * 3,
            100,
            90,
            40,
            7_500,
            7_400,
            0,
        );
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        let ledger_snapshot = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("ledger snapshot");
        let expected_second_penalty = round_xor_quantity_ratio(
            &bonded_after_first,
            u128::from(penalty_policy.penalty_bond_bps),
            10_000,
        )
        .expect("expected second penalty");
        let expected_total_penalty = expected_first_penalty
            .checked_add(&expected_second_penalty)
            .expect("expected cumulative penalty");
        assert!(
            settlement_window_secs
                .checked_add(cooldown_secs)
                .expect("settlement plus cooldown")
                <= settlement_window_secs * 3,
            "third window must fall outside cooldown"
        );
        assert_eq!(ledger_snapshot.penalty_events, 2);
        assert_eq!(ledger_snapshot.penalty_slashed, expected_total_penalty);
        assert_eq!(credit_snapshot.slashed, expected_total_penalty);
        assert_eq!(
            credit_snapshot.last_penalty_epoch,
            Some(settlement_window_secs * 3)
        );
        assert_eq!(
            credit_snapshot.bonded,
            bonded
                .checked_sub(&expected_total_penalty)
                .expect("bond covers cumulative penalty")
        );
        assert_eq!(credit_snapshot.under_delivery_strikes, 0);
    }
    #[test]
    fn record_capacity_telemetry_forces_penalty_on_pdp_failure() {
        let mut state = make_state();
        let proof_health = ProofHealthFixture::all_proofs(3, 5_000, 1);
        proof_health.configure(&mut state);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = proof_health.install(&mut stx, 6_000_000_000);
        let window = SECONDS_PER_BILLING_MONTH;
        record_capacity_window_with_proofs(
            &mut stx,
            provider,
            0,
            window,
            100,
            100,
            80,
            10_000,
            10_000,
            0,
            ProofWindowCounters {
                pdp_challenges: 5,
                pdp_failures: 1,
                ..ProofWindowCounters::default()
            },
        );
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        assert!(
            !credit_snapshot.slashed.is_zero(),
            "PDP failure should slash collateral immediately"
        );
        assert_eq!(credit_snapshot.under_delivery_strikes, 0);
        assert_eq!(credit_snapshot.last_penalty_epoch, Some(window));
        let ledger_snapshot = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("ledger snapshot");
        assert_eq!(ledger_snapshot.penalty_events, 1);
        assert_eq!(ledger_snapshot.penalty_slashed, credit_snapshot.slashed);
    }
    #[test]
    fn record_capacity_telemetry_penalises_pdp_failures_without_challenge_count() {
        let mut state = make_state();
        let proof_health = ProofHealthFixture::all_proofs(3, 5_000, 1);
        proof_health.configure(&mut state);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = proof_health.install(&mut stx, 6_000_000_000);
        let window = SECONDS_PER_BILLING_MONTH;
        record_capacity_window_with_proofs(
            &mut stx,
            provider,
            0,
            window,
            100,
            100,
            80,
            10_000,
            10_000,
            0,
            ProofWindowCounters {
                pdp_challenges: 0,
                pdp_failures: 1,
                ..ProofWindowCounters::default()
            },
        );
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        assert!(
            !credit_snapshot.slashed.is_zero(),
            "PDP failure without challenges should still slash collateral"
        );
        assert_eq!(credit_snapshot.last_penalty_epoch, Some(window));
        let ledger_snapshot = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("ledger snapshot");
        assert_eq!(ledger_snapshot.penalty_events, 1);
        assert_eq!(ledger_snapshot.penalty_slashed, credit_snapshot.slashed);
    }
    #[test]
    fn record_capacity_telemetry_does_not_mutate_capacity_disputes() {
        let mut state = make_state();
        let proof_health = ProofHealthFixture::all_proofs(3, 5_000, 1);
        proof_health.configure(&mut state);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = proof_health.install(&mut stx, 6_000_000_000);
        let window = SECONDS_PER_BILLING_MONTH;
        let proof = ProofWindowCounters {
            pdp_challenges: 5,
            pdp_failures: 2,
            potr_windows: 0,
            potr_breaches: 0,
        };
        record_capacity_window_with_proofs(
            &mut stx, provider, 0, window, 100, 90, 40, 7_500, 7_400, 128, proof,
        );
        assert_eq!(
            stx.world.capacity_disputes.iter().count(),
            0,
            "telemetry must not bypass canonical RegisterCapacityDispute execution"
        );
    }
    #[test]
    fn duplicate_proof_failure_telemetry_remains_dispute_free() {
        let mut state = make_state();
        let proof_health = ProofHealthFixture::all_proofs(3, 5_000, 1);
        proof_health.configure(&mut state);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = proof_health.install(&mut stx, 6_000_000_000);
        let window = SECONDS_PER_BILLING_MONTH;
        let telemetry = CapacityTelemetryRecord::new(
            provider, 0, window, 100, 90, 40, 1, 1, 7_500, 7_400, 128, 5, 1, 0, 0,
        )
        .with_nonce(window);
        RecordCapacityTelemetry { record: telemetry }
            .execute(&alice(), &mut stx)
            .expect("first telemetry submission");
        RecordCapacityTelemetry { record: telemetry }
            .execute(&alice(), &mut stx)
            .expect("duplicate telemetry submission");
        assert_eq!(
            stx.world.capacity_disputes.iter().count(),
            0,
            "duplicate telemetry must not create an independent capacity dispute"
        );
    }
    #[test]
    fn proof_failure_telemetry_replay_is_deterministic() {
        fn run_once() -> (CapacityFeeLedgerEntry, ProviderCreditRecord) {
            let mut state = make_state();
            let proof_health = ProofHealthFixture::all_proofs(3, 5_000, 1);
            proof_health.configure(&mut state);
            let mut block = state.block(block_header());
            let mut stx =
                block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
            let provider = proof_health.install(&mut stx, 6_000_000_000);
            let window = SECONDS_PER_BILLING_MONTH;
            record_capacity_window_with_proofs(
                &mut stx,
                provider,
                0,
                window,
                96,
                96,
                70,
                9_800,
                9_600,
                256,
                ProofWindowCounters {
                    pdp_challenges: 4,
                    pdp_failures: 2,
                    potr_windows: 2,
                    potr_breaches: 1,
                },
            );
            let ledger = stx
                .world
                .capacity_fee_ledger
                .get(&provider)
                .cloned()
                .expect("ledger snapshot");
            let credit_snapshot = stx
                .world
                .provider_credit_ledger
                .get(&provider)
                .cloned()
                .expect("credit snapshot");
            assert_eq!(
                stx.world.capacity_disputes.iter().count(),
                0,
                "telemetry replay must stay outside canonical dispute mutation"
            );
            (ledger, credit_snapshot)
        }
        let (ledger_a, credit_a) = run_once();
        let (ledger_b, credit_b) = run_once();
        assert_eq!(ledger_a, ledger_b, "ledger replay must be deterministic");
        assert_eq!(credit_a, credit_b, "credits must replay identically");
    }
    #[test]
    fn record_capacity_telemetry_emits_proof_health_event() {
        let mut state = make_state();
        let proof_health = ProofHealthFixture::all_proofs(2, 5_000, 0);
        proof_health.configure(&mut state);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = proof_health.install(&mut stx, 5_000_000_000);
        let window = SECONDS_PER_BILLING_MONTH;
        record_capacity_window_with_proofs(
            &mut stx,
            provider,
            0,
            window,
            64,
            64,
            40,
            10_000,
            10_000,
            0,
            ProofWindowCounters {
                pdp_challenges: 4,
                pdp_failures: 2,
                ..ProofWindowCounters::default()
            },
        );
        let event = proof_health_alerts(&stx)
            .into_iter()
            .next()
            .expect("proof health alert should be emitted");
        assert_eq!(event.provider_id, provider);
        assert_eq!(event.window_end_epoch, window);
        assert!(event.triggered_by_pdp);
        assert!(!event.triggered_by_potr);
        assert_eq!(event.pdp_failures, 2);
        assert_eq!(event.max_pdp_failures, 0);
        assert!(!event.cooldown_active);
        assert_eq!(event.prior_strikes, 0);
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        assert_eq!(event.penalty_applied, credit_snapshot.slashed);
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn proof_health_alert_emitted_for_potr_failures() {
        let mut state = make_state();
        let proof_health = ProofHealthFixture::potr(1, 4_000, 0);
        proof_health.configure(&mut state);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = proof_health.install(&mut stx, 3_500_000_000);
        let window = SECONDS_PER_BILLING_MONTH;
        record_capacity_window_with_proofs(
            &mut stx,
            provider,
            0,
            window,
            64,
            64,
            50,
            10_000,
            10_000,
            0,
            ProofWindowCounters {
                potr_windows: 3,
                potr_breaches: 1,
                ..ProofWindowCounters::default()
            },
        );
        let event = proof_health_alerts(&stx)
            .into_iter()
            .next()
            .expect("proof health alert should be emitted");
        assert_eq!(event.provider_id, provider);
        assert!(event.triggered_by_potr);
        assert!(!event.triggered_by_pdp);
        assert_eq!(event.potr_breaches, 1);
        assert_eq!(event.max_potr_breaches, 0);
        assert_eq!(event.prior_strikes, 0);
        assert!(!event.cooldown_active);
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        assert_eq!(event.penalty_applied, credit_snapshot.slashed);
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn proof_health_alert_reports_cooldown_state() {
        let mut state = make_state();
        let proof_health = ProofHealthFixture::pdp(1, 5_000, 2);
        proof_health.configure(&mut state);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = proof_health.install(&mut stx, 4_000_000_000);
        let window = SECONDS_PER_BILLING_MONTH;
        record_capacity_window_with_proofs(
            &mut stx,
            provider,
            0,
            window,
            64,
            64,
            40,
            10_000,
            10_000,
            0,
            ProofWindowCounters {
                pdp_challenges: 2,
                pdp_failures: 1,
                ..ProofWindowCounters::default()
            },
        );
        record_capacity_window_with_proofs(
            &mut stx,
            provider,
            window,
            window * 2,
            64,
            64,
            38,
            10_000,
            10_000,
            0,
            ProofWindowCounters {
                pdp_challenges: 1,
                pdp_failures: 1,
                ..ProofWindowCounters::default()
            },
        );
        let alerts = proof_health_alerts(&stx);
        assert_eq!(alerts.len(), 2);
        let first = &alerts[0];
        let second = &alerts[1];
        assert!(!first.cooldown_active);
        assert!(second.cooldown_active);
        assert!(!first.penalty_applied.is_zero());
        assert_eq!(second.penalty_applied, Quantity::zero());
        assert!(first.window_end_epoch < second.window_end_epoch);
        let credit_snapshot = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("credit snapshot");
        assert_eq!(credit_snapshot.slashed, first.penalty_applied);
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn capacity_fee_ledger_30_day_soak_deterministic() {
        let mut state = make_state();
        state.gov.sorafs_penalty.penalty_bond_bps = 0;
        state.gov.sorafs_penalty.strike_threshold = u32::MAX;
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let mut schedule = PricingScheduleRecord::launch_default();
        schedule.credit = CreditPolicy {
            settlement_window_secs: SECONDS_PER_BILLING_MONTH,
            settlement_grace_secs: 0,
            low_balance_alert_bps: 1_000,
        };
        schedule.collateral = CollateralPolicy {
            multiplier_bps: 30_000,
            onboarding_discount_bps: 5_000,
            onboarding_period_secs: SECONDS_PER_BILLING_MONTH,
        };
        SetPricingSchedule {
            schedule: schedule.clone(),
        }
        .execute(&alice(), &mut stx)
        .expect("set pricing schedule");
        let mut expected_ledgers: std::collections::BTreeMap<ProviderId, CapacityFeeLedgerEntry> =
            std::collections::BTreeMap::new();
        let mut providers = Vec::new();
        for index in 0_u8..5 {
            let provider = ProviderId::new([index.wrapping_add(1); 32]);
            let committed = 256 + u64::from(index) * 32;
            let declaration = CapacityDeclarationV1 {
                version: CAPACITY_DECLARATION_VERSION_V1,
                provider_id: provider.as_bytes().to_owned(),
                stake: StakePointer {
                    pool_id: [index.wrapping_add(40); 32],
                    stake_amount: "1".parse().expect("canonical XOR stake"),
                },
                committed_capacity_gib: committed,
                chunker_commitments: vec![ChunkerCommitmentV1 {
                    profile_id: "sorafs.sf1@1.0.0".to_string(),
                    profile_aliases: None,
                    committed_gib: committed,
                    capability_refs: vec![CapabilityType::ToriiGateway],
                }],
                lane_commitments: Vec::new(),
                pricing: None,
                valid_from: 1_700_000_000,
                valid_until: 1_700_000_000 + (SECONDS_PER_BILLING_MONTH * 64),
                metadata: vec![
                    CapacityMetadataEntry {
                        key: PROVIDER_OWNER_METADATA_KEY.to_owned(),
                        value: account_literal(&alice()),
                    },
                    CapacityMetadataEntry {
                        key: STORAGE_CLASS_METADATA_KEY.to_owned(),
                        value: "hot".to_owned(),
                    },
                ],
            };
            let canonical_bytes =
                norito::to_bytes(&declaration).expect("serialize capacity declaration");
            let record = CapacityDeclarationRecord::new(
                provider,
                canonical_bytes,
                committed,
                5,
                declaration.valid_from,
                declaration.valid_until,
                Metadata::default(),
            );
            register_governed_capacity_declaration(&mut stx, &alice(), record.clone())
                .expect("register capacity declaration");
            let credit = provider_credit_nanos(provider, 1_000_000_000_000_000, 12_000_000_000);
            upsert_provider_credit_with_reserve_fixture(&mut stx, &alice(), credit)
                .expect("seed provider credit");
            expected_ledgers.insert(
                provider,
                CapacityFeeLedgerEntry {
                    provider_id: provider,
                    total_declared_gib: u128::from(committed),
                    last_updated_epoch: record.registered_epoch,
                    ..Default::default()
                },
            );
            providers.push(provider);
        }
        let window = SECONDS_PER_BILLING_MONTH;
        for day in 0_u64..30 {
            let start = day * window;
            let end = (day + 1) * window;
            for (index, provider) in providers.iter().enumerate() {
                let index_u64 = index as u64;
                let declared = 192 + index_u64 * 16;
                let utilised = 120 + ((day + index_u64) % 48);
                let egress_bytes = (index_u64 + 1)
                    .checked_mul((day + 5) * 2_048)
                    .expect("soak egress bytes");
                record_capacity_window(
                    &mut stx,
                    *provider,
                    start,
                    end,
                    declared,
                    declared,
                    utilised,
                    10_000,
                    9_900,
                    egress_bytes,
                );
                let storage_fee = schedule
                    .storage_charge(StorageClass::Hot, utilised, window)
                    .expect("soak storage fee");
                let uptime_bps = u128::from(10_000_u32);
                let por_bps = u128::from(9_900_u32);
                let health_multiplier = uptime_bps
                    .checked_mul(por_bps)
                    .expect("soak health multiplier");
                let storage_fee = round_xor_quantity_ratio(
                    &storage_fee,
                    health_multiplier,
                    10_000_u128 * 10_000_u128,
                )
                .expect("soak health-adjusted storage fee");
                let egress_fee = schedule
                    .egress_charge_bytes(StorageClass::Hot, egress_bytes)
                    .expect("soak egress fee");
                let expected_settlement = schedule
                    .expected_settlement_storage_charge(StorageClass::Hot, utilised)
                    .expect("soak expected settlement storage fee")
                    .checked_add(&egress_fee)
                    .expect("soak expected settlement sum");
                let entry =
                    expected_ledgers
                        .entry(*provider)
                        .or_insert_with(|| CapacityFeeLedgerEntry {
                            provider_id: *provider,
                            ..Default::default()
                        });
                entry
                    .accrue(&CapacityAccrual {
                        declared_delta_gib: u128::from(declared),
                        utilised_delta_gib: u128::from(utilised),
                        storage_fee_delta: storage_fee,
                        egress_fee_delta: egress_fee,
                        expected_settlement,
                        window_start_epoch: start,
                        window_end_epoch: end,
                        nonce: end,
                    })
                    .expect("soak capacity ledger accrual");
            }
        }
        let actual_ledgers: std::collections::BTreeMap<ProviderId, CapacityFeeLedgerEntry> = stx
            .world
            .capacity_fee_ledger
            .iter()
            .map(|(provider, entry)| (*provider, entry.clone()))
            .collect();
        assert_eq!(actual_ledgers.len(), providers.len());
        for provider in providers {
            let expected = expected_ledgers.get(&provider).expect("expected ledger");
            let actual = actual_ledgers.get(&provider).expect("actual ledger");
            assert_eq!(actual.total_declared_gib, expected.total_declared_gib);
            assert_eq!(actual.total_utilised_gib, expected.total_utilised_gib);
            assert_eq!(actual.storage_fee, expected.storage_fee);
            assert_eq!(actual.egress_fee, expected.egress_fee);
            assert_eq!(actual.accrued_fee, expected.accrued_fee);
            assert_eq!(actual.expected_settlement, expected.expected_settlement);
            assert_eq!(actual.penalty_slashed, Quantity::zero());
            assert_eq!(actual.penalty_events, 0);
        }
        let mut hasher = blake3::Hasher::new();
        for (provider, entry) in &actual_ledgers {
            hasher.update(provider.as_bytes());
            hasher.update(&entry.total_declared_gib.to_le_bytes());
            hasher.update(&entry.total_utilised_gib.to_le_bytes());
            hasher.update(&exact_xor_nanos(&entry.storage_fee).to_le_bytes());
            hasher.update(&exact_xor_nanos(&entry.egress_fee).to_le_bytes());
            hasher.update(&exact_xor_nanos(&entry.accrued_fee).to_le_bytes());
            hasher.update(&exact_xor_nanos(&entry.expected_settlement).to_le_bytes());
        }
        let digest = hasher.finalize().to_hex().to_string();
        // Update `expected_digest` when SoraFS capacity accrual semantics or the
        // launch pricing schedule change. Run this test with `-- --nocapture`
        // to print the current digest before refreshing the value below.
        let expected_digest = "71db9e1a17f66920cd4fe6d2bb6a1b008f9cfe1acbb3149d727fa9c80eee80d1";
        println!("capacity_soak_digest={digest}");
        assert_eq!(
            digest, expected_digest,
            "refresh the soak digest if the accrual math or launch pricing schedule changes"
        );
    }
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn record_capacity_telemetry_charges_egress() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, record) = sample_capacity_record();
        register_governed_capacity_declaration(&mut stx, &alice(), record)
            .expect("register capacity declaration");
        let mut schedule = PricingScheduleRecord::launch_default();
        replace_test_tier(
            &mut schedule,
            TierRate::new(
                StorageClass::Hot,
                xor_quantity_nanos(1),
                xor_quantity_nanos(2_000_000),
            ),
        );
        SetPricingSchedule { schedule }
            .execute(&alice(), &mut stx)
            .expect("set pricing schedule");
        let credit = provider_credit_nanos(provider, 5_000_000_000, 0);
        upsert_provider_credit_with_reserve_fixture(&mut stx, &alice(), credit)
            .expect("seed provider credit");
        let telemetry = CapacityTelemetryRecord::new(
            provider,
            0,
            10,
            100,
            100,
            1,
            0,
            0,
            10_000,
            10_000,
            BYTES_PER_GIB,
            0,
            0,
            0,
            0,
        )
        .with_nonce(10);
        RecordCapacityTelemetry { record: telemetry }
            .execute(&alice(), &mut stx)
            .expect("record capacity telemetry with egress");
        let ledger = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("capacity fee ledger stored");
        let pricing = stx.world.sorafs_pricing.get();
        let expected_storage_fee = pricing
            .storage_charge(StorageClass::Hot, 1, telemetry.window_end_epoch)
            .expect("expected storage fee");
        let expected_egress_fee = pricing
            .egress_charge_bytes(StorageClass::Hot, BYTES_PER_GIB)
            .expect("expected egress fee");
        let expected_settlement = pricing
            .expected_settlement_storage_charge(StorageClass::Hot, 1)
            .expect("expected settlement storage fee")
            .checked_add(&expected_egress_fee)
            .expect("expected settlement sum");
        assert_eq!(ledger.storage_fee, expected_storage_fee);
        assert_eq!(ledger.egress_fee, expected_egress_fee);
        assert_eq!(
            ledger.accrued_fee,
            expected_storage_fee
                .checked_add(&expected_egress_fee)
                .expect("bounded expected accrued fee")
        );
        assert_eq!(ledger.expected_settlement, expected_settlement);
        let credit_after = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .expect("provider credit stored");
        let debit = expected_storage_fee
            .checked_add(&expected_egress_fee)
            .expect("expected debit sum");
        assert_eq!(
            credit_after.available_credit,
            xor_quantity_nanos(5_000_000_000)
                .checked_sub(&debit)
                .expect("fixture credit covers debit")
        );
        assert_eq!(credit_after.expected_settlement, expected_settlement);
    }
    #[test]
    fn record_capacity_telemetry_uses_declaration_storage_class() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let mut declaration = sample_capacity_declaration();
        set_capacity_storage_class(&mut declaration, "cold");
        let canonical_bytes = norito::to_bytes(&declaration).expect("serialize declaration");
        let provider = ProviderId::new(declaration.provider_id);
        let record = CapacityDeclarationRecord::new(
            provider,
            canonical_bytes,
            declaration.committed_capacity_gib,
            5,
            declaration.valid_from,
            declaration.valid_until,
            Metadata::default(),
        );
        register_governed_capacity_declaration(&mut stx, &alice(), record)
            .expect("register capacity declaration");
        let key: Name = STORAGE_CLASS_METADATA_KEY
            .parse()
            .expect("metadata key parses");
        let stored = stx
            .world
            .capacity_declarations
            .get(&provider)
            .expect("declaration stored");
        let stored_value = stored
            .metadata
            .get(&key)
            .expect("metadata copied from declaration");
        let stored_str: String = stored_value
            .try_into_any()
            .expect("metadata decodes as string");
        assert_eq!(stored_str, "cold");
        let mut schedule = PricingScheduleRecord::launch_default();
        schedule.default_storage_class = StorageClass::Hot;
        replace_test_tier(
            &mut schedule,
            TierRate::new(
                StorageClass::Hot,
                xor_quantity_nanos(5_000_000),
                xor_quantity_nanos(5_000),
            ),
        );
        replace_test_tier(
            &mut schedule,
            TierRate::new(
                StorageClass::Cold,
                xor_quantity_nanos(1_000_000),
                xor_quantity_nanos(1_000),
            ),
        );
        SetPricingSchedule { schedule }
            .execute(&alice(), &mut stx)
            .expect("set pricing schedule");
        let credit = provider_credit_nanos(provider, 1_000_000_000, 0);
        upsert_provider_credit_with_reserve_fixture(&mut stx, &alice(), credit)
            .expect("seed provider credit");
        let telemetry = CapacityTelemetryRecord::new(
            provider,
            0,
            SECONDS_PER_BILLING_MONTH,
            100,
            100,
            100,
            0,
            0,
            10_000,
            10_000,
            0,
            0,
            0,
            0,
            0,
        )
        .with_nonce(SECONDS_PER_BILLING_MONTH);
        RecordCapacityTelemetry { record: telemetry }
            .execute(&alice(), &mut stx)
            .expect("record capacity telemetry");
        let ledger = stx
            .world
            .capacity_fee_ledger
            .get(&provider)
            .expect("capacity fee ledger stored");
        assert_eq!(ledger.storage_fee, xor_quantity_nanos(100_000_000));
    }
    #[test]
    fn stored_capacity_declaration_rejects_metadata_conflict() {
        let (_, mut record) = capacity_record_with_owner(&alice());
        record.metadata.insert(
            STORAGE_CLASS_METADATA_KEY.parse::<Name>().unwrap(),
            Json::new("cold"),
        );
        let error = validate_stored_capacity_declaration(&record, "conflicting metadata")
            .expect_err("stored metadata must exactly reflect its canonical payload");
        assert!(
            matches!(error, InstructionExecutionError::InvariantViolation(message)
            if message.contains("metadata conflict"))
        );
    }
    #[test]
    fn stored_capacity_metadata_failure_retains_exact_inner_parameter_reason() {
        let (provider, original) = capacity_record_with_owner(&alice());
        let declaration = validate_stored_capacity_declaration(&original, "original metadata")
            .expect("unmodified canonical record must pass stored validation");
        assert_eq!(declaration.provider_id, *provider.as_bytes());
        for (key, value, payload_value) in [
            (
                STORAGE_CLASS_METADATA_KEY,
                "cold".to_owned(),
                "hot".to_owned(),
            ),
            (
                PROVIDER_OWNER_METADATA_KEY,
                account_literal(&bob()),
                account_literal(&alice()),
            ),
        ] {
            let mut record = original.clone();
            record
                .metadata
                .insert(key.parse::<Name>().unwrap(), Json::new(value.clone()));
            assert_eq!(record.declaration, original.declaration);
            let expected = format!(
                "capacity declaration metadata conflict for provider {} on key `{key}`: record value `{value}`, payload value `{payload_value}`",
                hex::encode(provider.as_bytes()),
            );
            let mut retained_metadata = record.metadata.clone();
            let error = merge_declaration_metadata_into_record(
                provider,
                &mut retained_metadata,
                &declaration.metadata,
            )
            .expect_err("exact payload/record mismatch must retain its typed parameter reason");
            assert_eq!(
                error,
                InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                    expected.clone()
                )),
            );
            assert_eq!(
                validate_stored_capacity_declaration(&record, "conflicting metadata"),
                Err(InstructionExecutionError::InvariantViolation(
                    format!("capacity declaration conflicting metadata is invalid: Invalid smart contract: {expected}").into()
                )),
            );
        }
    }
    #[test]
    fn capacity_declaration_rejects_metadata_whitespace_without_normalization() {
        for case in ["payload_storage", "record_storage", "payload_owner"] {
            let state = make_state();
            let mut block = state.block(block_header());
            let mut stx =
                block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
            let (provider, mut record) = capacity_record_with_owner(&alice());
            seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::from(1_u32));
            let mut declaration =
                decode_capacity_declaration_payload(&record.declaration).expect("decode fixture");
            let metadata_key = match case {
                "payload_owner" => PROVIDER_OWNER_METADATA_KEY,
                "payload_storage" | "record_storage" => STORAGE_CLASS_METADATA_KEY,
                _ => unreachable!("closed fixture cases"),
            };
            let payload_entry = declaration
                .metadata
                .iter_mut()
                .find(|entry| entry.key == metadata_key)
                .expect("fixture metadata entry");
            if case != "record_storage" {
                payload_entry.value.insert(0, ' ');
            }
            record.declaration =
                norito::encode_canonical(&declaration).expect("encode adversarial declaration");
            if case != "payload_storage" {
                let key: Name = metadata_key.parse().expect("static metadata key");
                let retained = if case == "payload_owner" {
                    format!(" {}", alice())
                } else {
                    " hot".to_owned()
                };
                record.metadata.insert(key, Json::new(retained));
            }

            if case == "record_storage" {
                validate_stored_capacity_declaration(&record, case)
                    .expect_err("stored metadata whitespace must never be normalized");
            } else {
                RegisterCapacityDeclaration::new(record.declaration)
                    .execute(&alice(), &mut stx)
                    .expect_err("payload metadata whitespace must never be normalized");
            }
            assert!(
                stx.world.capacity_declarations.get(&provider).is_none(),
                "rejected {case} metadata must not mutate capacity state"
            );
        }
    }
    include!("sorafs/storage_class_default_test.rs");
    #[test]
    fn register_capacity_declaration_requires_explicit_storage_class() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, mut record) = capacity_record_with_owner(&alice());
        let mut declaration =
            decode_capacity_declaration_payload(&record.declaration).expect("decode declaration");
        declaration
            .metadata
            .retain(|entry| entry.key != STORAGE_CLASS_METADATA_KEY);
        record.declaration =
            norito::encode_canonical(&declaration).expect("encode declaration without class");
        let error = RegisterCapacityDeclaration {
            declaration: record.declaration,
        }
        .execute(&alice(), &mut stx)
        .expect_err("record-only storage class must reject registration");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("must explicitly declare")
        ));
        assert!(stx.world.capacity_declarations.get(&provider).is_none());
    }
    #[test]
    fn register_capacity_declaration_requires_owner_in_canonical_payload() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, mut record) = capacity_record_with_owner(&alice());
        let mut declaration =
            decode_capacity_declaration_payload(&record.declaration).expect("decode declaration");
        declaration
            .metadata
            .retain(|entry| entry.key != PROVIDER_OWNER_METADATA_KEY);
        record.declaration =
            norito::encode_canonical(&declaration).expect("encode declaration without owner");
        let error = RegisterCapacityDeclaration {
            declaration: record.declaration,
        }
        .execute(&alice(), &mut stx)
        .expect_err("record-only owner must reject registration");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains(PROVIDER_OWNER_METADATA_KEY)
                && message.contains("canonical payload")
        ));
        assert!(stx.world.capacity_declarations.get(&provider).is_none());
    }
    #[test]
    fn storage_class_metadata_rejects_noncanonical_case_and_whitespace() {
        let provider = ProviderId::new([0x22; 32]);
        let key: Name = STORAGE_CLASS_METADATA_KEY
            .parse()
            .expect("metadata key must parse");
        for value in ["CoLd", " cold", "cold "] {
            let mut metadata = Metadata::default();
            let _ = metadata.insert(key.clone(), Json::new(value));
            super::storage_class_from_declaration_metadata(provider, &metadata)
                .expect_err("storage class must use the exact lowercase spelling");
        }
    }
    #[test]
    fn storage_class_metadata_rejects_invalid_value() {
        let provider = ProviderId::new([0x33; 32]);
        let mut metadata = Metadata::default();
        let key = STORAGE_CLASS_METADATA_KEY
            .parse()
            .expect("metadata key must parse");
        let _ = metadata.insert(key, Json::new("glacier"));
        let err = super::storage_class_from_declaration_metadata(provider, &metadata)
            .expect_err("invalid value must error");
        match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => {
                assert!(
                    message.contains("exactly one of lowercase hot, warm, or cold"),
                    "unexpected error: {message}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
    #[test]
    fn storage_class_from_declaration_record_rejects_unmerged_payload_metadata() {
        let mut declaration = sample_capacity_declaration();
        set_capacity_storage_class(&mut declaration, "cold");
        let canonical_bytes = norito::to_bytes(&declaration).expect("serialize declaration");
        let provider = ProviderId::new(declaration.provider_id);
        let record = CapacityDeclarationRecord::new(
            provider,
            canonical_bytes,
            declaration.committed_capacity_gib,
            5,
            declaration.valid_from,
            declaration.valid_until,
            Metadata::default(),
        );
        super::storage_class_from_declaration_record(&record)
            .expect_err("stored record must explicitly retain payload metadata");
    }
    #[test]
    fn upsert_provider_credit_requires_registered_provider() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let record = provider_credit_nanos(ProviderId::new([0x55; 32]), 1_000, 0);
        let err = UpsertProviderCredit {
            expected_current: None,
            record,
        }
        .execute(&alice(), &mut stx)
        .expect_err("provider must exist before credit entry");
        let message = match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(
            message.contains("has no governance-established owner"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn upsert_provider_credit_cannot_mint_bonded_stake() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        seed_governed_capacity_provider(
            &mut stx,
            ProviderId::new([0xE8; 32]),
            &alice(),
            Quantity::from(1_u32),
        );
        let provider = ProviderId::new([0x56; 32]);
        seed_provider_owners(&mut stx, &[provider], &alice());
        let record = ProviderCreditRecord::new(
            provider,
            Quantity::zero(),
            Quantity::from(1_u32),
            Quantity::zero(),
            Quantity::zero(),
            0,
            0,
            Metadata::default(),
        );
        let error = UpsertProviderCredit {
            expected_current: None,
            record,
        }
        .execute(&alice(), &mut stx)
        .expect_err("an administrator-authored number cannot create bonded stake");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("no owner-funded reserve account")
        ));
        assert!(stx.world.provider_credit_ledger.get(&provider).is_none());
    }
    #[test]
    fn upsert_provider_credit_cannot_diverge_from_native_reserve() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = ProviderId::new([0x57; 32]);
        seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::from(1_u32));
        let forged = ProviderCreditRecord::new(
            provider,
            Quantity::zero(),
            Quantity::from(2_u32),
            Quantity::zero(),
            Quantity::zero(),
            0,
            0,
            Metadata::default(),
        );
        let error = UpsertProviderCredit {
            expected_current: stx
                .world
                .provider_credit_ledger
                .get(&provider)
                .map(iroha_crypto::HashOf::new),
            record: forged,
        }
        .execute(&alice(), &mut stx)
        .expect_err("credit projection cannot exceed native reserve custody");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("must equal its owner-funded native reserve")
        ));
        assert_eq!(
            stx.world
                .provider_credit_ledger
                .get(&provider)
                .expect("original projection remains")
                .bonded,
            Quantity::from(1_u32)
        );
    }
    #[test]
    fn upsert_provider_credit_cannot_release_a_custody_backed_slash_lien() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = ProviderId::new([0x58; 32]);
        seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::from(2_u32));
        let mut penalized = stx
            .world
            .provider_credit_ledger
            .get(&provider)
            .cloned()
            .expect("credit fixture");
        penalized
            .apply_penalty(&Quantity::from(1_u32), 1)
            .expect("apply custody-backed slash lien");
        stx.world
            .provider_credit_ledger
            .insert(provider, penalized.clone());
        let reset = ProviderCreditRecord::new(
            provider,
            Quantity::zero(),
            Quantity::from(2_u32),
            Quantity::zero(),
            Quantity::zero(),
            0,
            0,
            Metadata::default(),
        );
        let error = UpsertProviderCredit {
            expected_current: stx
                .world
                .provider_credit_ledger
                .get(&provider)
                .map(iroha_crypto::HashOf::new),
            record: reset,
        }
        .execute(&alice(), &mut stx)
        .expect_err("credit upsert must not erase a native-custody slash lien");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("cannot reset its custody-backed slash lien")
        ));
        assert_eq!(
            stx.world.provider_credit_ledger.get(&provider),
            Some(&penalized)
        );
    }
    #[test]
    fn stored_capacity_declaration_rejects_provider_mismatch() {
        let (_, mut record) = capacity_record_with_owner(&alice());
        record.provider_id = ProviderId::new([0x33; 32]);
        let error = validate_stored_capacity_declaration(&record, "corrupt summary")
            .expect_err("stored projection must match canonical payload");
        assert!(
            matches!(error, InstructionExecutionError::InvariantViolation(message)
            if message.contains("payload provider does not match"))
        );
    }
    #[test]
    fn stored_capacity_declaration_rejects_committed_capacity_mismatch() {
        let (_, mut record) = capacity_record_with_owner(&alice());
        record.committed_capacity_gib += 1;
        let error = validate_stored_capacity_declaration(&record, "corrupt summary")
            .expect_err("stored projection must match canonical payload");
        assert!(
            matches!(error, InstructionExecutionError::InvariantViolation(message)
            if message.contains("payload capacity does not match"))
        );
    }
    #[test]
    fn register_capacity_declaration_rejects_noncanonical_and_resource_bomb_payloads() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let (provider, base_record) = sample_capacity_record();
        let alternate = {
            let _guard = norito::core::DecodeFlagsGuard::enter(0);
            norito::to_bytes(&sample_capacity_declaration())
                .expect("encode alternate-layout capacity declaration")
        };
        assert_ne!(alternate, base_record.declaration);
        let mut allocation_bomb = sample_capacity_declaration();
        allocation_bomb.metadata.push(CapacityMetadataEntry {
            key: "bomb".to_owned(),
            value: "x".repeat(sorafs_manifest::capacity::MAX_CAPACITY_METADATA_VALUE_BYTES + 1),
        });
        let allocation_bomb = norito::to_bytes(&allocation_bomb)
            .expect("encode capacity declaration allocation bomb");
        assert!(allocation_bomb.len() <= MAX_CAPACITY_DECLARATION_PAYLOAD_BYTES);
        for (payload, expected) in [
            (Vec::new(), "invalid capacity declaration payload"),
            (vec![0xFF], "invalid capacity declaration payload"),
            (
                vec![0xA5; MAX_CAPACITY_DECLARATION_PAYLOAD_BYTES + 1],
                "invalid capacity declaration payload",
            ),
            (alternate, "invalid capacity declaration payload"),
            (allocation_bomb, "capacity declaration validation failed"),
        ] {
            let mut record = base_record.clone();
            record.declaration = payload;
            let err = RegisterCapacityDeclaration {
                declaration: record.declaration,
            }
            .execute(&alice(), &mut stx)
            .expect_err("invalid capacity declaration payload must be rejected");
            let message = match err {
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(message),
                ) => message,
                other => panic!("unexpected error: {other:?}"),
            };
            assert!(
                message.contains(expected),
                "unexpected error message: {message}"
            );
            assert!(stx.world.capacity_declarations.get(&provider).is_none());
            assert!(stx.world.provider_owners.get(&provider).is_none());
        }
    }
    #[test]
    fn direct_provider_owner_instructions_are_retired_even_for_permission_holder() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = ProviderId::new([0xA1; 32]);
        let register_error = RegisterProviderOwner {
            provider_id: provider,
            owner: bob(),
        }
        .execute(&alice(), &mut stx)
        .expect_err("direct registration must be retired");
        assert!(matches!(
            register_error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("direct SoraFS provider-owner registration is retired")
        ));
        stx.world.provider_owners.insert(provider, alice());
        let unregister_error = UnregisterProviderOwner {
            provider_id: provider,
        }
        .execute(&alice(), &mut stx)
        .expect_err("direct removal must be retired");
        assert!(matches!(
            unregister_error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("direct SoraFS provider-owner removal is retired")
        ));
        assert_eq!(stx.world.provider_owners.get(&provider), Some(&alice()));
    }
    #[test]
    fn governed_provider_owner_actions_enforce_compare_and_set() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = ProviderId::new([0xA2; 32]);
        assert!(
            apply_governed_provider_owner_action(
                SorafsProviderGovernanceActionV1::Establish(EstablishSorafsProviderOwnerV1 {
                    provider_id: provider,
                    owner: alice(),
                },),
                &mut stx,
            )
            .expect("establish owner")
        );
        assert!(
            !apply_governed_provider_owner_action(
                SorafsProviderGovernanceActionV1::Rebind(RebindSorafsProviderOwnerV1 {
                    provider_id: provider,
                    expected_owner: bob(),
                    next_owner: alice(),
                }),
                &mut stx,
            )
            .expect("stale rebind is superseded")
        );
        assert_eq!(stx.world.provider_owners.get(&provider), Some(&alice()));
        assert!(
            apply_governed_provider_owner_action(
                SorafsProviderGovernanceActionV1::Rebind(RebindSorafsProviderOwnerV1 {
                    provider_id: provider,
                    expected_owner: alice(),
                    next_owner: bob(),
                }),
                &mut stx,
            )
            .expect("exact rebind")
        );
        assert_eq!(stx.world.provider_owners.get(&provider), Some(&bob()));
        assert!(
            !apply_governed_provider_owner_action(
                SorafsProviderGovernanceActionV1::Remove(RemoveSorafsProviderOwnerV1 {
                    provider_id: provider,
                    expected_owner: alice(),
                }),
                &mut stx,
            )
            .expect("stale removal is superseded")
        );
        assert_eq!(stx.world.provider_owners.get(&provider), Some(&bob()));
        assert!(
            apply_governed_provider_owner_action(
                SorafsProviderGovernanceActionV1::Remove(RemoveSorafsProviderOwnerV1 {
                    provider_id: provider,
                    expected_owner: bob(),
                }),
                &mut stx,
            )
            .expect("exact removal")
        );
        assert!(stx.world.provider_owners.get(&provider).is_none());
    }
    #[test]
    fn pending_replication_blocks_authority_revocation_and_owner_change_atomically() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let providers = seed_eligible_auto_replication_providers_for_test(
            &mut stx,
            &alice(),
            1,
            StorageClass::Hot,
            &default_chunker(),
            5,
            u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1),
            1,
        )
        .expect("seed eligible provider");
        let provider = providers[0];
        let mut manifest = manifest_fixture(0xAA);
        manifest.pin_policy.min_replicas = 1;
        RegisterPinManifest {
            manifest_payload: manifest.encode().expect("encode manifest"),
            alias: None,
            successor_of: None,
        }
        .execute(&alice(), &mut stx)
        .expect("register manifest and automatic order");
        let completion_authority = stx
            .world
            .provider_ingest_completion_authorities
            .get(&provider)
            .cloned()
            .expect("completion authority retained");

        let error =
            RevokeProviderIngestCompletionAuthority::new(provider, completion_authority.clone())
                .execute(&alice(), &mut stx)
                .expect_err("pending assignment must prevent authority revocation");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("still required by pending replication order")
        ));
        assert_eq!(
            stx.world
                .provider_ingest_completion_authorities
                .get(&provider),
            Some(&completion_authority)
        );

        let error = apply_governed_provider_owner_action(
            SorafsProviderGovernanceActionV1::Rebind(RebindSorafsProviderOwnerV1 {
                provider_id: provider,
                expected_owner: alice(),
                next_owner: bob(),
            }),
            &mut stx,
        )
        .expect_err("pending assignment must prevent owner rebinding");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("still required by pending replication order")
        ));
        assert_eq!(stx.world.provider_owners.get(&provider), Some(&alice()));
    }
    #[test]
    fn provider_ingest_completion_authority_requires_exact_predecessor_chain() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = ProviderId::new([0xA6; 32]);
        stx.world.provider_owners.insert(provider, alice());
        let revision_one = completion_authority(&alice(), 1);
        let error = SetProviderIngestCompletionAuthority::new(provider, None, revision_one.clone())
            .execute(&bob(), &mut stx)
            .expect_err(
                "a transferable proposal token must not rotate another owner's signer policy",
            );
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("exact governed provider owner")
        ));
        let error = SetProviderIngestCompletionAuthority::new(
            provider,
            None,
            completion_authority(&alice(), 2),
        )
        .execute(&alice(), &mut stx)
        .expect_err("initial policy must begin at revision one");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("must begin at revision 1")
        ));
        SetProviderIngestCompletionAuthority::new(provider, None, revision_one.clone())
            .execute(&alice(), &mut stx)
            .expect("install initial completion authority");
        SetProviderIngestCompletionAuthority::new(provider, None, revision_one.clone())
            .execute(&alice(), &mut stx)
            .expect("exact initial authority replay is idempotent");
        SetProviderIngestCompletionAuthority::new(
            provider,
            Some(revision_one.clone()),
            revision_one.clone(),
        )
        .execute(&alice(), &mut stx)
        .expect("exact policy replay is idempotent");
        let mut wrong_predecessor = completion_authority(&alice(), 2);
        wrong_predecessor.signer_policy.predecessor_digest = Some([0xEE; 32]);
        let error = SetProviderIngestCompletionAuthority::new(
            provider,
            Some(revision_one.clone()),
            wrong_predecessor,
        )
        .execute(&alice(), &mut stx)
        .expect_err("substituted predecessor digest must fail");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("predecessor-bound")
        ));
        assert_eq!(
            stx.world
                .provider_ingest_completion_authorities
                .get(&provider),
            Some(&revision_one)
        );
        let revision_two = completion_authority(&alice(), 2);
        SetProviderIngestCompletionAuthority::new(
            provider,
            Some(revision_one),
            revision_two.clone(),
        )
        .execute(&alice(), &mut stx)
        .expect("install exact predecessor-bound successor");
        assert_eq!(
            stx.world
                .provider_ingest_completion_authorities
                .get(&provider),
            Some(&revision_two)
        );
        let mut malformed_replacement = completion_authority(&alice(), 2);
        malformed_replacement.signer_policy.policy_id = [0xB1; 32];
        let error = SetProviderIngestCompletionAuthority::new(
            provider,
            Some(revision_two.clone()),
            malformed_replacement,
        )
        .execute(&alice(), &mut stx)
        .expect_err("replacement policy identity must restart at revision one");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("replacement") && message.contains("revision 1")
        ));
        let replacement = ProviderIngestCompletionAuthorityV1::new(
            alice().clone(),
            alice(),
            ProviderIngestCompletionSignerPolicyV1 {
                policy_id: [0xB1; 32],
                revision: 1,
                predecessor_digest: None,
                policy_digest: [0xB2; 32],
            },
        );
        SetProviderIngestCompletionAuthority::new(
            provider,
            Some(revision_two),
            replacement.clone(),
        )
        .execute(&alice(), &mut stx)
        .expect("canonical replacement policy identity starts at revision one");
        assert_eq!(
            stx.world
                .provider_ingest_completion_authorities
                .get(&provider),
            Some(&replacement)
        );
        let error = RevokeProviderIngestCompletionAuthority::new(provider, replacement.clone())
            .execute(&bob(), &mut stx)
            .expect_err("a non-owner must not revoke the governed owner's signer policy");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("exact governed provider owner")
        ));
        RevokeProviderIngestCompletionAuthority::new(provider, replacement)
            .execute(&alice(), &mut stx)
            .expect("the exact governed owner may revoke its signer policy");
        assert!(
            stx.world
                .provider_ingest_completion_authorities
                .get(&provider)
                .is_none()
        );
    }
    #[test]
    fn sorafs_provider_owner_query_resolves_binding() {
        use crate::smartcontracts::ValidSingularQuery;
        let mut state = make_state();
        let provider = ProviderId::new([0xA4; 32]);
        state.world.provider_owners.insert(provider, alice());
        let query = iroha_data_model::query::sorafs::prelude::FindSorafsProviderOwner {
            provider_id: provider,
        };
        let result = query.execute(&state.view()).expect("query resolves owner");
        assert_eq!(result, alice());
    }
    #[test]
    fn pin_manifest_query_is_finalized_cursor_bound_and_authoritative() {
        use crate::smartcontracts::ValidSingularQuery;
        let mut state = make_state();
        let digest = default_digest();
        let record = PinManifestRecord::new(
            digest,
            default_root_cid(),
            default_chunker(),
            default_chunk_digest(),
            por_root_for_manifest(digest),
            default_content_length(),
            default_policy(),
            alice(),
            5,
            None,
            None,
            Metadata::default(),
        );
        state.world.pin_manifests.insert(digest, record.clone());
        state.world.smart_contract_state.insert(
            pin_global_usage_key().clone(),
            encode_pin_accounting_state(
                &PinResourceUsage {
                    manifest_count: 1,
                    content_bytes: record.content_length,
                },
                "query fixture global usage",
            )
            .expect("encode query fixture usage"),
        );
        state
            .world
            .smart_contract_state
            .insert(pin_status_index_key(&record.status, &digest), Vec::new());
        let header = block_header();
        let block_hash = iroha_crypto::HashOf::new(&header);
        let block_hash_bytes = *block_hash.as_ref();
        state.push_block_hash_for_testing(block_hash);
        let result = FindSorafsPinManifest::new(digest, None)
            .execute(&state.view())
            .expect("finalized pin-manifest query");
        assert_eq!(result.manifest, record);
        assert_eq!(result.finalized_cursor.height, 1);
        assert_eq!(result.finalized_cursor.block_hash, block_hash_bytes);
        let page = FindSorafsPinManifests::new(
            None,
            Some(PinStatusKindV1::Pending),
            None,
            1,
            PIN_MANIFEST_QUERY_MIN_PAGE_BYTES_V1,
        )
        .execute(&state.view())
        .expect("bounded finalized pin-manifest page");
        assert_eq!(page.finalized_cursor, result.finalized_cursor);
        assert_eq!(page.charged_usage.manifest_count, 1);
        assert_eq!(page.manifests, vec![PinManifestSummaryV1::from(&record)]);
        assert!(!page.has_more);
        assert_eq!(page.next_after_digest, None);
        let exhausted = FindSorafsPinManifests::new(
            Some(result.finalized_cursor),
            Some(PinStatusKindV1::Pending),
            Some(digest),
            1,
            PIN_MANIFEST_QUERY_MIN_PAGE_BYTES_V1,
        )
        .execute(&state.view())
        .expect("exclusive cursor exhausts the one-record page");
        assert!(exhausted.manifests.is_empty());
        assert!(!exhausted.has_more);
        let outdated = PinManifestFinalizedCursorV1 {
            height: 1,
            block_hash: [0xED; 32],
        };
        assert_eq!(
            FindSorafsPinManifest::new(digest, Some(outdated)).execute(&state.view()),
            Err(QueryExecutionFail::Expired)
        );
        assert_eq!(
            FindSorafsPinManifests::new(
                Some(outdated),
                None,
                None,
                1,
                PIN_MANIFEST_QUERY_MIN_PAGE_BYTES_V1,
            )
            .execute(&state.view()),
            Err(QueryExecutionFail::Expired)
        );
        assert_eq!(
            FindSorafsPinManifest::new(ManifestDigest::new([0xEF; 32]), None)
                .execute(&state.view()),
            Err(QueryExecutionFail::Find(FindError::SorafsPinManifest(
                ManifestDigest::new([0xEF; 32])
            )))
        );
    }
    #[test]
    fn pin_manifest_page_enforces_byte_ceiling_and_authenticated_status_index() {
        use crate::smartcontracts::ValidSingularQuery;
        const RECORD_COUNT: u64 = 24;
        let mut state = make_state();
        let mut first_digest = None;
        for ordinal in 1..=RECORD_COUNT {
            let seed = u8::try_from(ordinal).expect("small ordinal");
            let digest = manifest_digest_for_seed(seed);
            first_digest =
                Some(first_digest.map_or(digest, |first: ManifestDigest| first.min(digest)));
            let record = PinManifestRecord::new(
                digest,
                root_cid_for_manifest(digest),
                default_chunker(),
                chunk_digest_for_seed(seed),
                por_root_for_manifest(digest),
                default_content_length(),
                default_policy(),
                alice(),
                5,
                None,
                None,
                Metadata::default(),
            );
            state.world.pin_manifests.insert(digest, record.clone());
            state
                .world
                .smart_contract_state
                .insert(pin_status_index_key(&record.status, &digest), Vec::new());
        }
        state.world.smart_contract_state.insert(
            pin_global_usage_key().clone(),
            encode_pin_accounting_state(
                &PinResourceUsage {
                    manifest_count: RECORD_COUNT,
                    content_bytes: default_content_length()
                        .checked_mul(RECORD_COUNT)
                        .expect("fixture usage fits u64"),
                },
                "byte-ceiling query fixture global usage",
            )
            .expect("encode byte-ceiling query fixture usage"),
        );
        let block_hash = block_header().hash();
        state.push_block_hash_for_testing(block_hash);
        let page = FindSorafsPinManifests::new(
            None,
            Some(PinStatusKindV1::Pending),
            None,
            u32::try_from(RECORD_COUNT).expect("fixture count fits u32"),
            PIN_MANIFEST_QUERY_MIN_PAGE_BYTES_V1,
        )
        .execute(&state.view())
        .expect("byte-bounded finalized page");
        assert!(
            page.has_more,
            "the minimum byte ceiling must truncate this fixture"
        );
        assert!(
            !page.manifests.is_empty(),
            "the minimum byte ceiling fits one row"
        );
        assert!(
            page.manifests.len() < usize::try_from(RECORD_COUNT).expect("fixture count fits usize")
        );
        assert_eq!(
            page.next_after_digest,
            page.manifests.last().map(|entry| entry.digest)
        );
        assert!(
            norito::encode_canonical(&page)
                .expect("encode byte-bounded page")
                .len()
                <= usize::try_from(PIN_MANIFEST_QUERY_MIN_PAGE_BYTES_V1)
                    .expect("page byte limit fits usize")
        );
        let cursor = page
            .next_after_digest
            .expect("truncated page carries an exclusive cursor");
        let next_page = FindSorafsPinManifests::new(
            Some(page.finalized_cursor),
            Some(PinStatusKindV1::Pending),
            Some(cursor),
            u32::try_from(RECORD_COUNT).expect("fixture count fits u32"),
            PIN_MANIFEST_QUERY_MAX_PAGE_BYTES_V1,
        )
        .execute(&state.view())
        .expect("exclusive cursor continues from the next digest");
        assert!(
            next_page
                .manifests
                .first()
                .is_some_and(|entry| entry.digest > cursor)
        );
        let first_digest = first_digest.expect("fixture contains records");
        state.world.smart_contract_state.insert(
            pin_status_index_key(&PinStatus::Pending, &first_digest),
            vec![1],
        );
        assert!(matches!(
            FindSorafsPinManifests::new(
                None,
                Some(PinStatusKindV1::Pending),
                None,
                1,
                PIN_MANIFEST_QUERY_MIN_PAGE_BYTES_V1,
            )
            .execute(&state.view()),
            Err(QueryExecutionFail::Conversion(message))
                if message.contains("status-index marker is not empty")
        ));
    }
    #[test]
    fn repair_report_payload_boundary_is_shared_and_rejection_is_atomic() {
        let mut state = make_state();
        let provider = ProviderId::new([0xC7; 32]);
        let authority = alice();
        let source_identity = [0xC8; 32];
        grant_repair_operator(&mut state, &authority, provider);
        let report = repair_report(
            "REP-PAYLOAD-BOUNDARY",
            provider,
            [0xC9; 32],
            &authority,
            2_000,
        );
        let (largest_accepted, first_rejected) = repair_report_payloads_at_ledger_boundary(&report);
        decode_repair_payload::<RepairReportV1>(&largest_accepted, "repair report")
            .expect("largest in-bound canonical report passes the native decoder");
        let decode_error =
            decode_repair_payload::<RepairReportV1>(&first_rejected, "repair report")
                .expect_err("first out-of-bound canonical report fails the native decoder");
        let decode_message = smart_contract_error_message(&decode_error);
        assert!(
            decode_message.contains("payload length"),
            "unexpected boundary decode error: {decode_error:?}"
        );
        let error = transact_repair(&mut state, 1, 2_000_000, |transaction| {
            SubmitSorafsRepairTask::new(source_identity, first_rejected.clone())
                .execute(&authority, transaction)
        })
        .expect_err("oversized canonical report must not mutate repair state");
        let error_message = smart_contract_error_message(&error);
        assert!(
            error_message.contains("payload length"),
            "unexpected oversized report error: {error:?}"
        );
        {
            let view = state.view();
            let world = view.world();
            assert!(
                read_repair_status(world)
                    .expect("read repair status")
                    .is_none()
            );
            assert!(
                read_repair_source_binding(world, source_identity)
                    .expect("read repair source binding")
                    .is_none()
            );
            assert!(
                read_repair_task(world, &report.ticket_id.0)
                    .expect("read repair task")
                    .is_none()
            );
            assert!(
                read_repair_event_journal_head(world)
                    .expect("read repair event journal")
                    .is_none()
            );
        }
        transact_repair(&mut state, 1, 2_000_000, |transaction| {
            SubmitSorafsRepairTask::new(source_identity, largest_accepted.clone())
                .execute(&authority, transaction)
        })
        .expect("largest in-bound canonical report commits");
        let view = state.view();
        let world = view.world();
        let status = read_repair_status(world)
            .expect("read committed repair status")
            .expect("repair status exists");
        assert_eq!(status.tasks, 1);
        let task = read_repair_task(world, &report.ticket_id.0)
            .expect("read committed repair task")
            .expect("repair task exists");
        assert_eq!(task.canonical_report, largest_accepted);
        assert_eq!(
            read_repair_source_binding(world, source_identity)
                .expect("read committed source binding")
                .expect("source binding exists")
                .task_id,
            task.task_id
        );
        assert_eq!(
            read_repair_event_journal_head(world)
                .expect("read committed repair journal")
                .expect("repair journal exists")
                .last_sequence,
            1
        );
    }
    #[test]
    fn repair_durable_frames_preserve_source_and_journal_bindings() {
        fn check<T>(
            world: &impl crate::state::WorldReadOnly,
            key: &StatePath,
            name: &str,
            decode: impl Fn(&[u8]) -> Result<T, InstructionExecutionError>,
        ) where
            T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
        {
            let bytes = world
                .smart_contract_state()
                .get(key)
                .expect("persisted owner frame");
            assert_eq!(T::nominal_name(), name);
            assert_eq!(T::frame_name(), name);
            let view = norito::core::from_bytes_view(bytes).expect("valid persisted envelope");
            assert_eq!(view.schema(), norito::schema::identity::frame_hash::<T>());
            let decoded = decode(bytes).expect("bounded production state decoder");
            assert_eq!(
                norito::encode_canonical(&decoded).expect("re-encode all fields"),
                *bytes
            );
            let mut substituted = bytes.clone();
            substituted[6..22]
                .copy_from_slice(&norito::schema::identity::frame_hash::<iroha_crypto::Hash>());
            assert!(matches!(
                norito::decode_canonical::<T>(&substituted),
                Err(norito::Error::SchemaMismatch)
            ));
            assert!(decode(&substituted).is_err());
            assert!(decode(&bytes[..bytes.len() - 1]).is_err());
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(decode(&trailing).is_err());
        }
        let mut state = make_state();
        let authority = alice();
        let provider = ProviderId::new([0xD1; 32]);
        grant_repair_operator(&mut state, &authority, provider);
        let report = repair_report("REP-FRAME-1", provider, [0xD2; 32], &authority, 2_000);
        let source_identity = [0xD3; 32];
        transact_repair(&mut state, 1, 2_000_000, |transaction| {
            SubmitSorafsRepairTask::new(source_identity, to_bytes(&report).expect("report frame"))
                .execute(&authority, transaction)
        })
        .expect("commit repair submission");
        let view = state.view();
        let world = view.world();
        let source = read_repair_source_binding(world, source_identity)
            .expect("validated source binding")
            .expect("source exists");
        assert_eq!(source.ticket_id, report.ticket_id.0);
        let head = read_repair_event_journal_head(world)
            .expect("journal head agrees with event")
            .expect("head exists");
        assert_eq!(head.last_sequence, 1);
        let event = read_repair_persisted_event(world, head.last_sequence)
            .expect("validated event")
            .expect("event exists");
        validate_repair_event_task_binding(world, &event).expect("event matches stored task");
        check::<RepairSourceBindingV1>(
            world,
            &repair_source_key(source_identity),
            "iroha_core::smartcontracts::isi::sorafs::RepairSourceBindingV1",
            |bytes| decode_repair_state(bytes, "test repair source binding"),
        );
        check::<RepairPersistedEventV1>(
            world,
            &repair_event_key(head.last_sequence),
            "iroha_core::smartcontracts::isi::sorafs::RepairPersistedEventV1",
            |bytes| decode_repair_state(bytes, "test repair persisted event"),
        );
        check::<RepairEventJournalHeadV1>(
            world,
            repair_event_journal_head_key(),
            "iroha_core::smartcontracts::isi::sorafs::RepairEventJournalHeadV1",
            |bytes| decode_repair_state(bytes, "test repair journal head"),
        );
    }
    #[test]
    fn repair_ledger_prevents_split_brain_and_duplicate_terminal_outcomes() {
        let mut state = make_state();
        let provider = ProviderId::new([0xD1; 32]);
        grant_repair_operator(&mut state, &alice(), provider);
        grant_repair_operator(&mut state, &bob(), provider);
        let report = repair_report("REP-CHAIN-1", provider, [0xD2; 32], &alice(), 2_000);
        let report_payload = to_bytes(&report).expect("encode repair report");
        let source_identity = [0xD3; 32];
        let first_header = repair_block_header(1, 2_000_000);
        let first_hash = iroha_crypto::HashOf::new(&first_header);
        let first_hash_bytes = *first_hash.as_ref();
        {
            let mut block = state.block(first_header.clone());
            let mut transaction = block.transaction();
            SubmitSorafsRepairTask::new(source_identity, report_payload.clone())
                .execute(&alice(), &mut transaction)
                .expect("submit repair task");
            SubmitSorafsRepairTask::new(source_identity, report_payload.clone())
                .execute(&alice(), &mut transaction)
                .expect("exact source replay is idempotent");
            let conflicting_report =
                repair_report("REP-CHAIN-CONFLICT", provider, [0xD2; 32], &alice(), 2_000);
            let conflict = SubmitSorafsRepairTask::new(
                source_identity,
                to_bytes(&conflicting_report).expect("encode conflicting report"),
            )
            .execute(&alice(), &mut transaction)
            .expect_err("source identity cannot bind a different report");
            assert!(smart_contract_error_message(&conflict).contains("different canonical report"));
            ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                1,
                SorafsRepairTaskActionV1::Claim(SorafsRepairClaimV1 {
                    lease_duration_ms: REPAIR_LEDGER_MIN_LEASE_MS_V1,
                    idempotency_key: "claim-alice".to_owned(),
                }),
            )
            .execute(&alice(), &mut transaction)
            .expect("first worker claims task");
            let competing_claim = ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                2,
                SorafsRepairTaskActionV1::Claim(SorafsRepairClaimV1 {
                    lease_duration_ms: REPAIR_LEDGER_MIN_LEASE_MS_V1,
                    idempotency_key: "claim-bob-early".to_owned(),
                }),
            )
            .execute(&bob(), &mut transaction)
            .expect_err("second worker cannot claim an unexpired lease");
            assert!(smart_contract_error_message(&competing_claim).contains("lease is held"));
            transaction.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("commit first repair block");
        }
        state.push_block_hash_for_testing(first_hash);
        let second_header = repair_block_header(2, 2_001_000);
        let second_hash = iroha_crypto::HashOf::new(&second_header);
        let second_hash_bytes = *second_hash.as_ref();
        {
            let mut block = state.block(second_header.clone());
            let mut transaction = block.transaction();
            ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                2,
                SorafsRepairTaskActionV1::Claim(SorafsRepairClaimV1 {
                    lease_duration_ms: REPAIR_LEDGER_MIN_LEASE_MS_V1,
                    idempotency_key: "claim-bob-expired".to_owned(),
                }),
            )
            .execute(&bob(), &mut transaction)
            .expect("expired lease can be reclaimed exactly once");
            let stale_terminal = ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                3,
                SorafsRepairTaskActionV1::Complete(SorafsRepairCompleteV1 {
                    lease_generation: 1,
                    evidence_digest: [0xD4; 32],
                    idempotency_key: "complete-stale".to_owned(),
                }),
            )
            .execute(&alice(), &mut transaction)
            .expect_err("old lease owner cannot finalize after reclaim");
            let stale_terminal_message = smart_contract_error_message(&stale_terminal);
            assert!(
                stale_terminal_message.contains("different account")
                    || stale_terminal_message.contains("generation mismatch")
            );
            let completion = ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                3,
                SorafsRepairTaskActionV1::Complete(SorafsRepairCompleteV1 {
                    lease_generation: 2,
                    evidence_digest: [0xD5; 32],
                    idempotency_key: "complete-bob".to_owned(),
                }),
            );
            completion
                .clone()
                .execute(&bob(), &mut transaction)
                .expect("current lease owner completes task");
            completion
                .execute(&bob(), &mut transaction)
                .expect("exact terminal replay is idempotent");
            let reused_key = ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                3,
                SorafsRepairTaskActionV1::Fail(SorafsRepairFailV1 {
                    lease_generation: 2,
                    failure_digest: [0xD6; 32],
                    idempotency_key: "complete-bob".to_owned(),
                }),
            )
            .execute(&bob(), &mut transaction)
            .expect_err("same idempotency key cannot authorize a different terminal");
            assert!(smart_contract_error_message(&reused_key).contains("different action"));
            let second_terminal = ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                4,
                SorafsRepairTaskActionV1::Fail(SorafsRepairFailV1 {
                    lease_generation: 2,
                    failure_digest: [0xD7; 32],
                    idempotency_key: "fail-after-complete".to_owned(),
                }),
            )
            .execute(&bob(), &mut transaction)
            .expect_err("a task has exactly one terminal outcome");
            assert!(smart_contract_error_message(&second_terminal).contains("terminal outcome"));
            transaction.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("commit second repair block");
        }
        state.push_block_hash_for_testing(second_hash);
        let view = state.view();
        let task = FindSorafsRepairTask::new(report.ticket_id.0.clone(), None)
            .execute(&view)
            .expect("typed finalized task query");
        assert_eq!(task.task.revision, 4);
        assert!(matches!(
            task.task.terminal_outcome,
            Some(RepairLedgerTerminalOutcomeV1 {
                kind: RepairLedgerTerminalKindV1::Completed(_),
                lease_generation: 2,
                ..
            })
        ));
        assert_eq!(task.finalized_cursor.height, 2);
        assert_eq!(task.finalized_cursor.block_hash, second_hash_bytes);
        let status = FindSorafsRepairStatus::new(Some(task.finalized_cursor))
            .execute(&view)
            .expect("typed finalized status query");
        assert_eq!(status.status.tasks, 1);
        assert_eq!(status.status.terminal_outcomes, 1);
        assert_eq!(status.status.completed, 1);
        assert_eq!(status.status.leased_tasks, 0);
        let first_event_page = FindSorafsRepairEvents::new(Some(task.finalized_cursor), None, 2)
            .execute(&view)
            .expect("first finalized repair event page");
        assert_eq!(first_event_page.events.len(), 2);
        assert!(first_event_page.has_more);
        assert_eq!(
            first_event_page
                .events
                .iter()
                .map(|event| (event.sequence, event.block_height, event.event_index))
                .collect::<Vec<_>>(),
            vec![(1, 1, 0), (2, 1, 1)]
        );
        assert!(
            first_event_page
                .events
                .iter()
                .all(|event| event.block_hash == first_hash_bytes)
        );
        let event_cursor = first_event_page
            .next_after
            .expect("first event page has continuation cursor");
        assert_eq!(
            event_cursor,
            first_event_page
                .events
                .last()
                .expect("first event page is non-empty")
                .cursor()
        );
        let second_event_page =
            FindSorafsRepairEvents::new(Some(task.finalized_cursor), Some(event_cursor), 2)
                .execute(&view)
                .expect("second finalized repair event page");
        assert_eq!(second_event_page.events.len(), 2);
        assert!(!second_event_page.has_more);
        assert_eq!(
            second_event_page
                .events
                .iter()
                .map(|event| (event.sequence, event.block_height, event.event_index))
                .collect::<Vec<_>>(),
            vec![(3, 2, 0), (4, 2, 1)]
        );
        assert!(
            second_event_page
                .events
                .iter()
                .all(|event| event.block_hash == second_hash_bytes)
        );
        assert_eq!(
            second_event_page.events[1].event.kind,
            SorafsRepairLedgerEventKind::Completed
        );
        let task_page = FindSorafsRepairTasks::new(Some(task.finalized_cursor), None, 1)
            .execute(&view)
            .expect("bounded repair task page");
        assert_eq!(task_page.tasks, vec![task.task.clone()]);
        assert!(!task_page.has_more);
        let mut stale_anchor = task.finalized_cursor;
        stale_anchor.height = 1;
        assert_eq!(
            FindSorafsRepairStatus::new(Some(stale_anchor)).execute(&view),
            Err(QueryExecutionFail::Expired)
        );
        let mut tampered_event_cursor = event_cursor;
        tampered_event_cursor.block_hash[0] ^= 0xFF;
        assert_eq!(
            FindSorafsRepairEvents::new(
                Some(task.finalized_cursor),
                Some(tampered_event_cursor),
                1,
            )
            .execute(&view),
            Err(QueryExecutionFail::Expired)
        );
        for limit in [0, REPAIR_QUERY_MAX_ITEMS_V1 + 1] {
            assert!(matches!(
                FindSorafsRepairTasks::new(None, None, limit).execute(&view),
                Err(QueryExecutionFail::Conversion(_))
            ));
            assert!(matches!(
                FindSorafsRepairEvents::new(None, None, limit).execute(&view),
                Err(QueryExecutionFail::Conversion(_))
            ));
        }
    }
    #[test]
    fn repair_status_and_task_queries_prove_a_clean_empty_ledger() {
        let mut state = make_state();
        transact_repair(&mut state, 1, 1_000, |_| Ok(())).expect("commit empty finalized block");
        let view = state.view();
        let status = FindSorafsRepairStatus::new(None)
            .execute(&view)
            .expect("clean repair ledger status");
        assert_eq!(status.status, RepairLedgerStatusV1::default());
        let page = FindSorafsRepairTasks::new(Some(status.finalized_cursor), None, 10)
            .execute(&view)
            .expect("clean empty repair task page");
        assert_eq!(page.finalized_cursor, status.finalized_cursor);
        assert!(page.tasks.is_empty());
        assert!(!page.has_more);
        assert_eq!(page.next_after_task_id, None);
    }
    #[test]
    fn absent_repair_status_rejects_every_orphaned_namespace() {
        let orphan_keys = [
            repair_task_key("REP-ORPHAN-TASK"),
            repair_source_key([0x91; 32]),
            repair_event_key(1),
            repair_event_journal_head_key().clone(),
        ];
        for (index, orphan_key) in orphan_keys.into_iter().enumerate() {
            let mut state = make_state();
            transact_repair(
                &mut state,
                1,
                2_000 + u64::try_from(index).expect("index fits u64"),
                |transaction| {
                    transaction
                        .world
                        .smart_contract_state
                        .insert(orphan_key, vec![0xFF]);
                    Ok(())
                },
            )
            .expect("commit orphaned repair state");
            let view = state.view();
            assert!(matches!(
                FindSorafsRepairStatus::new(None).execute(&view),
                Err(QueryExecutionFail::Conversion(_))
            ));
            assert!(matches!(
                FindSorafsRepairTasks::new(None, None, 10).execute(&view),
                Err(QueryExecutionFail::Conversion(_))
            ));
        }
    }
    #[test]
    fn revoked_lease_owner_cannot_mutate_and_authorized_worker_reclaims_immediately() {
        let mut state = make_state();
        let provider = ProviderId::new([0xB1; 32]);
        grant_repair_operator(&mut state, &alice(), provider);
        grant_repair_operator(&mut state, &bob(), provider);
        let report = repair_report("REP-REVOKE-1", provider, [0xB2; 32], &alice(), 7_000);
        let report_payload = to_bytes(&report).expect("encode revoked-worker repair report");
        let claim = ApplySorafsRepairTaskAction::new(
            report.ticket_id.0.clone(),
            1,
            SorafsRepairTaskActionV1::Claim(SorafsRepairClaimV1 {
                lease_duration_ms: REPAIR_LEDGER_MIN_LEASE_MS_V1,
                idempotency_key: "claim-before-revocation".to_owned(),
            }),
        );
        transact_repair(&mut state, 1, 7_000_000, |transaction| {
            SubmitSorafsRepairTask::new([0xB3; 32], report_payload)
                .execute(&alice(), transaction)?;
            claim.clone().execute(&alice(), transaction)
        })
        .expect("commit initial repair lease");
        revoke_repair_operator(&mut state, &alice(), provider);
        transact_repair(&mut state, 2, 7_000_500, |transaction| {
            claim
                .execute(&alice(), transaction)
                .expect("exact pre-revocation claim replay remains a no-op");
            let revoked_renewal = ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                2,
                SorafsRepairTaskActionV1::Renew(SorafsRepairRenewV1 {
                    lease_generation: 1,
                    lease_duration_ms: REPAIR_LEDGER_MIN_LEASE_MS_V1,
                    idempotency_key: "revoked-renewal".to_owned(),
                }),
            )
            .execute(&alice(), transaction)
            .expect_err("revoked lease owner cannot renew");
            assert!(
                smart_contract_error_message(&revoked_renewal).contains("current provider-scoped")
            );
            let revoked_terminal = ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                2,
                SorafsRepairTaskActionV1::Complete(SorafsRepairCompleteV1 {
                    lease_generation: 1,
                    evidence_digest: [0xB4; 32],
                    idempotency_key: "revoked-completion".to_owned(),
                }),
            )
            .execute(&alice(), transaction)
            .expect_err("revoked lease owner cannot commit a terminal outcome");
            assert!(
                smart_contract_error_message(&revoked_terminal).contains("current provider-scoped")
            );
            let revoked_slash = ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                2,
                SorafsRepairTaskActionV1::Escalate(SorafsRepairEscalateV1 {
                    lease_generation: 1,
                    slash_proposal_payload: vec![0xFF],
                    idempotency_key: "revoked-escalation".to_owned(),
                }),
            )
            .execute(&alice(), transaction)
            .expect_err("revoked lease owner cannot commit a slash proposal");
            assert!(
                smart_contract_error_message(&revoked_slash).contains("current provider-scoped")
            );
            ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                2,
                SorafsRepairTaskActionV1::Claim(SorafsRepairClaimV1 {
                    lease_duration_ms: REPAIR_LEDGER_MIN_LEASE_MS_V1,
                    idempotency_key: "authorized-reclaim".to_owned(),
                }),
            )
            .execute(&bob(), transaction)
            .expect("authorized worker reclaims revoked owner's unexpired lease");
            let revoked_after_reclaim = ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                3,
                SorafsRepairTaskActionV1::Fail(SorafsRepairFailV1 {
                    lease_generation: 1,
                    failure_digest: [0xB5; 32],
                    idempotency_key: "revoked-failure".to_owned(),
                }),
            )
            .execute(&alice(), transaction)
            .expect_err("revoked former owner cannot race the replacement");
            assert!(
                smart_contract_error_message(&revoked_after_reclaim)
                    .contains("current provider-scoped")
            );
            let completion = ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                3,
                SorafsRepairTaskActionV1::Complete(SorafsRepairCompleteV1 {
                    lease_generation: 2,
                    evidence_digest: [0xB6; 32],
                    idempotency_key: "replacement-completion".to_owned(),
                }),
            );
            completion
                .clone()
                .execute(&bob(), transaction)
                .expect("replacement commits the single terminal outcome");
            completion
                .execute(&bob(), transaction)
                .expect("replacement terminal replay is idempotent");
            let duplicate_terminal = ApplySorafsRepairTaskAction::new(
                report.ticket_id.0.clone(),
                4,
                SorafsRepairTaskActionV1::Fail(SorafsRepairFailV1 {
                    lease_generation: 2,
                    failure_digest: [0xB7; 32],
                    idempotency_key: "replacement-second-terminal".to_owned(),
                }),
            )
            .execute(&bob(), transaction)
            .expect_err("replacement cannot commit a second terminal outcome");
            assert!(smart_contract_error_message(&duplicate_terminal).contains("terminal outcome"));
            Ok(())
        })
        .expect("commit permission-revocation takeover");
        let view = state.view();
        let task = FindSorafsRepairTask::new(report.ticket_id.0, None)
            .execute(&view)
            .expect("query revoked-worker repair task");
        assert_eq!(task.task.revision, 4);
        assert!(matches!(
            task.task.terminal_outcome,
            Some(RepairLedgerTerminalOutcomeV1 {
                kind: RepairLedgerTerminalKindV1::Completed(_),
                lease_generation: 2,
                ref finalized_by,
                ..
            }) if finalized_by == &bob()
        ));
        let events = FindSorafsRepairEvents::new(Some(task.finalized_cursor), None, 10)
            .execute(&view)
            .expect("query permission-revocation event journal");
        assert_eq!(
            events
                .events
                .iter()
                .map(|event| (event.event.kind, event.event.authority.clone()))
                .collect::<Vec<_>>(),
            vec![
                (SorafsRepairLedgerEventKind::TaskSubmitted, alice()),
                (SorafsRepairLedgerEventKind::LeaseClaimed, alice()),
                (SorafsRepairLedgerEventKind::LeaseClaimed, bob()),
                (SorafsRepairLedgerEventKind::Completed, bob()),
            ],
            "replays and rejected revoked-worker mutations must not create journal events"
        );
    }
    #[test]
    fn repair_task_pages_are_deterministic_and_exclusive() {
        let mut state = make_state();
        let provider = ProviderId::new([0xC1; 32]);
        grant_repair_operator(&mut state, &alice(), provider);
        let fixtures = [
            ("REP-PAGE-1", [0x31; 32], [0x41; 32]),
            ("REP-PAGE-2", [0x32; 32], [0x42; 32]),
            ("REP-PAGE-3", [0x33; 32], [0x43; 32]),
        ];
        transact_repair(&mut state, 1, 5_000_000, |transaction| {
            for (ticket_id, source_identity, manifest_digest) in fixtures {
                let report = repair_report(ticket_id, provider, manifest_digest, &alice(), 5_000);
                SubmitSorafsRepairTask::new(
                    source_identity,
                    to_bytes(&report).expect("encode paginated repair report"),
                )
                .execute(&alice(), transaction)?;
            }
            Ok(())
        })
        .expect("commit paginated repair tasks");
        let view = state.view();
        let first = FindSorafsRepairTasks::new(None, None, 1)
            .execute(&view)
            .expect("first repair task page");
        let anchor = first.finalized_cursor;
        let mut page = first;
        let mut tasks = Vec::new();
        loop {
            let expected_after = page.tasks.last().map(|task| task.task_id);
            let next_after = page.next_after_task_id;
            tasks.extend(page.tasks);
            let Some(after) = next_after else {
                assert!(!page.has_more);
                break;
            };
            assert!(page.has_more);
            assert_eq!(Some(after), expected_after);
            page = FindSorafsRepairTasks::new(Some(anchor), Some(after), 1)
                .execute(&view)
                .expect("continued repair task page");
            assert_eq!(page.finalized_cursor, anchor);
        }
        assert_eq!(tasks.len(), fixtures.len());
        assert!(
            tasks
                .windows(2)
                .all(|pair| pair[0].task_id < pair[1].task_id),
            "repair task pages must follow immutable task-id order"
        );
        let expected = fixtures
            .into_iter()
            .map(|(_, source_identity, _)| sorafs_repair_task_id_v1(source_identity))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            tasks
                .iter()
                .map(|task| task.task_id)
                .collect::<BTreeSet<_>>(),
            expected
        );
        let events = FindSorafsRepairEvents::new(Some(anchor), None, 10)
            .execute(&view)
            .expect("query task-submission events");
        assert_eq!(events.events.len(), fixtures.len());
        assert!(
            events
                .events
                .iter()
                .all(|event| event.event.kind == SorafsRepairLedgerEventKind::TaskSubmitted)
        );
    }
    include!("sorafs/repair_query_tail_tests.rs");
    include!("sorafs/canonical_accounting_tests.rs");
    include!("sorafs/provider_credit_cas_tests.rs");
    include!("sorafs/replication_lifecycle_tests.rs");
    include!("sorafs/completion_authority_tests.rs");
    include!("sorafs/repair_schema_identity_tests.rs");
}

#[cfg(test)]
#[path = "sorafs/core_schema_test_support.rs"]
pub(super) mod schema_test_support;
