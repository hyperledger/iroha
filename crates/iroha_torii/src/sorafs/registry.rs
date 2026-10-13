//! Capacity registry helpers exposed via Torii.
use crate::sorafs::capability_name;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use hex::ToHex;
use iroha_core::state::{WorldReadOnly, WorldView};
#[cfg(test)]
use iroha_data_model::sorafs::capacity::CapacityDisputeEvidence;
#[cfg(test)]
use iroha_data_model::sorafs::pin_registry::{PinManifestRecord, PinPolicy, StorageClass};
use iroha_data_model::sorafs::{
    capacity::{
        CapacityDeclarationRecord, CapacityDisputeId, CapacityDisputeRecord, CapacityDisputeStatus,
        CapacityFeeLedgerEntry, ProviderId,
    },
    pin_registry::{
        ManifestAliasId, ManifestAliasRecord, ManifestDigest, PinStatus, ReplicationOrderId,
        ReplicationOrderRecord, ReplicationOrderStatus,
    },
    pricing::ProviderCreditRecord,
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::{json::Json, numeric::Quantity};
use mv::storage::StorageReadOnly;
use norito::{
    DecodeLimits,
    core::Error as NoritoDecodeError,
    decode_from_bytes_with_limits,
    json::{self, Map, Value},
    to_bytes,
};
use sorafs_manifest::{
    capacity::{
        CapacityDeclarationV1, CapacityMetadataEntry, ChunkerCommitmentV1, LaneCommitmentV1,
        PricingScheduleV1, ReplicationOrderV1,
    },
    provider_advert::{CapabilityType, StakePointer},
};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
const METADATA_STATUS_TIMESTAMP_KEY: &str = "sorafs_status_timestamp_unix";
const METADATA_GOVERNANCE_REFS_KEY: &str = "sorafs_governance_refs";
const REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1: usize = 256 * 1024;
const REPLICATION_ORDER_PAGE_MAX_ITEMS_V1: usize = 500;
const ALIAS_PAGE_MAX_ITEMS_V1: usize = 500;
const REPLICATION_ORDER_DECODE_LIMITS_V1: DecodeLimits = DecodeLimits::new(
    sorafs_manifest::capacity::MAX_CAPACITY_METADATA_VALUE_BYTES,
    REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1,
    131_072,
    REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1 * 4,
    32,
);
/// Collect a snapshot of provider declarations and fee ledger entries.
pub(crate) fn collect_snapshot(
    world: &WorldView<'_>,
    limit: usize,
) -> Result<CapacitySnapshot, RegistryError> {
    let capacity_declarations = world.capacity_declarations();
    let capacity_fee_ledger = world.capacity_fee_ledger();
    let provider_credit_ledger = world.provider_credit_ledger();
    let capacity_disputes = world.capacity_disputes();
    let declaration_count = capacity_declarations.len();
    let fee_ledger_count = capacity_fee_ledger.len();
    let credit_ledger_count = provider_credit_ledger.len();
    let dispute_count = capacity_disputes.len();
    // Apply the response bound before decoding and projecting registry values. Capacity
    // declarations can contain sizeable canonical payloads, so truncating after projection
    // would let a small read request consume work proportional to the entire registry.
    let declarations = build_declarations(capacity_declarations.iter().take(limit))?;
    let fee_ledger = build_fee_ledger(capacity_fee_ledger.iter().take(limit));
    let credit_ledger = build_credit_ledger(provider_credit_ledger.iter().take(limit));
    let disputes = build_disputes(capacity_disputes.iter().take(limit));
    Ok(CapacitySnapshot {
        declaration_count,
        fee_ledger_count,
        credit_ledger_count,
        dispute_count,
        declarations,
        fee_ledger,
        credit_ledger,
        disputes,
    })
}
/// Aggregated registry snapshot returned by both REST and gRPC facades.
#[derive(Debug, Clone)]
pub(crate) struct CapacitySnapshot {
    /// Total declarations in the registry before applying the response limit.
    pub(crate) declaration_count: usize,
    /// Total fee ledger entries before applying the response limit.
    pub(crate) fee_ledger_count: usize,
    /// Total credit ledger entries before applying the response limit.
    pub(crate) credit_ledger_count: usize,
    /// Total disputes before applying the response limit.
    pub(crate) dispute_count: usize,
    /// Provider capacity declarations.
    pub(crate) declarations: Vec<RegistryDeclaration>,
    /// Fee ledger entries per provider.
    pub(crate) fee_ledger: Vec<RegistryFeeLedgerEntry>,
    /// Credit ledger entries per provider.
    pub(crate) credit_ledger: Vec<RegistryCreditLedgerEntry>,
    /// Disputes filed against providers.
    pub(crate) disputes: Vec<RegistryDispute>,
}
/// Provider declaration projection ready for JSON serialization.
#[derive(Debug, Clone)]
pub(crate) struct RegistryDeclaration {
    pub(crate) provider_id_hex: String,
    pub(crate) committed_capacity_gib: u64,
    pub(crate) registered_epoch: u64,
    pub(crate) valid_from_epoch: u64,
    pub(crate) valid_until_epoch: u64,
    pub(crate) declaration_json: Value,
    pub(crate) metadata_json: Value,
}
impl RegistryDeclaration {
    /// Convert the declaration into a Norito JSON value.
    pub fn into_json(self) -> Result<Value, json::Error> {
        let mut map = Map::new();
        map.insert(
            "provider_id_hex".into(),
            Value::String(self.provider_id_hex),
        );
        map.insert(
            "committed_capacity_gib".into(),
            json::to_value(&self.committed_capacity_gib)?,
        );
        map.insert(
            "registered_epoch".into(),
            json::to_value(&self.registered_epoch)?,
        );
        map.insert(
            "valid_from_epoch".into(),
            json::to_value(&self.valid_from_epoch)?,
        );
        map.insert(
            "valid_until_epoch".into(),
            json::to_value(&self.valid_until_epoch)?,
        );
        map.insert("declaration".into(), self.declaration_json);
        map.insert("metadata".into(), self.metadata_json);
        Ok(Value::Object(map))
    }
}
/// Fee ledger projection ready for JSON serialization.
#[derive(Debug, Clone)]
pub(crate) struct RegistryFeeLedgerEntry {
    pub(crate) provider_id_hex: String,
    pub(crate) total_declared_gib: u128,
    pub(crate) total_utilised_gib: u128,
    pub(crate) storage_fee: Quantity,
    pub(crate) egress_fee: Quantity,
    pub(crate) accrued_fee: Quantity,
    pub(crate) expected_settlement: Quantity,
    pub(crate) penalty_slashed: Quantity,
    pub(crate) penalty_events: u32,
    pub(crate) last_updated_epoch: u64,
}
impl RegistryFeeLedgerEntry {
    /// Convert the ledger entry into a Norito JSON value.
    pub fn into_json(self) -> Result<Value, json::Error> {
        let mut map = Map::new();
        map.insert(
            "provider_id_hex".into(),
            Value::String(self.provider_id_hex),
        );
        map.insert(
            "total_declared_gib".into(),
            json::to_value(&self.total_declared_gib)?,
        );
        map.insert(
            "total_utilised_gib".into(),
            json::to_value(&self.total_utilised_gib)?,
        );
        map.insert("storage_fee".into(), json::to_value(&self.storage_fee)?);
        map.insert("egress_fee".into(), json::to_value(&self.egress_fee)?);
        map.insert("accrued_fee".into(), json::to_value(&self.accrued_fee)?);
        map.insert(
            "expected_settlement".into(),
            json::to_value(&self.expected_settlement)?,
        );
        map.insert(
            "penalty_slashed".into(),
            json::to_value(&self.penalty_slashed)?,
        );
        map.insert(
            "penalty_events".into(),
            json::to_value(&self.penalty_events)?,
        );
        map.insert(
            "last_updated_epoch".into(),
            json::to_value(&self.last_updated_epoch)?,
        );
        Ok(Value::Object(map))
    }
}
/// Credit ledger projection ready for JSON serialization.
#[derive(Debug, Clone)]
pub(crate) struct RegistryCreditLedgerEntry {
    pub(crate) provider_id_hex: String,
    pub(crate) available_credit: Quantity,
    pub(crate) bonded: Quantity,
    pub(crate) required_bond: Quantity,
    pub(crate) expected_settlement: Quantity,
    pub(crate) onboarding_epoch: u64,
    pub(crate) last_settlement_epoch: u64,
    pub(crate) low_balance_since_epoch: Option<u64>,
    pub(crate) slashed: Quantity,
    pub(crate) under_delivery_strikes: u32,
    pub(crate) last_penalty_epoch: Option<u64>,
    pub(crate) metadata_json: Value,
}
impl RegistryCreditLedgerEntry {
    /// Convert the credit ledger entry into a Norito JSON value.
    pub fn into_json(self) -> Result<Value, json::Error> {
        let mut map = Map::new();
        map.insert(
            "provider_id_hex".into(),
            Value::String(self.provider_id_hex),
        );
        map.insert(
            "available_credit".into(),
            json::to_value(&self.available_credit)?,
        );
        map.insert("bonded".into(), json::to_value(&self.bonded)?);
        map.insert("required_bond".into(), json::to_value(&self.required_bond)?);
        map.insert(
            "expected_settlement".into(),
            json::to_value(&self.expected_settlement)?,
        );
        map.insert(
            "onboarding_epoch".into(),
            json::to_value(&self.onboarding_epoch)?,
        );
        map.insert(
            "last_settlement_epoch".into(),
            json::to_value(&self.last_settlement_epoch)?,
        );
        map.insert(
            "low_balance_since_epoch".into(),
            json::to_value(&self.low_balance_since_epoch)?,
        );
        map.insert("slashed".into(), json::to_value(&self.slashed)?);
        map.insert(
            "under_delivery_strikes".into(),
            json::to_value(&self.under_delivery_strikes)?,
        );
        map.insert(
            "last_penalty_epoch".into(),
            json::to_value(&self.last_penalty_epoch)?,
        );
        map.insert("metadata".into(), self.metadata_json);
        Ok(Value::Object(map))
    }
}
/// Dispute projection ready for JSON serialization.
#[derive(Debug, Clone)]
pub(crate) struct RegistryDispute {
    pub(crate) dispute_id_hex: String,
    pub(crate) provider_id_hex: String,
    pub(crate) complainant_id_hex: String,
    pub(crate) replication_order_id_hex: Option<String>,
    pub(crate) kind: String,
    pub(crate) submitted_epoch: u64,
    pub(crate) description: String,
    pub(crate) requested_remedy: Option<String>,
    pub(crate) status: String,
    pub(crate) resolution_epoch: Option<u64>,
    pub(crate) resolution_outcome: Option<String>,
    pub(crate) resolution_notes: Option<String>,
    pub(crate) evidence_digest_hex: String,
    pub(crate) evidence_media_type: Option<String>,
    pub(crate) evidence_uri: Option<String>,
    pub(crate) evidence_size_bytes: Option<u64>,
    pub(crate) dispute_b64: String,
}
impl RegistryDispute {
    /// Convert the dispute record into a JSON value.
    pub fn into_json(self) -> Result<Value, json::Error> {
        let mut map = Map::new();
        map.insert("dispute_id_hex".into(), Value::String(self.dispute_id_hex));
        map.insert(
            "provider_id_hex".into(),
            Value::String(self.provider_id_hex),
        );
        map.insert(
            "complainant_id_hex".into(),
            Value::String(self.complainant_id_hex),
        );
        map.insert(
            "replication_order_id_hex".into(),
            self.replication_order_id_hex
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert("kind".into(), Value::String(self.kind));
        map.insert(
            "submitted_epoch".into(),
            json::to_value(&self.submitted_epoch)?,
        );
        map.insert("description".into(), Value::String(self.description));
        map.insert(
            "requested_remedy".into(),
            self.requested_remedy
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert("status".into(), Value::String(self.status));
        map.insert(
            "resolution_epoch".into(),
            self.resolution_epoch
                .map(|value| json::to_value(&value))
                .transpose()?
                .unwrap_or(Value::Null),
        );
        map.insert(
            "resolution_outcome".into(),
            self.resolution_outcome
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "resolution_notes".into(),
            self.resolution_notes
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "evidence_digest_hex".into(),
            Value::String(self.evidence_digest_hex),
        );
        map.insert(
            "evidence_media_type".into(),
            self.evidence_media_type
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "evidence_uri".into(),
            self.evidence_uri.map(Value::String).unwrap_or(Value::Null),
        );
        map.insert(
            "evidence_size_bytes".into(),
            self.evidence_size_bytes
                .map(|value| json::to_value(&value))
                .transpose()?
                .unwrap_or(Value::Null),
        );
        map.insert("dispute_b64".into(), Value::String(self.dispute_b64));
        Ok(Value::Object(map))
    }
}
/// Errors raised while preparing registry projections.
#[derive(Debug, Error)]
pub(crate) enum RegistryError {
    #[error("failed to decode capacity declaration for {provider_id_hex}: {source}")]
    DecodeDeclaration {
        provider_id_hex: String,
        #[source]
        source: NoritoDecodeError,
    },
    #[error("failed to serialize capacity declaration JSON for {provider_id_hex}: {source}")]
    SerializeDeclaration {
        provider_id_hex: String,
        #[source]
        source: json::Error,
    },
    #[error("failed to serialize metadata for {provider_id_hex}: {source}")]
    SerializeMetadata {
        provider_id_hex: String,
        #[source]
        source: json::Error,
    },
}
fn build_declarations<'a, I>(records: I) -> Result<Vec<RegistryDeclaration>, RegistryError>
where
    I: IntoIterator<Item = (&'a ProviderId, &'a CapacityDeclarationRecord)>,
{
    let mut out = Vec::new();
    for (provider_id, record) in records.into_iter() {
        let provider_id_hex = provider_id.as_bytes().encode_hex::<String>();
        let declaration = norito::decode_from_bytes::<CapacityDeclarationV1>(&record.declaration)
            .map_err(|source| RegistryError::DecodeDeclaration {
            provider_id_hex: provider_id_hex.clone(),
            source,
        })?;
        let declaration_json = capacity_declaration_to_json(&declaration, &record.declaration)
            .map_err(|source| RegistryError::SerializeDeclaration {
                provider_id_hex: provider_id_hex.clone(),
                source,
            })?;
        let metadata_json = metadata_to_json(&record.metadata).map_err(|source| {
            RegistryError::SerializeMetadata {
                provider_id_hex: provider_id_hex.clone(),
                source,
            }
        })?;
        out.push(RegistryDeclaration {
            provider_id_hex,
            committed_capacity_gib: record.committed_capacity_gib,
            registered_epoch: record.registered_epoch,
            valid_from_epoch: record.valid_from_epoch,
            valid_until_epoch: record.valid_until_epoch,
            declaration_json,
            metadata_json,
        });
    }
    Ok(out)
}
fn build_fee_ledger<'a, I>(entries: I) -> Vec<RegistryFeeLedgerEntry>
where
    I: IntoIterator<Item = (&'a ProviderId, &'a CapacityFeeLedgerEntry)>,
{
    entries
        .into_iter()
        .map(|(provider_id, entry)| RegistryFeeLedgerEntry {
            provider_id_hex: provider_id.as_bytes().encode_hex::<String>(),
            total_declared_gib: entry.total_declared_gib,
            total_utilised_gib: entry.total_utilised_gib,
            storage_fee: entry.storage_fee.clone(),
            egress_fee: entry.egress_fee.clone(),
            accrued_fee: entry.accrued_fee.clone(),
            expected_settlement: entry.expected_settlement.clone(),
            penalty_slashed: entry.penalty_slashed.clone(),
            penalty_events: entry.penalty_events,
            last_updated_epoch: entry.last_updated_epoch,
        })
        .collect()
}
fn build_credit_ledger<'a, I>(entries: I) -> Vec<RegistryCreditLedgerEntry>
where
    I: IntoIterator<Item = (&'a ProviderId, &'a ProviderCreditRecord)>,
{
    entries
        .into_iter()
        .map(|(provider_id, record)| {
            let metadata_json =
                metadata_to_json(&record.metadata).unwrap_or_else(|_| Value::Object(Map::new()));
            RegistryCreditLedgerEntry {
                provider_id_hex: provider_id.as_bytes().encode_hex::<String>(),
                available_credit: record.available_credit.clone(),
                bonded: record.bonded.clone(),
                required_bond: record.required_bond.clone(),
                expected_settlement: record.expected_settlement.clone(),
                onboarding_epoch: record.onboarding_epoch,
                last_settlement_epoch: record.last_settlement_epoch,
                low_balance_since_epoch: record.low_balance_since_epoch,
                slashed: record.slashed.clone(),
                under_delivery_strikes: record.under_delivery_strikes,
                last_penalty_epoch: record.last_penalty_epoch,
                metadata_json,
            }
        })
        .collect()
}
fn build_disputes<'a, I>(entries: I) -> Vec<RegistryDispute>
where
    I: IntoIterator<Item = (&'a CapacityDisputeId, &'a CapacityDisputeRecord)>,
{
    entries
        .into_iter()
        .map(|(dispute_id, record)| {
            let dispute_b64 = BASE64_STD.encode(&record.dispute_payload);
            let replication_order_id_hex = record
                .replication_order_id
                .map(|id| id.encode_hex::<String>());
            let status = match &record.status {
                CapacityDisputeStatus::Pending => "pending".to_owned(),
                CapacityDisputeStatus::Resolved(_) => "resolved".to_owned(),
            };
            let (resolution_epoch, resolution_outcome, resolution_notes) = match &record.status {
                CapacityDisputeStatus::Pending => (None, None, None),
                CapacityDisputeStatus::Resolved(resolution) => (
                    Some(resolution.resolved_epoch),
                    Some(match resolution.outcome {
                        iroha_data_model::sorafs::capacity::CapacityDisputeOutcome::Upheld => {
                            "upheld"
                        }
                        iroha_data_model::sorafs::capacity::CapacityDisputeOutcome::Dismissed => {
                            "dismissed"
                        }
                        iroha_data_model::sorafs::capacity::CapacityDisputeOutcome::Withdrawn => {
                            "withdrawn"
                        }
                    }
                    .to_owned()),
                    resolution.notes.clone(),
                ),
            };
            RegistryDispute {
                dispute_id_hex: dispute_id.as_bytes().encode_hex::<String>(),
                provider_id_hex: record.provider_id.as_bytes().encode_hex::<String>(),
                complainant_id_hex: record.complainant_id.encode_hex::<String>(),
                replication_order_id_hex,
                kind: dispute_kind_label(record.kind).to_owned(),
                submitted_epoch: record.submitted_epoch,
                description: record.description.clone(),
                requested_remedy: record.requested_remedy.clone(),
                status,
                resolution_epoch,
                resolution_outcome,
                resolution_notes,
                evidence_digest_hex: record.evidence.digest.encode_hex::<String>(),
                evidence_media_type: record.evidence.media_type.clone(),
                evidence_uri: record.evidence.uri.clone(),
                evidence_size_bytes: record.evidence.size_bytes,
                dispute_b64,
            }
        })
        .collect()
}
fn dispute_kind_label(kind: u8) -> &'static str {
    match kind {
        1 => "replication_shortfall",
        2 => "uptime_breach",
        3 => "proof_failure",
        4 => "fee_dispute",
        _ => "other",
    }
}
fn capacity_declaration_to_json(
    declaration: &CapacityDeclarationV1,
    canonical_bytes: &[u8],
) -> Result<Value, json::Error> {
    let mut map = Map::new();
    map.insert("version".into(), json::to_value(&declaration.version)?);
    map.insert(
        "provider_id_hex".into(),
        Value::String(declaration.provider_id.encode_hex::<String>()),
    );
    map.insert("stake".into(), stake_pointer_to_json(&declaration.stake)?);
    map.insert(
        "committed_capacity_gib".into(),
        json::to_value(&declaration.committed_capacity_gib)?,
    );
    map.insert(
        "chunker_commitments".into(),
        Value::Array(
            declaration
                .chunker_commitments
                .iter()
                .map(chunker_commitment_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );
    map.insert(
        "lane_commitments".into(),
        Value::Array(
            declaration
                .lane_commitments
                .iter()
                .map(lane_commitment_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );
    map.insert(
        "pricing".into(),
        match declaration.pricing.as_ref() {
            Some(pricing) => pricing_to_json(pricing)?,
            None => Value::Null,
        },
    );
    map.insert(
        "valid_from".into(),
        json::to_value(&declaration.valid_from)?,
    );
    map.insert(
        "valid_until".into(),
        json::to_value(&declaration.valid_until)?,
    );
    map.insert(
        "metadata".into(),
        capacity_metadata_entries_to_json(&declaration.metadata),
    );
    map.insert(
        "norito_b64".into(),
        Value::String(BASE64_STD.encode(canonical_bytes)),
    );
    Ok(Value::Object(map))
}
fn stake_pointer_to_json(stake: &StakePointer) -> Result<Value, json::Error> {
    let mut map = Map::new();
    map.insert(
        "pool_id_hex".into(),
        Value::String(stake.pool_id.encode_hex::<String>()),
    );
    map.insert("stake_amount".into(), json::to_value(&stake.stake_amount)?);
    Ok(Value::Object(map))
}
fn chunker_commitment_to_json(commitment: &ChunkerCommitmentV1) -> Result<Value, json::Error> {
    let mut map = Map::new();
    map.insert("profile_id".into(), json::to_value(&commitment.profile_id)?);
    map.insert(
        "profile_aliases".into(),
        json::to_value(&commitment.profile_aliases)?,
    );
    map.insert(
        "committed_gib".into(),
        json::to_value(&commitment.committed_gib)?,
    );
    map.insert(
        "capability_refs".into(),
        Value::Array(
            commitment
                .capability_refs
                .iter()
                .map(|cap| capability_ref_to_json(*cap))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );
    Ok(Value::Object(map))
}
fn capability_ref_to_json(capability: CapabilityType) -> Result<Value, json::Error> {
    let mut map = Map::new();
    map.insert(
        "type".into(),
        Value::String(capability_name(capability).to_string()),
    );
    map.insert("type_id".into(), json::to_value(&(capability as u16))?);
    Ok(Value::Object(map))
}
fn lane_commitment_to_json(lane: &LaneCommitmentV1) -> Result<Value, json::Error> {
    let mut map = Map::new();
    map.insert("lane_id".into(), json::to_value(&lane.lane_id)?);
    map.insert("max_gib".into(), json::to_value(&lane.max_gib)?);
    Ok(Value::Object(map))
}
fn pricing_to_json(pricing: &PricingScheduleV1) -> Result<Value, json::Error> {
    let mut map = Map::new();
    map.insert("currency".into(), json::to_value(&pricing.currency)?);
    map.insert(
        "rate_per_gib_hour_milliu".into(),
        json::to_value(&pricing.rate_per_gib_hour_milliu)?,
    );
    map.insert(
        "min_commitment_hours".into(),
        json::to_value(&pricing.min_commitment_hours)?,
    );
    map.insert("notes".into(), json::to_value(&pricing.notes)?);
    Ok(Value::Object(map))
}
fn capacity_metadata_entries_to_json(entries: &[CapacityMetadataEntry]) -> Value {
    let mut metadata = Map::new();
    for entry in entries {
        metadata.insert(entry.key.clone(), Value::String(entry.value.clone()));
    }
    Value::Object(metadata)
}
fn metadata_to_json(metadata: &Metadata) -> Result<Value, json::Error> {
    json::to_value(metadata)
}
/// Pin registry snapshot containing manifests, aliases, and replication orders.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct PinRegistrySnapshot {
    pub(crate) manifests: Vec<RegistryManifest>,
    pub(crate) aliases: Vec<RegistryAlias>,
    pub(crate) replication_orders: Vec<RegistryReplicationOrder>,
}
/// Bounded replication-order projection decoded after filtering and pagination.
#[derive(Debug, Clone)]
pub(crate) struct ReplicationOrderPage {
    /// Exact number of raw records matching the requested filters.
    pub(crate) total_count: usize,
    /// At most the requested bounded page of decoded records.
    pub(crate) orders: Vec<RegistryReplicationOrder>,
}
/// One bounded alias page projected without materializing the full pin registry.
#[derive(Debug, Clone)]
pub(crate) struct AliasPage {
    /// Exact number of aliases matching the requested filters.
    pub(crate) total_count: usize,
    /// At most the requested bounded page of aliases and their required presentation context.
    pub(crate) entries: Vec<AliasPageEntry>,
}
/// Presentation inputs for one alias in a bounded page.
#[derive(Debug, Clone)]
pub(crate) struct AliasPageEntry {
    /// Bounded alias projection returned to the caller.
    pub(crate) alias: RegistryAlias,
    /// Governance references required to derive presentation for this alias.
    pub(crate) governance: GovernanceSummary,
    /// Deterministically selected successor lineage for this alias manifest.
    pub(crate) lineage: ManifestLineageSummary,
}
/// Aggregated metrics extracted from a [`PinRegistrySnapshot`].
#[cfg(test)]
#[derive(Debug, Default, Clone)]
pub(crate) struct PinRegistryMetricsSummary {
    pub(crate) manifests_pending: u64,
    pub(crate) manifests_approved: u64,
    pub(crate) manifests_retired: u64,
    pub(crate) alias_total: u64,
    pub(crate) orders_pending: u64,
    pub(crate) orders_completed: u64,
    pub(crate) orders_expired: u64,
    pub(crate) orders_cancelled: u64,
    pub(crate) sla_met: u64,
    pub(crate) sla_missed: u64,
    pub(crate) completion_latencies: Vec<f64>,
    pub(crate) deadline_slack_epochs: Vec<f64>,
}
#[cfg(test)]
impl PinRegistryMetricsSummary {
    /// Build a summary from the supplied snapshot.
    #[must_use]
    pub(crate) fn from_snapshot(snapshot: &PinRegistrySnapshot) -> Self {
        let mut summary = Self {
            alias_total: snapshot.aliases.len() as u64,
            ..Self::default()
        };
        for manifest in &snapshot.manifests {
            match &manifest.status {
                ManifestStatusProjection::Pending => {
                    summary.manifests_pending = summary.manifests_pending.saturating_add(1);
                }
                ManifestStatusProjection::Approved { .. } => {
                    summary.manifests_approved = summary.manifests_approved.saturating_add(1);
                }
                ManifestStatusProjection::Retired { .. } => {
                    summary.manifests_retired = summary.manifests_retired.saturating_add(1);
                }
            }
        }
        for order in &snapshot.replication_orders {
            match &order.status {
                ReplicationOrderStatusProjection::Pending => {
                    summary.orders_pending = summary.orders_pending.saturating_add(1);
                    let slack = order.deadline_epoch().saturating_sub(order.issued_epoch()) as f64;
                    summary.deadline_slack_epochs.push(slack);
                }
                ReplicationOrderStatusProjection::Completed { .. } => {
                    summary.orders_completed = summary.orders_completed.saturating_add(1);
                    if let Some(completion_epoch) = order.completion_epoch() {
                        let latency = completion_epoch.saturating_sub(order.issued_epoch()) as f64;
                        summary.completion_latencies.push(latency);
                        if completion_epoch <= order.deadline_epoch() {
                            summary.sla_met = summary.sla_met.saturating_add(1);
                        } else {
                            summary.sla_missed = summary.sla_missed.saturating_add(1);
                        }
                    } else {
                        summary.sla_missed = summary.sla_missed.saturating_add(1);
                    }
                }
                ReplicationOrderStatusProjection::Expired { .. } => {
                    summary.orders_expired = summary.orders_expired.saturating_add(1);
                    summary.sla_missed = summary.sla_missed.saturating_add(1);
                }
                ReplicationOrderStatusProjection::Cancelled { .. } => {
                    summary.orders_cancelled = summary.orders_cancelled.saturating_add(1);
                }
            }
        }
        summary
    }
}
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct RegistryManifest {
    digest_hex: String,
    chunker: RegistryChunkerHandle,
    chunk_digest_hex: String,
    pin_policy: Value,
    submitted_by: String,
    submitted_epoch: u64,
    approved_epoch: Option<u64>,
    alias: Option<AliasBindingProjection>,
    metadata: Value,
    successor_of_hex: Option<String>,
    status: ManifestStatusProjection,
    council_envelope_digest_hex: Option<String>,
    status_timestamp_unix: Option<u64>,
    governance_refs: Vec<GovernanceReference>,
}
#[cfg(test)]
#[derive(Debug, Clone)]
struct RegistryChunkerHandle {
    profile_id: u32,
    namespace: String,
    name: String,
    semver: String,
    multihash_code: u64,
}
#[cfg(test)]
#[derive(Debug, Clone)]
struct AliasBindingProjection {
    namespace: String,
    name: String,
    proof_b64: String,
}
#[derive(Debug, Clone)]
pub(crate) enum ManifestStatusProjection {
    Pending,
    Approved { epoch: u64 },
    Retired { epoch: u64 },
}
#[derive(Debug, Clone)]
pub(crate) struct RegistryAlias {
    alias_label: String,
    namespace: String,
    name: String,
    manifest_digest_hex: String,
    bound_by: String,
    bound_epoch: u64,
    expiry_epoch: u64,
    proof_b64: String,
}
#[derive(Debug, Clone)]
pub(crate) struct RegistryReplicationOrder {
    order_id_hex: String,
    manifest_digest_hex: String,
    issued_by: String,
    issued_epoch: u64,
    deadline_epoch: u64,
    status: ReplicationOrderStatusProjection,
    canonical_order_b64: String,
    assignment_revision: u64,
    order_json: Value,
    providers: Vec<String>,
    provider_completions: Vec<RegistryReplicationCompletion>,
}
#[derive(Debug, Clone)]
struct RegistryReplicationCompletion {
    provider_hex: String,
    completed_by: String,
    completion_epoch: u64,
    assignment_revision: u64,
    provider_owner: String,
    completion_signer: String,
    signer_policy_id_hex: String,
    signer_policy_revision: u64,
    signer_policy_predecessor_digest_hex: Option<String>,
    signer_policy_digest_hex: String,
    finalized_height: u64,
    finalized_block_hash_hex: String,
}
#[derive(Debug, Clone)]
enum ReplicationOrderStatusProjection {
    Pending,
    Completed { epoch: u64 },
    Expired { epoch: u64 },
    Cancelled { epoch: u64 },
}
#[derive(Debug, Clone)]
pub(crate) struct ManifestLineageSummary {
    pub successor_of_hex: Option<String>,
    pub head_hex: String,
    pub depth_to_head: u32,
    pub approved_successor: Option<LineageSuccessor>,
    pub immediate_successor: Option<LineageSuccessor>,
    pub anomalies: Vec<String>,
}
#[derive(Debug, Clone)]
pub(crate) struct LineageSuccessor {
    pub digest_hex: String,
    pub status: ManifestStatusProjection,
    pub approved_epoch: Option<u64>,
    pub status_timestamp_unix: Option<u64>,
}
#[derive(Debug, Clone)]
pub(crate) struct GovernanceSummary {
    pub references: Vec<GovernanceReference>,
    pub revoked: Option<GovernanceReference>,
    pub frozen: Option<GovernanceReference>,
    pub rotated: Option<GovernanceReference>,
}
#[derive(Debug, Clone)]
pub(crate) struct GovernanceReference {
    pub cid: Option<String>,
    pub kind: GovernanceRefKind,
    pub effective_at_unix: Option<u64>,
    #[cfg(test)]
    pub alias_label: Option<String>,
    pub manifest_digest_hex: Option<String>,
    #[cfg(test)]
    pub signers: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GovernanceRefKind {
    AliasRotate,
    FreezeAlias,
    UnfreezeAlias,
    RevokeManifest,
    Other(String),
}
const MAX_LINEAGE_DEPTH: usize = 64;
fn unix_to_rfc3339_string(unix: u64) -> Option<String> {
    let seconds = i64::try_from(unix).ok()?;
    let timestamp = OffsetDateTime::from_unix_timestamp(seconds).ok()?;
    timestamp.format(&Rfc3339).ok()
}
#[cfg(test)]
pub(crate) fn optional_rfc3339(unix: Option<u64>) -> Option<String> {
    unix.and_then(unix_to_rfc3339_string)
}
fn lineage_rfc3339_to_json(unix: Option<u64>) -> Result<Value, json::Error> {
    unix.map_or_else(
        || Ok(Value::Null),
        |unix| {
            unix_to_rfc3339_string(unix)
                .map(Value::String)
                .ok_or_else(|| {
                    json::Error::Message(format!(
                        "lineage timestamp {unix} is outside the canonical RFC 3339 range"
                    ))
                })
        },
    )
}
fn metadata_timestamp_hint(metadata: &Metadata, key: &str) -> Option<u64> {
    let name = Name::from_str(key).ok()?;
    metadata.get(&name).and_then(json_u64)
}
fn json_u64(value: &Json) -> Option<u64> {
    value
        .try_into_any::<Value>()
        .ok()
        .and_then(|json| norito::json::Value::as_u64(&json))
}
fn governance_refs_from_metadata(
    metadata: &Metadata,
    manifest_digest_hex: &str,
) -> Vec<GovernanceReference> {
    let name = match Name::from_str(METADATA_GOVERNANCE_REFS_KEY) {
        Ok(name) => name,
        Err(_) => return Vec::new(),
    };
    let value = match metadata.get(&name) {
        Some(value) => value,
        None => return Vec::new(),
    };
    let parsed: Value = match value.try_into_any::<Value>().ok() {
        Some(parsed) => parsed,
        None => return Vec::new(),
    };
    let Value::Array(entries) = parsed else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter_map(|entry| parse_governance_reference(entry, manifest_digest_hex))
        .collect()
}
fn parse_governance_reference(
    value: Value,
    manifest_digest_hex: &str,
) -> Option<GovernanceReference> {
    let object = value.as_object()?;
    let kind = object
        .get("kind")
        .and_then(norito::json::Value::as_str)
        .map(parse_governance_kind)?;
    let cid = object
        .get("cid")
        .and_then(norito::json::Value::as_str)
        .map(str::to_owned);
    let effective_at_unix = object
        .get("effective_at")
        .and_then(norito::json::Value::as_u64);
    let targets = object.get("targets").and_then(|raw| raw.as_object());
    #[cfg(test)]
    let alias_label = targets
        .and_then(|map| map.get("alias"))
        .and_then(norito::json::Value::as_str)
        .map(str::to_owned);
    let manifest_digest_override = targets
        .and_then(|map| map.get("pin_digest_hex"))
        .and_then(norito::json::Value::as_str)
        .map(str::to_owned);
    let manifest_digest_hex = manifest_digest_override.or_else(|| match kind {
        GovernanceRefKind::RevokeManifest => Some(manifest_digest_hex.to_owned()),
        _ => None,
    });
    #[cfg(test)]
    let signers = object
        .get("signers")
        .and_then(|raw| raw.as_array())
        .map(|array| {
            array
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    Some(GovernanceReference {
        cid,
        kind,
        effective_at_unix,
        #[cfg(test)]
        alias_label,
        manifest_digest_hex,
        #[cfg(test)]
        signers,
    })
}
fn parse_governance_kind(raw: &str) -> GovernanceRefKind {
    match raw {
        "AliasRotate" => GovernanceRefKind::AliasRotate,
        "FreezeAlias" => GovernanceRefKind::FreezeAlias,
        "UnfreezeAlias" => GovernanceRefKind::UnfreezeAlias,
        "RevokeManifest" => GovernanceRefKind::RevokeManifest,
        other => GovernanceRefKind::Other(other.to_owned()),
    }
}
impl GovernanceReference {
    #[cfg(test)]
    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "cid".into(),
            self.cid
                .as_ref()
                .map(|cid| Value::String(cid.clone()))
                .unwrap_or(Value::Null),
        );
        map.insert("kind".into(), Value::String(self.kind.as_str().to_owned()));
        map.insert(
            "effective_at".into(),
            optional_rfc3339(self.effective_at_unix)
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "effective_at_unix".into(),
            json::to_value(&self.effective_at_unix).unwrap_or(Value::Null),
        );
        let mut targets = Map::new();
        if let Some(alias) = &self.alias_label {
            targets.insert("alias".into(), Value::String(alias.clone()));
        }
        if let Some(digest) = &self.manifest_digest_hex {
            targets.insert("pin_digest_hex".into(), Value::String(digest.clone()));
        }
        map.insert("targets".into(), Value::Object(targets));
        let signers = self.signers.iter().cloned().map(Value::String).collect();
        map.insert("signers".into(), Value::Array(signers));
        Value::Object(map)
    }
}
impl GovernanceRefKind {
    #[cfg(test)]
    fn as_str(&self) -> &str {
        match self {
            GovernanceRefKind::AliasRotate => "AliasRotate",
            GovernanceRefKind::FreezeAlias => "FreezeAlias",
            GovernanceRefKind::UnfreezeAlias => "UnfreezeAlias",
            GovernanceRefKind::RevokeManifest => "RevokeManifest",
            GovernanceRefKind::Other(value) => value.as_str(),
        }
    }
}
#[cfg(test)]
pub(crate) fn approved_successor_for_tests(
    digest_hex: impl Into<String>,
    approved_epoch: u64,
    status_timestamp_unix: Option<u64>,
) -> LineageSuccessor {
    LineageSuccessor {
        digest_hex: digest_hex.into(),
        status: ManifestStatusProjection::Approved {
            epoch: approved_epoch,
        },
        approved_epoch: Some(approved_epoch),
        status_timestamp_unix,
    }
}
fn lineage_successor_to_json(successor: &LineageSuccessor) -> Result<Value, json::Error> {
    let mut map = Map::new();
    map.insert(
        "digest_hex".into(),
        Value::String(successor.digest_hex.clone()),
    );
    map.insert("status".into(), successor.status.to_json()?);
    map.insert(
        "approved_epoch".into(),
        json::to_value(&successor.approved_epoch)?,
    );
    map.insert(
        "approved_at".into(),
        lineage_rfc3339_to_json(successor.status_timestamp_unix)?,
    );
    map.insert(
        "status_timestamp_unix".into(),
        json::to_value(&successor.status_timestamp_unix)?,
    );
    Ok(Value::Object(map))
}
pub(crate) fn lineage_to_json(lineage: &ManifestLineageSummary) -> Result<Value, json::Error> {
    let mut map = Map::new();
    map.insert(
        "successor_of_hex".into(),
        lineage
            .successor_of_hex
            .as_ref()
            .map(|hex| Value::String(hex.clone()))
            .unwrap_or(Value::Null),
    );
    map.insert("head_hex".into(), Value::String(lineage.head_hex.clone()));
    map.insert(
        "depth_to_head".into(),
        json::to_value(&lineage.depth_to_head)?,
    );
    let is_head = lineage.immediate_successor.is_none();
    map.insert("is_head".into(), Value::Bool(is_head));
    map.insert(
        "superseded_by".into(),
        match lineage.approved_successor.as_ref() {
            Some(successor) => lineage_successor_to_json(successor)?,
            None => Value::Null,
        },
    );
    map.insert(
        "immediate_successor".into(),
        match lineage.immediate_successor.as_ref() {
            Some(successor) => lineage_successor_to_json(successor)?,
            None => Value::Null,
        },
    );
    map.insert(
        "anomalies".into(),
        Value::Array(
            lineage
                .anomalies
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    Ok(Value::Object(map))
}
/// Errors raised while preparing pin registry projections.
#[derive(Debug, Error)]
pub(crate) enum PinRegistryError {
    #[error("alias {alias_label} references missing manifest {digest_hex}")]
    MissingAliasManifest {
        alias_label: String,
        digest_hex: String,
    },
    #[cfg(test)]
    #[error("failed to serialize manifest metadata for {digest_hex}: {source}")]
    SerializeManifestMetadata {
        digest_hex: String,
        #[source]
        source: json::Error,
    },
    #[cfg(test)]
    #[error("failed to serialize manifest policy for {digest_hex}: {source}")]
    SerializeManifestPolicy {
        digest_hex: String,
        #[source]
        source: json::Error,
    },
    #[cfg(test)]
    #[error("invalid manifest lifecycle for {digest_hex}: {reason}")]
    InvalidManifestLifecycle { digest_hex: String, reason: String },
    #[error("failed to decode replication order payload for {order_id_hex}: {source}")]
    DecodeReplicationOrder {
        order_id_hex: String,
        #[source]
        source: NoritoDecodeError,
    },
    #[error("failed to serialize replication order payload for {order_id_hex}: {source}")]
    SerializeReplicationOrder {
        order_id_hex: String,
        #[source]
        source: json::Error,
    },
    #[error("invalid canonical replication order payload for {order_id_hex}: {reason}")]
    InvalidReplicationOrder {
        order_id_hex: String,
        reason: String,
    },
}
/// Collect the current pin registry snapshot (manifests, aliases, and replication orders).
#[cfg(test)]
pub(crate) fn collect_pin_registry(
    world: &WorldView<'_>,
) -> Result<PinRegistrySnapshot, PinRegistryError> {
    let mut manifests = Vec::new();
    for (digest, record) in world.pin_manifests().iter() {
        manifests.push(RegistryManifest::from_store(digest, record)?);
    }
    manifests.sort_by(|a, b| a.digest_hex.cmp(&b.digest_hex));
    let mut aliases = Vec::new();
    for (alias_id, record) in world.manifest_aliases().iter() {
        aliases.push(RegistryAlias::from_store(alias_id, record));
    }
    aliases.sort_by(|a, b| a.alias_label.cmp(&b.alias_label));
    let mut replication_orders = Vec::new();
    for (order_id, record) in world.replication_orders().iter() {
        replication_orders.push(RegistryReplicationOrder::from_store(order_id, record)?);
    }
    replication_orders.sort_by(|a, b| a.order_id_hex.cmp(&b.order_id_hex));
    Ok(PinRegistrySnapshot {
        manifests,
        aliases,
        replication_orders,
    })
}
#[derive(Debug, Clone)]
struct LineageCandidate {
    digest: ManifestDigest,
    status: ManifestStatusProjection,
    submitted_epoch: u64,
    approved_epoch: Option<u64>,
    status_timestamp_unix: Option<u64>,
}
#[derive(Debug, Clone, Default)]
struct LineageSelection {
    best: Option<LineageCandidate>,
    count: usize,
}
struct LineageState {
    successor_of_hex: Option<String>,
    current_digest: ManifestDigest,
    head: ManifestDigest,
    depth: u32,
    approved_successor: Option<LineageSuccessor>,
    immediate_successor: Option<LineageSuccessor>,
    anomalies: Vec<String>,
    visited: HashSet<ManifestDigest>,
    finished: bool,
}
fn manifest_status_projection(status: PinStatus) -> ManifestStatusProjection {
    match status {
        PinStatus::Pending => ManifestStatusProjection::Pending,
        PinStatus::Approved(epoch) => ManifestStatusProjection::Approved { epoch },
        PinStatus::Retired(epoch) => ManifestStatusProjection::Retired { epoch },
    }
}
fn lineage_candidate_is_better(candidate: &LineageCandidate, current: &LineageCandidate) -> bool {
    match (candidate.approved_epoch, current.approved_epoch) {
        (Some(candidate_epoch), Some(current_epoch)) => {
            candidate_epoch > current_epoch
                || (candidate_epoch == current_epoch && candidate.digest > current.digest)
        }
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => {
            candidate.submitted_epoch > current.submitted_epoch
                || (candidate.submitted_epoch == current.submitted_epoch
                    && candidate.digest > current.digest)
        }
    }
}
fn lineage_successor_from_candidate(candidate: &LineageCandidate) -> LineageSuccessor {
    LineageSuccessor {
        digest_hex: candidate.digest.as_bytes().encode_hex::<String>(),
        status: candidate.status.clone(),
        approved_epoch: candidate.approved_epoch,
        status_timestamp_unix: candidate.status_timestamp_unix,
    }
}
fn deduplicate_lineage_anomalies(anomalies: &mut Vec<String>) {
    let mut seen = HashSet::with_capacity(anomalies.len());
    anomalies.retain(|anomaly| seen.insert(anomaly.clone()));
}
fn collect_manifest_lineages(
    world: &WorldView<'_>,
    digests: &[ManifestDigest],
) -> Vec<ManifestLineageSummary> {
    let mut states = digests
        .iter()
        .map(|digest| {
            let manifest = world.pin_manifests().get(digest);
            let mut visited = HashSet::with_capacity(MAX_LINEAGE_DEPTH.saturating_add(1));
            visited.insert(*digest);
            LineageState {
                successor_of_hex: manifest.and_then(|record| {
                    record
                        .successor_of
                        .as_ref()
                        .map(|predecessor| predecessor.as_bytes().encode_hex::<String>())
                }),
                current_digest: *digest,
                head: *digest,
                depth: 0,
                approved_successor: None,
                immediate_successor: None,
                anomalies: if manifest.is_none() {
                    vec!["ManifestMissing".to_owned()]
                } else {
                    Vec::new()
                },
                visited,
                finished: manifest.is_none(),
            }
        })
        .collect::<Vec<_>>();
    // Resolve every selected alias in one registry scan per lineage hop. This keeps both memory
    // and scan count independent of `page_size * registry_size` while preserving the established
    // deterministic fork selection.
    for hop in 1..=MAX_LINEAGE_DEPTH.saturating_add(1) {
        let mut active = HashMap::<ManifestDigest, Vec<usize>>::new();
        for (index, state) in states.iter().enumerate() {
            if !state.finished {
                active.entry(state.current_digest).or_default().push(index);
            }
        }
        if active.is_empty() {
            break;
        }
        let mut selections = vec![LineageSelection::default(); states.len()];
        for (digest, record) in world.pin_manifests().iter() {
            let Some(predecessor) = record.successor_of.as_ref() else {
                continue;
            };
            let Some(indices) = active.get(predecessor) else {
                continue;
            };
            let candidate = LineageCandidate {
                digest: *digest,
                status: manifest_status_projection(record.status),
                submitted_epoch: record.submitted_epoch,
                approved_epoch: record.approved_epoch,
                status_timestamp_unix: metadata_timestamp_hint(
                    &record.metadata,
                    METADATA_STATUS_TIMESTAMP_KEY,
                ),
            };
            for index in indices {
                let selection = &mut selections[*index];
                selection.count = selection.count.saturating_add(1);
                let replace = selection.best.as_ref().map_or(true, |current| {
                    lineage_candidate_is_better(&candidate, current)
                });
                if replace {
                    selection.best = Some(candidate.clone());
                }
            }
        }
        for (index, state) in states.iter_mut().enumerate() {
            if state.finished {
                continue;
            }
            let selection = &mut selections[index];
            if selection.count > 1 {
                state.anomalies.push("SuccessorForkResolved".to_owned());
            }
            let Some(next) = selection.best.take() else {
                state.finished = true;
                continue;
            };
            if hop > MAX_LINEAGE_DEPTH {
                state.anomalies.push("LineageDepthExceeded".to_owned());
                state.finished = true;
                continue;
            }
            if !state.visited.insert(next.digest) {
                state.anomalies.push("LineageCycleDetected".to_owned());
                state.finished = true;
                continue;
            }
            let successor = lineage_successor_from_candidate(&next);
            if state.immediate_successor.is_none() {
                state.immediate_successor = Some(successor.clone());
            }
            if state.approved_successor.is_none() && next.approved_epoch.is_some() {
                state.approved_successor = Some(successor);
            }
            state.depth = state.depth.saturating_add(1);
            state.head = next.digest;
            state.current_digest = next.digest;
        }
    }
    states
        .into_iter()
        .map(|mut state| {
            deduplicate_lineage_anomalies(&mut state.anomalies);
            ManifestLineageSummary {
                successor_of_hex: state.successor_of_hex,
                head_hex: state.head.as_bytes().encode_hex::<String>(),
                depth_to_head: state.depth,
                approved_successor: state.approved_successor,
                immediate_successor: state.immediate_successor,
                anomalies: state.anomalies,
            }
        })
        .collect()
}
/// Collect one alias page without decoding or retaining the complete pin registry.
///
/// The canonical alias store is already ordered by `(namespace, name)`, which is the same order
/// as the public `namespace/name` label. Filters and the exact count are evaluated on typed records;
/// only the selected page's aliases and manifests are projected. Lineage traversal retains at most
/// the protocol's fixed 64-hop path and scans successors without building a registry-wide index.
pub(crate) fn collect_alias_page(
    world: &WorldView<'_>,
    offset: usize,
    limit: usize,
    namespace_filter: Option<&str>,
    digest_filter: Option<&str>,
) -> Result<AliasPage, PinRegistryError> {
    let digest_filter = match digest_filter {
        None => None,
        Some(encoded) => {
            if encoded.len() != 64 {
                return Ok(AliasPage {
                    total_count: 0,
                    entries: Vec::new(),
                });
            }
            let mut bytes = [0_u8; 32];
            if hex::decode_to_slice(encoded, &mut bytes).is_err() {
                return Ok(AliasPage {
                    total_count: 0,
                    entries: Vec::new(),
                });
            }
            Some(ManifestDigest::new(bytes))
        }
    };
    let limit = limit.min(ALIAS_PAGE_MAX_ITEMS_V1);
    let mut total_count = 0_usize;
    let mut selected = Vec::with_capacity(limit);
    for (alias_id, alias_record) in world.manifest_aliases().iter() {
        if namespace_filter.is_some_and(|namespace| alias_id.namespace != namespace)
            || digest_filter.is_some_and(|digest| alias_record.manifest != digest)
        {
            continue;
        }
        let position = total_count;
        total_count = total_count.saturating_add(1);
        if position < offset || selected.len() >= limit {
            continue;
        }
        let alias = RegistryAlias::from_store(alias_id, alias_record);
        let digest_hex = alias_record.manifest.as_bytes().encode_hex::<String>();
        let manifest_record = world
            .pin_manifests()
            .get(&alias_record.manifest)
            .ok_or_else(|| PinRegistryError::MissingAliasManifest {
                alias_label: alias.alias_label().to_owned(),
                digest_hex: digest_hex.clone(),
            })?;
        let governance = GovernanceSummary::from_references(governance_refs_from_metadata(
            &manifest_record.metadata,
            &digest_hex,
        ));
        selected.push((alias, governance, alias_record.manifest));
    }
    let selected_digests = selected
        .iter()
        .map(|(_, _, digest)| *digest)
        .collect::<Vec<_>>();
    let lineages = collect_manifest_lineages(world, &selected_digests);
    let entries = selected
        .into_iter()
        .zip(lineages)
        .map(|((alias, governance, _), lineage)| AliasPageEntry {
            alias,
            governance,
            lineage,
        })
        .collect();
    Ok(AliasPage {
        total_count,
        entries,
    })
}
/// Collect one replication-order page without decoding the full registry.
///
/// Status and digest filters are evaluated on the stored typed record. Only matching records inside
/// the requested page are decoded and projected, so a small response cannot allocate work
/// proportional to every canonical order payload retained by the ledger.
pub(crate) fn collect_replication_order_page<F>(
    world: &WorldView<'_>,
    offset: usize,
    limit: usize,
    mut matches: F,
) -> Result<ReplicationOrderPage, PinRegistryError>
where
    F: FnMut(&ReplicationOrderRecord) -> bool,
{
    let limit = limit.min(REPLICATION_ORDER_PAGE_MAX_ITEMS_V1);
    let mut total_count = 0_usize;
    let mut orders = Vec::with_capacity(limit);
    for (order_id, record) in world.replication_orders().iter() {
        if !matches(record) {
            continue;
        }
        let position = total_count;
        total_count = total_count.saturating_add(1);
        if position < offset || orders.len() >= limit {
            continue;
        }
        orders.push(RegistryReplicationOrder::from_store(order_id, record)?);
    }
    Ok(ReplicationOrderPage {
        total_count,
        orders,
    })
}
#[cfg(test)]
impl RegistryManifest {
    #[cfg(test)]
    fn from_store(
        digest: &ManifestDigest,
        record: &PinManifestRecord,
    ) -> Result<Self, PinRegistryError> {
        let digest_hex = digest.as_bytes().encode_hex::<String>();
        let approval_history_is_valid = match record.status {
            PinStatus::Pending => record.approved_epoch.is_none(),
            PinStatus::Approved(epoch) => {
                record.approved_epoch == Some(epoch) && record.submitted_epoch <= epoch
            }
            PinStatus::Retired(retired_epoch) => {
                record.submitted_epoch <= retired_epoch
                    && record.approved_epoch.is_none_or(|approved_epoch| {
                        record.submitted_epoch <= approved_epoch && approved_epoch <= retired_epoch
                    })
            }
        };
        if !approval_history_is_valid {
            return Err(PinRegistryError::InvalidManifestLifecycle {
                digest_hex,
                reason: "status, submitted epoch, and retained approval epoch are inconsistent"
                    .to_owned(),
            });
        }
        let chunker = RegistryChunkerHandle {
            profile_id: record.chunker.profile_id,
            namespace: record.chunker.namespace.clone(),
            name: record.chunker.name.clone(),
            semver: record.chunker.semver.clone(),
            multihash_code: record.chunker.multihash_code,
        };
        let pin_policy = pin_policy_to_json(&record.policy).map_err(|source| {
            PinRegistryError::SerializeManifestPolicy {
                digest_hex: digest_hex.clone(),
                source,
            }
        })?;
        let metadata = metadata_to_json(&record.metadata).map_err(|source| {
            PinRegistryError::SerializeManifestMetadata {
                digest_hex: digest_hex.clone(),
                source,
            }
        })?;
        let alias = record.alias.as_ref().map(|binding| AliasBindingProjection {
            namespace: binding.namespace.clone(),
            name: binding.name.clone(),
            proof_b64: BASE64_STD.encode(&binding.proof),
        });
        let status = manifest_status_projection(record.status);
        let successor_of_hex = record
            .successor_of
            .as_ref()
            .map(|parent| parent.as_bytes().encode_hex::<String>());
        let status_timestamp_unix =
            metadata_timestamp_hint(&record.metadata, METADATA_STATUS_TIMESTAMP_KEY);
        let governance_refs = governance_refs_from_metadata(&record.metadata, &digest_hex);
        Ok(Self {
            digest_hex,
            chunker,
            chunk_digest_hex: record.chunk_digest_sha3_256.encode_hex::<String>(),
            pin_policy,
            submitted_by: record.submitted_by.to_string(),
            submitted_epoch: record.submitted_epoch,
            approved_epoch: record.approved_epoch,
            alias,
            metadata,
            successor_of_hex,
            status,
            council_envelope_digest_hex: record
                .council_envelope_digest
                .map(|digest| digest.encode_hex::<String>()),
            status_timestamp_unix,
            governance_refs,
        })
    }
    #[cfg(test)]
    pub(crate) fn to_json(&self) -> Result<Value, json::Error> {
        let mut map = Map::new();
        map.insert("digest_hex".into(), Value::String(self.digest_hex.clone()));
        map.insert("chunker".into(), self.chunker.to_json()?);
        map.insert(
            "chunk_digest_sha3_256_hex".into(),
            Value::String(self.chunk_digest_hex.clone()),
        );
        map.insert("pin_policy".into(), self.pin_policy.clone());
        map.insert(
            "submitted_by".into(),
            Value::String(self.submitted_by.clone()),
        );
        map.insert(
            "submitted_epoch".into(),
            json::to_value(&self.submitted_epoch)?,
        );
        map.insert(
            "approved_epoch".into(),
            json::to_value(&self.approved_epoch)?,
        );
        map.insert("status".into(), self.status.to_json()?);
        map.insert("metadata".into(), self.metadata.clone());
        if let Some(alias) = &self.alias {
            map.insert("alias".into(), alias.to_json());
        } else {
            map.insert("alias".into(), Value::Null);
        }
        map.insert(
            "successor_of_hex".into(),
            self.successor_of_hex
                .as_ref()
                .map(|hex| Value::String(hex.clone()))
                .unwrap_or(Value::Null),
        );
        map.insert(
            "status_timestamp_unix".into(),
            json::to_value(&self.status_timestamp_unix)?,
        );
        let governance_values = self
            .governance_refs
            .iter()
            .map(GovernanceReference::to_json)
            .collect();
        map.insert("governance_refs".into(), Value::Array(governance_values));
        map.insert(
            "council_envelope_digest_hex".into(),
            self.council_envelope_digest_hex
                .as_ref()
                .map(|hex| Value::String(hex.clone()))
                .unwrap_or(Value::Null),
        );
        Ok(Value::Object(map))
    }
}
impl GovernanceSummary {
    fn from_references(references: Vec<GovernanceReference>) -> Self {
        let mut revoked = None;
        let mut frozen = None;
        let mut rotated = None;
        for reference in &references {
            match reference.kind {
                GovernanceRefKind::RevokeManifest => revoked = Some(reference.clone()),
                GovernanceRefKind::FreezeAlias => frozen = Some(reference.clone()),
                GovernanceRefKind::AliasRotate => rotated = Some(reference.clone()),
                GovernanceRefKind::UnfreezeAlias | GovernanceRefKind::Other(_) => {}
            }
        }
        Self {
            references,
            revoked,
            frozen,
            rotated,
        }
    }
}
#[cfg(test)]
impl RegistryChunkerHandle {
    #[cfg(test)]
    fn to_json(&self) -> Result<Value, json::Error> {
        let mut map = Map::new();
        map.insert("profile_id".into(), json::to_value(&self.profile_id)?);
        map.insert("namespace".into(), Value::String(self.namespace.clone()));
        map.insert("name".into(), Value::String(self.name.clone()));
        map.insert("semver".into(), Value::String(self.semver.clone()));
        map.insert(
            "multihash_code".into(),
            json::to_value(&self.multihash_code)?,
        );
        Ok(Value::Object(map))
    }
}
#[cfg(test)]
impl AliasBindingProjection {
    #[cfg(test)]
    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("namespace".into(), Value::String(self.namespace.clone()));
        map.insert("name".into(), Value::String(self.name.clone()));
        map.insert("proof_b64".into(), Value::String(self.proof_b64.clone()));
        Value::Object(map)
    }
}
impl ManifestStatusProjection {
    fn label(&self) -> &'static str {
        match self {
            ManifestStatusProjection::Pending => "pending",
            ManifestStatusProjection::Approved { .. } => "approved",
            ManifestStatusProjection::Retired { .. } => "retired",
        }
    }
    fn to_json(&self) -> Result<Value, json::Error> {
        let mut map = Map::new();
        map.insert("state".into(), Value::String(self.label().to_owned()));
        match self {
            ManifestStatusProjection::Approved { epoch }
            | ManifestStatusProjection::Retired { epoch } => {
                map.insert("epoch".into(), json::to_value(epoch)?);
            }
            ManifestStatusProjection::Pending => {}
        }
        Ok(Value::Object(map))
    }
}
impl RegistryAlias {
    fn from_store(alias_id: &ManifestAliasId, record: &ManifestAliasRecord) -> Self {
        let alias_label = alias_id.as_label();
        Self {
            alias_label,
            namespace: alias_id.namespace.clone(),
            name: alias_id.name.clone(),
            manifest_digest_hex: record.manifest.as_bytes().encode_hex::<String>(),
            bound_by: record.bound_by.to_string(),
            bound_epoch: record.bound_epoch,
            expiry_epoch: record.expiry_epoch,
            proof_b64: BASE64_STD.encode(&record.binding.proof),
        }
    }
    pub(crate) fn alias_label(&self) -> &str {
        &self.alias_label
    }
    pub(crate) fn proof_b64(&self) -> &str {
        &self.proof_b64
    }
    pub(crate) fn to_json(&self) -> Result<Value, json::Error> {
        let mut map = Map::new();
        map.insert("alias".into(), Value::String(self.alias_label.clone()));
        map.insert("namespace".into(), Value::String(self.namespace.clone()));
        map.insert("name".into(), Value::String(self.name.clone()));
        map.insert(
            "manifest_digest_hex".into(),
            Value::String(self.manifest_digest_hex.clone()),
        );
        map.insert("bound_by".into(), Value::String(self.bound_by.clone()));
        map.insert("bound_epoch".into(), json::to_value(&self.bound_epoch)?);
        map.insert("expiry_epoch".into(), json::to_value(&self.expiry_epoch)?);
        map.insert("proof_b64".into(), Value::String(self.proof_b64.clone()));
        Ok(Value::Object(map))
    }
}
impl RegistryReplicationOrder {
    fn from_store(
        order_id: &ReplicationOrderId,
        record: &ReplicationOrderRecord,
    ) -> Result<Self, PinRegistryError> {
        let order_id_hex = order_id.as_bytes().encode_hex::<String>();
        if record.canonical_order.is_empty()
            || record.canonical_order.len() > REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1
        {
            return Err(PinRegistryError::InvalidReplicationOrder {
                order_id_hex,
                reason: format!(
                    "canonical payload length must be 1..={REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1} bytes"
                ),
            });
        }
        let order: ReplicationOrderV1 = decode_from_bytes_with_limits(
            &record.canonical_order,
            REPLICATION_ORDER_DECODE_LIMITS_V1,
        )
        .map_err(|source| PinRegistryError::DecodeReplicationOrder {
            order_id_hex: order_id_hex.clone(),
            source,
        })?;
        order
            .validate()
            .map_err(|error| PinRegistryError::InvalidReplicationOrder {
                order_id_hex: order_id_hex.clone(),
                reason: error.to_string(),
            })?;
        let canonical =
            to_bytes(&order).map_err(|error| PinRegistryError::InvalidReplicationOrder {
                order_id_hex: order_id_hex.clone(),
                reason: format!("failed to re-encode payload: {error}"),
            })?;
        if canonical != record.canonical_order
            || order.order_id != *record.order_id.as_bytes()
            || order.manifest_digest != *record.manifest_digest.as_bytes()
            || order.manifest_cid.as_slice() != record.manifest_root_cid.as_bytes()
            || order.issued_at != record.issued_epoch
            || order.deadline_at != record.deadline_epoch
        {
            return Err(PinRegistryError::InvalidReplicationOrder {
                order_id_hex,
                reason: "payload is non-canonical or substituted from its ledger record".to_owned(),
            });
        }
        let target_replicas = usize::from(order.target_replicas);
        if record.assignment_revision == 0 {
            return Err(PinRegistryError::InvalidReplicationOrder {
                order_id_hex,
                reason: "assignment revision must be non-zero".to_owned(),
            });
        }
        if record.provider_completions.len() > target_replicas {
            return Err(PinRegistryError::InvalidReplicationOrder {
                order_id_hex,
                reason: "provider completion count exceeds the redundancy target".to_owned(),
            });
        }
        let mut completed_providers = HashSet::new();
        let mut previous_completion_epoch = None;
        for completion in &record.provider_completions {
            if !order
                .assignments
                .iter()
                .any(|assignment| assignment.provider_id == *completion.provider_id.as_bytes())
                || !completed_providers.insert(*completion.provider_id.as_bytes())
                || completion.completion_epoch < record.issued_epoch
                || completion.completion_epoch > record.deadline_epoch
                || previous_completion_epoch
                    .is_some_and(|previous| completion.completion_epoch < previous)
                || completion.assignment_revision != record.assignment_revision
                || !completion.completion_authority.is_valid()
                || completion.completed_by != completion.completion_authority.completion_signer
                || !completion.finalized_anchor.is_valid()
            {
                return Err(PinRegistryError::InvalidReplicationOrder {
                    order_id_hex,
                    reason: "provider completion state is duplicate, out of order, unassigned, outside the ledger epoch window, or not bound to the exact assignment, authority, and finalized anchor".to_owned(),
                });
            }
            previous_completion_epoch = Some(completion.completion_epoch);
        }
        let lifecycle_consistent = match record.status {
            ReplicationOrderStatus::Pending => record.provider_completions.len() < target_replicas,
            ReplicationOrderStatus::Cancelled(epoch) => {
                record.provider_completions.len() < target_replicas
                    && epoch >= record.issued_epoch
                    && epoch <= record.deadline_epoch
            }
            ReplicationOrderStatus::Expired(epoch) => {
                record.provider_completions.len() < target_replicas && epoch > record.deadline_epoch
            }
            ReplicationOrderStatus::Completed(epoch) => {
                record.provider_completions.len() == target_replicas
                    && record
                        .provider_completions
                        .last()
                        .is_some_and(|completion| completion.completion_epoch == epoch)
            }
        };
        if !lifecycle_consistent {
            return Err(PinRegistryError::InvalidReplicationOrder {
                order_id_hex,
                reason: "lifecycle is inconsistent with provider completion state".to_owned(),
            });
        }
        let order_json = replication_order_to_json(&order).map_err(|source| {
            PinRegistryError::SerializeReplicationOrder {
                order_id_hex: order_id_hex.clone(),
                source,
            }
        })?;
        let providers = order
            .assignments
            .iter()
            .map(|assignment| hex::encode(assignment.provider_id))
            .collect();
        let provider_completions = record
            .provider_completions
            .iter()
            .map(|completion| RegistryReplicationCompletion {
                provider_hex: hex::encode(completion.provider_id.as_bytes()),
                completed_by: completion.completed_by.to_string(),
                completion_epoch: completion.completion_epoch,
                assignment_revision: completion.assignment_revision,
                provider_owner: completion.completion_authority.provider_owner.to_string(),
                completion_signer: completion
                    .completion_authority
                    .completion_signer
                    .to_string(),
                signer_policy_id_hex: hex::encode(
                    completion.completion_authority.signer_policy.policy_id,
                ),
                signer_policy_revision: completion.completion_authority.signer_policy.revision,
                signer_policy_predecessor_digest_hex: completion
                    .completion_authority
                    .signer_policy
                    .predecessor_digest
                    .map(hex::encode),
                signer_policy_digest_hex: hex::encode(
                    completion.completion_authority.signer_policy.policy_digest,
                ),
                finalized_height: completion.finalized_anchor.height,
                finalized_block_hash_hex: hex::encode(completion.finalized_anchor.block_hash),
            })
            .collect();
        let status = match record.status {
            ReplicationOrderStatus::Pending => ReplicationOrderStatusProjection::Pending,
            ReplicationOrderStatus::Completed(epoch) => {
                ReplicationOrderStatusProjection::Completed { epoch }
            }
            ReplicationOrderStatus::Expired(epoch) => {
                ReplicationOrderStatusProjection::Expired { epoch }
            }
            ReplicationOrderStatus::Cancelled(epoch) => {
                ReplicationOrderStatusProjection::Cancelled { epoch }
            }
        };
        Ok(Self {
            order_id_hex,
            manifest_digest_hex: record.manifest_digest.as_bytes().encode_hex::<String>(),
            issued_by: record.issued_by.to_string(),
            issued_epoch: record.issued_epoch,
            deadline_epoch: record.deadline_epoch,
            status,
            canonical_order_b64: BASE64_STD.encode(&record.canonical_order),
            assignment_revision: record.assignment_revision,
            order_json,
            providers,
            provider_completions,
        })
    }
    /// Epoch when the replication order was issued.
    #[cfg(test)]
    pub(crate) fn issued_epoch(&self) -> u64 {
        self.issued_epoch
    }
    /// Epoch by which the replication order must complete.
    #[cfg(test)]
    pub(crate) fn deadline_epoch(&self) -> u64 {
        self.deadline_epoch
    }
    /// Completion epoch when the order succeeded, if applicable.
    #[cfg(test)]
    pub(crate) fn completion_epoch(&self) -> Option<u64> {
        match self.status {
            ReplicationOrderStatusProjection::Completed { epoch } => Some(epoch),
            _ => None,
        }
    }
    pub(crate) fn to_json(&self) -> Result<Value, json::Error> {
        let mut map = Map::new();
        map.insert(
            "order_id_hex".into(),
            Value::String(self.order_id_hex.clone()),
        );
        map.insert(
            "manifest_digest_hex".into(),
            Value::String(self.manifest_digest_hex.clone()),
        );
        map.insert("issued_by".into(), Value::String(self.issued_by.clone()));
        map.insert("issued_epoch".into(), json::to_value(&self.issued_epoch)?);
        map.insert(
            "deadline_epoch".into(),
            json::to_value(&self.deadline_epoch)?,
        );
        map.insert("status".into(), self.status.to_json()?);
        map.insert(
            "canonical_order_b64".into(),
            Value::String(self.canonical_order_b64.clone()),
        );
        map.insert(
            "assignment_revision".into(),
            json::to_value(&self.assignment_revision)?,
        );
        map.insert("order".into(), self.order_json.clone());
        let provider_completions = self
            .provider_completions
            .iter()
            .map(RegistryReplicationCompletion::to_json)
            .collect::<Result<Vec<_>, _>>()?;
        map.insert(
            "provider_completions".into(),
            Value::Array(provider_completions),
        );
        let providers = self
            .providers
            .iter()
            .map(|provider| Value::String(provider.clone()))
            .collect();
        map.insert("providers".into(), Value::Array(providers));
        Ok(Value::Object(map))
    }
}
impl RegistryReplicationCompletion {
    fn to_json(&self) -> Result<Value, json::Error> {
        let mut map = Map::new();
        map.insert(
            "provider_hex".into(),
            Value::String(self.provider_hex.clone()),
        );
        map.insert(
            "completed_by".into(),
            Value::String(self.completed_by.clone()),
        );
        map.insert(
            "completion_epoch".into(),
            json::to_value(&self.completion_epoch)?,
        );
        map.insert(
            "assignment_revision".into(),
            json::to_value(&self.assignment_revision)?,
        );
        let mut signer_policy = Map::new();
        signer_policy.insert(
            "policy_id_hex".into(),
            Value::String(self.signer_policy_id_hex.clone()),
        );
        signer_policy.insert(
            "revision".into(),
            json::to_value(&self.signer_policy_revision)?,
        );
        signer_policy.insert(
            "predecessor_digest_hex".into(),
            self.signer_policy_predecessor_digest_hex
                .as_ref()
                .map_or(Value::Null, |digest| Value::String(digest.clone())),
        );
        signer_policy.insert(
            "policy_digest_hex".into(),
            Value::String(self.signer_policy_digest_hex.clone()),
        );
        let mut completion_authority = Map::new();
        completion_authority.insert(
            "provider_owner".into(),
            Value::String(self.provider_owner.clone()),
        );
        completion_authority.insert(
            "completion_signer".into(),
            Value::String(self.completion_signer.clone()),
        );
        completion_authority.insert("signer_policy".into(), Value::Object(signer_policy));
        map.insert(
            "completion_authority".into(),
            Value::Object(completion_authority),
        );
        let mut finalized_anchor = Map::new();
        finalized_anchor.insert("height".into(), json::to_value(&self.finalized_height)?);
        finalized_anchor.insert(
            "block_hash_hex".into(),
            Value::String(self.finalized_block_hash_hex.clone()),
        );
        map.insert("finalized_anchor".into(), Value::Object(finalized_anchor));
        Ok(Value::Object(map))
    }
}
impl ReplicationOrderStatusProjection {
    fn label(&self) -> &'static str {
        match self {
            ReplicationOrderStatusProjection::Pending => "pending",
            ReplicationOrderStatusProjection::Completed { .. } => "completed",
            ReplicationOrderStatusProjection::Expired { .. } => "expired",
            ReplicationOrderStatusProjection::Cancelled { .. } => "cancelled",
        }
    }
    fn to_json(&self) -> Result<Value, json::Error> {
        let mut map = Map::new();
        map.insert("state".into(), Value::String(self.label().to_owned()));
        match self {
            ReplicationOrderStatusProjection::Completed { epoch }
            | ReplicationOrderStatusProjection::Expired { epoch }
            | ReplicationOrderStatusProjection::Cancelled { epoch } => {
                map.insert("epoch".into(), json::to_value(epoch)?);
            }
            ReplicationOrderStatusProjection::Pending => {}
        }
        Ok(Value::Object(map))
    }
}
#[cfg(test)]
fn pin_policy_to_json(policy: &PinPolicy) -> Result<Value, json::Error> {
    let mut map = Map::new();
    map.insert("min_replicas".into(), json::to_value(&policy.min_replicas)?);
    map.insert(
        "storage_class".into(),
        Value::String(storage_class_label(policy.storage_class).to_owned()),
    );
    map.insert(
        "retention_epoch".into(),
        json::to_value(&policy.retention_epoch)?,
    );
    Ok(Value::Object(map))
}
fn replication_order_to_json(order: &ReplicationOrderV1) -> Result<Value, json::Error> {
    let mut map = Map::new();
    map.insert("version".into(), json::to_value(&order.version)?);
    map.insert(
        "order_id_hex".into(),
        Value::String(order.order_id.encode_hex::<String>()),
    );
    map.insert(
        "manifest_cid_b64".into(),
        Value::String(BASE64_STD.encode(&order.manifest_cid)),
    );
    map.insert(
        "manifest_digest_hex".into(),
        Value::String(order.manifest_digest.encode_hex::<String>()),
    );
    map.insert(
        "chunking_profile".into(),
        Value::String(order.chunking_profile.clone()),
    );
    map.insert(
        "target_replicas".into(),
        json::to_value(&order.target_replicas)?,
    );
    let assignments = order
        .assignments
        .iter()
        .map(|assignment| {
            let mut assignment_json = Map::new();
            assignment_json.insert(
                "provider_id_hex".into(),
                Value::String(assignment.provider_id.encode_hex::<String>()),
            );
            assignment_json.insert("slice_gib".into(), json::to_value(&assignment.slice_gib)?);
            assignment_json.insert(
                "lane".into(),
                assignment
                    .lane
                    .as_ref()
                    .map(|lane| Value::String(lane.clone()))
                    .unwrap_or(Value::Null),
            );
            Ok(Value::Object(assignment_json))
        })
        .collect::<Result<Vec<_>, json::Error>>()?;
    map.insert("assignments".into(), Value::Array(assignments));
    map.insert("issued_at".into(), json::to_value(&order.issued_at)?);
    map.insert("deadline_at".into(), json::to_value(&order.deadline_at)?);
    let mut sla = Map::new();
    sla.insert(
        "ingest_deadline_secs".into(),
        json::to_value(&order.sla.ingest_deadline_secs)?,
    );
    sla.insert(
        "min_availability_percent_milli".into(),
        json::to_value(&order.sla.min_availability_percent_milli)?,
    );
    sla.insert(
        "min_por_success_percent_milli".into(),
        json::to_value(&order.sla.min_por_success_percent_milli)?,
    );
    map.insert("sla".into(), Value::Object(sla));
    map.insert("metadata".into(), json::to_value(&order.metadata)?);
    Ok(Value::Object(map))
}
#[cfg(test)]
fn storage_class_label(class: StorageClass) -> &'static str {
    match class {
        StorageClass::Hot => "hot",
        StorageClass::Warm => "warm",
        StorageClass::Cold => "cold",
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lineage_anomalies_are_unique_without_reordering() {
        let mut anomalies = vec![
            "SuccessorForkResolved".to_owned(),
            "LineageCycleDetected".to_owned(),
            "SuccessorForkResolved".to_owned(),
        ];
        deduplicate_lineage_anomalies(&mut anomalies);
        assert_eq!(
            anomalies,
            vec![
                "SuccessorForkResolved".to_owned(),
                "LineageCycleDetected".to_owned(),
            ]
        );
    }
    use base64::engine::general_purpose::STANDARD as BASE64_STD;
    use iroha_crypto::PublicKey;
    use iroha_data_model::{
        account::AccountId,
        sorafs::{
            capacity::{CapacityDeclarationRecord, CapacityFeeLedgerEntry},
            pin_registry::{
                ChunkerProfileHandle, ManifestAliasBinding, ManifestDigest, ManifestRootCid,
                PinManifestRecord, PinPolicy, ProviderIngestCompletionAuthorityV1,
                ProviderIngestCompletionSignerPolicyV1, ProviderIngestFinalizedAnchorV1,
                ReplicationOrderCompletionRecord, ReplicationOrderId, ReplicationOrderRecord,
                ReplicationOrderStatus, StorageClass,
            },
            pricing::ProviderCreditRecord,
        },
    };
    use iroha_model_base::metadata::Metadata;
    use sorafs_manifest::{
        capacity::{
            CapacityDeclarationV1, ChunkerCommitmentV1, LaneCommitmentV1, PricingScheduleV1,
            REPLICATION_ORDER_VERSION_V1, ReplicationAssignmentV1, ReplicationOrderSlaV1,
            ReplicationOrderV1,
        },
        provider_advert::StakePointer,
    };
    fn fixture_manifest_root_cid() -> ManifestRootCid {
        let manifest: sorafs_manifest::ManifestV1 = norito::decode_from_bytes(include_bytes!(
            "../../../../fixtures/sorafs_gateway/1.0.0/manifest_v1.to"
        ))
        .expect("decode canonical SoraFS fixture manifest");
        ManifestRootCid::try_from_slice(&manifest.root_cid)
            .expect("fixture manifest root CID must be canonical")
    }
    fn sample_declaration() -> (ProviderId, CapacityDeclarationRecord, CapacityDeclarationV1) {
        let provider_id = ProviderId::new([0x11; 32]);
        let declaration = CapacityDeclarationV1 {
            version: sorafs_manifest::capacity::CAPACITY_DECLARATION_VERSION_V1,
            provider_id: provider_id.as_bytes().to_owned(),
            stake: StakePointer {
                pool_id: [0xAA; 32],
                stake_amount: "42".parse().expect("canonical stake quantity"),
            },
            committed_capacity_gib: 1_024,
            chunker_commitments: vec![ChunkerCommitmentV1 {
                profile_id: "sorafs.sf1@1.0.0".to_owned(),
                profile_aliases: Some(vec!["sorafs-sf1".to_owned()]),
                committed_gib: 1_024,
                capability_refs: vec![],
            }],
            lane_commitments: vec![LaneCommitmentV1 {
                lane_id: "global".to_owned(),
                max_gib: 1_024,
            }],
            pricing: Some(PricingScheduleV1 {
                currency: "xor".to_owned(),
                rate_per_gib_hour_milliu: 1_000,
                min_commitment_hours: Some(24),
                notes: Some("standard tier".to_owned()),
            }),
            valid_from: 1_700_000_000,
            valid_until: 1_700_086_400,
            metadata: Vec::new(),
        };
        let encoded = norito::to_bytes(&declaration).expect("encode declaration");
        let record = CapacityDeclarationRecord::new(
            provider_id,
            encoded,
            declaration.committed_capacity_gib,
            42,
            48,
            96,
            Metadata::default(),
        );
        (provider_id, record, declaration)
    }
    #[test]
    fn build_declarations_decodes_records() {
        let (provider_id, record, declaration) = sample_declaration();
        let entries = [(provider_id, record)];
        let declarations = build_declarations(entries.iter().map(|(id, rec)| (id, rec)))
            .expect("build declarations");
        assert_eq!(declarations.len(), 1);
        let json_value = declarations[0]
            .declaration_json
            .as_object()
            .expect("json object");
        let norito_b64 = json_value
            .get("norito_b64")
            .and_then(Value::as_str)
            .expect("norito base64");
        let canonical_bytes = BASE64_STD
            .decode(norito_b64.as_bytes())
            .expect("decode base64 payload");
        let decoded: CapacityDeclarationV1 =
            norito::decode_from_bytes(&canonical_bytes).expect("decode declaration bytes");
        assert_eq!(decoded.provider_id, declaration.provider_id);
        assert_eq!(declarations[0].registered_epoch, 42);
    }
    #[test]
    fn build_fee_ledger_projects_entries() {
        let provider_id = ProviderId::new([0x22; 32]);
        let storage_fee: Quantity = "0.0000000001".parse().expect("sub-nano quantity");
        let egress_fee: Quantity = "12000".parse().expect("egress quantity");
        let accrued_fee = storage_fee
            .checked_add(&egress_fee)
            .expect("representable accrued fee");
        let entry = CapacityFeeLedgerEntry {
            provider_id,
            total_declared_gib: 10_240,
            total_utilised_gib: 8_192,
            storage_fee: storage_fee.clone(),
            egress_fee: egress_fee.clone(),
            accrued_fee: accrued_fee.clone(),
            expected_settlement: "84000.25".parse().expect("settlement quantity"),
            penalty_slashed: Quantity::zero(),
            penalty_events: 0,
            last_updated_epoch: 128,
            last_window_start_epoch: 120,
            last_window_end_epoch: 128,
            last_nonce: 7,
        };
        let entries = [(provider_id, entry)];
        let ledger = build_fee_ledger(entries.iter().map(|(id, rec)| (id, rec)));
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger[0].provider_id_hex,
            provider_id.as_bytes().encode_hex::<String>()
        );
        assert_eq!(ledger[0].total_utilised_gib, 8_192);
        assert_eq!(ledger[0].storage_fee, storage_fee);
        assert_eq!(ledger[0].egress_fee, egress_fee);
        assert_eq!(ledger[0].accrued_fee, accrued_fee);
        assert_eq!(ledger[0].expected_settlement.to_string(), "84000.25");
        let json = ledger[0].clone().into_json().expect("serialize fee ledger");
        let object = json.as_object().expect("fee ledger object");
        assert_eq!(
            object.get("storage_fee").and_then(Value::as_str),
            Some("0.0000000001")
        );
        for retired in [
            "storage_fee_nano",
            "egress_fee_nano",
            "accrued_fee_nano",
            "expected_settlement_nano",
            "penalty_slashed_nano",
        ] {
            assert!(
                !object.contains_key(retired),
                "retired fixed-nano field {retired} must not be exposed"
            );
        }
    }
    #[test]
    fn build_credit_ledger_preserves_canonical_quantities() {
        let provider_id = ProviderId::new([0x23; 32]);
        let available_credit: Quantity = "340282366920938463463374607431768211456.0000000001"
            .parse()
            .expect("quantity wider than u128 with a sub-nano fraction");
        let mut record = ProviderCreditRecord::new(
            provider_id,
            available_credit.clone(),
            "12.5".parse().expect("bonded quantity"),
            "10".parse().expect("required bond quantity"),
            "0.0000000000000000000000000001"
                .parse()
                .expect("scale-28 settlement quantity"),
            32,
            64,
            Metadata::default(),
        );
        record.slashed = "0.25".parse().expect("slashed quantity");
        let entries = [(provider_id, record)];
        let ledger = build_credit_ledger(entries.iter().map(|(id, rec)| (id, rec)));
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].available_credit, available_credit);
        let json = ledger[0]
            .clone()
            .into_json()
            .expect("serialize credit ledger");
        let object = json.as_object().expect("credit ledger object");
        assert_eq!(
            object.get("available_credit").and_then(Value::as_str),
            Some("340282366920938463463374607431768211456.0000000001")
        );
        assert_eq!(
            object.get("expected_settlement").and_then(Value::as_str),
            Some("0.0000000000000000000000000001")
        );
        for retired in [
            "available_credit_nano",
            "bonded_nano",
            "required_bond_nano",
            "expected_settlement_nano",
            "slashed_nano",
        ] {
            assert!(
                !object.contains_key(retired),
                "retired fixed-nano field {retired} must not be exposed"
            );
        }
    }
    #[test]
    fn build_disputes_projects_entries() {
        use sorafs_manifest::capacity::{
            CapacityDisputeEvidenceV1, CapacityDisputeKind, CapacityDisputeV1,
        };
        let provider_id = ProviderId::new([0x33; 32]);
        let dispute = CapacityDisputeV1 {
            version: sorafs_manifest::capacity::CAPACITY_DISPUTE_VERSION_V1,
            provider_id: provider_id.as_bytes().to_owned(),
            complainant_id: [0x44; 32],
            replication_order_id: Some([0x55; 32]),
            kind: CapacityDisputeKind::ReplicationShortfall,
            evidence: CapacityDisputeEvidenceV1 {
                evidence_digest: [0xAB; 32],
                media_type: Some("application/zip".into()),
                uri: Some("https://example.com/evidence.zip".into()),
                size_bytes: Some(1024),
            },
            submitted_epoch: 1_700_100_000,
            description: "provider missed ingestion window".into(),
            requested_remedy: Some("slash stake".into()),
        };
        let payload = norito::to_bytes(&dispute).expect("encode dispute");
        let canonical_payload = payload.clone();
        let dispute_id = CapacityDisputeId::new(*blake3::hash(&payload).as_bytes());
        let evidence = CapacityDisputeEvidence {
            digest: dispute.evidence.evidence_digest,
            media_type: dispute.evidence.media_type.clone(),
            uri: dispute.evidence.uri.clone(),
            size_bytes: dispute.evidence.size_bytes,
        };
        let record = CapacityDisputeRecord::new_pending(
            dispute_id,
            provider_id,
            dispute.complainant_id,
            dispute.replication_order_id,
            dispute.kind as u8,
            dispute.submitted_epoch,
            dispute.description.clone(),
            dispute.requested_remedy.clone(),
            evidence,
            payload,
        );
        let entries = [(dispute_id, record)];
        let disputes = build_disputes(entries.iter().map(|(id, rec)| (id, rec)));
        assert_eq!(disputes.len(), 1);
        let json = disputes[0].clone().into_json().expect("serialize dispute");
        let object = json.as_object().expect("json object");
        assert_eq!(
            object.get("kind").and_then(Value::as_str),
            Some("replication_shortfall")
        );
        assert_eq!(
            object.get("status").and_then(Value::as_str),
            Some("pending")
        );
        assert_eq!(
            object
                .get("dispute_id_hex")
                .and_then(Value::as_str)
                .map(str::len),
            Some(64)
        );
        let dispute_b64 = object
            .get("dispute_b64")
            .and_then(Value::as_str)
            .expect("dispute base64 field");
        let decoded = BASE64_STD
            .decode(dispute_b64.as_bytes())
            .expect("decode dispute payload");
        assert_eq!(decoded, canonical_payload);
    }
    #[test]
    fn registry_manifest_to_json_includes_alias() {
        let digest = ManifestDigest::new([0xAA; 32]);
        let chunker = ChunkerProfileHandle {
            profile_id: 1,
            namespace: "sorafs".to_owned(),
            name: "sf1".to_owned(),
            semver: "1.0.0".to_owned(),
            multihash_code: 0x1F,
        };
        let policy = PinPolicy {
            min_replicas: 2,
            storage_class: StorageClass::Hot,
            retention_epoch: 512,
        };
        let alias = ManifestAliasBinding {
            name: "docs".to_owned(),
            namespace: "sora".to_owned(),
            proof: vec![0xAB, 0xCD, 0xEF],
        };
        let public_key: PublicKey =
            "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
                .parse()
                .expect("public key");
        let submitter = AccountId::new(public_key);
        let mut record = PinManifestRecord::new(
            digest,
            fixture_manifest_root_cid(),
            chunker,
            [0xBB; 32],
            [0; 32],
            0,
            policy,
            submitter,
            42,
            Some(alias.clone()),
            None,
            Metadata::default(),
        );
        record.approve(64, Some([0x10; 32]));
        let manifest = RegistryManifest::from_store(&digest, &record).expect("registry manifest");
        let value = manifest.to_json().expect("serialize manifest");
        let object = value.as_object().expect("manifest json object");
        let expected_digest = hex::encode(digest.as_bytes());
        assert_eq!(
            object.get("digest_hex").and_then(Value::as_str),
            Some(expected_digest.as_str())
        );
        let status = object
            .get("status")
            .and_then(Value::as_object)
            .expect("status json");
        assert_eq!(
            status.get("state").and_then(Value::as_str),
            Some("approved")
        );
        assert_eq!(
            object.get("approved_epoch").and_then(Value::as_u64),
            Some(64)
        );
        let alias_json = object
            .get("alias")
            .and_then(Value::as_object)
            .expect("alias json");
        assert_eq!(alias_json.get("name").and_then(Value::as_str), Some("docs"));
        let expected_proof = BASE64_STD.encode(alias.proof);
        assert_eq!(
            alias_json.get("proof_b64").and_then(Value::as_str),
            Some(expected_proof.as_str())
        );
        let mut invalid_history = record.clone();
        invalid_history.approved_epoch = None;
        assert!(matches!(
            RegistryManifest::from_store(&digest, &invalid_history),
            Err(PinRegistryError::InvalidManifestLifecycle { .. })
        ));
    }
    #[test]
    fn registry_replication_order_serializes_providers() {
        let manifest_root_cid = fixture_manifest_root_cid();
        let order_payload = ReplicationOrderV1 {
            version: REPLICATION_ORDER_VERSION_V1,
            order_id: [0x11; 32],
            manifest_cid: manifest_root_cid.as_bytes().to_vec(),
            manifest_digest: [0x55; 32],
            chunking_profile: "sorafs.sf1@1.0.0".to_owned(),
            target_replicas: 1,
            assignments: vec![
                ReplicationAssignmentV1 {
                    provider_id: [0x22; 32],
                    slice_gib: 1,
                    lane: None,
                },
                ReplicationAssignmentV1 {
                    provider_id: [0x33; 32],
                    slice_gib: 1,
                    lane: None,
                },
            ],
            issued_at: 10,
            deadline_at: 20,
            sla: ReplicationOrderSlaV1 {
                ingest_deadline_secs: 10,
                min_availability_percent_milli: 99_000,
                min_por_success_percent_milli: 98_000,
            },
            metadata: Vec::new(),
        };
        order_payload
            .validate()
            .expect("valid replication order fixture");
        let canonical = norito::to_bytes(&order_payload).expect("encode order");
        let public_key: PublicKey =
            "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
                .parse()
                .expect("public key");
        let issuer = AccountId::new(public_key);
        let signer_key =
            iroha_crypto::KeyPair::try_from_seed(vec![0xd3; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("dedicated completion key");
        let completion_signer = AccountId::new(signer_key.public_key().clone());
        assert_ne!(issuer, completion_signer);
        let record = ReplicationOrderRecord {
            order_id: ReplicationOrderId::new(order_payload.order_id),
            manifest_digest: ManifestDigest::new([0x55; 32]),
            manifest_root_cid,
            musubi_archive: None,
            issued_by: issuer.clone(),
            issued_epoch: 10,
            deadline_epoch: 20,
            canonical_order: canonical.clone(),
            assignment_revision: 1,
            provider_completions: vec![ReplicationOrderCompletionRecord {
                provider_id: ProviderId::new(order_payload.assignments[0].provider_id),
                completed_by: completion_signer.clone(),
                completion_epoch: 15,
                assignment_revision: 1,
                completion_authority: ProviderIngestCompletionAuthorityV1::new(
                    issuer.clone(),
                    completion_signer.clone(),
                    ProviderIngestCompletionSignerPolicyV1 {
                        policy_id: [0xA1; 32],
                        revision: 1,
                        predecessor_digest: None,
                        policy_digest: [0xA2; 32],
                    },
                ),
                finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                    height: 15,
                    block_hash: [0xA3; 32],
                },
            }],
            status: ReplicationOrderStatus::Completed(15),
        };
        let order = RegistryReplicationOrder::from_store(&record.order_id, &record)
            .expect("registry order");
        let value = order.to_json().expect("serialize order");
        let object = value.as_object().expect("order json object");
        let providers = object
            .get("providers")
            .and_then(Value::as_array)
            .expect("providers array");
        assert_eq!(providers.len(), 2);
        let expected0 = hex::encode(order_payload.assignments[0].provider_id);
        let expected1 = hex::encode(order_payload.assignments[1].provider_id);
        assert_eq!(providers[0].as_str(), Some(expected0.as_str()));
        assert_eq!(providers[1].as_str(), Some(expected1.as_str()));
        let completions = object
            .get("provider_completions")
            .and_then(Value::as_array)
            .expect("provider completions array");
        assert_eq!(completions.len(), 1);
        assert_eq!(
            object.get("assignment_revision").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            completions[0]
                .as_object()
                .and_then(|completion| completion.get("provider_hex"))
                .and_then(Value::as_str),
            Some(expected0.as_str())
        );
        let completion = completions[0]
            .as_object()
            .expect("provider completion object");
        assert_eq!(
            completion
                .get("assignment_revision")
                .and_then(Value::as_u64),
            Some(1)
        );
        let authority = completion
            .get("completion_authority")
            .and_then(Value::as_object)
            .expect("completion authority");
        let expected_owner = issuer.to_string();
        let expected_signer = completion_signer.to_string();
        assert_eq!(
            authority.get("completion_signer").and_then(Value::as_str),
            Some(expected_signer.as_str())
        );
        assert_eq!(
            authority.get("provider_owner").and_then(Value::as_str),
            Some(expected_owner.as_str())
        );
        let signer_policy = authority
            .get("signer_policy")
            .and_then(Value::as_object)
            .expect("completion signer policy");
        let expected_policy_id = hex::encode([0xA1; 32]);
        assert_eq!(
            signer_policy.get("policy_id_hex").and_then(Value::as_str),
            Some(expected_policy_id.as_str())
        );
        assert_eq!(
            signer_policy.get("revision").and_then(Value::as_u64),
            Some(1)
        );
        assert!(
            signer_policy
                .get("predecessor_digest_hex")
                .is_some_and(Value::is_null)
        );
        let expected_policy_digest = hex::encode([0xA2; 32]);
        assert_eq!(
            signer_policy
                .get("policy_digest_hex")
                .and_then(Value::as_str),
            Some(expected_policy_digest.as_str())
        );
        let anchor = completion
            .get("finalized_anchor")
            .and_then(Value::as_object)
            .expect("finalized anchor");
        assert_eq!(anchor.get("height").and_then(Value::as_u64), Some(15));
        let expected_block_hash = hex::encode([0xA3; 32]);
        assert_eq!(
            anchor.get("block_hash_hex").and_then(Value::as_str),
            Some(expected_block_hash.as_str())
        );
        assert_eq!(
            object
                .get("canonical_order_b64")
                .and_then(Value::as_str)
                .map(|s| BASE64_STD.decode(s.as_bytes()).expect("decode base64")),
            Some(canonical)
        );
        let mut cancelled_record = record.clone();
        cancelled_record.provider_completions.clear();
        cancelled_record.status = ReplicationOrderStatus::Cancelled(16);
        let cancelled =
            RegistryReplicationOrder::from_store(&cancelled_record.order_id, &cancelled_record)
                .expect("cancelled registry order");
        let cancelled_value = cancelled.to_json().expect("serialize cancelled order");
        let cancelled_status = cancelled_value
            .as_object()
            .and_then(|order| order.get("status"))
            .and_then(Value::as_object)
            .expect("cancelled status object");
        assert_eq!(
            cancelled_status.get("state").and_then(Value::as_str),
            Some("cancelled")
        );
        assert_eq!(
            cancelled_status.get("epoch").and_then(Value::as_u64),
            Some(16)
        );
        let mut invalid_records = Vec::new();
        let mut owner_signed_completion = record.clone();
        owner_signed_completion.provider_completions[0].completed_by = issuer;
        invalid_records.push(owner_signed_completion);
        let mut zero_assignment_revision = record.clone();
        zero_assignment_revision.assignment_revision = 0;
        invalid_records.push(zero_assignment_revision);
        let mut substituted_assignment_revision = record.clone();
        substituted_assignment_revision.provider_completions[0].assignment_revision = 2;
        invalid_records.push(substituted_assignment_revision);
        let mut invalid_policy = record.clone();
        invalid_policy.provider_completions[0]
            .completion_authority
            .signer_policy
            .policy_digest = [0; 32];
        invalid_records.push(invalid_policy);
        let mut invalid_anchor = record.clone();
        invalid_anchor.provider_completions[0]
            .finalized_anchor
            .block_hash = [0; 32];
        invalid_records.push(invalid_anchor);
        let mut premature_expiry = record.clone();
        premature_expiry.provider_completions.clear();
        premature_expiry.status = ReplicationOrderStatus::Expired(record.deadline_epoch);
        invalid_records.push(premature_expiry);
        let mut premature_cancellation = record.clone();
        premature_cancellation.provider_completions.clear();
        premature_cancellation.status =
            ReplicationOrderStatus::Cancelled(record.issued_epoch.saturating_sub(1));
        invalid_records.push(premature_cancellation);
        let mut substituted_issued_epoch = record.clone();
        substituted_issued_epoch.issued_epoch += 1;
        invalid_records.push(substituted_issued_epoch);
        let mut substituted_deadline_epoch = record.clone();
        substituted_deadline_epoch.deadline_epoch += 1;
        invalid_records.push(substituted_deadline_epoch);
        let mut two_target_payload = order_payload.clone();
        two_target_payload.target_replicas = 2;
        let mut decreasing_completion_epochs = record.clone();
        decreasing_completion_epochs.canonical_order =
            norito::to_bytes(&two_target_payload).expect("encode two-target order");
        let mut second_completion = decreasing_completion_epochs.provider_completions[0].clone();
        second_completion.provider_id = ProviderId::new(order_payload.assignments[1].provider_id);
        second_completion.completion_epoch = 14;
        second_completion.finalized_anchor = ProviderIngestFinalizedAnchorV1 {
            height: 14,
            block_hash: [0xA4; 32],
        };
        decreasing_completion_epochs
            .provider_completions
            .push(second_completion);
        decreasing_completion_epochs.status = ReplicationOrderStatus::Completed(14);
        invalid_records.push(decreasing_completion_epochs);
        for invalid in invalid_records {
            assert!(
                RegistryReplicationOrder::from_store(&invalid.order_id, &invalid).is_err(),
                "invalid assignment, authority, or finalized-anchor binding must fail closed"
            );
        }
    }
    #[test]
    fn lineage_json_preserves_typed_status_and_epochs_without_fallbacks() {
        let successor = LineageSuccessor {
            digest_hex: "ab".repeat(32),
            status: ManifestStatusProjection::Retired { epoch: 4 },
            approved_epoch: Some(3),
            status_timestamp_unix: Some(4),
        };
        let lineage = ManifestLineageSummary {
            successor_of_hex: Some("cd".repeat(32)),
            head_hex: successor.digest_hex.clone(),
            depth_to_head: 1,
            approved_successor: Some(successor.clone()),
            immediate_successor: Some(successor),
            anomalies: Vec::new(),
        };
        let value = lineage_to_json(&lineage).expect("serialize exact lineage projection");
        let object = value.as_object().expect("lineage object");
        assert_eq!(object.get("depth_to_head").and_then(Value::as_u64), Some(1));
        for field in ["superseded_by", "immediate_successor"] {
            let projected = object
                .get(field)
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{field} successor object"));
            let status = projected
                .get("status")
                .and_then(Value::as_object)
                .expect("typed successor status");
            assert_eq!(status.get("state").and_then(Value::as_str), Some("retired"));
            assert_eq!(status.get("epoch").and_then(Value::as_u64), Some(4));
            assert_eq!(
                projected.get("approved_epoch").and_then(Value::as_u64),
                Some(3)
            );
            assert_eq!(
                projected
                    .get("status_timestamp_unix")
                    .and_then(Value::as_u64),
                Some(4)
            );
        }
        let mut unrepresentable = lineage;
        unrepresentable
            .immediate_successor
            .as_mut()
            .expect("immediate successor")
            .status_timestamp_unix = Some(u64::MAX);
        assert!(
            lineage_to_json(&unrepresentable).is_err(),
            "an unrepresentable retained timestamp must fail the response instead of becoming null"
        );
    }
}
