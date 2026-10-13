//! Globally replicated public state for finalized private settlement bundles.
//!
//! Application is deliberately split into a read-only planning pass and an
//! infallible mutation pass. A bad leg therefore cannot expose any subset of a
//! bundle's roots, nullifiers, commitments, encrypted outputs, or receipt.

use super::{
    protocol::{
        validate_private_settlement_prepare_barrier_v1, verify_private_settlement_receipt_v1,
    },
    state::{
        PrivateSettlementPoolGovernanceProjectionV1, PrivateSettlementPoolStateV1,
        PrivateSettlementStateErrorV1,
    },
};
use iroha_crypto::Hash;
#[cfg(test)]
use iroha_data_model::nexus::PrivateSettlementPoolGovernanceV1;
use iroha_data_model::{
    nexus::{
        PrivateSettlementAbortReceiptV1, PrivateSettlementDeltaV1,
        PrivateSettlementPrepareBarrierV1, PrivateSettlementReceiptV1, PrivateSettlementRouteV1,
    },
    privacy::{
        PrivacyCommitmentV1, PrivacyEncryptedOutputV1, PrivacyNullifierV1, PrivacyPoolIdV1,
        PrivacyRecipientIdV1, PrivacyRootV1,
    },
};
use mv::storage::StorageReadOnly;
use norito::codec::{Decode, Encode};
use norito::derive::{JsonDeserialize, JsonSerialize};
use norito::json;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const RECEIPT_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:global-receipt:v1\0";

pub(crate) fn canonical_receipt_digest_v1(
    receipt: &PrivateSettlementReceiptV1,
) -> Result<Hash, PrivateSettlementGlobalStateErrorV1> {
    let encoded = norito::encode_canonical(receipt)
        .map_err(|_| PrivateSettlementGlobalStateErrorV1::Encoding)?;
    let encoded_len =
        u64::try_from(encoded.len()).map_err(|_| PrivateSettlementGlobalStateErrorV1::Encoding)?;
    Ok(Hash::new_from_chunks(&[
        RECEIPT_DIGEST_DOMAIN_V1,
        &encoded_len.to_le_bytes(),
        encoded.as_slice(),
    ]))
}

/// Exact route-scoped identity of one governed confidential settlement pool.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    JsonDeserialize,
    JsonSerialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::private_settlement::global_state::PrivateSettlementPoolKeyV1")]
pub(crate) struct PrivateSettlementPoolKeyV1 {
    route: PrivateSettlementRouteV1,
    pool_id: PrivacyPoolIdV1,
}

impl PrivateSettlementPoolKeyV1 {
    /// Construct the key used by every private-settlement state map.
    pub(crate) fn new(
        route: PrivateSettlementRouteV1,
        pool_id: PrivacyPoolIdV1,
    ) -> Result<Self, PrivateSettlementGlobalStateErrorV1> {
        if route.lane_incarnation == Hash::prehashed([0; Hash::LENGTH]) || pool_id.is_zero() {
            return Err(PrivateSettlementGlobalStateErrorV1::Pool);
        }
        Ok(Self { route, pool_id })
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    JsonDeserialize,
    JsonSerialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::private_settlement::global_state::PrivateSettlementRootKeyV1")]
pub(crate) struct PrivateSettlementRootKeyV1 {
    pub(crate) pool: PrivateSettlementPoolKeyV1,
    pub(crate) epoch: u64,
    pub(crate) root: PrivacyRootV1,
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    JsonDeserialize,
    JsonSerialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::private_settlement::global_state::PrivateSettlementNullifierKeyV1"
)]
pub(crate) struct PrivateSettlementNullifierKeyV1 {
    pub(crate) pool: PrivateSettlementPoolKeyV1,
    pub(crate) nullifier: PrivacyNullifierV1,
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    JsonDeserialize,
    JsonSerialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::private_settlement::global_state::PrivateSettlementOutputKeyV1"
)]
pub(crate) struct PrivateSettlementOutputKeyV1 {
    pub(crate) pool: PrivateSettlementPoolKeyV1,
    pub(crate) commitment: PrivacyCommitmentV1,
}

/// Canonical key for one globally replicated private-settlement staged lock.
///
/// The bundle row stores the complete public Prepare barrier exactly once.
/// Resource rows provide deterministic exclusivity without repeating that
/// potentially large barrier for every fixed-shape state item.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    JsonDeserialize,
    JsonSerialize,
)]
#[norito(tag = "kind", content = "key", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::global_state::PrivateSettlementStagedLockKeyV1"
)]
pub(crate) enum PrivateSettlementStagedLockKeyV1 {
    /// One exact complete-bundle Prepare registration.
    Bundle(Hash),
    /// The authoritative predecessor frontier of one governed pool.
    PoolHead {
        /// Opaque route-scoped pool identity.
        pool: PrivateSettlementPoolKeyV1,
        /// Exact predecessor epoch.
        epoch: u64,
        /// Exact predecessor root.
        root: PrivacyRootV1,
    },
    /// One fixed-slot nullifier reservation.
    Nullifier(PrivateSettlementNullifierKeyV1),
    /// One fixed-slot output commitment reservation.
    Output(PrivateSettlementOutputKeyV1),
    /// One globally one-time recipient/view-key reservation.
    Recipient(PrivacyRecipientIdV1),
}

/// Canonical value stored under a private-settlement staged-lock key.
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, JsonDeserialize, JsonSerialize)]
#[norito(tag = "kind", content = "record", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::global_state::PrivateSettlementStagedLockRecordV1"
)]
pub(crate) enum PrivateSettlementStagedLockRecordV1 {
    /// Complete public all-Prepare barrier and its global registration height.
    Bundle {
        /// Exact barrier bytes authorized by the sponsor.
        barrier: PrivateSettlementPrepareBarrierV1,
        /// Height at which the control-lock carrier committed globally.
        registered_at_height: u64,
    },
    /// Compact owner reference for one resource row.
    Resource {
        /// Opaque owner bundle identity.
        bundle_id: Hash,
        /// Exact complete-bundle Prepare digest.
        prepared_bundle_digest: Hash,
        /// Canonical leg owning this resource.
        leg_ordinal: u8,
    },
}

fn encode_private_settlement_storage_key_v1<T: norito::NoritoSerialize>(key: &T, out: &mut String) {
    let encoded = norito::to_bytes(key).expect("fixed private-settlement keys always encode");
    json::write_json_string(&hex::encode_upper(encoded), out);
}

fn decode_private_settlement_storage_key_v1<
    T: for<'__frame> norito::NoritoDeserialize<'__frame> + norito::NoritoSerialize,
>(
    encoded: &str,
) -> Result<T, json::Error> {
    let bytes = hex::decode(encoded).map_err(|error| {
        json::Error::Message(format!("invalid private-settlement key hex: {error}"))
    })?;
    let key: T = norito::decode_from_bytes(&bytes).map_err(|error| {
        json::Error::Message(format!("invalid private-settlement key encoding: {error}"))
    })?;
    let canonical = norito::to_bytes(&key).map_err(|error| {
        json::Error::Message(format!(
            "failed to re-encode private-settlement key: {error}"
        ))
    })?;
    if encoded != hex::encode_upper(canonical) {
        return Err(json::Error::Message(
            "private-settlement key is not canonical uppercase exact Norito hex".to_owned(),
        ));
    }
    Ok(key)
}

macro_rules! impl_private_settlement_json_key_v1 {
    ($($key:ty),+ $(,)?) => {
        $(
            impl norito::json::JsonKeyCodec for $key {
                fn encode_json_key(&self, out: &mut String) {
                    encode_private_settlement_storage_key_v1(self, out);
                }

                fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
                    decode_private_settlement_storage_key_v1(encoded)
                }
            }
        )+
    };
}

impl_private_settlement_json_key_v1!(
    PrivateSettlementPoolKeyV1,
    PrivateSettlementRootKeyV1,
    PrivateSettlementNullifierKeyV1,
    PrivateSettlementOutputKeyV1,
    PrivateSettlementStagedLockKeyV1,
);

/// Public provenance shared by every state item created by one finalized leg.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    JsonDeserialize,
    JsonSerialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::private_settlement::global_state::PrivateSettlementFinalizationReferenceV1"
)]
pub(crate) struct PrivateSettlementFinalizationReferenceV1 {
    pub(crate) bundle_id: Hash,
    pub(crate) receipt_digest: Hash,
    pub(crate) leg_ordinal: u8,
    pub(crate) finalized_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode, JsonDeserialize, JsonSerialize)]
#[norito(tag = "origin", content = "record", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::global_state::PrivateSettlementRootProvenanceV1"
)]
pub(crate) enum PrivateSettlementRootProvenanceV1 {
    Governance {
        governance_digest: Hash,
        admitted_at_height: u64,
    },
    Settlement(PrivateSettlementFinalizationReferenceV1),
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    JsonDeserialize,
    JsonSerialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::private_settlement::global_state::PrivateSettlementOutputRecordV1"
)]
pub(crate) struct PrivateSettlementOutputRecordV1 {
    pub(crate) reference: PrivateSettlementFinalizationReferenceV1,
    pub(crate) encrypted_output: PrivacyEncryptedOutputV1,
}

/// Test/reference aggregate over the production private-settlement planner maps.
#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::global_state::PrivateSettlementGlobalStateV1"
)]
pub(crate) struct PrivateSettlementGlobalStateV1 {
    governance: BTreeMap<PrivateSettlementPoolKeyV1, PrivateSettlementPoolGovernanceProjectionV1>,
    pools: BTreeMap<PrivateSettlementPoolKeyV1, PrivateSettlementPoolStateV1>,
    roots: BTreeMap<PrivateSettlementRootKeyV1, PrivateSettlementRootProvenanceV1>,
    nullifiers: BTreeMap<PrivateSettlementNullifierKeyV1, PrivateSettlementFinalizationReferenceV1>,
    outputs: BTreeMap<PrivateSettlementOutputKeyV1, PrivateSettlementOutputRecordV1>,
    recipient_index: BTreeMap<PrivacyRecipientIdV1, PrivateSettlementFinalizationReferenceV1>,
    staged_locks: BTreeMap<PrivateSettlementStagedLockKeyV1, PrivateSettlementStagedLockRecordV1>,
    receipts: BTreeMap<Hash, PrivateSettlementReceiptV1>,
    aborts: BTreeMap<Hash, PrivateSettlementAbortReceiptV1>,
}

/// Outcome of an idempotent global-state operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateSettlementGlobalStateOutcomeV1 {
    /// The complete operation was applied.
    Applied,
    /// The exact operation was already durable.
    Idempotent,
}

pub(crate) struct PrivateSettlementPlannedLegV1 {
    pub(crate) key: PrivateSettlementPoolKeyV1,
    pub(crate) next_pool: PrivateSettlementPoolStateV1,
    pub(crate) root_key: PrivateSettlementRootKeyV1,
    pub(crate) reference: PrivateSettlementFinalizationReferenceV1,
    pub(crate) nullifiers: Vec<PrivateSettlementNullifierKeyV1>,
    pub(crate) outputs: Vec<(
        PrivateSettlementOutputKeyV1,
        PrivateSettlementOutputRecordV1,
    )>,
    pub(crate) recipients: Vec<PrivacyRecipientIdV1>,
}

/// Complete infallible write set for one globally replicated Prepare registration.
pub(crate) struct PrivateSettlementPrepareLockPlanV1 {
    pub(crate) records:
        BTreeMap<PrivateSettlementStagedLockKeyV1, PrivateSettlementStagedLockRecordV1>,
}

/// Complete infallible finalization write set, including exact lock release.
pub(crate) struct PrivateSettlementReceiptPlanV1 {
    pub(crate) legs: Vec<PrivateSettlementPlannedLegV1>,
    pub(crate) staged_lock_keys: Vec<PrivateSettlementStagedLockKeyV1>,
}

/// Complete infallible write set for bootstrapping one governed pool.
pub(crate) struct PrivateSettlementPoolBootstrapPlanV1 {
    pub(crate) key: PrivateSettlementPoolKeyV1,
    pub(crate) governance: PrivateSettlementPoolGovernanceProjectionV1,
    pub(crate) pool: PrivateSettlementPoolStateV1,
    pub(crate) root_key: PrivateSettlementRootKeyV1,
    pub(crate) root_provenance: PrivateSettlementRootProvenanceV1,
}

/// Complete infallible write set for one policy/key rotation.
pub(crate) struct PrivateSettlementPoolRotationPlanV1 {
    pub(crate) key: PrivateSettlementPoolKeyV1,
    pub(crate) governance: PrivateSettlementPoolGovernanceProjectionV1,
    pub(crate) pool: PrivateSettlementPoolStateV1,
}

fn governance_origin_matches_current_v1(
    current: &PrivateSettlementPoolGovernanceProjectionV1,
    origin_governance_digest: Hash,
    origin_admitted_at_height: u64,
) -> bool {
    if origin_admitted_at_height == 0
        || origin_governance_digest == Hash::prehashed([0; Hash::LENGTH])
    {
        return false;
    }
    let origin = current
        .prior_revisions
        .first()
        .copied()
        .unwrap_or_else(|| current.current_revision());
    origin.lifecycle.governance_revision == 1
        && origin.governance_digest == origin_governance_digest
        && origin.lifecycle.is_active_at(origin_admitted_at_height)
}

fn receipt_leg_matches_governance_lineage_v1(
    governance: &PrivateSettlementPoolGovernanceProjectionV1,
    receipt: &PrivateSettlementReceiptV1,
    delta: &PrivateSettlementDeltaV1,
) -> bool {
    let context_revision = governance.revision_at(receipt.manifest.authority_context_height);
    let finalized_revision = governance.revision_at(receipt.finalized_height);
    let Some(revision) = context_revision.filter(|revision| Some(*revision) == finalized_revision)
    else {
        return false;
    };
    delta.asset_binding_commitment == governance.asset_binding_commitment
        && delta.audit_policy_digest == revision.audit_policy_digest
        && delta.audit_key_epoch == revision.audit_key_epoch
        && revision
            .lifecycle
            .retirement_height
            .is_none_or(|retirement| receipt.manifest.expiry_height < retirement)
}

/// Validate and plan one governed pool bootstrap without mutating persistent state.
pub(crate) fn plan_private_settlement_pool_bootstrap_v1(
    governance_store: &impl StorageReadOnly<
        PrivateSettlementPoolKeyV1,
        PrivateSettlementPoolGovernanceProjectionV1,
    >,
    pools: &impl StorageReadOnly<PrivateSettlementPoolKeyV1, PrivateSettlementPoolStateV1>,
    roots: &impl StorageReadOnly<PrivateSettlementRootKeyV1, PrivateSettlementRootProvenanceV1>,
    governance: PrivateSettlementPoolGovernanceProjectionV1,
    initial_commitments: &[PrivacyCommitmentV1],
    admitted_at_height: u64,
) -> Result<Option<PrivateSettlementPoolBootstrapPlanV1>, PrivateSettlementGlobalStateErrorV1> {
    governance
        .validate()
        .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
    if admitted_at_height == 0 || !governance.lifecycle.is_active_at(admitted_at_height) {
        return Err(PrivateSettlementGlobalStateErrorV1::Governance);
    }
    let key = PrivateSettlementPoolKeyV1::new(governance.route, governance.pool_id)?;
    let pool = PrivateSettlementPoolStateV1::bootstrap(
        governance.route,
        governance.pool_id,
        governance.governance_digest,
        initial_commitments,
    )
    .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
    let root_key = PrivateSettlementRootKeyV1 {
        pool: key,
        epoch: pool.epoch(),
        root: pool.root(),
    };
    if let Some(existing) = governance_store.get(&key) {
        return if existing == &governance
            && pools.get(&key) == Some(&pool)
            && matches!(
                roots.get(&root_key),
                Some(PrivateSettlementRootProvenanceV1::Governance {
                    governance_digest,
                    admitted_at_height,
                }) if governance_digest == &governance.governance_digest
                    && governance.lifecycle.is_active_at(*admitted_at_height)
            ) {
            Ok(None)
        } else {
            Err(PrivateSettlementGlobalStateErrorV1::Substitution)
        };
    }
    if pools.get(&key).is_some() || roots.get(&root_key).is_some() {
        return Err(PrivateSettlementGlobalStateErrorV1::Substitution);
    }
    let governance_digest = governance.governance_digest;
    Ok(Some(PrivateSettlementPoolBootstrapPlanV1 {
        key,
        governance,
        pool,
        root_key,
        root_provenance: PrivateSettlementRootProvenanceV1::Governance {
            governance_digest,
            admitted_at_height,
        },
    }))
}

/// Validate and plan one exact governance rotation without changing the pool frontier.
pub(crate) fn plan_private_settlement_pool_rotation_v1(
    governance_store: &impl StorageReadOnly<
        PrivateSettlementPoolKeyV1,
        PrivateSettlementPoolGovernanceProjectionV1,
    >,
    pools: &impl StorageReadOnly<PrivateSettlementPoolKeyV1, PrivateSettlementPoolStateV1>,
    receipts: &impl StorageReadOnly<Hash, PrivateSettlementReceiptV1>,
    expected_governance_digest: Hash,
    replacement: PrivateSettlementPoolGovernanceProjectionV1,
    admitted_at_height: u64,
) -> Result<Option<PrivateSettlementPoolRotationPlanV1>, PrivateSettlementGlobalStateErrorV1> {
    replacement
        .validate_current_fields()
        .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
    if admitted_at_height <= 1
        || replacement.lifecycle.activation_height != admitted_at_height
        || !replacement.lifecycle.is_active_at(admitted_at_height)
    {
        return Err(PrivateSettlementGlobalStateErrorV1::Governance);
    }
    let key = PrivateSettlementPoolKeyV1::new(replacement.route, replacement.pool_id)?;
    let current = governance_store
        .get(&key)
        .ok_or(PrivateSettlementGlobalStateErrorV1::Governance)?;
    let pool = pools
        .get(&key)
        .ok_or(PrivateSettlementGlobalStateErrorV1::Pool)?;
    current
        .validate()
        .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
    if !replacement.prior_revisions.is_empty() {
        return Err(PrivateSettlementGlobalStateErrorV1::Governance);
    }
    if current.current_fields_equal(&replacement)
        && pool.restricted_pool_policy_digest() == replacement.governance_digest
    {
        return Ok(None);
    }
    let expected_revision = current
        .lifecycle
        .governance_revision
        .checked_add(1)
        .ok_or(PrivateSettlementGlobalStateErrorV1::Governance)?;
    if current.governance_digest != expected_governance_digest {
        return Err(PrivateSettlementGlobalStateErrorV1::Substitution);
    }
    if current.version != replacement.version
        || current.route != replacement.route
        || current.pool_id != replacement.pool_id
        || current.asset_binding_commitment != replacement.asset_binding_commitment
        || current.audit_policy_digest == replacement.audit_policy_digest
        || current.audit_key_epoch >= replacement.audit_key_epoch
        || current.governance_digest == replacement.governance_digest
        || replacement.lifecycle.governance_revision != expected_revision
        || !current
            .lifecycle
            .is_active_at(admitted_at_height.saturating_sub(1))
        || pool.route() != current.route
        || pool.pool_id() != current.pool_id
        || pool.restricted_pool_policy_digest() != current.governance_digest
        || receipts.iter().any(|(_, receipt)| {
            receipt.finalized_height == admitted_at_height
                && receipt.legs.iter().any(|leg| {
                    leg.delta.route == replacement.route && leg.delta.pool_id == replacement.pool_id
                })
        })
    {
        return Err(PrivateSettlementGlobalStateErrorV1::Governance);
    }
    let replacement = current
        .with_replacement(replacement)
        .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
    let rotated_pool = pool
        .rotate_governance_digest(current.governance_digest, replacement.governance_digest)
        .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
    Ok(Some(PrivateSettlementPoolRotationPlanV1 {
        key,
        governance: replacement,
        pool: rotated_pool,
    }))
}

fn staged_lock_resource_record_v1(
    barrier: &PrivateSettlementPrepareBarrierV1,
    leg_ordinal: u8,
) -> PrivateSettlementStagedLockRecordV1 {
    PrivateSettlementStagedLockRecordV1::Resource {
        bundle_id: barrier.manifest.bundle_id,
        prepared_bundle_digest: barrier.prepared_bundle_digest,
        leg_ordinal,
    }
}

/// Derive the exact bundle and resource rows for one complete Prepare barrier.
pub(crate) fn private_settlement_staged_lock_records_v1(
    barrier: &PrivateSettlementPrepareBarrierV1,
    registered_at_height: u64,
) -> Result<
    BTreeMap<PrivateSettlementStagedLockKeyV1, PrivateSettlementStagedLockRecordV1>,
    PrivateSettlementGlobalStateErrorV1,
> {
    validate_private_settlement_prepare_barrier_v1(barrier)
        .map_err(|_| PrivateSettlementGlobalStateErrorV1::PrepareBarrier)?;
    if registered_at_height == 0
        || registered_at_height < barrier.manifest.authority_context_height
        || registered_at_height >= barrier.manifest.expiry_height
    {
        return Err(PrivateSettlementGlobalStateErrorV1::Height);
    }
    let mut records = BTreeMap::new();
    records.insert(
        PrivateSettlementStagedLockKeyV1::Bundle(barrier.manifest.bundle_id),
        PrivateSettlementStagedLockRecordV1::Bundle {
            barrier: barrier.clone(),
            registered_at_height,
        },
    );
    for (index, delta) in barrier.deltas.iter().enumerate() {
        let leg_ordinal =
            u8::try_from(index).map_err(|_| PrivateSettlementGlobalStateErrorV1::Bounds)?;
        let pool = PrivateSettlementPoolKeyV1::new(delta.route, delta.pool_id)?;
        let resource = staged_lock_resource_record_v1(barrier, leg_ordinal);
        let keys = std::iter::once(PrivateSettlementStagedLockKeyV1::PoolHead {
            pool,
            epoch: delta.old_epoch,
            root: delta.old_root,
        })
        .chain(delta.nullifiers.iter().copied().map(|nullifier| {
            PrivateSettlementStagedLockKeyV1::Nullifier(PrivateSettlementNullifierKeyV1 {
                pool,
                nullifier,
            })
        }))
        .chain(delta.output_commitments.iter().copied().map(|commitment| {
            PrivateSettlementStagedLockKeyV1::Output(PrivateSettlementOutputKeyV1 {
                pool,
                commitment,
            })
        }))
        .chain(
            delta
                .encrypted_outputs
                .iter()
                .map(|output| PrivateSettlementStagedLockKeyV1::Recipient(output.recipient)),
        );
        for key in keys {
            if records.insert(key, resource.clone()).is_some() {
                return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
            }
        }
    }
    Ok(records)
}

fn prepare_barrier_from_receipt_v1(
    receipt: &PrivateSettlementReceiptV1,
) -> Result<PrivateSettlementPrepareBarrierV1, PrivateSettlementGlobalStateErrorV1> {
    let prepared_bundle_digest = receipt
        .legs
        .first()
        .map(|leg| leg.commit.body.prepared_bundle_digest)
        .ok_or(PrivateSettlementGlobalStateErrorV1::PrepareBarrier)?;
    let barrier = PrivateSettlementPrepareBarrierV1 {
        version: receipt.version,
        manifest: receipt.manifest.clone(),
        authority_catalog: receipt.authority_catalog.clone(),
        deltas: receipt.legs.iter().map(|leg| leg.delta.clone()).collect(),
        prepare_certificates: receipt.legs.iter().map(|leg| leg.prepare.clone()).collect(),
        prepared_bundle_digest,
    };
    validate_private_settlement_prepare_barrier_v1(&barrier)
        .map_err(|_| PrivateSettlementGlobalStateErrorV1::PrepareBarrier)?;
    Ok(barrier)
}

fn exact_staged_lock_keys_v1(
    staged_locks: &impl StorageReadOnly<
        PrivateSettlementStagedLockKeyV1,
        PrivateSettlementStagedLockRecordV1,
    >,
    barrier: &PrivateSettlementPrepareBarrierV1,
) -> Result<Vec<PrivateSettlementStagedLockKeyV1>, PrivateSettlementGlobalStateErrorV1> {
    let bundle_key = PrivateSettlementStagedLockKeyV1::Bundle(barrier.manifest.bundle_id);
    let (stored_barrier, registered_at_height) = match staged_locks.get(&bundle_key) {
        Some(PrivateSettlementStagedLockRecordV1::Bundle {
            barrier: existing,
            registered_at_height,
        }) if existing.quorum_equivalent_to(barrier) => (existing, *registered_at_height),
        Some(_) => return Err(PrivateSettlementGlobalStateErrorV1::Substitution),
        None => return Err(PrivateSettlementGlobalStateErrorV1::MissingPrepareLock),
    };
    let expected = private_settlement_staged_lock_records_v1(stored_barrier, registered_at_height)?;
    if expected
        .iter()
        .any(|(key, record)| staged_locks.get(key) != Some(record))
        || staged_locks.iter().any(|(key, record)| {
            matches!(
                record,
                PrivateSettlementStagedLockRecordV1::Resource { bundle_id, .. }
                    if *bundle_id == barrier.manifest.bundle_id && !expected.contains_key(key)
            )
        })
    {
        return Err(PrivateSettlementGlobalStateErrorV1::Substitution);
    }
    Ok(expected.into_keys().collect())
}

/// Verify that one all-Prepare certified-body identity owns a complete live WSV lock set.
///
/// The stored barrier keeps its original aggregate QC bytes. A retry or
/// recovered coordinator may supply independently valid quorum-equivalent QCs;
/// signer-subset encoding therefore does not orphan the replicated lock.
pub(crate) fn validate_private_settlement_prepare_lock_registration_v1(
    staged_locks: &impl StorageReadOnly<
        PrivateSettlementStagedLockKeyV1,
        PrivateSettlementStagedLockRecordV1,
    >,
    barrier: &PrivateSettlementPrepareBarrierV1,
    current_height: u64,
) -> Result<(), PrivateSettlementGlobalStateErrorV1> {
    validate_private_settlement_prepare_barrier_v1(barrier)
        .map_err(|_| PrivateSettlementGlobalStateErrorV1::PrepareBarrier)?;
    if current_height < barrier.manifest.authority_context_height
        || current_height > barrier.manifest.expiry_height
    {
        return Err(PrivateSettlementGlobalStateErrorV1::Height);
    }
    exact_staged_lock_keys_v1(staged_locks, barrier).map(|_| ())
}

/// Validate and plan one complete all-Prepare control-lock registration.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_private_settlement_prepare_locks_v1(
    governance: &impl StorageReadOnly<
        PrivateSettlementPoolKeyV1,
        PrivateSettlementPoolGovernanceProjectionV1,
    >,
    pools: &impl StorageReadOnly<PrivateSettlementPoolKeyV1, PrivateSettlementPoolStateV1>,
    roots: &impl StorageReadOnly<PrivateSettlementRootKeyV1, PrivateSettlementRootProvenanceV1>,
    nullifiers: &impl StorageReadOnly<
        PrivateSettlementNullifierKeyV1,
        PrivateSettlementFinalizationReferenceV1,
    >,
    outputs: &impl StorageReadOnly<PrivateSettlementOutputKeyV1, PrivateSettlementOutputRecordV1>,
    recipient_index: &impl StorageReadOnly<
        PrivacyRecipientIdV1,
        PrivateSettlementFinalizationReferenceV1,
    >,
    staged_locks: &impl StorageReadOnly<
        PrivateSettlementStagedLockKeyV1,
        PrivateSettlementStagedLockRecordV1,
    >,
    receipts: &impl StorageReadOnly<Hash, PrivateSettlementReceiptV1>,
    aborts: &impl StorageReadOnly<Hash, PrivateSettlementAbortReceiptV1>,
    barrier: &PrivateSettlementPrepareBarrierV1,
    current_height: u64,
) -> Result<Option<PrivateSettlementPrepareLockPlanV1>, PrivateSettlementGlobalStateErrorV1> {
    validate_private_settlement_prepare_barrier_v1(barrier)
        .map_err(|_| PrivateSettlementGlobalStateErrorV1::PrepareBarrier)?;
    if current_height == 0
        || current_height < barrier.manifest.authority_context_height
        || current_height >= barrier.manifest.expiry_height
    {
        return Err(PrivateSettlementGlobalStateErrorV1::Height);
    }
    let bundle_id = barrier.manifest.bundle_id;
    if receipts.get(&bundle_id).is_some() || aborts.get(&bundle_id).is_some() {
        return Err(PrivateSettlementGlobalStateErrorV1::Terminal);
    }
    let bundle_key = PrivateSettlementStagedLockKeyV1::Bundle(bundle_id);
    if staged_locks.get(&bundle_key).is_some() {
        exact_staged_lock_keys_v1(staged_locks, barrier)?;
        return Ok(None);
    }
    if staged_locks.iter().any(|(_, record)| {
        matches!(
            record,
            PrivateSettlementStagedLockRecordV1::Resource {
                bundle_id: existing,
                ..
            } if *existing == bundle_id
        )
    }) {
        return Err(PrivateSettlementGlobalStateErrorV1::Substitution);
    }

    let records = private_settlement_staged_lock_records_v1(barrier, current_height)?;
    for delta in &barrier.deltas {
        let key = PrivateSettlementPoolKeyV1::new(delta.route, delta.pool_id)?;
        let governed_pool = governance
            .get(&key)
            .ok_or(PrivateSettlementGlobalStateErrorV1::Governance)?;
        let pool = pools
            .get(&key)
            .ok_or(PrivateSettlementGlobalStateErrorV1::Pool)?;
        let next_pool = pool
            .apply_certified_delta(
                delta,
                governed_pool,
                barrier.manifest.authority_context_height,
                barrier.manifest.expiry_height,
                current_height,
            )
            .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
        if roots
            .get(&PrivateSettlementRootKeyV1 {
                pool: key,
                epoch: next_pool.epoch(),
                root: next_pool.root(),
            })
            .is_some()
            || delta.nullifiers.iter().any(|nullifier| {
                nullifiers
                    .get(&PrivateSettlementNullifierKeyV1 {
                        pool: key,
                        nullifier: *nullifier,
                    })
                    .is_some()
            })
            || delta.output_commitments.iter().any(|commitment| {
                outputs
                    .get(&PrivateSettlementOutputKeyV1 {
                        pool: key,
                        commitment: *commitment,
                    })
                    .is_some()
            })
            || delta
                .encrypted_outputs
                .iter()
                .any(|output| recipient_index.get(&output.recipient).is_some())
        {
            return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
        }
    }
    if records.keys().any(|key| staged_locks.get(key).is_some()) {
        return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
    }
    Ok(Some(PrivateSettlementPrepareLockPlanV1 { records }))
}

/// Validate and plan a complete certified receipt without mutating persistent state.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_private_settlement_receipt_v1(
    governance: &impl StorageReadOnly<
        PrivateSettlementPoolKeyV1,
        PrivateSettlementPoolGovernanceProjectionV1,
    >,
    pools: &impl StorageReadOnly<PrivateSettlementPoolKeyV1, PrivateSettlementPoolStateV1>,
    roots: &impl StorageReadOnly<PrivateSettlementRootKeyV1, PrivateSettlementRootProvenanceV1>,
    nullifiers: &impl StorageReadOnly<
        PrivateSettlementNullifierKeyV1,
        PrivateSettlementFinalizationReferenceV1,
    >,
    outputs: &impl StorageReadOnly<PrivateSettlementOutputKeyV1, PrivateSettlementOutputRecordV1>,
    recipient_index: &impl StorageReadOnly<
        PrivacyRecipientIdV1,
        PrivateSettlementFinalizationReferenceV1,
    >,
    staged_locks: &impl StorageReadOnly<
        PrivateSettlementStagedLockKeyV1,
        PrivateSettlementStagedLockRecordV1,
    >,
    receipts: &impl StorageReadOnly<Hash, PrivateSettlementReceiptV1>,
    aborts: &impl StorageReadOnly<Hash, PrivateSettlementAbortReceiptV1>,
    receipt: &PrivateSettlementReceiptV1,
    current_height: u64,
) -> Result<Option<PrivateSettlementReceiptPlanV1>, PrivateSettlementGlobalStateErrorV1> {
    verify_private_settlement_receipt_v1(receipt)
        .map_err(|_| PrivateSettlementGlobalStateErrorV1::Receipt)?;
    if current_height == 0 || receipt.finalized_height != current_height {
        return Err(PrivateSettlementGlobalStateErrorV1::Height);
    }
    let bundle_id = receipt.manifest.bundle_id;
    if let Some(existing) = receipts.get(&bundle_id) {
        return if existing == receipt {
            Err(PrivateSettlementGlobalStateErrorV1::Replay)
        } else {
            Err(PrivateSettlementGlobalStateErrorV1::Substitution)
        };
    }
    if aborts.get(&bundle_id).is_some() {
        return Err(PrivateSettlementGlobalStateErrorV1::Terminal);
    }
    let barrier = prepare_barrier_from_receipt_v1(receipt)?;
    let staged_lock_keys = exact_staged_lock_keys_v1(staged_locks, &barrier)?;
    let receipt_digest = canonical_receipt_digest_v1(receipt)?;
    let mut seen_pools = BTreeSet::new();
    let mut seen_nullifiers = BTreeSet::new();
    let mut seen_outputs = BTreeSet::new();
    let mut seen_recipients = BTreeSet::new();
    let mut plan = Vec::with_capacity(receipt.legs.len());
    for (index, leg) in receipt.legs.iter().enumerate() {
        let ordinal =
            u8::try_from(index).map_err(|_| PrivateSettlementGlobalStateErrorV1::Receipt)?;
        let key = PrivateSettlementPoolKeyV1::new(leg.delta.route, leg.delta.pool_id)?;
        if !seen_pools.insert(key) {
            return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
        }
        let governed_pool = governance
            .get(&key)
            .ok_or(PrivateSettlementGlobalStateErrorV1::Governance)?;
        let pool = pools
            .get(&key)
            .ok_or(PrivateSettlementGlobalStateErrorV1::Pool)?;
        let next_pool = pool
            .apply_certified_delta(
                &leg.delta,
                governed_pool,
                receipt.manifest.authority_context_height,
                receipt.manifest.expiry_height,
                receipt.finalized_height,
            )
            .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
        let root_key = PrivateSettlementRootKeyV1 {
            pool: key,
            epoch: next_pool.epoch(),
            root: next_pool.root(),
        };
        if roots.get(&root_key).is_some() {
            return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
        }
        let reference = PrivateSettlementFinalizationReferenceV1 {
            bundle_id,
            receipt_digest,
            leg_ordinal: ordinal,
            finalized_height: current_height,
        };
        let mut planned_nullifiers = Vec::with_capacity(leg.delta.nullifiers.len());
        for nullifier in &leg.delta.nullifiers {
            let nullifier_key = PrivateSettlementNullifierKeyV1 {
                pool: key,
                nullifier: *nullifier,
            };
            if !seen_nullifiers.insert(nullifier_key) || nullifiers.get(&nullifier_key).is_some() {
                return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
            }
            planned_nullifiers.push(nullifier_key);
        }
        let mut planned_outputs = Vec::with_capacity(leg.delta.output_commitments.len());
        let mut planned_recipients = Vec::with_capacity(leg.delta.output_commitments.len());
        for (commitment, encrypted_output) in leg
            .delta
            .output_commitments
            .iter()
            .zip(&leg.delta.encrypted_outputs)
        {
            let output_key = PrivateSettlementOutputKeyV1 {
                pool: key,
                commitment: *commitment,
            };
            if !seen_outputs.insert(output_key)
                || outputs.get(&output_key).is_some()
                || !seen_recipients.insert(encrypted_output.recipient)
                || recipient_index.get(&encrypted_output.recipient).is_some()
            {
                return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
            }
            planned_recipients.push(encrypted_output.recipient);
            planned_outputs.push((
                output_key,
                PrivateSettlementOutputRecordV1 {
                    reference,
                    encrypted_output: encrypted_output.clone(),
                },
            ));
        }
        plan.push(PrivateSettlementPlannedLegV1 {
            key,
            next_pool,
            root_key,
            reference,
            nullifiers: planned_nullifiers,
            outputs: planned_outputs,
            recipients: planned_recipients,
        });
    }
    Ok(Some(PrivateSettlementReceiptPlanV1 {
        legs: plan,
        staged_lock_keys,
    }))
}

/// Validate an abort marker against terminal WSV state without mutating it.
pub(crate) fn plan_private_settlement_abort_v1(
    staged_locks: &impl StorageReadOnly<
        PrivateSettlementStagedLockKeyV1,
        PrivateSettlementStagedLockRecordV1,
    >,
    receipts: &impl StorageReadOnly<Hash, PrivateSettlementReceiptV1>,
    aborts: &impl StorageReadOnly<Hash, PrivateSettlementAbortReceiptV1>,
    receipt: &PrivateSettlementAbortReceiptV1,
    current_height: u64,
) -> Result<Vec<PrivateSettlementStagedLockKeyV1>, PrivateSettlementGlobalStateErrorV1> {
    receipt
        .validate()
        .map_err(|_| PrivateSettlementGlobalStateErrorV1::Receipt)?;
    if current_height == 0 || receipt.finalized_height != current_height {
        return Err(PrivateSettlementGlobalStateErrorV1::Height);
    }
    if receipts.get(&receipt.bundle_id).is_some() {
        return Err(PrivateSettlementGlobalStateErrorV1::Terminal);
    }
    if let Some(existing) = aborts.get(&receipt.bundle_id) {
        return if existing == receipt {
            Err(PrivateSettlementGlobalStateErrorV1::Replay)
        } else {
            Err(PrivateSettlementGlobalStateErrorV1::Substitution)
        };
    }
    let bundle_key = PrivateSettlementStagedLockKeyV1::Bundle(receipt.bundle_id);
    let Some(bundle_record) = staged_locks.get(&bundle_key) else {
        if staged_locks.iter().any(|(_, record)| {
            matches!(
                record,
                PrivateSettlementStagedLockRecordV1::Resource { bundle_id, .. }
                    if *bundle_id == receipt.bundle_id
            )
        }) {
            return Err(PrivateSettlementGlobalStateErrorV1::Substitution);
        }
        return Ok(Vec::new());
    };
    let PrivateSettlementStagedLockRecordV1::Bundle { barrier, .. } = bundle_record else {
        return Err(PrivateSettlementGlobalStateErrorV1::Substitution);
    };
    if barrier
        .manifest
        .manifest_digest()
        .map_err(|_| PrivateSettlementGlobalStateErrorV1::Encoding)?
        != receipt.manifest_digest
    {
        return Err(PrivateSettlementGlobalStateErrorV1::Substitution);
    }
    exact_staged_lock_keys_v1(staged_locks, barrier)
}

/// Return every exact row whose owner bundle expired before `current_height`.
pub(crate) fn expired_private_settlement_staged_lock_keys_v1(
    staged_locks: &impl StorageReadOnly<
        PrivateSettlementStagedLockKeyV1,
        PrivateSettlementStagedLockRecordV1,
    >,
    current_height: u64,
) -> Result<Vec<PrivateSettlementStagedLockKeyV1>, PrivateSettlementGlobalStateErrorV1> {
    if current_height == 0 {
        return Ok(Vec::new());
    }
    let expired = staged_locks
        .iter()
        .filter_map(|(key, record)| match (key, record) {
            (
                PrivateSettlementStagedLockKeyV1::Bundle(bundle_id),
                PrivateSettlementStagedLockRecordV1::Bundle { barrier, .. },
            ) if bundle_id == &barrier.manifest.bundle_id
                && barrier.manifest.expiry_height < current_height =>
            {
                Some((*bundle_id, barrier))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut keys = BTreeSet::new();
    for (_, barrier) in expired {
        keys.extend(exact_staged_lock_keys_v1(staged_locks, barrier)?);
    }
    Ok(keys.into_iter().collect())
}

/// Rebuild the derived one-time recipient index from canonical encrypted outputs.
///
/// The index is deliberately omitted from snapshots. A duplicate recipient is
/// therefore detected from canonical state during every restore instead of
/// being hidden by last-write-wins map construction.
pub(crate) fn rebuild_private_settlement_recipient_index_v1(
    outputs: &impl StorageReadOnly<PrivateSettlementOutputKeyV1, PrivateSettlementOutputRecordV1>,
) -> Result<
    BTreeMap<PrivacyRecipientIdV1, PrivateSettlementFinalizationReferenceV1>,
    PrivateSettlementGlobalStateErrorV1,
> {
    let mut recipient_index = BTreeMap::new();
    for (_, record) in outputs.iter() {
        if record.encrypted_output.recipient.is_zero()
            || recipient_index
                .insert(record.encrypted_output.recipient, record.reference)
                .is_some()
        {
            return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
        }
    }
    Ok(recipient_index)
}

/// Validate every private-settlement map and cross-reference after snapshot recovery.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn validate_private_settlement_persisted_state_v1(
    governance: &impl StorageReadOnly<
        PrivateSettlementPoolKeyV1,
        PrivateSettlementPoolGovernanceProjectionV1,
    >,
    pools: &impl StorageReadOnly<PrivateSettlementPoolKeyV1, PrivateSettlementPoolStateV1>,
    roots: &impl StorageReadOnly<PrivateSettlementRootKeyV1, PrivateSettlementRootProvenanceV1>,
    nullifiers: &impl StorageReadOnly<
        PrivateSettlementNullifierKeyV1,
        PrivateSettlementFinalizationReferenceV1,
    >,
    outputs: &impl StorageReadOnly<PrivateSettlementOutputKeyV1, PrivateSettlementOutputRecordV1>,
    recipient_index: &impl StorageReadOnly<
        PrivacyRecipientIdV1,
        PrivateSettlementFinalizationReferenceV1,
    >,
    staged_locks: &impl StorageReadOnly<
        PrivateSettlementStagedLockKeyV1,
        PrivateSettlementStagedLockRecordV1,
    >,
    receipts: &impl StorageReadOnly<Hash, PrivateSettlementReceiptV1>,
    aborts: &impl StorageReadOnly<Hash, PrivateSettlementAbortReceiptV1>,
) -> Result<(), PrivateSettlementGlobalStateErrorV1> {
    let rebuilt_recipient_index = rebuild_private_settlement_recipient_index_v1(outputs)?;
    if rebuilt_recipient_index.len() != recipient_index.iter().count()
        || rebuilt_recipient_index
            .iter()
            .any(|(recipient, reference)| recipient_index.get(recipient) != Some(reference))
    {
        return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
    }
    let mut roots_by_pool =
        BTreeMap::<PrivateSettlementPoolKeyV1, BTreeMap<u64, PrivacyRootV1>>::new();
    for (key, _) in roots.iter() {
        if key.epoch == 0
            || key.root.is_zero()
            || roots_by_pool
                .entry(key.pool)
                .or_default()
                .insert(key.epoch, key.root)
                .is_some()
        {
            return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
        }
    }
    for (key, governed_pool) in governance.iter() {
        governed_pool
            .validate()
            .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
        if key.route != governed_pool.route || key.pool_id != governed_pool.pool_id {
            return Err(PrivateSettlementGlobalStateErrorV1::Governance);
        }
        let pool = pools
            .get(key)
            .ok_or(PrivateSettlementGlobalStateErrorV1::Pool)?;
        pool.validate()
            .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
        if pool.route() != key.route
            || pool.pool_id() != key.pool_id
            || pool.restricted_pool_policy_digest() != governed_pool.governance_digest
            || roots
                .get(&PrivateSettlementRootKeyV1 {
                    pool: *key,
                    epoch: pool.epoch(),
                    root: pool.root(),
                })
                .is_none()
            || roots_by_pool
                .get(key)
                .and_then(|pool_roots| pool_roots.get(&1))
                .is_none_or(|origin_root| {
                    !matches!(
                        roots.get(&PrivateSettlementRootKeyV1 {
                            pool: *key,
                            epoch: 1,
                            root: *origin_root,
                        }),
                        Some(PrivateSettlementRootProvenanceV1::Governance {
                            governance_digest,
                            admitted_at_height,
                        }) if governance_origin_matches_current_v1(
                            governed_pool,
                            *governance_digest,
                            *admitted_at_height,
                        )
                    )
                })
        {
            return Err(PrivateSettlementGlobalStateErrorV1::Pool);
        }
    }
    if pools.iter().count() != governance.iter().count() {
        return Err(PrivateSettlementGlobalStateErrorV1::Pool);
    }

    let mut receipt_digests = BTreeMap::new();
    let mut transitions = BTreeMap::<PrivateSettlementRootKeyV1, PrivateSettlementRootKeyV1>::new();
    let mut transition_targets = BTreeSet::new();
    for (bundle_id, receipt) in receipts.iter() {
        verify_private_settlement_receipt_v1(receipt)
            .map_err(|_| PrivateSettlementGlobalStateErrorV1::Receipt)?;
        if bundle_id != &receipt.manifest.bundle_id || aborts.get(bundle_id).is_some() {
            return Err(PrivateSettlementGlobalStateErrorV1::Receipt);
        }
        receipt_digests.insert(*bundle_id, canonical_receipt_digest_v1(receipt)?);
    }
    let validate_reference = |reference: PrivateSettlementFinalizationReferenceV1| {
        let receipt = receipts
            .get(&reference.bundle_id)
            .ok_or(PrivateSettlementGlobalStateErrorV1::Receipt)?;
        if receipt.finalized_height != reference.finalized_height
            || receipt_digests.get(&reference.bundle_id) != Some(&reference.receipt_digest)
            || usize::from(reference.leg_ordinal) >= receipt.legs.len()
        {
            return Err(PrivateSettlementGlobalStateErrorV1::Receipt);
        }
        Ok(())
    };
    for (bundle_id, receipt) in receipts.iter() {
        let receipt_digest = receipt_digests
            .get(bundle_id)
            .copied()
            .ok_or(PrivateSettlementGlobalStateErrorV1::Receipt)?;
        for (index, leg) in receipt.legs.iter().enumerate() {
            let leg_ordinal =
                u8::try_from(index).map_err(|_| PrivateSettlementGlobalStateErrorV1::Receipt)?;
            let pool = PrivateSettlementPoolKeyV1::new(leg.delta.route, leg.delta.pool_id)?;
            let governed_pool = governance
                .get(&pool)
                .ok_or(PrivateSettlementGlobalStateErrorV1::Governance)?;
            if !receipt_leg_matches_governance_lineage_v1(governed_pool, receipt, &leg.delta)
                || leg.delta.old_epoch.checked_add(1) != Some(leg.delta.new_epoch)
            {
                return Err(PrivateSettlementGlobalStateErrorV1::Governance);
            }
            let reference = PrivateSettlementFinalizationReferenceV1 {
                bundle_id: *bundle_id,
                receipt_digest,
                leg_ordinal,
                finalized_height: receipt.finalized_height,
            };
            let old_root_key = PrivateSettlementRootKeyV1 {
                pool,
                epoch: leg.delta.old_epoch,
                root: leg.delta.old_root,
            };
            let new_root_key = PrivateSettlementRootKeyV1 {
                pool,
                epoch: leg.delta.new_epoch,
                root: leg.delta.new_root,
            };
            if roots.get(&old_root_key).is_none()
                || roots.get(&new_root_key)
                    != Some(&PrivateSettlementRootProvenanceV1::Settlement(reference))
                || transitions.insert(old_root_key, new_root_key).is_some()
                || !transition_targets.insert(new_root_key)
            {
                return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
            }
            for nullifier in &leg.delta.nullifiers {
                if nullifiers.get(&PrivateSettlementNullifierKeyV1 {
                    pool,
                    nullifier: *nullifier,
                }) != Some(&reference)
                {
                    return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
                }
            }
            for (commitment, encrypted_output) in leg
                .delta
                .output_commitments
                .iter()
                .zip(&leg.delta.encrypted_outputs)
            {
                let record = outputs
                    .get(&PrivateSettlementOutputKeyV1 {
                        pool,
                        commitment: *commitment,
                    })
                    .ok_or(PrivateSettlementGlobalStateErrorV1::Conflict)?;
                if record.reference != reference || &record.encrypted_output != encrypted_output {
                    return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
                }
            }
        }
    }
    for (key, reference) in nullifiers.iter() {
        validate_reference(*reference)?;
        let receipt = receipts
            .get(&reference.bundle_id)
            .ok_or(PrivateSettlementGlobalStateErrorV1::Receipt)?;
        let delta = &receipt.legs[usize::from(reference.leg_ordinal)].delta;
        if key.pool.route != delta.route
            || key.pool.pool_id != delta.pool_id
            || !delta.nullifiers.contains(&key.nullifier)
        {
            return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
        }
    }
    for (key, record) in outputs.iter() {
        validate_reference(record.reference)?;
        if record.encrypted_output.commitment != key.commitment {
            return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
        }
        let receipt = receipts
            .get(&record.reference.bundle_id)
            .ok_or(PrivateSettlementGlobalStateErrorV1::Receipt)?;
        let delta = &receipt.legs[usize::from(record.reference.leg_ordinal)].delta;
        if key.pool.route != delta.route
            || key.pool.pool_id != delta.pool_id
            || !delta.encrypted_outputs.contains(&record.encrypted_output)
        {
            return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
        }
    }
    for (key, provenance) in roots.iter() {
        match provenance {
            PrivateSettlementRootProvenanceV1::Governance {
                governance_digest,
                admitted_at_height,
            } => {
                if key.epoch != 1
                    || *admitted_at_height == 0
                    || governance.get(&key.pool).is_none_or(|record| {
                        !governance_origin_matches_current_v1(
                            record,
                            *governance_digest,
                            *admitted_at_height,
                        )
                    })
                {
                    return Err(PrivateSettlementGlobalStateErrorV1::Governance);
                }
            }
            PrivateSettlementRootProvenanceV1::Settlement(reference) => {
                validate_reference(*reference)?;
                let receipt = receipts
                    .get(&reference.bundle_id)
                    .ok_or(PrivateSettlementGlobalStateErrorV1::Receipt)?;
                let delta = &receipt.legs[usize::from(reference.leg_ordinal)].delta;
                if key.pool.route != delta.route
                    || key.pool.pool_id != delta.pool_id
                    || key.epoch != delta.new_epoch
                    || key.root != delta.new_root
                {
                    return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
                }
            }
        }
    }
    for (key, pool) in pools.iter() {
        let origin_root = roots_by_pool
            .get(key)
            .and_then(|pool_roots| pool_roots.get(&1))
            .copied()
            .ok_or(PrivateSettlementGlobalStateErrorV1::Conflict)?;
        let mut cursor = PrivateSettlementRootKeyV1 {
            pool: *key,
            epoch: 1,
            root: origin_root,
        };
        let transition_count = transitions
            .keys()
            .filter(|root_key| root_key.pool == *key)
            .count();
        let mut traversed = 0_usize;
        while let Some(next) = transitions.get(&cursor).copied() {
            if next.pool != *key || cursor.epoch.checked_add(1) != Some(next.epoch) {
                return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
            }
            cursor = next;
            traversed = traversed
                .checked_add(1)
                .ok_or(PrivateSettlementGlobalStateErrorV1::Conflict)?;
            if traversed > transition_count {
                return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
            }
        }
        if cursor.epoch != pool.epoch()
            || cursor.root != pool.root()
            || traversed != transition_count
            || roots_by_pool.get(key).map(BTreeMap::len) != Some(transition_count + 1)
        {
            return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
        }
    }
    for (bundle_id, abort) in aborts.iter() {
        abort
            .validate()
            .map_err(|_| PrivateSettlementGlobalStateErrorV1::Receipt)?;
        if bundle_id != &abort.bundle_id || receipts.get(bundle_id).is_some() {
            return Err(PrivateSettlementGlobalStateErrorV1::Receipt);
        }
    }
    let mut expected_staged_locks = BTreeMap::new();
    for (key, record) in staged_locks.iter() {
        let (
            PrivateSettlementStagedLockKeyV1::Bundle(bundle_id),
            PrivateSettlementStagedLockRecordV1::Bundle {
                barrier,
                registered_at_height,
            },
        ) = (key, record)
        else {
            continue;
        };
        if bundle_id != &barrier.manifest.bundle_id
            || receipts.get(bundle_id).is_some()
            || aborts.get(bundle_id).is_some()
        {
            return Err(PrivateSettlementGlobalStateErrorV1::Terminal);
        }
        let bundle_records =
            private_settlement_staged_lock_records_v1(barrier, *registered_at_height)?;
        for delta in &barrier.deltas {
            let pool_key = PrivateSettlementPoolKeyV1::new(delta.route, delta.pool_id)?;
            let governed_pool = governance
                .get(&pool_key)
                .ok_or(PrivateSettlementGlobalStateErrorV1::Governance)?;
            let pool = pools
                .get(&pool_key)
                .ok_or(PrivateSettlementGlobalStateErrorV1::Pool)?;
            if pool.epoch() != delta.old_epoch
                || pool.root() != delta.old_root
                || delta.asset_binding_commitment != governed_pool.asset_binding_commitment
                || delta.audit_policy_digest
                    != governed_pool
                        .revision_at(barrier.manifest.authority_context_height)
                        .ok_or(PrivateSettlementGlobalStateErrorV1::Governance)?
                        .audit_policy_digest
                || nullifiers.iter().any(|(key, _)| {
                    key.pool == pool_key && delta.nullifiers.contains(&key.nullifier)
                })
                || outputs.iter().any(|(key, _)| {
                    key.pool == pool_key && delta.output_commitments.contains(&key.commitment)
                })
                || delta
                    .encrypted_outputs
                    .iter()
                    .any(|output| recipient_index.get(&output.recipient).is_some())
            {
                return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
            }
        }
        for (record_key, record) in bundle_records {
            if expected_staged_locks.insert(record_key, record).is_some() {
                return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
            }
        }
    }
    if expected_staged_locks.len() != staged_locks.iter().count()
        || expected_staged_locks
            .iter()
            .any(|(key, record)| staged_locks.get(key) != Some(record))
    {
        return Err(PrivateSettlementGlobalStateErrorV1::Substitution);
    }
    Ok(())
}

#[cfg(test)]
impl PrivateSettlementGlobalStateV1 {
    /// Explicitly bootstrap one restricted pool through governance.
    pub(crate) fn bootstrap_pool(
        &mut self,
        governance: PrivateSettlementPoolGovernanceV1,
        initial_commitments: &[PrivacyCommitmentV1],
        admitted_at_height: u64,
    ) -> Result<PrivateSettlementGlobalStateOutcomeV1, PrivateSettlementGlobalStateErrorV1> {
        governance
            .validate()
            .map_err(|_| PrivateSettlementGlobalStateErrorV1::Governance)?;
        if admitted_at_height == 0 || !governance.body.lifecycle.is_active_at(admitted_at_height) {
            return Err(PrivateSettlementGlobalStateErrorV1::Governance);
        }
        let key = PrivateSettlementPoolKeyV1::new(governance.body.route, governance.body.pool_id)?;
        let governance_projection =
            PrivateSettlementPoolGovernanceProjectionV1::from_restricted(&governance)
                .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
        let pool = PrivateSettlementPoolStateV1::bootstrap(
            governance.body.route,
            governance.body.pool_id,
            governance.governance_digest,
            initial_commitments,
        )
        .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
        if let Some(existing) = self.governance.get(&key) {
            return if existing == &governance_projection && self.pools.get(&key) == Some(&pool) {
                Ok(PrivateSettlementGlobalStateOutcomeV1::Idempotent)
            } else {
                Err(PrivateSettlementGlobalStateErrorV1::Substitution)
            };
        }
        let root_key = PrivateSettlementRootKeyV1 {
            pool: key,
            epoch: pool.epoch(),
            root: pool.root(),
        };
        if self.pools.contains_key(&key) || self.roots.contains_key(&root_key) {
            return Err(PrivateSettlementGlobalStateErrorV1::Substitution);
        }
        self.governance.insert(key, governance_projection);
        self.pools.insert(key, pool);
        self.roots.insert(
            root_key,
            PrivateSettlementRootProvenanceV1::Governance {
                governance_digest: governance.governance_digest,
                admitted_at_height,
            },
        );
        Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
    }

    /// Rotate one pool governance projection while preserving its exact frontier.
    pub(crate) fn rotate_pool_policy(
        &mut self,
        expected_governance_digest: Hash,
        replacement: PrivateSettlementPoolGovernanceProjectionV1,
        admitted_at_height: u64,
    ) -> Result<PrivateSettlementGlobalStateOutcomeV1, PrivateSettlementGlobalStateErrorV1> {
        let replacement_key =
            PrivateSettlementPoolKeyV1::new(replacement.route, replacement.pool_id)?;
        if self.staged_locks.keys().any(|key| {
            matches!(
                key,
                PrivateSettlementStagedLockKeyV1::PoolHead { pool, .. }
                    if *pool == replacement_key
            )
        }) {
            return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
        }
        let governance = mv::storage::Storage::from_iter(self.governance.clone());
        let pools = mv::storage::Storage::from_iter(self.pools.clone());
        let receipts = mv::storage::Storage::from_iter(self.receipts.clone());
        let plan = plan_private_settlement_pool_rotation_v1(
            &governance.view(),
            &pools.view(),
            &receipts.view(),
            expected_governance_digest,
            replacement,
            admitted_at_height,
        )?;
        let Some(plan) = plan else {
            return Ok(PrivateSettlementGlobalStateOutcomeV1::Idempotent);
        };
        self.governance.insert(plan.key, plan.governance);
        self.pools.insert(plan.key, plan.pool);
        Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
    }

    /// Register one exact complete all-Prepare barrier before Commit voting.
    pub(crate) fn register_prepare(
        &mut self,
        barrier: PrivateSettlementPrepareBarrierV1,
        current_height: u64,
    ) -> Result<PrivateSettlementGlobalStateOutcomeV1, PrivateSettlementGlobalStateErrorV1> {
        let governance = mv::storage::Storage::from_iter(self.governance.clone());
        let pools = mv::storage::Storage::from_iter(self.pools.clone());
        let roots = mv::storage::Storage::from_iter(self.roots.clone());
        let nullifiers = mv::storage::Storage::from_iter(self.nullifiers.clone());
        let outputs = mv::storage::Storage::from_iter(self.outputs.clone());
        let recipient_index = mv::storage::Storage::from_iter(self.recipient_index.clone());
        let staged_locks = mv::storage::Storage::from_iter(self.staged_locks.clone());
        let receipts = mv::storage::Storage::from_iter(self.receipts.clone());
        let aborts = mv::storage::Storage::from_iter(self.aborts.clone());
        let plan = plan_private_settlement_prepare_locks_v1(
            &governance.view(),
            &pools.view(),
            &roots.view(),
            &nullifiers.view(),
            &outputs.view(),
            &recipient_index.view(),
            &staged_locks.view(),
            &receipts.view(),
            &aborts.view(),
            &barrier,
            current_height,
        )?;
        let Some(plan) = plan else {
            return Ok(PrivateSettlementGlobalStateOutcomeV1::Idempotent);
        };
        self.staged_locks.extend(plan.records);
        Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
    }

    /// Apply all certified legs and their receipt together or leave state unchanged.
    pub(crate) fn apply_receipt(
        &mut self,
        receipt: PrivateSettlementReceiptV1,
        current_height: u64,
    ) -> Result<PrivateSettlementGlobalStateOutcomeV1, PrivateSettlementGlobalStateErrorV1> {
        let governance = mv::storage::Storage::from_iter(self.governance.clone());
        let pools = mv::storage::Storage::from_iter(self.pools.clone());
        let roots = mv::storage::Storage::from_iter(self.roots.clone());
        let nullifiers = mv::storage::Storage::from_iter(self.nullifiers.clone());
        let outputs = mv::storage::Storage::from_iter(self.outputs.clone());
        let recipient_index = mv::storage::Storage::from_iter(self.recipient_index.clone());
        let staged_locks = mv::storage::Storage::from_iter(self.staged_locks.clone());
        let receipts = mv::storage::Storage::from_iter(self.receipts.clone());
        let aborts = mv::storage::Storage::from_iter(self.aborts.clone());
        let plan = plan_private_settlement_receipt_v1(
            &governance.view(),
            &pools.view(),
            &roots.view(),
            &nullifiers.view(),
            &outputs.view(),
            &recipient_index.view(),
            &staged_locks.view(),
            &receipts.view(),
            &aborts.view(),
            &receipt,
            current_height,
        )?
        .ok_or(PrivateSettlementGlobalStateErrorV1::Replay)?;

        // No fallible validation or encoding occurs below this atomic mutation barrier.
        for leg in plan.legs {
            self.pools.insert(leg.key, leg.next_pool);
            self.roots.insert(
                leg.root_key,
                PrivateSettlementRootProvenanceV1::Settlement(leg.reference),
            );
            for key in leg.nullifiers {
                self.nullifiers.insert(key, leg.reference);
            }
            for (key, record) in leg.outputs {
                self.outputs.insert(key, record);
            }
            for recipient in leg.recipients {
                self.recipient_index.insert(recipient, leg.reference);
            }
        }
        for key in plan.staged_lock_keys {
            self.staged_locks.remove(&key);
        }
        self.receipts.insert(receipt.manifest.bundle_id, receipt);
        Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
    }

    /// Persist an optional public abort/expiry marker without private contents.
    pub(crate) fn apply_abort(
        &mut self,
        receipt: PrivateSettlementAbortReceiptV1,
        current_height: u64,
    ) -> Result<PrivateSettlementGlobalStateOutcomeV1, PrivateSettlementGlobalStateErrorV1> {
        let staged_locks = mv::storage::Storage::from_iter(self.staged_locks.clone());
        let receipts = mv::storage::Storage::from_iter(self.receipts.clone());
        let aborts = mv::storage::Storage::from_iter(self.aborts.clone());
        let keys = plan_private_settlement_abort_v1(
            &staged_locks.view(),
            &receipts.view(),
            &aborts.view(),
            &receipt,
            current_height,
        )?;
        for key in keys {
            self.staged_locks.remove(&key);
        }
        self.aborts.insert(receipt.bundle_id, receipt);
        Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
    }

    /// Return the current root head for a restricted pool without exposing its asset mapping.
    pub(crate) fn pool_head(
        &self,
        route: PrivateSettlementRouteV1,
        pool_id: PrivacyPoolIdV1,
    ) -> Option<(u64, PrivacyRootV1)> {
        let key = PrivateSettlementPoolKeyV1::new(route, pool_id).ok()?;
        self.pools.get(&key).map(|pool| (pool.epoch(), pool.root()))
    }

    /// Query one public finalized receipt by opaque bundle id.
    pub(crate) fn receipt(&self, bundle_id: &Hash) -> Option<&PrivateSettlementReceiptV1> {
        self.receipts.get(bundle_id)
    }

    /// Validate all restored maps and cross-references before accepting a snapshot.
    pub(crate) fn validate(&self) -> Result<(), PrivateSettlementGlobalStateErrorV1> {
        let governance_storage = mv::storage::Storage::from_iter(self.governance.clone());
        let pool_storage = mv::storage::Storage::from_iter(self.pools.clone());
        let root_storage = mv::storage::Storage::from_iter(self.roots.clone());
        let nullifier_storage = mv::storage::Storage::from_iter(self.nullifiers.clone());
        let output_storage = mv::storage::Storage::from_iter(self.outputs.clone());
        let recipient_storage = mv::storage::Storage::from_iter(self.recipient_index.clone());
        let staged_lock_storage = mv::storage::Storage::from_iter(self.staged_locks.clone());
        let receipt_storage = mv::storage::Storage::from_iter(self.receipts.clone());
        let abort_storage = mv::storage::Storage::from_iter(self.aborts.clone());
        validate_private_settlement_persisted_state_v1(
            &governance_storage.view(),
            &pool_storage.view(),
            &root_storage.view(),
            &nullifier_storage.view(),
            &output_storage.view(),
            &recipient_storage.view(),
            &staged_lock_storage.view(),
            &receipt_storage.view(),
            &abort_storage.view(),
        )?;
        if rebuild_private_settlement_recipient_index_v1(&output_storage.view())?
            != self.recipient_index
        {
            return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
        }
        for (key, governance) in &self.governance {
            governance
                .validate()
                .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
            if key.route != governance.route || key.pool_id != governance.pool_id {
                return Err(PrivateSettlementGlobalStateErrorV1::Governance);
            }
            let pool = self
                .pools
                .get(key)
                .ok_or(PrivateSettlementGlobalStateErrorV1::Pool)?;
            pool.validate()
                .map_err(PrivateSettlementGlobalStateErrorV1::from_pool)?;
            if pool.route() != key.route
                || pool.pool_id() != key.pool_id
                || pool.restricted_pool_policy_digest() != governance.governance_digest
                || !self.roots.contains_key(&PrivateSettlementRootKeyV1 {
                    pool: *key,
                    epoch: pool.epoch(),
                    root: pool.root(),
                })
            {
                return Err(PrivateSettlementGlobalStateErrorV1::Pool);
            }
        }
        if self.pools.len() != self.governance.len() {
            return Err(PrivateSettlementGlobalStateErrorV1::Pool);
        }
        let mut receipt_digests = BTreeMap::new();
        for (bundle_id, receipt) in &self.receipts {
            verify_private_settlement_receipt_v1(receipt)
                .map_err(|_| PrivateSettlementGlobalStateErrorV1::Receipt)?;
            if bundle_id != &receipt.manifest.bundle_id || self.aborts.contains_key(bundle_id) {
                return Err(PrivateSettlementGlobalStateErrorV1::Receipt);
            }
            for leg in &receipt.legs {
                let key = PrivateSettlementPoolKeyV1::new(leg.delta.route, leg.delta.pool_id)?;
                let governance = self
                    .governance
                    .get(&key)
                    .ok_or(PrivateSettlementGlobalStateErrorV1::Governance)?;
                if !receipt_leg_matches_governance_lineage_v1(governance, receipt, &leg.delta) {
                    return Err(PrivateSettlementGlobalStateErrorV1::Governance);
                }
            }
            receipt_digests.insert(*bundle_id, canonical_receipt_digest_v1(receipt)?);
        }
        let validate_reference = |reference: PrivateSettlementFinalizationReferenceV1| {
            let receipt = self
                .receipts
                .get(&reference.bundle_id)
                .ok_or(PrivateSettlementGlobalStateErrorV1::Receipt)?;
            if receipt.finalized_height != reference.finalized_height
                || receipt_digests.get(&reference.bundle_id) != Some(&reference.receipt_digest)
                || usize::from(reference.leg_ordinal) >= receipt.legs.len()
            {
                return Err(PrivateSettlementGlobalStateErrorV1::Receipt);
            }
            Ok(())
        };
        for (key, reference) in &self.nullifiers {
            validate_reference(*reference)?;
            let receipt = &self.receipts[&reference.bundle_id];
            let delta = &receipt.legs[usize::from(reference.leg_ordinal)].delta;
            if key.pool.route != delta.route
                || key.pool.pool_id != delta.pool_id
                || !delta.nullifiers.contains(&key.nullifier)
            {
                return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
            }
        }
        for (key, record) in &self.outputs {
            validate_reference(record.reference)?;
            if record.encrypted_output.commitment != key.commitment {
                return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
            }
            let receipt = &self.receipts[&record.reference.bundle_id];
            let delta = &receipt.legs[usize::from(record.reference.leg_ordinal)].delta;
            if key.pool.route != delta.route
                || key.pool.pool_id != delta.pool_id
                || !delta.encrypted_outputs.contains(&record.encrypted_output)
            {
                return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
            }
        }
        for (key, provenance) in &self.roots {
            match provenance {
                PrivateSettlementRootProvenanceV1::Governance {
                    governance_digest,
                    admitted_at_height,
                } => {
                    if *admitted_at_height == 0
                        || self.governance.get(&key.pool).is_none_or(|record| {
                            !governance_origin_matches_current_v1(
                                record,
                                *governance_digest,
                                *admitted_at_height,
                            )
                        })
                    {
                        return Err(PrivateSettlementGlobalStateErrorV1::Governance);
                    }
                }
                PrivateSettlementRootProvenanceV1::Settlement(reference) => {
                    validate_reference(*reference)?;
                    let delta = &self.receipts[&reference.bundle_id].legs
                        [usize::from(reference.leg_ordinal)]
                    .delta;
                    if key.pool.route != delta.route
                        || key.pool.pool_id != delta.pool_id
                        || key.epoch != delta.new_epoch
                        || key.root != delta.new_root
                    {
                        return Err(PrivateSettlementGlobalStateErrorV1::Conflict);
                    }
                }
            }
        }
        for (bundle_id, abort) in &self.aborts {
            abort
                .validate()
                .map_err(|_| PrivateSettlementGlobalStateErrorV1::Receipt)?;
            if bundle_id != &abort.bundle_id || self.receipts.contains_key(bundle_id) {
                return Err(PrivateSettlementGlobalStateErrorV1::Receipt);
            }
        }
        Ok(())
    }
}

/// Redacted global-state failure safe for consensus diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum PrivateSettlementGlobalStateErrorV1 {
    /// The governed feature is disabled in the consensus configuration.
    #[error("private-settlement is disabled")]
    Disabled,
    /// The carrier or governance operation precedes governed activation.
    #[error("private-settlement is not active at this height")]
    Activation,
    /// The configured node capability cannot enforce the V1 proof/policy profile.
    #[error("private-settlement capability is unavailable")]
    Capability,
    /// Network identity differs from the local consensus security domain.
    #[error("private-settlement network binding is invalid")]
    Network,
    /// Participant, expiry, or encoded carrier bounds exceed consensus configuration.
    #[error("private-settlement consensus bounds are invalid")]
    Bounds,
    /// Restricted pool governance is missing, malformed, or inactive.
    #[error("private-settlement pool governance is invalid")]
    Governance,
    /// The pool state or caller-selected successor is invalid.
    #[error("private-settlement pool transition is invalid")]
    Pool,
    /// The finalized receipt or its phase certificates are invalid.
    #[error("private-settlement receipt is invalid")]
    Receipt,
    /// The complete all-Prepare barrier or one Prepare QC is invalid.
    #[error("private-settlement Prepare barrier is invalid")]
    PrepareBarrier,
    /// Commit voting/finalization has no exact globally replicated Prepare lock.
    #[error("private-settlement globally prepared lock is missing")]
    MissingPrepareLock,
    /// State application height differs from the receipt.
    #[error("private-settlement finalization height is invalid")]
    Height,
    /// A nullifier, output, root, or pool conflicts with durable state.
    #[error("private-settlement state conflict")]
    Conflict,
    /// The bundle already has the opposite terminal marker.
    #[error("private-settlement bundle is terminal")]
    Terminal,
    /// An exact finalized or expired bundle was submitted again.
    #[error("private-settlement terminal replay was rejected")]
    Replay,
    /// A replay attempted to replace existing evidence.
    #[error("private-settlement substitution was rejected")]
    Substitution,
    /// Canonical receipt encoding failed.
    #[error("private-settlement canonical encoding failed")]
    Encoding,
}

impl PrivateSettlementGlobalStateErrorV1 {
    fn from_pool(_: PrivateSettlementStateErrorV1) -> Self {
        Self::Pool
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::private_settlement::{
        protocol::{
            aggregate_private_settlement_phase_votes_v1, private_settlement_phase_body_v1,
            private_settlement_prepared_bundle_digest_v1,
            private_settlement_reserved_prepared_bundle_digest_v1,
            sign_private_settlement_phase_vote_v1,
        },
        sidecar_store::tests::{SidecarFixtureV1, sidecar_fixture},
    };
    use iroha_crypto::{HashOf, KeyPair};
    use iroha_data_model::nexus::{
        ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, PRIVATE_SETTLEMENT_INPUT_SLOTS_V1,
        PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1, PrivateSettlementAuditPolicyV1,
        PrivateSettlementAuthorityCatalogV1, PrivateSettlementCommitteeAuthorityV1,
        PrivateSettlementDeltaV1, PrivateSettlementLegReceiptV1,
        PrivateSettlementPhaseCertificateV1, PrivateSettlementPhaseV1,
        PrivateSettlementPoolGovernanceLifecycleV1,
    };
    use iroha_model_base::peer::PeerId;

    /// Verify one declared owner frame, reconstruction, and strict malformed-frame rejection.
    pub(crate) fn assert_private_settlement_frame_v1<T>(value: &T, nominal: &str)
    where
        T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de> + PartialEq,
    {
        assert_eq!(T::nominal_name(), nominal);
        assert_eq!(T::frame_name(), nominal);
        let frame = norito::encode_canonical(value).expect("declared owner frame encodes");
        assert_eq!(frame[6..22], norito::schema::identity::frame_hash::<T>());
        let decoded: T = norito::decode_canonical(&frame).expect("declared owner frame decodes");
        assert!(
            decoded == *value,
            "owner frame must preserve every payload field"
        );
        assert_eq!(
            norito::encode_canonical(&decoded).expect("owner re-encodes"),
            frame
        );
        let mut wrong_owner = frame.clone();
        wrong_owner[6] ^= 1;
        assert!(matches!(
            norito::decode_canonical::<T>(&wrong_owner),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(norito::decode_canonical::<T>(&frame[..frame.len() - 1]).is_err());
        let mut trailing = frame;
        trailing.push(0);
        assert!(norito::decode_canonical::<T>(&trailing).is_err());
    }

    #[test]
    fn global_state_frame_owners_roundtrip_with_exact_declared_roots() {
        let (state, receipt, _) = fixture();
        let delta = &receipt.legs[0].delta;
        let pool = PrivateSettlementPoolKeyV1::new(delta.route, delta.pool_id).expect("pool key");
        let root = PrivateSettlementRootKeyV1 {
            pool,
            epoch: delta.old_epoch,
            root: delta.old_root,
        };
        let nullifier = PrivateSettlementNullifierKeyV1 {
            pool,
            nullifier: delta.nullifiers[0],
        };
        let output = PrivateSettlementOutputKeyV1 {
            pool,
            commitment: delta.output_commitments[0],
        };
        let reference = PrivateSettlementFinalizationReferenceV1 {
            bundle_id: receipt.manifest.bundle_id,
            receipt_digest: canonical_receipt_digest_v1(&receipt).expect("receipt digest"),
            leg_ordinal: 0,
            finalized_height: 20,
        };
        macro_rules! check {
            ($owner:ident, $value:expr) => {
                assert_private_settlement_frame_v1::<$owner>(
                    &$value,
                    concat!(
                        "iroha_core::private_settlement::global_state::",
                        stringify!($owner)
                    ),
                );
            };
        }
        check!(PrivateSettlementPoolKeyV1, pool);
        check!(PrivateSettlementRootKeyV1, root);
        check!(PrivateSettlementNullifierKeyV1, nullifier);
        check!(PrivateSettlementOutputKeyV1, output);
        check!(
            PrivateSettlementStagedLockKeyV1,
            PrivateSettlementStagedLockKeyV1::PoolHead {
                pool,
                epoch: root.epoch,
                root: root.root,
            }
        );
        check!(
            PrivateSettlementStagedLockRecordV1,
            PrivateSettlementStagedLockRecordV1::Resource {
                bundle_id: reference.bundle_id,
                prepared_bundle_digest: Hash::new(b"prepared bundle"),
                leg_ordinal: 0,
            }
        );
        check!(PrivateSettlementFinalizationReferenceV1, reference);
        check!(
            PrivateSettlementRootProvenanceV1,
            PrivateSettlementRootProvenanceV1::Settlement(reference)
        );
        check!(
            PrivateSettlementOutputRecordV1,
            PrivateSettlementOutputRecordV1 {
                reference,
                encrypted_output: delta.encrypted_outputs[0].clone(),
            }
        );
        check!(PrivateSettlementGlobalStateV1, state);
    }

    #[test]
    fn private_settlement_json_keys_require_the_exact_owner_and_uppercase_frame() {
        fn check<T>(value: T)
        where
            T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de> + PartialEq,
        {
            let bytes = norito::to_bytes(&value).expect("key frame");
            let uppercase = hex::encode_upper(&bytes);
            let decoded: T =
                decode_private_settlement_storage_key_v1(&uppercase).expect("exact key");
            assert!(decoded == value);
            let mut encoded = String::new();
            encode_private_settlement_storage_key_v1(&value, &mut encoded);
            assert_eq!(encoded, format!("\"{uppercase}\""));
            assert!(
                decode_private_settlement_storage_key_v1::<T>(&uppercase.to_lowercase()).is_err()
            );
            assert!(
                decode_private_settlement_storage_key_v1::<T>(&format!("{uppercase}00")).is_err()
            );
            let mut wrong_owner = bytes;
            wrong_owner[6] ^= 1;
            assert!(
                decode_private_settlement_storage_key_v1::<T>(&hex::encode_upper(wrong_owner))
                    .is_err()
            );
        }
        let (state, receipt, _) = fixture();
        let pool = *state.pools.keys().next().expect("governed pool");
        let root = *state.roots.keys().next().expect("governed root");
        let delta = &receipt.legs[0].delta;
        check(pool);
        check(root);
        check(PrivateSettlementNullifierKeyV1 {
            pool,
            nullifier: delta.nullifiers[0],
        });
        check(PrivateSettlementOutputKeyV1 {
            pool,
            commitment: delta.output_commitments[0],
        });
        check(PrivateSettlementStagedLockKeyV1::Bundle(
            receipt.manifest.bundle_id,
        ));
    }

    fn certificate(
        manifest: &iroha_data_model::nexus::AtomicPrivateSettlementV1,
        delta: &PrivateSettlementDeltaV1,
        authority: &PrivateSettlementCommitteeAuthorityV1,
        keys: &[KeyPair],
        phase: PrivateSettlementPhaseV1,
        prepared_bundle_digest: Hash,
    ) -> PrivateSettlementPhaseCertificateV1 {
        let body = private_settlement_phase_body_v1(
            manifest,
            delta,
            authority,
            phase,
            prepared_bundle_digest,
        )
        .expect("phase body");
        let votes = keys[..3]
            .iter()
            .map(|key| sign_private_settlement_phase_vote_v1(body, key).expect("phase vote"))
            .collect::<Vec<_>>();
        aggregate_private_settlement_phase_votes_v1(body, delta.leg_ordinal, authority, &votes)
            .expect("phase certificate")
    }

    fn recertify_receipt_with_validator_keys(
        mut receipt: PrivateSettlementReceiptV1,
        validator_keys: &[KeyPair],
    ) -> PrivateSettlementReceiptV1 {
        let mut ordered_keys = validator_keys.to_vec();
        ordered_keys.sort_by_cached_key(|key| {
            crate::sumeragi::schedule::consensus_key(&PeerId::from(key.public_key().clone()))
                .expect("native committee key")
        });
        let validators = ordered_keys
            .iter()
            .map(|key| PeerId::from(key.public_key().clone()))
            .collect::<Vec<_>>();
        let validator_pops = ordered_keys
            .iter()
            .map(|key| {
                iroha_crypto::bls_normal_pop_prove(key.private_key()).expect("validator PoP")
            })
            .collect::<Vec<_>>();
        let authorities = receipt
            .manifest
            .legs
            .iter()
            .map(|leg| PrivateSettlementCommitteeAuthorityV1 {
                route: leg.route,
                validator_set_hash: HashOf::new(&validators),
                validators: validators.clone(),
                validator_pops: validator_pops.clone(),
            })
            .collect::<Vec<_>>();
        let deltas = receipt
            .legs
            .iter()
            .map(|leg| leg.delta.clone())
            .collect::<Vec<_>>();
        let prepares = deltas
            .iter()
            .zip(&authorities)
            .map(|(delta, authority)| {
                certificate(
                    &receipt.manifest,
                    delta,
                    authority,
                    &ordered_keys,
                    PrivateSettlementPhaseV1::Prepare,
                    private_settlement_reserved_prepared_bundle_digest_v1(),
                )
            })
            .collect::<Vec<_>>();
        let authority_catalog = PrivateSettlementAuthorityCatalogV1::from_leg_authorities(
            &receipt.manifest,
            &authorities,
        )
        .expect("authority catalog");
        let prepared_bundle_digest = private_settlement_prepared_bundle_digest_v1(
            &receipt.manifest,
            &authority_catalog,
            &deltas,
            &prepares,
        )
        .expect("prepared bundle digest");
        receipt.legs = deltas
            .iter()
            .zip(&authorities)
            .zip(prepares)
            .map(
                |((delta, authority), prepare)| PrivateSettlementLegReceiptV1 {
                    delta: delta.clone(),
                    prepare,
                    commit: certificate(
                        &receipt.manifest,
                        delta,
                        authority,
                        &ordered_keys,
                        PrivateSettlementPhaseV1::Commit,
                        prepared_bundle_digest,
                    ),
                },
            )
            .collect();
        receipt.authority_catalog = authority_catalog;
        verify_private_settlement_receipt_v1(&receipt).expect("recertified receipt");
        receipt
    }

    fn private_settlement_transaction_bytes(
        transaction: &crate::state::StateTransaction<'_, '_>,
    ) -> Vec<u8> {
        let state = PrivateSettlementGlobalStateV1 {
            governance: transaction
                .world
                .private_settlement_governance
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect(),
            pools: transaction
                .world
                .private_settlement_pools
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect(),
            roots: transaction
                .world
                .private_settlement_roots
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect(),
            nullifiers: transaction
                .world
                .private_settlement_nullifiers
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect(),
            outputs: transaction
                .world
                .private_settlement_outputs
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect(),
            recipient_index: transaction
                .world
                .private_settlement_recipient_index
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect(),
            staged_locks: transaction
                .world
                .private_settlement_staged_locks
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect(),
            receipts: transaction
                .world
                .private_settlement_receipts
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect(),
            aborts: transaction
                .world
                .private_settlement_aborts
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect(),
        };
        norito::encode_canonical(&state).expect("private-settlement transaction state encodes")
    }

    fn install_private_settlement_authority_fixture(
        state: &crate::state::State,
        receipt: &PrivateSettlementReceiptV1,
        validator_keys: &[KeyPair],
    ) {
        use crate::state::derive_committee_key_id;
        use iroha_data_model::{
            consensus::{ConsensusKeyRecord, ConsensusKeyStatus},
            sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLaneRecord},
        };

        let mut world = state.world.block();
        {
            let mut peers = world.peers_mut_for_testing().transaction();
            for key in validator_keys {
                let peer = PeerId::from(key.public_key().clone());
                if !peers.iter().any(|existing| existing == &peer) {
                    peers.push(peer);
                }
            }
            peers.apply();
        }
        for key in validator_keys {
            let id = derive_committee_key_id(key.public_key());
            let record = ConsensusKeyRecord {
                id: id.clone(),
                public_key: key.public_key().clone(),
                pop: Some(
                    iroha_crypto::bls_normal_pop_prove(key.private_key())
                        .expect("authority fixture PoP"),
                ),
                activation_height: 0,
                expiry_height: None,
                replaces: None,
                status: ConsensusKeyStatus::Active,
            };
            world.consensus_keys.insert(id, record.clone());
            world
                .consensus_keys_by_pk
                .insert(record.public_key.to_string(), vec![record.id]);
        }
        // Component setup installs the committed native owner. Physical catalog
        // metadata cannot substitute for native authority or its pinned PoPs.
        for (index, leg) in receipt.manifest.legs.iter().enumerate() {
            let authority = receipt
                .authority_catalog
                .authority_for_leg(&receipt.manifest, index)
                .expect("fixture route authority");
            world.sumeragi_lanes.get_mut().upsert(SumeragiLaneRecord {
                da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
                lane: leg.route.lane_id,
                dataspace: leg.route.dataspace_id,
                incarnation: leg.route.lane_incarnation.into(),
                params: iroha_data_model::parameter::system::SumeragiParameters::default(),
                committee: authority
                    .validators
                    .into_iter()
                    .zip(authority.validator_pops)
                    .map(|(peer, pop)| SumeragiLaneMember { peer, pop })
                    .collect(),
                created_at: 1,
                active_from: 3,
                closing: None,
                anchor_freshness: 16,
                merged: SumeragiLaneFrontier::default(),
                merged_at: 3,
                rescued: 0,
            });
        }
        world.commit();
    }

    pub(crate) fn fixture() -> (
        PrivateSettlementGlobalStateV1,
        PrivateSettlementReceiptV1,
        SidecarFixtureV1,
    ) {
        let fixture = sidecar_fixture();
        let mut manifest = fixture.sidecar.manifest.clone();
        let first_governance = fixture.pool_governance.clone();
        let mut second_policy_body = fixture.sidecar.policy.body.clone();
        second_policy_body.dataspace_id = manifest.legs[1].route.dataspace_id;
        second_policy_body.policy_id = Hash::new(b"second-dataspace-audit-policy");
        let second_policy =
            PrivateSettlementAuditPolicyV1::new(second_policy_body).expect("second audit policy");
        let second_governance = PrivateSettlementPoolGovernanceV1::from_restricted_mapping(
            manifest.legs[1].route,
            manifest.legs[1].pool_id,
            first_governance.body.asset_definition_id.clone(),
            [0x4B; 32],
            &second_policy,
            PrivateSettlementPoolGovernanceLifecycleV1 {
                governance_revision: 1,
                activation_height: 5,
                retirement_height: Some(500),
            },
        )
        .expect("second pool governance");
        manifest.legs[1].asset_binding_commitment = second_governance.body.asset_binding_commitment;
        manifest.legs[1].audit_policy_digest = second_policy.policy_digest;
        manifest.bundle_id = manifest.computed_bundle_id().expect("bundle id");

        let initial_commitments = [PrivacyCommitmentV1::new([0xE1; 32])];
        let first_pool = PrivateSettlementPoolStateV1::bootstrap(
            first_governance.body.route,
            first_governance.body.pool_id,
            first_governance.governance_digest,
            &initial_commitments,
        )
        .expect("first pool");
        let second_pool = PrivateSettlementPoolStateV1::bootstrap(
            second_governance.body.route,
            second_governance.body.pool_id,
            second_governance.governance_digest,
            &initial_commitments,
        )
        .expect("second pool");
        let mut deltas = vec![
            fixture.sidecar.payload.delta.clone(),
            fixture.sidecar.payload.delta.clone(),
        ];
        for (index, pool) in [&first_pool, &second_pool].into_iter().enumerate() {
            let manifest_leg = manifest.legs[index].clone();
            let delta = &mut deltas[index];
            delta.bundle_id = manifest.bundle_id;
            delta.leg_ordinal = u8::try_from(index).expect("fixture ordinal");
            delta.route = manifest_leg.route;
            delta.pool_id = manifest_leg.pool_id;
            delta.asset_binding_commitment = manifest_leg.asset_binding_commitment;
            delta.audit_policy_digest = manifest_leg.audit_policy_digest;
            delta.audit_key_epoch = if index == 0 {
                fixture.sidecar.policy.body.key_epoch
            } else {
                second_policy.body.key_epoch
            };
            if index != 0 {
                for (slot, output) in delta.encrypted_outputs.iter_mut().enumerate() {
                    let seed = 0x70_u8
                        .checked_add(
                            u8::try_from(index * PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1 + slot)
                                .expect("fixture output index fits u8"),
                        )
                        .expect("fixture recipient seed fits u8");
                    output.recipient = PrivacyRecipientIdV1::new([seed; 32]);
                }
            }
            delta.old_epoch = pool.epoch();
            delta.old_root = pool.root();
            let successor = pool
                .successor(&delta.output_commitments)
                .expect("successor");
            delta.new_epoch = successor.epoch;
            delta.new_root = successor.root;
            manifest.legs[index].delta_digest = delta.digest().expect("delta digest");
        }
        manifest.validate().expect("manifest");

        let validators = fixture
            .validator_keys
            .iter()
            .map(|key| PeerId::from(key.public_key().clone()))
            .collect::<Vec<_>>();
        let first_authority = fixture.sidecar.authority.clone();
        let second_authority = PrivateSettlementCommitteeAuthorityV1 {
            route: manifest.legs[1].route,
            validator_set_hash: HashOf::new(&validators),
            validators,
            validator_pops: fixture
                .validator_keys
                .iter()
                .map(|key| {
                    iroha_crypto::bls_normal_pop_prove(key.private_key()).expect("validator PoP")
                })
                .collect(),
        };
        let authorities = vec![first_authority, second_authority];
        let prepares = deltas
            .iter()
            .zip(&authorities)
            .map(|(delta, authority)| {
                certificate(
                    &manifest,
                    delta,
                    authority,
                    &fixture.validator_keys,
                    PrivateSettlementPhaseV1::Prepare,
                    private_settlement_reserved_prepared_bundle_digest_v1(),
                )
            })
            .collect::<Vec<_>>();
        let authority_catalog =
            PrivateSettlementAuthorityCatalogV1::from_leg_authorities(&manifest, &authorities)
                .expect("authority catalog");
        let prepared_bundle_digest = private_settlement_prepared_bundle_digest_v1(
            &manifest,
            &authority_catalog,
            &deltas,
            &prepares,
        )
        .expect("prepared bundle digest");
        let legs = deltas
            .iter()
            .zip(&authorities)
            .zip(prepares)
            .map(
                |((delta, authority), prepare)| PrivateSettlementLegReceiptV1 {
                    delta: delta.clone(),
                    prepare,
                    commit: certificate(
                        &manifest,
                        delta,
                        authority,
                        &fixture.validator_keys,
                        PrivateSettlementPhaseV1::Commit,
                        prepared_bundle_digest,
                    ),
                },
            )
            .collect();
        let receipt = PrivateSettlementReceiptV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            manifest,
            authority_catalog,
            legs,
            finalized_height: 20,
        };
        verify_private_settlement_receipt_v1(&receipt).expect("receipt");
        let mut state = PrivateSettlementGlobalStateV1::default();
        state
            .bootstrap_pool(first_governance, &initial_commitments, 5)
            .expect("first bootstrap");
        state
            .bootstrap_pool(second_governance, &initial_commitments, 5)
            .expect("second bootstrap");
        (state, receipt, fixture)
    }

    fn register_receipt_prepare(
        state: &mut PrivateSettlementGlobalStateV1,
        receipt: &PrivateSettlementReceiptV1,
    ) -> Result<PrivateSettlementGlobalStateOutcomeV1, PrivateSettlementGlobalStateErrorV1> {
        state.register_prepare(
            prepare_barrier_from_receipt_v1(receipt)?,
            receipt.manifest.authority_context_height,
        )
    }

    #[test]
    fn valid_receipt_advances_every_leg_exactly_once() {
        let (mut state, receipt, _) = fixture();
        assert_eq!(
            register_receipt_prepare(&mut state, &receipt),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
        );
        let old_heads = receipt
            .legs
            .iter()
            .map(|leg| {
                state
                    .pool_head(leg.delta.route, leg.delta.pool_id)
                    .expect("old head")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            state.apply_receipt(receipt.clone(), 20),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
        );
        for (index, leg) in receipt.legs.iter().enumerate() {
            assert_eq!(
                state.pool_head(leg.delta.route, leg.delta.pool_id),
                Some((leg.delta.new_epoch, leg.delta.new_root))
            );
            assert_ne!(old_heads[index], (leg.delta.new_epoch, leg.delta.new_root));
        }
        assert_eq!(state.nullifiers.len(), 4);
        assert_eq!(state.outputs.len(), 6);
        assert!(state.staged_locks.is_empty());
        assert_eq!(state.receipt(&receipt.manifest.bundle_id), Some(&receipt));
        state.validate().expect("restored state validates");
        assert_eq!(
            state.apply_receipt(receipt, 20),
            Err(PrivateSettlementGlobalStateErrorV1::Replay)
        );
    }

    #[test]
    fn prepare_registration_is_quorum_idempotent_and_restart_safe() {
        let (mut state, receipt, sidecar_fixture) = fixture();
        let barrier = prepare_barrier_from_receipt_v1(&receipt).expect("fixture Prepare barrier");
        let alternate_votes = sidecar_fixture.validator_keys[1..]
            .iter()
            .map(|key| {
                sign_private_settlement_phase_vote_v1(receipt.legs[0].prepare.body, key)
                    .expect("alternate Prepare vote")
            })
            .collect::<Vec<_>>();
        let alternate_prepare = aggregate_private_settlement_phase_votes_v1(
            receipt.legs[0].prepare.body,
            receipt.legs[0].prepare.authority_catalog_index,
            &sidecar_fixture.sidecar.authority,
            &alternate_votes,
        )
        .expect("alternate valid Prepare QC");
        assert_ne!(alternate_prepare, receipt.legs[0].prepare);
        let mut alternate_barrier = barrier.clone();
        alternate_barrier.prepare_certificates[0] = alternate_prepare.clone();
        assert!(barrier.quorum_equivalent_to(&alternate_barrier));
        assert_eq!(
            state.register_prepare(barrier.clone(), receipt.manifest.authority_context_height,),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
        );
        let registered_bytes = norito::encode_canonical(&state).expect("registered state bytes");
        assert_eq!(
            state.register_prepare(alternate_barrier, receipt.manifest.authority_context_height),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Idempotent)
        );
        assert_eq!(
            norito::encode_canonical(&state).expect("idempotent state bytes"),
            registered_bytes
        );
        let mut restored: PrivateSettlementGlobalStateV1 =
            norito::decode_from_bytes(&registered_bytes).expect("registered state decodes");
        restored
            .validate()
            .expect("registered staged locks survive restart validation");
        assert_eq!(restored, state);
        let mut recovered_receipt = receipt;
        recovered_receipt.legs[0].prepare = alternate_prepare;
        assert_eq!(
            restored.apply_receipt(recovered_receipt, 20),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Applied),
            "recovery with a quorum-equivalent Prepare QC must consume the original lock"
        );
        assert!(restored.staged_locks.is_empty());
    }

    #[test]
    fn prepare_registration_conflict_and_expiry_leave_no_partial_rows() {
        let (mut state, receipt, _) = fixture();
        let barrier = prepare_barrier_from_receipt_v1(&receipt).expect("fixture Prepare barrier");
        register_receipt_prepare(&mut state, &receipt).expect("register Prepare barrier");
        let first_resource_key = private_settlement_staged_lock_records_v1(
            &barrier,
            receipt.manifest.authority_context_height,
        )
        .expect("derive staged rows")
        .into_keys()
        .find(|key| !matches!(key, PrivateSettlementStagedLockKeyV1::Bundle(_)))
        .expect("fixture resource row");
        state.staged_locks.insert(
            first_resource_key,
            PrivateSettlementStagedLockRecordV1::Resource {
                bundle_id: Hash::new(b"conflicting staged owner"),
                prepared_bundle_digest: Hash::new(b"conflicting prepared digest"),
                leg_ordinal: 0,
            },
        );
        let before = norito::encode_canonical(&state).expect("conflicted state bytes");
        assert_eq!(
            state.register_prepare(barrier.clone(), receipt.manifest.authority_context_height),
            Err(PrivateSettlementGlobalStateErrorV1::Substitution)
        );
        assert_eq!(
            norito::encode_canonical(&state).expect("failed registration state bytes"),
            before,
            "a conflicted registration must not write a subset of staged rows"
        );

        state.staged_locks = private_settlement_staged_lock_records_v1(
            &barrier,
            receipt.manifest.authority_context_height,
        )
        .expect("restore exact staged rows");
        let staged_storage = mv::storage::Storage::from_iter(state.staged_locks.clone());
        let expired = expired_private_settlement_staged_lock_keys_v1(
            &staged_storage.view(),
            receipt.manifest.expiry_height + 1,
        )
        .expect("derive expired staged rows");
        assert_eq!(expired.len(), state.staged_locks.len());
        for key in expired {
            state.staged_locks.remove(&key);
        }
        assert!(state.staged_locks.is_empty());
        state.validate().expect("expired lock release validates");
    }

    #[test]
    fn prepare_registration_rejects_the_expiry_height_without_writes() {
        let (mut state, receipt, _) = fixture();
        let barrier = prepare_barrier_from_receipt_v1(&receipt).expect("fixture Prepare barrier");
        let before = norito::encode_canonical(&state).expect("pre-registration state bytes");
        assert_eq!(
            state.register_prepare(barrier, receipt.manifest.expiry_height),
            Err(PrivateSettlementGlobalStateErrorV1::Height),
            "a registration at expiry leaves no successor block for finalization"
        );
        assert_eq!(
            norito::encode_canonical(&state).expect("rejected registration state bytes"),
            before
        );
    }

    #[test]
    fn competing_bundle_cannot_reserve_an_active_pool_head() {
        let (mut state, receipt, sidecar_fixture) = fixture();
        register_receipt_prepare(&mut state, &receipt).expect("register first Prepare barrier");

        let mut competing = receipt.clone();
        competing.manifest.reimbursement_terms_commitment =
            Hash::new(b"competing active pool-head reservation");
        competing.manifest.bundle_id = competing
            .manifest
            .computed_bundle_id()
            .expect("competing bundle id");
        for (index, leg) in competing.legs.iter_mut().enumerate() {
            leg.delta.bundle_id = competing.manifest.bundle_id;
            competing.manifest.legs[index].delta_digest =
                leg.delta.digest().expect("competing delta digest");
        }
        competing
            .manifest
            .validate()
            .expect("competing manifest validates");
        let competing =
            recertify_receipt_with_validator_keys(competing, &sidecar_fixture.validator_keys);
        let competing_barrier =
            prepare_barrier_from_receipt_v1(&competing).expect("competing Prepare barrier");
        let before = norito::encode_canonical(&state).expect("locked state bytes");

        assert_eq!(
            state.register_prepare(
                competing_barrier,
                competing.manifest.authority_context_height,
            ),
            Err(PrivateSettlementGlobalStateErrorV1::Conflict)
        );
        assert_eq!(
            norito::encode_canonical(&state).expect("rejected competing state bytes"),
            before,
            "a competing active resource reservation must be byte-silent"
        );
    }

    #[test]
    fn block_start_expiry_is_rollback_safe_and_commits_the_full_release() {
        let world = prepared_world_fixture();
        let expiry_height = world
            .private_settlement_staged_locks
            .view()
            .iter()
            .find_map(|(key, record)| match (key, record) {
                (
                    PrivateSettlementStagedLockKeyV1::Bundle(_),
                    PrivateSettlementStagedLockRecordV1::Bundle { barrier, .. },
                ) => Some(barrier.manifest.expiry_height),
                _ => None,
            })
            .expect("prepared fixture has a bundle lock");
        let original_count = world.private_settlement_staged_locks.view().iter().count();
        let state = crate::state::State::new_for_testing(
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let header = || {
            iroha_data_model::block::BlockHeader::new(
                core::num::NonZeroU64::new(expiry_height + 1)
                    .expect("fixture successor height is non-zero"),
                None,
                None,
                0,
                0,
            )
        };

        {
            let block = state.block(header());
            assert_eq!(
                block.world.private_settlement_staged_locks.iter().count(),
                0,
                "incoming-height expiry must clear the complete overlay lock set"
            );
        }
        assert_eq!(
            state
                .world
                .private_settlement_staged_locks
                .view()
                .iter()
                .count(),
            original_count,
            "dropping the block overlay must restore every staged-lock row"
        );

        state
            .block(header())
            .commit_world_overlay_for_testing()
            .expect("commit block-start private-settlement expiry sweep");
        assert_eq!(
            state
                .world
                .private_settlement_staged_locks
                .view()
                .iter()
                .count(),
            0,
            "committed expiry must remove the complete staged-lock set"
        );
    }

    #[test]
    fn active_prepare_registration_blocks_pool_policy_rotation() {
        let (mut state, receipt, _) = fixture();
        register_receipt_prepare(&mut state, &receipt).expect("register Prepare barrier");
        let key = PrivateSettlementPoolKeyV1::new(
            receipt.legs[0].delta.route,
            receipt.legs[0].delta.pool_id,
        )
        .expect("fixture pool key");
        let current = state.governance.get(&key).expect("governance").clone();
        let mut replacement = current.clone();
        replacement.audit_policy_digest = Hash::new(b"locked rotation audit policy");
        replacement.audit_key_epoch += 1;
        replacement.lifecycle.governance_revision += 1;
        replacement.lifecycle.activation_height = receipt.finalized_height;
        replacement.governance_digest = Hash::new(b"locked rotation governance");
        let before = norito::encode_canonical(&state).expect("locked state bytes");
        assert_eq!(
            state.rotate_pool_policy(
                current.governance_digest,
                replacement,
                receipt.finalized_height,
            ),
            Err(PrivateSettlementGlobalStateErrorV1::Conflict)
        );
        assert_eq!(
            norito::encode_canonical(&state).expect("rejected rotation bytes"),
            before
        );
    }

    #[test]
    fn finalized_recipient_cannot_be_reused_by_a_later_bundle() {
        let (mut state, receipt, sidecar_fixture) = fixture();
        register_receipt_prepare(&mut state, &receipt).expect("register initial Prepare barrier");
        assert_eq!(
            state.apply_receipt(receipt.clone(), receipt.finalized_height),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
        );
        let reused_recipient = receipt.legs[0].delta.encrypted_outputs[0].recipient;
        let mut later = receipt.clone();
        later.manifest.reimbursement_terms_commitment =
            Hash::new(b"one-time recipient reuse adversarial bundle");
        later.manifest.bundle_id = later
            .manifest
            .computed_bundle_id()
            .expect("later bundle id");
        later.finalized_height = receipt.finalized_height + 1;
        for (leg_index, leg) in later.legs.iter_mut().enumerate() {
            let pool_key = PrivateSettlementPoolKeyV1::new(leg.delta.route, leg.delta.pool_id)
                .expect("fixture pool key");
            let pool = state.pools.get(&pool_key).expect("advanced fixture pool");
            leg.delta.bundle_id = later.manifest.bundle_id;
            leg.delta.old_epoch = pool.epoch();
            leg.delta.old_root = pool.root();
            for (slot, nullifier) in leg.delta.nullifiers.iter_mut().enumerate() {
                let seed = 0x90_u8
                    .checked_add(
                        u8::try_from(leg_index * PRIVATE_SETTLEMENT_INPUT_SLOTS_V1 + slot)
                            .expect("fixture nullifier index fits u8"),
                    )
                    .expect("fixture nullifier seed fits u8");
                *nullifier = PrivacyNullifierV1::new([seed; 32]);
            }
            for (slot, (commitment, output)) in leg
                .delta
                .output_commitments
                .iter_mut()
                .zip(&mut leg.delta.encrypted_outputs)
                .enumerate()
            {
                let offset = u8::try_from(leg_index * PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1 + slot)
                    .expect("fixture output index fits u8");
                *commitment = PrivacyCommitmentV1::new(
                    [0xA0_u8
                        .checked_add(offset)
                        .expect("commitment seed fits u8"); 32],
                );
                output.commitment = *commitment;
                output.ephemeral_public_key =
                    iroha_data_model::privacy::PrivacyEncryptionKeyV1::new(
                        [0xB0_u8
                            .checked_add(offset)
                            .expect("encryption seed fits u8"); 32],
                    );
                output.recipient = if leg_index == 0 && slot == 0 {
                    reused_recipient
                } else {
                    PrivacyRecipientIdV1::new(
                        [0xC0_u8.checked_add(offset).expect("recipient seed fits u8"); 32],
                    )
                };
            }
            let successor = pool
                .successor(&leg.delta.output_commitments)
                .expect("later successor");
            leg.delta.new_epoch = successor.epoch;
            leg.delta.new_root = successor.root;
            later.manifest.legs[leg_index].delta_digest =
                leg.delta.digest().expect("later delta digest");
        }
        later.manifest.validate().expect("later manifest");
        let later = recertify_receipt_with_validator_keys(later, &sidecar_fixture.validator_keys);
        let before = norito::encode_canonical(&state).expect("state bytes");
        assert_eq!(
            register_receipt_prepare(&mut state, &later),
            Err(PrivateSettlementGlobalStateErrorV1::Conflict)
        );
        assert_eq!(
            norito::encode_canonical(&state).expect("state bytes"),
            before,
            "recipient reuse must leave every state map byte-identical"
        );
    }

    #[test]
    fn policy_rotation_preserves_frontier_and_rejects_old_policy_bundles() {
        let (mut state, old_policy_receipt, _) = fixture();
        let key = PrivateSettlementPoolKeyV1::new(
            old_policy_receipt.legs[0].delta.route,
            old_policy_receipt.legs[0].delta.pool_id,
        )
        .expect("pool key");
        let current = state.governance.get(&key).expect("governance").clone();
        let old_head = state.pool_head(key.route, key.pool_id).expect("head");
        let old_roots = state.roots.clone();
        let old_nullifiers = state.nullifiers.clone();
        let old_outputs = state.outputs.clone();
        let old_receipts = state.receipts.clone();
        let mut replacement = current.clone();
        replacement.audit_policy_digest = Hash::new(b"rotated audit policy");
        replacement.audit_key_epoch += 1;
        replacement.lifecycle.governance_revision += 1;
        replacement.lifecycle.activation_height = 20;
        replacement.governance_digest = Hash::new(b"rotated restricted governance");

        assert_eq!(
            state.rotate_pool_policy(current.governance_digest, replacement.clone(), 20),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
        );
        assert_eq!(state.pool_head(key.route, key.pool_id), Some(old_head));
        assert_eq!(state.roots, old_roots);
        assert_eq!(state.nullifiers, old_nullifiers);
        assert_eq!(state.outputs, old_outputs);
        assert_eq!(state.receipts, old_receipts);
        state
            .validate()
            .expect("rotated state validates after restart");
        assert_eq!(
            state.rotate_pool_policy(current.governance_digest, replacement, 20),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Idempotent)
        );

        let before_old_bundle = norito::encode_canonical(&state).expect("state bytes");
        assert!(state.apply_receipt(old_policy_receipt, 20).is_err());
        assert_eq!(
            norito::encode_canonical(&state).expect("state bytes"),
            before_old_bundle,
            "a bundle spanning the policy boundary must not mutate any map"
        );
    }

    #[test]
    fn policy_rotation_retains_finalized_history_across_restart_and_replay() {
        let (mut state, receipt, _) = fixture();
        register_receipt_prepare(&mut state, &receipt).expect("register Prepare barrier");
        assert_eq!(
            state.apply_receipt(receipt.clone(), receipt.finalized_height),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
        );
        let key = PrivateSettlementPoolKeyV1::new(
            receipt.legs[0].delta.route,
            receipt.legs[0].delta.pool_id,
        )
        .expect("pool key");
        let current = state.governance.get(&key).expect("governance").clone();
        let old_head = state.pool_head(key.route, key.pool_id).expect("head");
        let mut replacement = current.clone();
        replacement.audit_policy_digest = Hash::new(b"post-finality audit policy");
        replacement.audit_key_epoch += 1;
        replacement.lifecycle.governance_revision += 1;
        replacement.lifecycle.activation_height = receipt.finalized_height + 1;
        replacement.governance_digest = Hash::new(b"post-finality governance");

        assert_eq!(
            state.rotate_pool_policy(
                current.governance_digest,
                replacement,
                receipt.finalized_height + 1,
            ),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
        );
        assert_eq!(state.pool_head(key.route, key.pool_id), Some(old_head));
        let persisted = norito::encode_canonical(&state).expect("state encodes");
        let mut restored: PrivateSettlementGlobalStateV1 =
            norito::decode_from_bytes(&persisted).expect("state decodes");
        restored
            .validate()
            .expect("pre-rotation receipt remains valid after restart");
        let world = world_from_private_settlement_state(restored.clone());
        validate_private_settlement_persisted_state_v1(
            &world.private_settlement_governance.view(),
            &world.private_settlement_pools.view(),
            &world.private_settlement_roots.view(),
            &world.private_settlement_nullifiers.view(),
            &world.private_settlement_outputs.view(),
            &world.private_settlement_recipient_index.view(),
            &world.private_settlement_staged_locks.view(),
            &world.private_settlement_receipts.view(),
            &world.private_settlement_aborts.view(),
        )
        .expect("WSV recovery accepts the anchored historical policy revision");
        let rotated = restored.governance.get(&key).expect("rotated governance");
        assert_eq!(rotated.prior_revisions.len(), 1);
        assert_eq!(
            rotated.prior_revisions[0].governance_digest,
            current.governance_digest
        );
        assert_eq!(
            restored.apply_receipt(receipt.clone(), receipt.finalized_height),
            Err(PrivateSettlementGlobalStateErrorV1::Replay)
        );
        assert_eq!(
            norito::encode_canonical(&restored).expect("state re-encodes"),
            persisted,
            "exact replay after rotation must leave every state byte unchanged"
        );
    }

    #[test]
    fn policy_rotation_rejects_a_same_height_pool_finalization() {
        let (mut state, receipt, _) = fixture();
        register_receipt_prepare(&mut state, &receipt).expect("register Prepare barrier");
        assert_eq!(
            state.apply_receipt(receipt.clone(), receipt.finalized_height),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
        );
        let key = PrivateSettlementPoolKeyV1::new(
            receipt.legs[0].delta.route,
            receipt.legs[0].delta.pool_id,
        )
        .expect("pool key");
        let current = state.governance.get(&key).expect("governance").clone();
        let mut replacement = current.clone();
        replacement.audit_policy_digest = Hash::new(b"same-height audit policy");
        replacement.audit_key_epoch += 1;
        replacement.lifecycle.governance_revision += 1;
        replacement.lifecycle.activation_height = receipt.finalized_height;
        replacement.governance_digest = Hash::new(b"same-height governance");
        let before = norito::encode_canonical(&state).expect("state bytes");

        assert_eq!(
            state.rotate_pool_policy(
                current.governance_digest,
                replacement,
                receipt.finalized_height,
            ),
            Err(PrivateSettlementGlobalStateErrorV1::Governance)
        );
        assert_eq!(
            norito::encode_canonical(&state).expect("state bytes"),
            before
        );
    }

    #[test]
    fn policy_rotation_rejects_stale_rollback_and_asset_substitution_without_mutation() {
        let (mut state, receipt, _) = fixture();
        let key = PrivateSettlementPoolKeyV1::new(
            receipt.legs[0].delta.route,
            receipt.legs[0].delta.pool_id,
        )
        .expect("pool key");
        let current = state.governance.get(&key).expect("governance").clone();
        let mut replacement = current.clone();
        replacement.audit_policy_digest = Hash::new(b"new policy");
        replacement.audit_key_epoch += 1;
        replacement.lifecycle.governance_revision += 1;
        replacement.lifecycle.activation_height = 20;
        replacement.governance_digest = Hash::new(b"new governance");

        for invalid in [
            PrivateSettlementPoolGovernanceProjectionV1 {
                audit_key_epoch: current.audit_key_epoch,
                ..replacement.clone()
            },
            PrivateSettlementPoolGovernanceProjectionV1 {
                lifecycle: current.lifecycle,
                ..replacement.clone()
            },
            PrivateSettlementPoolGovernanceProjectionV1 {
                asset_binding_commitment: Hash::new(b"substituted asset binding"),
                ..replacement.clone()
            },
        ] {
            let before = norito::encode_canonical(&state).expect("state bytes");
            assert!(
                state
                    .rotate_pool_policy(current.governance_digest, invalid, 20)
                    .is_err()
            );
            assert_eq!(
                norito::encode_canonical(&state).expect("state bytes"),
                before
            );
        }
        let before = norito::encode_canonical(&state).expect("state bytes");
        assert_eq!(
            state.rotate_pool_policy(Hash::new(b"stale expected digest"), replacement.clone(), 20,),
            Err(PrivateSettlementGlobalStateErrorV1::Substitution)
        );
        assert_eq!(
            norito::encode_canonical(&state).expect("state bytes"),
            before
        );
    }

    #[test]
    fn invalid_later_leg_leaves_all_state_bytes_identical() {
        let (mut state, mut receipt, _) = fixture();
        register_receipt_prepare(&mut state, &receipt).expect("register Prepare barrier");
        receipt.legs[1].delta.new_root = PrivacyRootV1::new([0xFF; 32]);
        let before = norito::encode_canonical(&state).expect("state bytes");
        assert!(state.apply_receipt(receipt, 20).is_err());
        let after = norito::encode_canonical(&state).expect("state bytes");
        assert_eq!(before, after);
    }

    #[test]
    fn persisted_state_rejects_duplicate_pool_epoch_roots() {
        let mut world = finalized_world_fixture();
        let (pool, governance_digest, admitted_at_height) = {
            let governance = world.private_settlement_governance.view();
            let (pool, record) = governance.iter().next().expect("governed fixture pool");
            let admitted_at_height = world
                .private_settlement_roots
                .view()
                .iter()
                .find_map(|(root, provenance)| {
                    (root.pool == *pool)
                        .then_some(provenance)
                        .and_then(|provenance| match provenance {
                            PrivateSettlementRootProvenanceV1::Governance {
                                admitted_at_height,
                                ..
                            } => Some(*admitted_at_height),
                            PrivateSettlementRootProvenanceV1::Settlement(_) => None,
                        })
                })
                .expect("governance origin root");
            (*pool, record.governance_digest, admitted_at_height)
        };
        world.private_settlement_roots.insert(
            PrivateSettlementRootKeyV1 {
                pool,
                epoch: 1,
                root: PrivacyRootV1::new([0xD7; 32]),
            },
            PrivateSettlementRootProvenanceV1::Governance {
                governance_digest,
                admitted_at_height,
            },
        );

        let error = validate_private_settlement_persisted_state_v1(
            &world.private_settlement_governance.view(),
            &world.private_settlement_pools.view(),
            &world.private_settlement_roots.view(),
            &world.private_settlement_nullifiers.view(),
            &world.private_settlement_outputs.view(),
            &world.private_settlement_recipient_index.view(),
            &world.private_settlement_staged_locks.view(),
            &world.private_settlement_receipts.view(),
            &world.private_settlement_aborts.view(),
        )
        .expect_err("two roots at one pool epoch must fail closed");
        assert_eq!(error, PrivateSettlementGlobalStateErrorV1::Conflict);
    }

    #[test]
    fn world_view_pool_head_requires_retained_root_provenance() {
        let world = finalized_world_fixture();
        let (pool_key, epoch, root) = {
            let pools = world.private_settlement_pools.view();
            let (pool_key, pool) = pools.iter().next().expect("governed fixture pool");
            (*pool_key, pool.epoch(), pool.root())
        };
        assert_eq!(
            world
                .view()
                .private_settlement_pool_head_v1(pool_key.route, pool_key.pool_id),
            Some((epoch, root))
        );

        {
            let mut roots = world.private_settlement_roots.block();
            roots.remove(PrivateSettlementRootKeyV1 {
                pool: pool_key,
                epoch,
                root,
            });
            roots.commit();
        }

        assert_eq!(
            world
                .view()
                .private_settlement_pool_head_v1(pool_key.route, pool_key.pool_id),
            None,
            "an unproven pool frontier must not be reported"
        );
    }

    #[test]
    fn persisted_state_rejects_a_stale_recipient_index() {
        let world = finalized_world_fixture();
        let recipient = world
            .private_settlement_recipient_index
            .view()
            .iter()
            .next()
            .map(|(recipient, _)| *recipient)
            .expect("finalized fixture recipient");
        let mut recipient_index = world.private_settlement_recipient_index.block();
        recipient_index.remove(recipient);
        recipient_index.commit();

        let error = validate_private_settlement_persisted_state_v1(
            &world.private_settlement_governance.view(),
            &world.private_settlement_pools.view(),
            &world.private_settlement_roots.view(),
            &world.private_settlement_nullifiers.view(),
            &world.private_settlement_outputs.view(),
            &world.private_settlement_recipient_index.view(),
            &world.private_settlement_staged_locks.view(),
            &world.private_settlement_receipts.view(),
            &world.private_settlement_aborts.view(),
        )
        .expect_err("a stale derived recipient index must fail closed");
        assert_eq!(error, PrivateSettlementGlobalStateErrorV1::Conflict);
    }

    #[test]
    fn persisted_state_rejects_receipt_disconnected_from_governance_origin() {
        let mut world = finalized_world_fixture();
        let (origin_key, origin_provenance) = {
            let roots = world.private_settlement_roots.view();
            roots
                .iter()
                .find_map(|(key, provenance)| {
                    matches!(
                        provenance,
                        PrivateSettlementRootProvenanceV1::Governance { .. }
                    )
                    .then_some((*key, *provenance))
                })
                .expect("governance origin root")
        };
        {
            let mut roots = world.private_settlement_roots.block();
            roots.remove(origin_key);
            roots.commit();
        }
        world.private_settlement_roots.insert(
            PrivateSettlementRootKeyV1 {
                root: PrivacyRootV1::new([0xD8; 32]),
                ..origin_key
            },
            origin_provenance,
        );

        let error = validate_private_settlement_persisted_state_v1(
            &world.private_settlement_governance.view(),
            &world.private_settlement_pools.view(),
            &world.private_settlement_roots.view(),
            &world.private_settlement_nullifiers.view(),
            &world.private_settlement_outputs.view(),
            &world.private_settlement_recipient_index.view(),
            &world.private_settlement_staged_locks.view(),
            &world.private_settlement_receipts.view(),
            &world.private_settlement_aborts.view(),
        )
        .expect_err("a certified target without its exact old root must fail closed");
        assert_eq!(error, PrivateSettlementGlobalStateErrorV1::Conflict);
    }

    #[test]
    fn abort_marker_excludes_later_finalization() {
        let (mut state, receipt, _) = fixture();
        let abort = PrivateSettlementAbortReceiptV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id: receipt.manifest.network_id.clone(),
            bundle_id: receipt.manifest.bundle_id,
            manifest_digest: receipt.manifest.manifest_digest().expect("manifest digest"),
            finalized_height: 19,
            reason: iroha_data_model::nexus::PrivateSettlementAbortReasonV1::ParticipantRejected,
        };
        assert_eq!(
            state.apply_abort(abort, 19),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
        );
        assert!(state.staged_locks.is_empty());
        let before = norito::encode_canonical(&state).expect("state bytes");
        assert_eq!(
            state.apply_receipt(receipt, 20),
            Err(PrivateSettlementGlobalStateErrorV1::Terminal)
        );
        assert_eq!(
            before,
            norito::encode_canonical(&state).expect("state bytes")
        );
    }

    #[test]
    fn expired_terminal_marker_rejects_exact_replay_without_mutation() {
        let (mut state, receipt, _) = fixture();
        let expired = PrivateSettlementAbortReceiptV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id: receipt.manifest.network_id,
            bundle_id: receipt.manifest.bundle_id,
            manifest_digest: receipt.manifest.manifest_digest().expect("manifest digest"),
            finalized_height: 21,
            reason: iroha_data_model::nexus::PrivateSettlementAbortReasonV1::Expired,
        };
        assert_eq!(
            state.apply_abort(expired.clone(), 21),
            Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
        );
        assert!(state.staged_locks.is_empty());
        let before = norito::encode_canonical(&state).expect("state bytes");
        assert_eq!(
            state.apply_abort(expired, 21),
            Err(PrivateSettlementGlobalStateErrorV1::Replay)
        );
        assert_eq!(
            before,
            norito::encode_canonical(&state).expect("state bytes"),
            "an exact expired replay must not mutate terminal state"
        );
    }

    pub(crate) fn world_from_private_settlement_state(
        state: PrivateSettlementGlobalStateV1,
    ) -> crate::state::World {
        let PrivateSettlementGlobalStateV1 {
            governance,
            pools,
            roots,
            nullifiers,
            outputs,
            recipient_index,
            staged_locks,
            receipts,
            aborts,
        } = state;
        let mut world = crate::state::World::default();
        world.private_settlement_governance = mv::storage::Storage::from_iter(governance);
        world.private_settlement_pools = mv::storage::Storage::from_iter(pools);
        world.private_settlement_roots = mv::storage::Storage::from_iter(roots);
        world.private_settlement_nullifiers = mv::storage::Storage::from_iter(nullifiers);
        world.private_settlement_outputs = mv::storage::Storage::from_iter(outputs);
        world.private_settlement_recipient_index = mv::storage::Storage::from_iter(recipient_index);
        world.private_settlement_staged_locks = mv::storage::Storage::from_iter(staged_locks);
        world.private_settlement_receipts = mv::storage::Storage::from_iter(receipts);
        world.private_settlement_aborts = mv::storage::Storage::from_iter(aborts);
        world
    }

    /// Build a valid World with one durable all-Prepare registration and no terminal marker.
    pub(crate) fn prepared_world_fixture() -> crate::state::World {
        let (mut private_state, receipt, _) = fixture();
        register_receipt_prepare(&mut private_state, &receipt)
            .expect("register prepared fixture barrier");
        world_from_private_settlement_state(private_state)
    }

    pub(crate) fn finalized_world_fixture() -> crate::state::World {
        let (mut private_state, receipt, _) = fixture();
        register_receipt_prepare(&mut private_state, &receipt)
            .expect("register finalized fixture Prepare barrier");
        private_state
            .apply_receipt(receipt.clone(), receipt.finalized_height)
            .expect("finalize private-settlement fixture");
        let abort = PrivateSettlementAbortReceiptV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id: receipt.manifest.network_id,
            bundle_id: Hash::new(b"private-settlement tiered abort fixture"),
            manifest_digest: Hash::new(b"private-settlement tiered abort manifest"),
            finalized_height: receipt.finalized_height + 1,
            reason: iroha_data_model::nexus::PrivateSettlementAbortReasonV1::Expired,
        };
        private_state
            .apply_abort(abort, receipt.finalized_height + 1)
            .expect("persist private-settlement abort fixture");
        world_from_private_settlement_state(private_state)
    }

    #[test]
    fn state_transaction_applies_all_legs_only_at_atomic_commit_boundaries() {
        use crate::{kura::Kura, query::store::LiveQueryStore, state::State};
        use iroha_data_model::{
            block::BlockHeader,
            nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
        };
        use iroha_model_base::chain::ChainId;
        use std::num::{NonZeroU32, NonZeroU64};

        let (mut private_state, receipt, sidecar_fixture) = fixture();
        let receipt =
            recertify_receipt_with_validator_keys(receipt, &sidecar_fixture.validator_keys);
        register_receipt_prepare(&mut private_state, &receipt)
            .expect("replicate the exact certified Prepare locks before finalization");
        let world = world_from_private_settlement_state(private_state);
        let state = State::new_with_chain_and_network_id_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            ChainId::from("private-settlement-wsv-test"),
            receipt.manifest.network_id.clone(),
        );
        install_private_settlement_authority_fixture(
            &state,
            &receipt,
            &sidecar_fixture.validator_keys,
        );
        let header = BlockHeader::new(
            NonZeroU64::new(receipt.finalized_height).expect("non-zero finalization height"),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        block.nexus.atomic_private_settlement.enabled = true;
        block.nexus.atomic_private_settlement.activation_height = Some(2);
        block
            .nexus
            .atomic_private_settlement
            .minimum_activation_notice_blocks =
            NonZeroU64::new(2).expect("non-zero settlement activation notice");
        let lane_bound = receipt
            .manifest
            .legs
            .iter()
            .map(|leg| leg.route.lane_id.as_u32())
            .max()
            .expect("receipt has participants")
            .checked_add(1)
            .and_then(NonZeroU32::new)
            .expect("fixture lane bound");
        let lane_catalog = LaneCatalog::new(
            lane_bound,
            receipt
                .manifest
                .legs
                .iter()
                .map(|leg| LaneConfig {
                    id: leg.route.lane_id,
                    dataspace_id: leg.route.dataspace_id,
                    alias: format!("private-settlement-{}", leg.route.lane_id.as_u32()),
                    governance: Some("parliament".to_owned()),
                    ..LaneConfig::default()
                })
                .collect(),
        )
        .expect("fixture settlement lane catalog");
        block.nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog);
        block.nexus.lane_catalog = lane_catalog;
        block.nexus.dataspace_catalog = DataSpaceCatalog::new(
            receipt
                .manifest
                .legs
                .iter()
                .map(|leg| DataSpaceMetadata {
                    id: leg.route.dataspace_id,
                    alias: format!("private-settlement-{}", leg.route.dataspace_id.as_u64()),
                    description: None,
                    fault_tolerance: 1,
                })
                .collect(),
        )
        .expect("fixture settlement dataspace catalog");

        let old_heads = receipt
            .legs
            .iter()
            .map(|leg| {
                let key = PrivateSettlementPoolKeyV1::new(leg.delta.route, leg.delta.pool_id)
                    .expect("seeded pool key");
                block
                    .world
                    .private_settlement_pools
                    .get(&key)
                    .map(|pool| (pool.epoch(), pool.root()))
                    .expect("seeded pool head")
            })
            .collect::<Vec<_>>();

        {
            let mut transaction = block.transaction();
            assert_eq!(
                transaction.apply_private_settlement_receipt_v1(receipt.clone()),
                Err(PrivateSettlementGlobalStateErrorV1::Capability),
                "WSV admission must not trust the Torii capability gate"
            );
            assert!(
                transaction
                    .private_settlement_receipt_v1(&receipt.manifest.bundle_id)
                    .is_none()
            );
            for (index, leg) in receipt.legs.iter().enumerate() {
                assert_eq!(
                    transaction.private_settlement_pool_head_v1(leg.delta.route, leg.delta.pool_id),
                    Some(old_heads[index])
                );
            }
        }
        assert!(
            block
                .world
                .private_settlement_receipts
                .get(&receipt.manifest.bundle_id)
                .is_none(),
            "missing compiled capability must leave the parent block byte-clean"
        );

        let protocol_id =
            iroha_data_model::privacy::PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1;
        let profile = crate::privacy_profiles::compiled_privacy_profile_v1(protocol_id)
            .expect("compiled IVM private-note profile");
        let proposed = profile.activation_record(
            iroha_data_model::privacy::PrivacyProtocolLifecycleV1::Proposed(
                iroha_data_model::privacy::PrivacyProposedLifecycleV1 {
                    proposed_at_height: 1,
                },
            ),
        );
        block.world.privacy_activations.insert(
            crate::privacy_state::PrivacyActivationKeyV1::new(protocol_id),
            proposed,
        );
        {
            let mut transaction = block.transaction();
            assert_eq!(
                transaction.apply_private_settlement_receipt_v1(receipt.clone()),
                Err(PrivateSettlementGlobalStateErrorV1::Activation),
                "a proposed generic capability must not activate the settlement profile"
            );
        }

        let active = profile.activation_record(
            iroha_data_model::privacy::PrivacyProtocolLifecycleV1::Active(
                iroha_data_model::privacy::PrivacyActiveLifecycleV1 {
                    proposed_at_height: 1,
                    activated_at_height: 2,
                    state_since_height: 2,
                },
            ),
        );
        block.world.privacy_activations.insert(
            crate::privacy_state::PrivacyActivationKeyV1::new(protocol_id),
            active,
        );
        {
            let mut transaction = block.transaction();
            assert_eq!(
                transaction.apply_private_settlement_receipt_v1(receipt.clone()),
                Err(PrivateSettlementGlobalStateErrorV1::Activation),
                "configuration activation earlier than the notice window must fail closed"
            );
        }
        block
            .nexus
            .atomic_private_settlement
            .minimum_activation_notice_blocks =
            NonZeroU64::new(1).expect("non-zero settlement activation notice");

        {
            let mut transaction = block.transaction();
            for key in &sidecar_fixture.validator_keys {
                let committee_id = crate::state::derive_committee_key_id(key.public_key());
                let mut record = transaction
                    .world
                    .consensus_keys
                    .get(&committee_id)
                    .cloned()
                    .expect("fixture has a purpose-specific committee key");
                let _ = transaction.world.consensus_keys.remove(committee_id);
                record.id = crate::state::derive_validator_key_id(key.public_key());
                transaction
                    .world
                    .consensus_keys_by_pk
                    .insert(record.public_key.to_string(), vec![record.id.clone()]);
                transaction
                    .world
                    .consensus_keys
                    .insert(record.id.clone(), record);
            }
            let before = private_settlement_transaction_bytes(&transaction);
            assert_eq!(
                transaction.apply_private_settlement_receipt_v1(receipt.clone()),
                Err(PrivateSettlementGlobalStateErrorV1::Receipt),
                "global-validator keys alone must not authorize private settlement"
            );
            assert_eq!(
                private_settlement_transaction_bytes(&transaction),
                before,
                "wrong-purpose authority must not mutate any private-state map"
            );
        }

        let forged_validator_keys = (0xB1_u8..=0xB4)
            .map(|seed| KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        let forged_receipt =
            recertify_receipt_with_validator_keys(receipt.clone(), &forged_validator_keys);
        {
            let mut transaction = block.transaction();
            let before = private_settlement_transaction_bytes(&transaction);
            assert_eq!(
                transaction.apply_private_settlement_receipt_v1(forged_receipt),
                Err(PrivateSettlementGlobalStateErrorV1::Receipt),
                "self-certified attacker keys must not authorize global state mutation"
            );
            let after = private_settlement_transaction_bytes(&transaction);
            assert_eq!(
                before, after,
                "forged-authority rejection must leave every private-state map byte-identical"
            );
        }

        let mut invalid = receipt.clone();
        invalid.legs[1].delta.new_root = PrivacyRootV1::new([0xFF; 32]);
        {
            let mut transaction = block.transaction();
            assert!(
                transaction
                    .apply_private_settlement_receipt_v1(invalid)
                    .is_err()
            );
            assert!(
                transaction
                    .private_settlement_receipt_v1(&receipt.manifest.bundle_id)
                    .is_none()
            );
            for (index, leg) in receipt.legs.iter().enumerate() {
                assert_eq!(
                    transaction.private_settlement_pool_head_v1(leg.delta.route, leg.delta.pool_id),
                    Some(old_heads[index])
                );
            }
        }
        assert!(
            block
                .world
                .private_settlement_receipts
                .get(&receipt.manifest.bundle_id)
                .is_none(),
            "dropping a failed StateTransaction must leave its parent block byte-clean"
        );

        {
            let mut transaction = block.transaction();
            for index in 0..receipt.manifest.legs.len() {
                let authority = receipt
                    .authority_catalog
                    .authority_for_leg(&receipt.manifest, index)
                    .expect("exact fixture authority");
                crate::private_settlement::protocol::validate_private_settlement_committee_authority_v1(
                    &transaction, receipt.manifest.authority_context_height, &authority,
                ).expect("the positive fixture uses the resolved ordered committee and live Committee keys");
            }
            assert_eq!(
                transaction.apply_private_settlement_receipt_v1(receipt.clone()),
                Ok(PrivateSettlementGlobalStateOutcomeV1::Applied)
            );
            for leg in &receipt.legs {
                assert_eq!(
                    transaction.private_settlement_pool_head_v1(leg.delta.route, leg.delta.pool_id),
                    Some((leg.delta.new_epoch, leg.delta.new_root))
                );
            }
            transaction.apply();
        }
        assert_eq!(
            block
                .world
                .private_settlement_receipts
                .get(&receipt.manifest.bundle_id),
            Some(&receipt)
        );
        block
            .commit_world_overlay_for_testing()
            .expect("commit private-settlement WorldBlock overlay");
        let committed = state.world.view();
        assert_eq!(
            committed.private_settlement_receipt_v1(&receipt.manifest.bundle_id),
            Some(&receipt)
        );
        for leg in &receipt.legs {
            assert_eq!(
                committed.private_settlement_pool_head_v1(leg.delta.route, leg.delta.pool_id),
                Some((leg.delta.new_epoch, leg.delta.new_root))
            );
        }
    }
}
