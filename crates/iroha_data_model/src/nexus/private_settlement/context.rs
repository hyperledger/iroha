//! Canonical public private-settlement state originals and authenticated World cuts.
//!
//! These data-only records replace the Core-owned wire records at first-release migration.
//! They carry no restricted asset opening, witness, auditor keys or proof-generation authority.

use super::{PrivateSettlementPoolGovernanceLifecycleV1, PrivateSettlementRouteV1};
use crate::privacy::{PrivacyCommitmentV1, PrivacyNullifierV1, PrivacyPoolIdV1, PrivacyRootV1};
use iroha_crypto::Hash;

mod authority;
mod governance;
pub use authority::*;
mod selected;
pub use selected::*;
mod proof;
pub use proof::{
    PrivateSettlementPoolCutProofRefV1, PrivateSettlementPoolCutProofV1,
    VerifiedPrivateSettlementPoolCutV1,
};

/// Exact route-scoped identity shared by every canonical private pool table.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementPoolKeyV1")]
pub struct PrivateSettlementPoolKeyV1 {
    /// Exact lane, dataspace and incarnation.
    pub route: PrivateSettlementRouteV1,
    /// Opaque governed pool identity.
    pub pool_id: PrivacyPoolIdV1,
}

/// Exact canonical nullifier-table key; no recipient index supplies its absence.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementNullifierKeyV1")]
pub struct PrivateSettlementNullifierKeyV1 {
    /// Route-scoped pool.
    pub pool: PrivateSettlementPoolKeyV1,
    /// Opaque spent-note marker.
    pub nullifier: PrivacyNullifierV1,
}

/// Exact canonical output-table key.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementOutputKeyV1")]
pub struct PrivateSettlementOutputKeyV1 {
    /// Route-scoped pool.
    pub pool: PrivateSettlementPoolKeyV1,
    /// Opaque output note commitment.
    pub commitment: PrivacyCommitmentV1,
}

/// Superseded governance revision retained in the exact canonical lineage.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementPoolGovernanceRevisionV1")]
pub struct PrivateSettlementPoolGovernanceRevisionV1 {
    /// Digest of the restricted audit policy.
    pub audit_policy_digest: Hash,
    /// Audit key epoch.
    pub audit_key_epoch: u64,
    /// Committed activation and retirement lifecycle.
    pub lifecycle: PrivateSettlementPoolGovernanceLifecycleV1,
    /// Exact restricted governance digest.
    pub governance_digest: Hash,
}

/// Canonical public governance row; restricted asset identity and opening are absent.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementPoolGovernanceProjectionV1")]
pub struct PrivateSettlementPoolGovernanceProjectionV1 {
    /// Fixed first-release wire version.
    pub version: u8,
    /// Exact participant route and incarnation.
    pub route: PrivateSettlementRouteV1,
    /// Opaque governed pool identity.
    pub pool_id: PrivacyPoolIdV1,
    /// Commitment to the restricted asset mapping and opening.
    pub asset_binding_commitment: Hash,
    /// Digest of the restricted audit policy.
    pub audit_policy_digest: Hash,
    /// Audit key epoch.
    pub audit_key_epoch: u64,
    /// Committed current revision lifecycle.
    pub lifecycle: PrivateSettlementPoolGovernanceLifecycleV1,
    /// Exact restricted governance digest.
    pub governance_digest: Hash,
    /// Complete superseded revision lineage, in ascending revision order.
    pub prior_revisions: Vec<PrivateSettlementPoolGovernanceRevisionV1>,
}

/// Canonical compact pool frontier; decoding grants no verified successor authority.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementPoolStateV1")]
pub struct PrivateSettlementPoolStateV1 {
    /// Fixed first-release wire version.
    pub version: u8,
    /// Exact participant route and incarnation.
    pub route: PrivateSettlementRouteV1,
    /// Opaque governed pool identity.
    pub pool_id: PrivacyPoolIdV1,
    /// Digest of the exact restricted governance record.
    pub restricted_pool_policy_digest: Hash,
    /// Current authoritative root epoch.
    pub epoch: u64,
    /// Current authoritative pool root.
    pub root: PrivacyRootV1,
    /// Number of leaves in the committed compact frontier.
    pub tree_size: u64,
    /// Compact frontier's last leaf, if present.
    pub leaf: Option<[u8; 32]>,
    /// Canonical compact frontier ommers.
    pub ommers: Vec<[u8; 32]>,
}

impl PrivateSettlementPoolStateV1 {
    /// Opaque pool identifier in the canonical row.
    #[must_use]
    pub const fn pool_id(&self) -> PrivacyPoolIdV1 {
        self.pool_id
    }
    /// Exact participant route and incarnation.
    #[must_use]
    pub const fn route(&self) -> PrivateSettlementRouteV1 {
        self.route
    }
    /// Bound restricted governance digest, not the restricted opening.
    #[must_use]
    pub const fn restricted_pool_policy_digest(&self) -> Hash {
        self.restricted_pool_policy_digest
    }
    /// Current root epoch in this data row.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Current opaque root in this data row.
    #[must_use]
    pub const fn root(&self) -> PrivacyRootV1 {
        self.root
    }
}

use norito::json;

/// Write one canonical uppercase Norito-frame key for native private-settlement tables.
///
/// The same owner encodes both Model keys and the remaining native Core keys.
pub fn encode_private_settlement_storage_key_v1<T: norito::NoritoSerialize>(
    key: &T,
    out: &mut String,
) {
    let encoded = norito::to_bytes(key).expect("fixed private-settlement keys always encode");
    json::write_json_string(&hex::encode_upper(encoded), out);
}

/// Decode the exact canonical uppercase Norito-frame key of a private-settlement table.
/// # Errors
/// Invalid hex, schema/layout mismatch, malformed frame, or noncanonical spelling.
pub fn decode_private_settlement_storage_key_v1<
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

macro_rules! private_settlement_json_key {
    ($($key:ty),+ $(,)?) => { $(
        impl norito::json::JsonKeyCodec for $key {
            fn encode_json_key(&self, out: &mut String) {
                encode_private_settlement_storage_key_v1(self, out);
            }
            fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
                decode_private_settlement_storage_key_v1(encoded)
            }
        }
    )+ };
}
private_settlement_json_key!(
    PrivateSettlementPoolKeyV1,
    PrivateSettlementNullifierKeyV1,
    PrivateSettlementOutputKeyV1,
);
