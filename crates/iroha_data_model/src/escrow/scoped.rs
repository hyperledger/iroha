//! Asset-scoped escrow completeness anchored in the existing canonical World map.
//!
//! The count is native-maintained, includes terminal records, and is never a
//! caller-provided assertion. Exact same-World row proofs plus distinct IDs and
//! this authenticated count establish completeness without querying other assets'
//! escrow preimages. The existing complete World carrier retains its own disclosure
//! and authorization constraints; this module does not create a selective World proof.

use crate::{
    asset::AssetDefinitionId, escrow::AssetEscrowRecord,
    nexus::AxtAssetIncarnationV1, sumeragi_finality::VerifiedWorldStateSnapshotV1,
    DeriveJsonDeserialize, DeriveJsonSerialize,
};
use iroha_model_base::state_path::StatePath;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Native-only completeness namespace, under the already-reserved physical `sc/` root.
/// `native` cannot be an exact 64-hex contract digest, so no contract owns this path.
/// Generic contract artifacts cannot mutate it, including before this scope exists.
pub const SCOPE_ROOT: &str = "sc/native/asset_escrow_scope_v1/";

/// Current completeness for one live asset incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, IntoSchema,
    DeriveJsonSerialize, DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::escrow::scoped::AssetEscrowScopeV1")]
pub struct AssetEscrowScopeV1 {
    /// Exact asset definition, independent of a caller's tenant label.
    pub asset_definition_id: AssetDefinitionId,
    /// Prevents re-registration from reviving a prior completeness scope.
    pub asset_incarnation: AxtAssetIncarnationV1,
    /// Starts at one; advances on every membership change.
    pub revision: u64,
    /// All canonical records for this asset, including closed records; zero is explicit.
    pub record_count: u64,
}

/// Complete, bounded query result; this struct by itself grants no finality authority.
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, IntoSchema,
    DeriveJsonSerialize, DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::escrow::scoped::AssetEscrowScopeOriginalV1")]
pub struct AssetEscrowScopeOriginalV1 {
    /// Exact canonical bytes retained in `world.smart_contract_state`.
    pub scope_original: Vec<u8>,
    /// Every escrow record for the selected asset, ordered by canonical escrow ID.
    pub records: Vec<AssetEscrowRecord>,
}

/// Canonical key of a scope; a missing key is uninitialized, never an empty table.
pub fn scope_key(asset: &AssetDefinitionId, incarnation: &AxtAssetIncarnationV1)
    -> Result<StatePath, &'static str>
{
    format!("{SCOPE_ROOT}{}/{}", hex::encode(asset.aid_bytes()),
        hex::encode(incarnation.as_bytes())).parse().map_err(|_| "invalid scope key")
}

/// Whether a physical canonical key is reserved for native escrow scope state.
pub fn is_native_scope_key(key: &str) -> bool {
    key == SCOPE_ROOT.trim_end_matches('/') || key.starts_with(SCOPE_ROOT)
}

impl AssetEscrowScopeV1 {
    /// Validate scope, live incarnation, counters, and the complete unique row set.
    /// This is shape validation only; use `verify_at_world` for certified evidence.
    pub fn validate_records(&self, asset: &AssetDefinitionId,
        incarnation: &AxtAssetIncarnationV1, records: &[AssetEscrowRecord])
        -> Result<(), &'static str>
    {
        if &self.asset_definition_id != asset || &self.asset_incarnation != incarnation
            || self.asset_incarnation.validate().is_err() || self.revision == 0
            || u64::try_from(records.len()).ok() != Some(self.record_count)
        { return Err("escrow scope differs from selected asset or complete count"); }
        let mut previous = None;
        for record in records {
            if &record.asset_definition != asset || previous.is_some_and(|id| id >= record.id)
            { return Err("escrow scope rows are foreign, repeated, or unordered"); }
            previous = Some(record.id);
        }
        Ok(())
    }
}

/// Authenticate the complete asset row set against the caller's already-certified World.
///
/// This never authenticates a server-selected root. The application must independently
/// select the World, its native schema, chain, freshness, and selected asset incarnation.
/// The same World must authenticate definition total and every ordinary/custody balance.
pub fn verify_at_world(world: &VerifiedWorldStateSnapshotV1, asset: &AssetDefinitionId,
    incarnation: &AxtAssetIncarnationV1, original: &AssetEscrowScopeOriginalV1,
    max_records: usize, max_scope_bytes: usize) -> Result<AssetEscrowScopeV1, &'static str>
{
    if original.records.len() > max_records || original.scope_original.is_empty()
        || original.scope_original.len() > max_scope_bytes
    { return Err("escrow scope original exceeds the reader bound"); }
    let scope: AssetEscrowScopeV1 = norito::decode_canonical_with_limits(
        &original.scope_original, norito::canonical_decode_limits(max_scope_bytes))
        .map_err(|_| "invalid canonical escrow scope original")?;
    scope.validate_records(asset, incarnation, &original.records)?;
    let key = scope_key(asset, incarnation)?;
    world.verify_table_value("world.smart_contract_state", &key, &original.scope_original)
        .map_err(|_| "escrow scope differs from the selected certified World")?;
    world.verify_table_value("world.axt_asset_incarnations", asset, incarnation)
        .map_err(|_| "escrow scope incarnation differs from the selected World")?;
    for record in &original.records {
        world.verify_table_value("world.asset_escrows", &record.id, record)
            .map_err(|_| "escrow record differs from the selected certified World")?;
    }
    Ok(scope)
}

#[cfg(test)]
mod tests;
