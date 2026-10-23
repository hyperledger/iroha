//! Native-only per-asset escrow cardinality, without a new World table or index.
//!
//! Uninitialized assets retain their existing execution behavior and have no
//! completeness authority. Initialization is an explicit owner transaction;
//! replay/restore never manufactures an anchor from the current node's memory.
//!
//! Public reads use the bounded ordinary-query source adapter. Initialization
//! has a deterministic protocol scan cap and cannot alter prior unactivated replay.

use super::*;
use iroha_data_model::{
    escrow::scoped::{AssetEscrowScopeV1, scope_key},
    nexus::AxtAssetIncarnationV1,
};

/// Deterministic work ceiling for explicit one-use initialization only.
pub(crate) const MAX_INITIALIZATION_ROWS: usize = 65_536;

#[cfg(test)]
use iroha_data_model::escrow::scoped::AssetEscrowScopeOriginalV1;

fn reject(message: &str) -> Error {
    Error::InvariantViolation(message.into())
}

fn incarnation(world: &impl WorldReadOnly, asset: &AssetDefinitionId)
    -> Result<AxtAssetIncarnationV1, Error>
{
    world.asset_definition(asset)?;
    world.axt_asset_incarnations().get(asset).copied()
        .ok_or_else(|| reject("escrow scope requires the live asset incarnation"))
}

fn key(world: &impl WorldReadOnly, asset: &AssetDefinitionId) -> Result<StatePath, Error> {
    scope_key(asset, &incarnation(world, asset)?).map_err(reject)
}

fn read_scope(world: &impl WorldReadOnly, asset: &AssetDefinitionId)
    -> Result<Option<AssetEscrowScopeV1>, Error>
{
    // Absence leaves unactivated historical mutation behavior unchanged.
    let Some(incarnation) = world.axt_asset_incarnations().get(asset).copied() else {
        return Ok(None);
    };
    let path = scope_key(asset, &incarnation).map_err(reject)?;
    let Some(bytes) = world.smart_contract_state().get(&path) else { return Ok(None); };
    let scope: AssetEscrowScopeV1 = norito::decode_canonical(bytes)
        .map_err(|_| reject("invalid canonical escrow scope anchor"))?;
    if scope.asset_definition_id != *asset || scope.asset_incarnation != incarnation
        || scope.revision == 0
    { return Err(reject("escrow scope anchor differs from its canonical key")); }
    Ok(Some(scope))
}

fn require_owner(world: &impl WorldReadOnly, asset: &AssetDefinitionId,
    authority: &AccountId) -> Result<(), Error>
{
    if world.asset_definition(asset)?.owned_by() != authority {
        return Err(reject("escrow scope requires the exact current asset owner"));
    }
    Ok(())
}

/// Explicit one-use owner initialization from all existing canonical records.
/// The admission layer must charge every row before inspection through `charge`.
pub(crate) fn initialize(world: &mut WorldTransaction<'_, '_>, authority: &AccountId,
    asset: &AssetDefinitionId, expected_incarnation: &AxtAssetIncarnationV1,
    expected_revision: u64,
    mut charge: impl FnMut(&EscrowId, &AssetEscrowRecord) -> Result<(), Error>)
    -> Result<(), Error>
{
    require_owner(world, asset, authority)?;
    if incarnation(world, asset)? != *expected_incarnation
        || expected_revision != 0 || read_scope(world, asset)?.is_some() {
        return Err(reject("escrow scope initialization requires an absent revision zero"));
    }
    if world.asset_escrows().iter().take(MAX_INITIALIZATION_ROWS + 1).count() > MAX_INITIALIZATION_ROWS {
        return Err(reject("escrow scope initialization exceeds the native scan bound"));
    }
    let mut record_count = 0_u64;
    for (id, record) in world.asset_escrows().iter() {
        charge(id, record)?;
        if &record.id != id { return Err(reject("escrow canonical key and record differ")); }
        if &record.asset_definition == asset {
            record_count = record_count.checked_add(1)
                .ok_or_else(|| reject("escrow count overflow"))?;
        }
    }
    let scope = AssetEscrowScopeV1 { asset_definition_id: asset.clone(),
        asset_incarnation: incarnation(world, asset)?, revision: 1, record_count };
    let bytes = norito::encode_canonical(&scope)
        .map_err(|_| reject("cannot encode escrow scope anchor"))?;
    let path = key(world, asset)?;
    world.smart_contract_state.insert(path, bytes);
    Ok(())
}

/// Opaque prepared native update; callers cannot supply a forged count.
pub(crate) struct PreparedScopeWrite(Option<(StatePath, Vec<u8>)>);
impl PreparedScopeWrite {
    /// Apply after the canonical escrow write, inside the same MV transaction.
    pub(crate) fn apply(self, world: &mut WorldTransaction<'_, '_>) {
        if let Some((key, bytes)) = self.0 { world.smart_contract_state.insert(key, bytes); }
    }
}

fn changed_count(mut scope: AssetEscrowScopeV1, inserted: bool)
    -> Result<AssetEscrowScopeV1, Error>
{
    scope.record_count = if inserted { scope.record_count.checked_add(1) }
        else { scope.record_count.checked_sub(1) }
        .ok_or_else(|| reject("escrow scope count overflow or underflow"))?;
    scope.revision = scope.revision.checked_add(1)
        .ok_or_else(|| reject("escrow scope revision overflow"))?;
    Ok(scope)
}

/// Prepare a new membership count before the canonical insertion mutates anything.
/// Existing-row updates preserve count; reassignment to another asset is refused.
pub(crate) fn prepare_insert(world: &impl WorldReadOnly, record: &AssetEscrowRecord)
    -> Result<PreparedScopeWrite, Error>
{
    if let Some(previous) = world.asset_escrows().get(&record.id) {
        if previous.asset_definition != record.asset_definition
            && (read_scope(world, &previous.asset_definition)?.is_some()
                || read_scope(world, &record.asset_definition)?.is_some())
        {
            return Err(reject("activated native escrow cannot change its asset definition"));
        }
        return Ok(PreparedScopeWrite(None));
    }
    // No auto-initialization: preserved pre-activation execution writes no new state.
    let Some(scope) = read_scope(world, &record.asset_definition)? else {
        return Ok(PreparedScopeWrite(None));
    };
    let scope = changed_count(scope, true)?;
    let bytes = norito::encode_canonical(&scope)
        .map_err(|_| reject("cannot encode escrow scope membership change"))?;
    Ok(PreparedScopeWrite(Some((key(world, &record.asset_definition)?, bytes))))
}

/// Future removal ports must call this before removing a canonical record.
/// No production canonical escrow removal exists in the pinned source census.
pub(crate) fn prepare_remove(world: &impl WorldReadOnly, id: &EscrowId)
    -> Result<PreparedScopeWrite, Error>
{
    let record = world.asset_escrows().get(id)
        .ok_or_else(|| reject("cannot remove an absent native escrow"))?;
    let Some(scope) = read_scope(world, &record.asset_definition)? else {
        return Ok(PreparedScopeWrite(None));
    };
    let scope = changed_count(scope, false)?;
    let bytes = norito::encode_canonical(&scope)
        .map_err(|_| reject("cannot encode escrow scope removal"))?;
    Ok(PreparedScopeWrite(Some((key(world, &record.asset_definition)?, bytes))))
}

/// Collect one complete asset result after exact current-owner admission.
/// A supplied tenant label, absent anchor, wrong owner, or incomplete scan cannot pass.
/// `charge` must refuse before cloning once the ordinary query budget is exhausted.
#[cfg(test)]
pub(crate) fn collect(world: &impl WorldReadOnly, authority: &AccountId,
    asset: &AssetDefinitionId, expected_incarnation: &AxtAssetIncarnationV1,
    mut charge: impl FnMut(&EscrowId, &AssetEscrowRecord) -> Result<(), Error>)
    -> Result<AssetEscrowScopeOriginalV1, Error>
{
    require_owner(world, asset, authority)?;
    if incarnation(world, asset)? != *expected_incarnation {
        return Err(reject("escrow scope query selected a different live incarnation"));
    }
    let scope = read_scope(world, asset)?
        .ok_or_else(|| reject("asset escrow scope is uninitialized"))?;
    let mut records = Vec::new();
    for (id, record) in world.asset_escrows().iter() {
        charge(id, record)?;
        if &record.id != id { return Err(reject("escrow canonical key and record differ")); }
        if &record.asset_definition == asset { records.push(record.clone()); }
    }
    scope.validate_records(asset, &incarnation(world, asset)?, &records).map_err(reject)?;
    let scope_original = world.smart_contract_state().get(&key(world, asset)?)
        .ok_or_else(|| reject("scope disappeared from retained World"))?.clone();
    Ok(AssetEscrowScopeOriginalV1 { scope_original, records })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope(count: u64) -> AssetEscrowScopeV1 {
        AssetEscrowScopeV1 {
            asset_definition_id: "61CtjvNd9T3THAR65GsMVHr82Bjc".parse().unwrap(),
            asset_incarnation: AxtAssetIncarnationV1::try_from_bytes(*Hash::new("scope").as_ref()).unwrap(),
            revision: 1, record_count: count,
        }
    }
    #[test]
    fn insertion_and_removal_advance_once_without_reset() {
        let added = changed_count(scope(2), true).unwrap();
        assert_eq!((added.record_count, added.revision), (3, 2));
        let removed = changed_count(added, false).unwrap();
        assert_eq!((removed.record_count, removed.revision), (2, 3));
    }
    #[test]
    fn count_overflow_and_underflow_refuse() {
        assert!(changed_count(scope(u64::MAX), true).is_err());
        assert!(changed_count(scope(0), false).is_err());
    }
    #[test]
    fn revision_overflow_refuses() {
        let mut value = scope(1); value.revision = u64::MAX;
        assert!(changed_count(value, true).is_err());
    }
    fn fixture() -> (World, AssetDefinitionId, AxtAssetIncarnationV1) {
        use iroha_data_model::prelude::Registrable;
        let selected = scope(0);
        let owner = iroha_test_samples::ALICE_ID.clone();
        let mut world = World::with([], [Account::new(owner.clone()).build(&owner)],
            [AssetDefinition::numeric(selected.asset_definition_id.clone(), "DS", iroha_data_model::asset::AssetBalancePolicy::Global, None).build(&owner)]);
        world.axt_asset_incarnations.insert(selected.asset_definition_id.clone(), selected.asset_incarnation);
        (world, selected.asset_definition_id, selected.asset_incarnation)
    }
    fn record(asset: &AssetDefinitionId, seed: &str) -> AssetEscrowRecord {
        use iroha_data_model::escrow::{AssetEscrowKind, AssetEscrowStatus};
        use iroha_primitives::numeric::Quantity;
        let seller = iroha_test_samples::ALICE_ID.clone();
        AssetEscrowRecord { id: EscrowId::new(Hash::new(seed)), seller: seller.clone(),
            buyer: None, asset_definition: asset.clone(), amount: Quantity::one(), custody: seller,
            status: AssetEscrowStatus::Locked, kind: AssetEscrowKind::Lock,
            remaining_amount: Quantity::one(), release_authority: None, expires_at_ms: None,
            evidence_hashes: Vec::new(), conditions: Vec::new(), created_at_ms: 1,
            accepted_at_ms: None, payment_sent_at_ms: None, disputed_at_ms: None,
            closed_at_ms: None, resolution: None }
    }
    #[test]
    fn non_owner_is_refused_before_scanning_or_returning_empty_rows() {
        let (mut world, asset, incarnation) = fixture();
        let mut block = world.block();
        let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
        let mut charged = 0;
        assert!(initialize(&mut tx, &iroha_test_samples::BOB_ID, &asset, &incarnation, 0,
            |_, _| { charged += 1; Ok(()) }).is_err());
        assert!(collect(&tx, &iroha_test_samples::BOB_ID, &asset, &incarnation,
            |_, _| { charged += 1; Ok(()) }).is_err());
        assert_eq!(charged, 0);
        assert!(read_scope(&tx, &asset).unwrap().is_none());
    }
    #[test]
    fn empty_scope_requires_owner_initialization_once_with_exact_incarnation() {
        let (mut world, asset, incarnation) = fixture();
        let mut block = world.block();
        let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
        assert!(collect(&tx, &iroha_test_samples::ALICE_ID, &asset, &incarnation, |_, _| Ok(())).is_err());
        initialize(&mut tx, &iroha_test_samples::ALICE_ID, &asset, &incarnation, 0, |_, _| Ok(())).unwrap();
        let result = collect(&tx, &iroha_test_samples::ALICE_ID, &asset, &incarnation, |_, _| Ok(())).unwrap();
        assert!(result.records.is_empty()); assert!(!result.scope_original.is_empty());
        assert!(initialize(&mut tx, &iroha_test_samples::ALICE_ID, &asset, &incarnation, 0, |_, _| Ok(())).is_err());
        let foreign = AxtAssetIncarnationV1::try_from_bytes(*Hash::new("wrong incarnation").as_ref()).unwrap();
        assert!(collect(&tx, &iroha_test_samples::ALICE_ID, &asset, &foreign, |_, _| Ok(())).is_err());
    }
    #[test]
    fn initialization_derives_existing_terminal_and_active_records() {
        let (mut world, asset, incarnation) = fixture();
        let first = record(&asset, "active"); let mut second = record(&asset, "terminal");
        second.status = iroha_data_model::escrow::AssetEscrowStatus::Released;
        world.asset_escrows.insert(first.id, first);
        world.asset_escrows.insert(second.id, second);
        let mut block = world.block();
        let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
        initialize(&mut tx, &iroha_test_samples::ALICE_ID, &asset, &incarnation, 0, |_, _| Ok(())).unwrap();
        assert_eq!(read_scope(&tx, &asset).unwrap().unwrap().record_count, 2);
        assert_eq!(collect(&tx, &iroha_test_samples::ALICE_ID, &asset, &incarnation, |_, _| Ok(())).unwrap().records.len(), 2);
    }
    #[test]
    fn insert_update_and_rollback_keep_anchor_with_canonical_rows() {
        let (mut world, asset, incarnation) = fixture();
        {
            let mut block = world.block();
            let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
            initialize(&mut tx, &iroha_test_samples::ALICE_ID, &asset, &incarnation, 0, |_, _| Ok(())).unwrap();
            tx.apply(); block.commit();
        }
        {
            let mut block = world.block();
            let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
            let mut value = record(&asset, "new");
            tx.insert_asset_escrow_entry(value.clone()).unwrap();
            assert_eq!(read_scope(&tx, &asset).unwrap().unwrap().record_count, 1);
            value.status = iroha_data_model::escrow::AssetEscrowStatus::Released;
            tx.insert_asset_escrow_entry(value).unwrap();
            let retained = read_scope(&tx, &asset).unwrap().unwrap();
            assert_eq!((retained.record_count, retained.revision), (1, 2));
            // Dropping this native MV transaction must roll back both tables.
        }
        let mut block = world.block();
        let tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
        assert_eq!(read_scope(&tx, &asset).unwrap().unwrap().record_count, 0);
        assert!(collect(&tx, &iroha_test_samples::ALICE_ID, &asset, &incarnation, |_, _| Ok(())).unwrap().records.is_empty());
    }

}
