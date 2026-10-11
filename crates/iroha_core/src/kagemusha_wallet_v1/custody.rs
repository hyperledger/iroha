//! Constant-time permanent reserve indexes used by the canonical asset movement owner.
//! These guards protect ordinary debits/retirement; they do not consult the offline blacklist.
use super::{storage, *};
use crate::state::WorldReadOnly;
use iroha_data_model::asset::{AssetDefinitionId, AssetId};
use mv::storage::StorageReadOnly as _;

pub(crate) fn reserve_registration(
    world: &impl WorldReadOnly,
    id: &AssetId,
) -> Result<Option<Registration>> {
    let key = storage::reserve_key(id)?;
    let Some(bytes) = world.kagemusha_wallet_ledger().get(&key) else {
        return Ok(None);
    };
    validate_row(&key, bytes)?;
    let owner: storage::ReserveOwner = storage::decode(bytes, 256)?;
    let key = storage::key(storage::REGISTRATION, owner.scheme, owner.asset);
    let bytes = world
        .kagemusha_wallet_ledger()
        .get(&key)
        .ok_or(Error::Unavailable)?;
    validate_row(&key, bytes)?;
    let registration: Registration = storage::decode(bytes, bytes.len())?;
    if *id != reserve_id(&registration) {
        return Err(Error::Binding);
    }
    Ok(Some(registration))
}
pub(super) fn reserve_id(registration: &Registration) -> AssetId {
    AssetId::with_scope(
        registration.asset.asset.clone(),
        registration.reserve.clone(),
        registration.balance_scope,
    )
}
pub(crate) fn is_reserve_account(world: &impl WorldReadOnly, account: &AccountId) -> Result<bool> {
    has_reference(world, &storage::reserve_account_key(account)?)
}
pub(crate) fn is_reserve_definition(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
) -> Result<bool> {
    has_reference(world, &storage::reserve_definition_key(definition)?)
}
fn has_reference(world: &impl WorldReadOnly, key: &KagemushaWalletLedgerKeyV1) -> Result<bool> {
    world
        .kagemusha_wallet_ledger()
        .get(key)
        .map(|bytes| validate_row(key, bytes))
        .transpose()
        .map(|value| value.is_some())
}
