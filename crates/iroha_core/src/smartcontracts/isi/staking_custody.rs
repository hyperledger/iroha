//! Exact staking custody retained independently of configuration and aliases.

use super::*;
use crate::state::WorldTransaction;

/// A checked change to one validator's custody and its exact asset reserve.
pub(crate) struct StakeCustodyChange {
    key: (LaneId, AccountId),
    asset: AssetId,
    previous_custody: Option<(AssetId, Quantity)>,
    previous_reserve: Option<Quantity>,
    custody_after: Quantity,
    reserve_after: Quantity,
}

impl StakeCustodyChange {
    /// Publish the prepared change under the transaction's exclusive writers.
    pub(crate) fn apply(&self, world: &mut WorldTransaction<'_, '_>) {
        if self.custody_after.is_zero() {
            world.public_lane_stake_custody.remove(self.key.clone());
        } else {
            world.public_lane_stake_custody.insert(
                self.key.clone(),
                (self.asset.clone(), self.custody_after.clone()),
            );
        }
        if self.reserve_after.is_zero() {
            world.public_lane_stake_reserves.remove(self.asset.clone());
        } else {
            world
                .public_lane_stake_reserves
                .insert(self.asset.clone(), self.reserve_after.clone());
        }
    }

    /// Restore both exact preimages when the associated transfer fails.
    pub(crate) fn restore(&self, world: &mut WorldTransaction<'_, '_>) {
        if let Some(previous) = &self.previous_custody {
            world
                .public_lane_stake_custody
                .insert(self.key.clone(), previous.clone());
        } else {
            world.public_lane_stake_custody.remove(self.key.clone());
        }
        if let Some(previous) = &self.previous_reserve {
            world
                .public_lane_stake_reserves
                .insert(self.asset.clone(), previous.clone());
        } else {
            world.public_lane_stake_reserves.remove(self.asset.clone());
        }
    }
}

fn prepare_change(
    world: &impl WorldReadOnly,
    lane_id: LaneId,
    validator: &AccountId,
    asset: &AssetId,
    amount: &Quantity,
    credit: bool,
) -> Result<StakeCustodyChange, Error> {
    if amount.is_zero() {
        return Err(Error::InvariantViolation(
            "staking custody changes must be positive".into(),
        ));
    }
    let key = (lane_id, validator.clone());
    let previous_custody = world.public_lane_stake_custody().get(&key).cloned();
    if previous_custody
        .as_ref()
        .is_some_and(|(pinned, _)| pinned != asset)
    {
        return Err(Error::InvariantViolation(
            "staking movement conflicts with its retained custody asset".into(),
        ));
    }
    let previous_reserve = world.public_lane_stake_reserves().get(asset).cloned();
    let held = previous_custody
        .as_ref()
        .map_or_else(Quantity::zero, |(_, amount)| amount.clone());
    let reserved = previous_reserve.clone().unwrap_or_else(Quantity::zero);
    if reserved < held
        || previous_custody
            .as_ref()
            .is_some_and(|(_, amount)| amount.is_zero())
        || previous_reserve.as_ref().is_some_and(Quantity::is_zero)
        || (!credit && previous_custody.is_none())
    {
        return Err(Error::InvariantViolation(
            "staking custody reserve is missing or inconsistent".into(),
        ));
    }
    let (custody_after, reserve_after) = if credit {
        (
            quantity_add(held, amount.clone())?,
            quantity_add(reserved, amount.clone())?,
        )
    } else {
        (
            quantity_sub(held, amount.clone())?,
            quantity_sub(reserved, amount.clone())?,
        )
    };
    Ok(StakeCustodyChange {
        key,
        asset: asset.clone(),
        previous_custody,
        previous_reserve,
        custody_after,
        reserve_after,
    })
}

/// Reserve a real deposit, including a same-account bond's available free funds.
pub(crate) fn prepare_stake_custody_credit(
    world: &impl WorldReadOnly,
    lane_id: LaneId,
    validator: &AccountId,
    asset: &AssetId,
    amount: &Quantity,
    balance_after: &Quantity,
) -> Result<StakeCustodyChange, Attempt<Error>> {
    let change = prepare_change(world, lane_id, validator, asset, amount, true)?;
    let fees = crate::validation_fee_rewards::reserved_fee_custody(world, asset)?;
    if balance_after < &quantity_add(change.reserve_after.clone(), fees)? {
        return Err(Error::InvariantViolation(
            "staking deposit is not backed by unreserved custody funds".into(),
        )
        .into());
    }
    Ok(change)
}

/// Release only the liability authenticated by a matured unbond or slash owner.
pub(crate) fn prepare_stake_custody_debit(
    world: &impl WorldReadOnly,
    lane_id: LaneId,
    validator: &AccountId,
    asset: &AssetId,
    amount: &Quantity,
) -> Result<StakeCustodyChange, Error> {
    prepare_change(world, lane_id, validator, asset, amount, false)
}

/// Resolve retained custody without trusting the current asset or account alias.
pub(crate) fn retained_stake_custody_asset(
    world: &impl WorldReadOnly,
    lane_id: LaneId,
    validator: &AccountId,
) -> Result<AssetId, Error> {
    world
        .public_lane_stake_custody()
        .get(&(lane_id, validator.clone()))
        .filter(|(_, amount)| !amount.is_zero())
        .map(|(asset, _)| asset.clone())
        .ok_or_else(|| {
            Error::InvariantViolation("validator has no retained positive stake custody".into())
        })
}
