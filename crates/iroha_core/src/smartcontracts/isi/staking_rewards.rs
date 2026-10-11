//! Additive principal and funded validation-fee custody floors for every asset debit.

use super::*;

/// Prevent debits from spending principal or funded fee obligations.
pub(crate) fn ensure_public_lane_reserves_after_debit(
    world: &impl WorldReadOnly,
    asset: &AssetId,
    balance_after: &Quantity,
) -> Result<(), Attempt<Error>> {
    let stake = world
        .public_lane_stake_reserves()
        .get(asset)
        .cloned()
        .unwrap_or_else(Quantity::zero);
    let fees = if cfg!(all(test, sumeragi_core_mutation = "HC56")) {
        Quantity::zero()
    } else {
        crate::validation_fee_rewards::reserved_fee_custody(world, asset)?
    };
    if balance_after < &quantity_add(stake, fees)? {
        return Err(Error::InvariantViolation(
            "asset debit would spend reserved public-lane stake custody or funded fee obligations"
                .into(),
        )
        .into());
    }
    Ok(())
}
