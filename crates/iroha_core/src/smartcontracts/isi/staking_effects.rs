//! Signed exact monetary effects for native public-lane staking instructions.

use super::*;
use iroha_data_model::nexus::{
    PublicLaneMonetaryPlanV1, PublicLaneMonetaryPreconditionV1, PublicLaneMonetaryScopeV1,
};

/// Restrict genesis consent to height one and network consent to a committed epoch window.
pub(super) fn validate_plan_context(
    state_transaction: &StateTransaction<'_, '_>,
    network_scope: &PublicLaneMonetaryScopeV1,
    valid_until_height: u64,
) -> Result<(), Attempt<Error>> {
    let scope_matches = match network_scope {
        PublicLaneMonetaryScopeV1::Genesis => {
            state_transaction._curr_block.is_genesis() && state_transaction.block_hashes.is_empty()
        }
        PublicLaneMonetaryScopeV1::Network(network_id) => {
            network_id == state_transaction.network_id()
        }
    };
    if !scope_matches {
        return Err((Error::InvariantViolation(
            "staking monetary plan does not match this authenticated genesis or network scope"
                .into(),
        ))
        .into());
    }
    let height = state_transaction.block_height();
    if matches!(network_scope, PublicLaneMonetaryScopeV1::Genesis) {
        // Genesis already authenticates every exact movement and custody
        // precondition. Its one-block lifetime does not depend on an election
        // schedule, which Permissioned genesis must not contain.
        if height != 1 || valid_until_height != 1 {
            return Err((Error::InvariantViolation(
                "genesis staking monetary plan must expire at the genesis height one".into(),
            ))
            .into());
        }
        return Ok(());
    }
    let parameters = state_transaction
        .world
        .sumeragi_npos_parameters()
        .map_err(|error| error.map_rejection(|message| Error::InvariantViolation(message.into())))?
        .ok_or_else(|| {
            Error::InvariantViolation(
                "staking monetary plans require committed NPoS epoch parameters".into(),
            )
        })?;
    parameters.validate().map_err(|error| {
        Error::InvariantViolation(
            format!("invalid staking monetary plan epoch parameters: {error}").into(),
        )
    })?;
    let latest = height
        .checked_add(parameters.epoch_length_blocks.get())
        .ok_or_else(|| {
            Error::InvariantViolation("staking monetary plan validity height overflow".into())
        })?;
    if valid_until_height < height || valid_until_height > latest {
        return Err((Error::InvariantViolation(
            "staking monetary plan must expire within the current committed epoch-length window"
                .into(),
        ))
        .into());
    }
    Ok(())
}

/// Compare every signed movement and custody direction with its freshly resolved operation.
pub(super) fn verify_transfer_plan(
    state_transaction: &StateTransaction<'_, '_>,
    plan: &PublicLaneMonetaryPlanV1,
    source_asset: &AssetId,
    destination_asset: &AssetId,
    amount: &Quantity,
    precondition: &PublicLaneMonetaryPreconditionV1,
) -> Result<(), Attempt<Error>> {
    validate_plan_context(
        state_transaction,
        &plan.network_scope,
        plan.valid_until_height,
    )?;
    if !plan.has_canonical_shape()
        || &plan.source_asset != source_asset
        || &plan.destination_asset != destination_asset
        || &plan.amount != amount
        || &plan.precondition != precondition
    {
        return Err((Error::InvariantViolation(
            "staking monetary plan does not match its exact current transfer and custody state"
                .into(),
        ))
        .into());
    }
    Ok(())
}
