//! Read-only exact staking plan construction from one coherent committed view.

use super::*;
use crate::state::StateReadOnly;
use iroha_data_model::nexus::{
    PublicLaneMonetaryBondV1, PublicLaneMonetaryRegistrationV1, PublicLaneMonetaryScopeV1,
    PublicLaneMonetaryUnbondV1, PublicLanePreparationBalanceV1, PublicLanePreparationOperationV1,
    PublicLanePreparationRequestV1, PublicLanePreparationV1, PublicLanePreparedPlanV1,
    PublicLaneRewardClaimPlanV1,
};
use std::collections::BTreeSet;

fn invalid(message: &str) -> Error {
    Error::InvariantViolation(message.to_owned().into())
}

fn balance(world: &impl WorldReadOnly, asset: &AssetId) -> Quantity {
    world
        .assets()
        .get(asset)
        .map_or_else(Quantity::zero, |value| value.as_ref().clone())
}

fn validator_record<'a>(
    world: &'a impl WorldReadOnly,
    lane: LaneId,
    validator: &AccountId,
) -> Result<&'a PublicLaneValidatorRecord, Error> {
    let key = validator_storage_key(lane, validator);
    let record = world
        .public_lane_validators()
        .get(&key)
        .ok_or_else(|| invalid("validator not registered"))?;
    ensure_public_lane_validator_record_matches_key(&key, record)?;
    Ok(record)
}

fn check_deposit(
    world: &impl WorldReadOnly,
    lane: LaneId,
    validator: &AccountId,
    context: &StakeEscrowContext,
    amount: &Quantity,
) -> Result<(), Attempt<Error>> {
    ensure_positive_amount(amount, "stake amount")?;
    let source_balance = balance(world, &context.staker_asset);
    let destination_after = if context.staker_asset == context.escrow_asset {
        source_balance
    } else {
        let remaining = quantity_sub(source_balance, amount.clone())?;
        ensure_public_lane_reserves_after_debit(world, &context.staker_asset, &remaining)?;
        quantity_add(balance(world, &context.escrow_asset), amount.clone())?
    };
    prepare_stake_custody_credit(
        world,
        lane,
        validator,
        &context.escrow_asset,
        amount,
        &destination_after,
    )?;
    Ok(())
}

/// Prepare exact monetary signing input without mutating state or authorizing execution.
///
/// The observed block identity is an observation, not a state proof. Election
/// calculations assume inclusion in the next block. Execution independently
/// checks scope, expiry, exact monetary legs, permissions, maturity and lifecycle.
///
/// # Errors
/// Defers when the original local read cannot complete. Rejects absent committed
/// state, malformed bounds, noncanonical custody, unavailable records, insufficient
/// unreserved deposit funds and stale inputs.
pub fn prepare_public_lane_plan(
    state: &impl StateReadOnly,
    request: PublicLanePreparationRequestV1,
) -> Result<PublicLanePreparationV1, Attempt<Error>> {
    let world = state.world();
    let parameters = world
        .sumeragi_npos_parameters()
        .map_err(|error| error.map_rejection(|message| invalid(&message)))?
        .ok_or_else(|| invalid("staking preparation requires committed NPoS parameters"))?;
    parameters
        .validate()
        .map_err(|_| invalid("invalid committed NPoS parameters"))?;
    let epoch_length = parameters.epoch_length_blocks.get();
    if request.valid_for_blocks == 0 || request.valid_for_blocks > epoch_length {
        return Err(invalid(
            "staking preparation validity must be one through one committed epoch of blocks",
        )
        .into());
    }
    let observed_height = u64::try_from(state.height())
        .map_err(|_| invalid("staking observation height overflow"))?;
    let observed_block_hash = state
        .latest_block_hash()
        .ok_or_else(|| invalid("staking preparation requires a committed block"))?
        .into();
    let observed_ledger_time_ms = state
        .authenticated_query_ledger_time_ms()
        .ok_or_else(|| invalid("staking preparation requires authenticated ledger time"))?;
    let assumed_execution_height = observed_height
        .checked_add(1)
        .ok_or_else(|| invalid("staking preparation height overflow"))?;
    let expiry = observed_height
        .checked_add(request.valid_for_blocks)
        .ok_or_else(|| invalid("staking preparation expiry overflow"))?;
    let scope = PublicLaneMonetaryScopeV1::Network(*state.network_id());
    let lane = request.lane_id;
    let monetary = |source_asset, destination_asset, amount, precondition| {
        PublicLanePreparedPlanV1::Monetary(PublicLaneMonetaryPlanV1 {
            network_scope: scope.clone(),
            valid_until_height: expiry,
            source_asset,
            destination_asset,
            amount,
            precondition,
        })
    };
    let plan = match &request.operation {
        PublicLanePreparationOperationV1::Registration(intent) => {
            let context = stake_context(
                world,
                &state.nexus().dataspace_catalog,
                &state.nexus().staking,
                &intent.validator,
                observed_ledger_time_ms,
            )?;
            check_deposit(world, lane, &intent.validator, &context, &intent.amount)?;
            let lead =
                if intent.candidate && !world.peers().iter().any(|peer| peer == &intent.peer_id) {
                    world.parameters().sumeragi.key_activation_lead_blocks
                } else {
                    0
                };
            let activation_height = validator_eligibility_height(
                state,
                lane,
                assumed_execution_height,
                assumed_execution_height
                    .checked_add(lead)
                    .ok_or_else(|| invalid("candidate key activation overflow"))?,
            )?;
            monetary(
                context.staker_asset,
                context.escrow_asset,
                intent.amount.clone(),
                PublicLaneMonetaryPreconditionV1::Registration(PublicLaneMonetaryRegistrationV1 {
                    activation_height,
                }),
            )
        }
        PublicLanePreparationOperationV1::Bond(intent) => {
            let record = validator_record(world, lane, &intent.validator)?;
            let context = stake_context(
                world,
                &state.nexus().dataspace_catalog,
                &state.nexus().staking,
                &intent.staker,
                observed_ledger_time_ms,
            )?;
            check_deposit(world, lane, &intent.validator, &context, &intent.amount)?;
            monetary(
                context.staker_asset,
                context.escrow_asset,
                intent.amount.clone(),
                PublicLaneMonetaryPreconditionV1::Bond(PublicLaneMonetaryBondV1 {
                    activation_height: record.activation_height,
                    peer_id: record.peer_id.clone(),
                }),
            )
        }
        PublicLanePreparationOperationV1::FinalizeUnbond(intent) => {
            let record = validator_record(world, lane, &intent.validator)?;
            let key = stake_key(lane, &intent.validator, &intent.staker);
            let share = world
                .public_lane_stake_shares()
                .get(&key)
                .ok_or_else(|| invalid("stake position not found"))?;
            ensure_public_lane_stake_share_matches_key(&key, share)?;
            let pending = share
                .pending_unbonds
                .get(&intent.request_id)
                .ok_or_else(|| invalid("unbond request not found"))?;
            ensure_canonical_pending_unbond(&intent.request_id, pending)?;
            let context = retained_stake_context(world, lane, &intent.validator, &intent.staker)?;
            let request_hash = public_lane_unbonding_commitment(pending).map_err(|error| {
                Error::InvariantViolation(format!("unbond commitment failed: {error}").into())
            })?;
            monetary(
                context.escrow_asset,
                context.staker_asset,
                pending.amount.clone(),
                PublicLaneMonetaryPreconditionV1::Unbond(PublicLaneMonetaryUnbondV1 {
                    activation_height: record.activation_height,
                    request_hash,
                }),
            )
        }
        PublicLanePreparationOperationV1::ClaimRewards(intent) => {
            let fee_claim = crate::validation_fee_rewards::fee_reward_claim_plan(
                world,
                assumed_execution_height,
                &intent.recipient,
                lane,
            )?
            .ok_or_else(|| invalid("no funded reward entitlement is available to claim"))?;
            let plan = PublicLaneRewardClaimPlanV1 {
                network_scope: scope.clone(),
                valid_until_height: expiry,
                fee_claim,
            };
            PublicLanePreparedPlanV1::Claim(plan)
        }
    };
    let mut assets = BTreeSet::new();
    match &plan {
        PublicLanePreparedPlanV1::Monetary(plan) => {
            if !plan.has_canonical_shape() {
                return Err(
                    invalid("staking preparation produced a non-canonical monetary plan").into(),
                );
            }
            assets.insert(plan.source_asset.clone());
            assets.insert(plan.destination_asset.clone());
        }
        PublicLanePreparedPlanV1::Claim(plan) => {
            assets.insert(plan.fee_claim.source_asset.clone());
            assets.insert(plan.fee_claim.destination_asset.clone());
        }
    }
    for asset in &assets {
        ensure_committed_xor_asset(world, asset.definition())?;
        crate::state::validate_xor_custody_shape(world, asset)?;
    }
    let balances = assets
        .into_iter()
        .map(|asset| -> Result<_, Attempt<Error>> {
            Ok(PublicLanePreparationBalanceV1 {
                balance: balance(world, &asset),
                stake_reserved: world
                    .public_lane_stake_reserves()
                    .get(&asset)
                    .cloned()
                    .unwrap_or_else(Quantity::zero),
                rewards_reserved: crate::validation_fee_rewards::reserved_fee_custody(
                    world, &asset,
                )?,
                asset,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PublicLanePreparationV1 {
        request,
        network_id: *state.network_id(),
        observed_height,
        observed_block_hash,
        observed_ledger_time_ms,
        assumed_execution_height,
        xor_asset_definition_id: parameters.xor_asset_definition_id.clone(),
        plan,
        balances,
    })
}
