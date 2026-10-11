//! Read-only automatic entitlement projection for the public staking API.

use super::*;
use iroha_data_model::nexus::PublicLanePendingReward;

/// Read an account's automatically accrued XOR entitlement, including dust.
///
/// The current authenticated beneficiary owns this view after recovery. A former
/// owner receives no entitlement; the claim threshold does not hide unpaid dust.
///
/// # Errors
/// Returns deferred resource failures or rejects invalid beneficiary, custody,
/// reward-state, or canonical XOR records.
pub fn pending_fee_reward(
    world: &impl WorldReadOnly,
    height: u64,
    account: &AccountId,
    lane: LaneId,
) -> Result<Option<PublicLanePendingReward>, ExecutionAttemptError<Error>> {
    let Some(binding) =
        crate::validation_fee::active_payout_binding_in_world_at_height(world, height)
            .map_err(|error| error.map_rejection(|error| fail(error.to_string())))?
            .filter(|binding| binding.validator_lane_id == lane)
    else {
        return Ok(None);
    };
    let original = beneficiary::root_in_world(world, &binding, account)?;
    let amount_minor =
        read_from_world::<u128>(world, &claimable_key(&binding, &original)?)?.unwrap_or(0);
    if amount_minor == 0 {
        return Ok(None);
    }
    crate::state::validate_network_xor_asset(world, &binding.xor_asset_id)?;
    let owner = beneficiary::owner_in_world(world, &binding, &original)?
        .ok_or_else(|| fail("reserved claim has no authenticated beneficiary owner"))?;
    if owner.account_id != *account {
        return Ok(None);
    }
    let asset = AssetId::new(
        binding.xor_asset_id.clone(),
        binding.reward_pool_account_id.clone(),
    );
    let state =
        read_from_world::<ValidationFeeRewardsState>(world, &state_key(&binding, "State")?)?
            .unwrap_or_default();
    let balance = world
        .assets()
        .get(&asset)
        .map_or_else(Quantity::zero, |value| value.as_ref().clone());
    if minor_units(&balance, 9)? < state.reserved_xor || amount_minor > state.reserved_xor {
        return Err(fail("validator rewards custody is underfunded").into());
    }
    crate::smartcontracts::isi::staking::ensure_public_lane_reserves_after_debit(
        world, &asset, &balance,
    )?;
    Ok(Some(PublicLanePendingReward {
        lane_id: lane,
        account: account.clone(),
        asset,
        amount: quantity(amount_minor, 9)?,
        beneficiary_id: original,
        beneficiary_revision: owner.revision,
        expected_claim_sequence: state.next_claim,
        lifecycle_seal: binding
            .lifecycle_seal()
            .map_err(|error| fail(error.to_string()))?,
        claimable: amount_minor >= u128::from(binding.min_reward_claim_xor_minor),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_view_exposes_funded_dust_and_exact_claim_coordinates() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
            let mut binding = active_bindings(stx).unwrap().remove(0);
            binding.min_reward_claim_xor_minor = 10;
            let registry =
                crate::validation_fee::tests::policy_registry(&[policy], &[binding.clone()]);
            crate::validation_fee::tests::install_policy_registry_fixture(&registry, stx);
            let claimant = binding.reference_provider_accounts[0].clone();
            assert!(
                pending_fee_reward(
                    &stx.world,
                    stx.block_height(),
                    &claimant,
                    binding.validator_lane_id
                )
                .unwrap()
                .is_none()
            );
            let original = beneficiary::ensure(stx, &binding, &claimant).unwrap();
            write(stx, claimable_key(&binding, &original).unwrap(), &7_u128).unwrap();
            save_state(
                stx,
                &binding,
                &ValidationFeeRewardsState {
                    reserved_xor: 7,
                    next_claim: 3,
                    ..Default::default()
                },
            )
            .unwrap();
            let asset = AssetId::new(
                binding.xor_asset_id.clone(),
                binding.reward_pool_account_id.clone(),
            );
            **stx
                .world
                .asset_or_insert_exact(&asset, Quantity::zero())
                .unwrap() = quantity(7, 9).unwrap();
            let pending = pending_fee_reward(
                &stx.world,
                stx.block_height(),
                &claimant,
                binding.validator_lane_id,
            )
            .unwrap()
            .unwrap();
            assert_eq!(pending.amount, quantity(7, 9).unwrap());
            assert_eq!(pending.beneficiary_id, original);
            assert_eq!(pending.expected_claim_sequence, 3);
            assert_eq!(pending.lifecycle_seal, binding.lifecycle_seal().unwrap());
            assert!(!pending.claimable);
            let encoded = norito::to_bytes(&pending).unwrap();
            assert_eq!(
                norito::decode_from_bytes::<PublicLanePendingReward>(&encoded).unwrap(),
                pending
            );
            let successor = binding.reference_provider_accounts[1].clone();
            beneficiary::rekey_beneficiary(stx, &claimant, &successor).unwrap();
            assert!(
                pending_fee_reward(
                    &stx.world,
                    stx.block_height(),
                    &claimant,
                    binding.validator_lane_id,
                )
                .unwrap()
                .is_none()
            );
            let recovered = pending_fee_reward(
                &stx.world,
                stx.block_height(),
                &successor,
                binding.validator_lane_id,
            )
            .unwrap()
            .unwrap();
            assert_eq!(recovered.account, successor);
            assert_eq!(recovered.beneficiary_id, original);
            assert_eq!(recovered.beneficiary_revision, 1);
            assert_eq!(recovered.amount, pending.amount);
            assert_eq!(
                recovered.expected_claim_sequence,
                pending.expected_claim_sequence
            );
            write(stx, claimable_key(&binding, &original).unwrap(), &11_u128).unwrap();
            assert!(
                pending_fee_reward(
                    &stx.world,
                    stx.block_height(),
                    &successor,
                    binding.validator_lane_id
                )
                .is_err()
            );
        });
    }
}
