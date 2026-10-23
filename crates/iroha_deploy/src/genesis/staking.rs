//! Producer-selected staking bounds with explicit canonical asset and custody identities.

use iroha_config::parameters::defaults::nexus::staking;
use iroha_data_model::{
    account::AccountId, asset::AssetDefinitionId, block::consensus::PublicLaneStakingPolicy,
};

/// Construct a genesis author's default bounds for its explicitly selected asset and custody.
///
/// Callers resolve network and liability-profile choices before signing. This function does
/// not inspect node configuration, decode account addresses, or fill an absent runtime policy.
#[must_use]
pub fn default_staking_policy(
    stake_asset_id: AssetDefinitionId,
    stake_escrow_account_id: AccountId,
    slash_sink_account_id: AccountId,
) -> PublicLaneStakingPolicy {
    PublicLaneStakingPolicy {
        min_validator_stake: staking::min_validator_stake(),
        max_stake_shares_per_validator: staking::MAX_STAKE_SHARES_PER_VALIDATOR,
        max_pending_unbonds_per_share: staking::MAX_PENDING_UNBONDS_PER_SHARE,
        unbonding_delay_ms: staking::UNBONDING_DELAY
            .as_millis()
            .try_into()
            .expect("fixed producer unbonding delay fits u64 milliseconds"),
        max_slash_bps: staking::MAX_SLASH_BPS,
        stake_asset_id,
        stake_escrow_account_id,
        slash_sink_account_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
    use iroha_model_base::domain::DomainId;

    #[test]
    fn explicit_author_identities_are_preserved_across_network_contexts() {
        let _caller = ChainDiscriminantGuard::enter(753);
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::parse_fully_qualified("staking.example").unwrap(),
            "bond".parse().unwrap(),
        );
        let escrow = AccountId::new(
            KeyPair::from_seed(vec![0x63; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let sink = AccountId::new(
            KeyPair::from_seed(vec![0x64; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let policy = default_staking_policy(asset.clone(), escrow.clone(), sink.clone());
        {
            let _author = ChainDiscriminantGuard::enter(369);
            assert_eq!(
                default_staking_policy(asset.clone(), escrow.clone(), sink.clone()),
                policy
            );
            let original = policy.clone().into_custom_parameter().unwrap();
            assert_eq!(
                PublicLaneStakingPolicy::from_custom_parameter(&original).unwrap(),
                policy
            );
        }
        assert_eq!(chain_discriminant(), 753);
        assert_eq!(policy.stake_asset_id, asset);
        assert_eq!(policy.stake_escrow_account_id, escrow);
        assert_eq!(policy.slash_sink_account_id, sink);
        assert_ne!(policy.stake_escrow_account_id, policy.slash_sink_account_id);
    }

    #[test]
    fn producer_bounds_are_explicit_and_can_select_a_liability_profile() {
        let account = iroha_config::parameters::defaults::governance::bond_escrow_account_id();
        let asset = iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
            .parse()
            .unwrap();
        let mut policy = default_staking_policy(asset, account.clone(), account);
        assert_eq!(policy.min_validator_stake, staking::min_validator_stake());
        assert_eq!(
            policy.max_stake_shares_per_validator,
            staking::MAX_STAKE_SHARES_PER_VALIDATOR
        );
        assert_eq!(
            policy.max_pending_unbonds_per_share,
            staking::MAX_PENDING_UNBONDS_PER_SHARE
        );
        assert_eq!(policy.unbonding_delay_ms, 0);
        assert_eq!(policy.max_slash_bps, staking::MAX_SLASH_BPS);
        policy.unbonding_delay_ms = super::super::sccp::UNBONDING_DELAY_MS;
        policy.max_slash_bps = super::super::sccp::MAX_SLASH_BPS;
        let encoded = policy.clone().into_custom_parameter().unwrap();
        assert_eq!(
            PublicLaneStakingPolicy::from_custom_parameter(&encoded).unwrap(),
            policy
        );
    }
}
