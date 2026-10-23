//! Original signed staking authorship and committed bootstrap in the real test chain.

use super::*;
use iroha_data_model::{block::consensus::PublicLaneStakingPolicy, isi::SetParameter};

#[test]
fn fixture_constructor_authors_exactly_one_signed_staking_parameter() {
    let config = TestChainConfig::new(World::new(), 1_000);
    let policies = config
        .genesis_parameters
        .iter()
        .filter_map(|parameter| match parameter {
            Parameter::Custom(custom)
                if custom.id() == &PublicLaneStakingPolicy::parameter_id() =>
            {
                Some(PublicLaneStakingPolicy::from_custom_parameter(custom).unwrap())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(policies.len(), 1);
    let authored = policies[0].clone();
    let prepared = CertifiedTestChain::prepare(config).expect("complete explicit fixture policy");
    let signed = prepared
        .genesis
        .block()
        .external_transactions()
        .flat_map(|transaction| {
            let iroha_data_model::transaction::Executable::Instructions(instructions) =
                transaction.instructions()
            else {
                panic!("genesis contains original instruction batches");
            };
            instructions.iter()
        })
        .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        .filter_map(|set| match set.inner() {
            Parameter::Custom(custom)
                if custom.id() == &PublicLaneStakingPolicy::parameter_id() =>
            {
                Some(PublicLaneStakingPolicy::from_custom_parameter(custom).unwrap())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(signed, vec![authored.clone()]);
    assert_eq!(
        PublicLaneStakingPolicy::from_parameters(
            &prepared.manifest.effective_parameters().unwrap()
        )
        .unwrap(),
        authored
    );
    let chain = CertifiedTestChain::from_prepared(prepared).expect("real signed genesis applies");
    let view = chain.state().view();
    assert_eq!(view.height(), 1);
    assert_eq!(view.world().parameters().staking_policy(), Some(&authored));
}

#[test]
fn custom_staking_authorship_preserves_every_field_through_original_execution() {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    let authored = PublicLaneStakingPolicy {
        min_validator_stake: "17.25".parse().unwrap(),
        max_stake_shares_per_validator: 19_u32.try_into().unwrap(),
        max_pending_unbonds_per_share: 3_u32.try_into().unwrap(),
        unbonding_delay_ms: 123_456,
        max_slash_bps: 4321,
        stake_asset_id: iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::parse_fully_qualified("staking.example").unwrap(),
            "bond".parse().unwrap(),
        ),
        stake_escrow_account_id: AccountId::new(
            KeyPair::from_seed(vec![0xB5; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        ),
        slash_sink_account_id: AccountId::new(
            KeyPair::from_seed(vec![0xB6; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        ),
    };
    assert_eq!(config.genesis_parameters.len(), 1);
    config.genesis_parameters[0] =
        Parameter::Custom(authored.clone().into_custom_parameter().unwrap());
    let prepared = CertifiedTestChain::prepare(config).expect("custom original authored policy");
    assert_eq!(
        PublicLaneStakingPolicy::from_parameters(
            &prepared.manifest.effective_parameters().unwrap()
        )
        .unwrap(),
        authored
    );
    // Asset/account registration and funded admission are separate obligations.
    // This bootstrap installs the exact original monetary policy without local defaults.
    let chain = CertifiedTestChain::from_prepared(prepared).expect("custom policy genesis applies");
    let view = chain.state().view();
    assert_eq!(view.world().parameters().staking_policy(), Some(&authored));
    assert_eq!(
        PublicLaneStakingPolicy::from_parameters(view.world().parameters()).unwrap(),
        authored
    );
}

#[test]
fn fixture_preparation_refuses_missing_and_duplicate_staking_authorship() {
    let mut missing = TestChainConfig::new(World::new(), 1_000);
    missing.genesis_parameters.clear();
    let error = CertifiedTestChain::prepare(missing)
        .err()
        .expect("missing monetary authority must fail before signing");
    assert!(
        error
            .error
            .to_string()
            .contains("missing committed public-lane staking policy")
    );
    let mut repeated = TestChainConfig::new(World::new(), 1_000);
    repeated
        .genesis_parameters
        .push(repeated.genesis_parameters[0].clone());
    let error = CertifiedTestChain::prepare(repeated)
        .err()
        .expect("equal duplicate monetary authority must fail before signing");
    assert!(
        error
            .error
            .to_string()
            .contains("repeated public_lane_staking_v1")
    );
}
#[test]
fn foreign_staking_author_context_preserves_identity_and_restores_caller() {
    use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
    let _caller = ChainDiscriminantGuard::enter(753);
    let expected = {
        let Parameter::Custom(parameter) = authored_staking_fixture_parameter() else {
            panic!("canonical custom staking parameter");
        };
        PublicLaneStakingPolicy::from_custom_parameter(&parameter).unwrap()
    };
    let prepared = {
        let _author = ChainDiscriminantGuard::enter(369);
        let config = TestChainConfig::new(World::new(), 1_000);
        let prepared = CertifiedTestChain::prepare(config).expect("foreign signed author context");
        assert_eq!(
            PublicLaneStakingPolicy::from_parameters(
                &prepared.manifest.effective_parameters().unwrap()
            )
            .unwrap(),
            expected
        );
        prepared
    };
    assert_eq!(chain_discriminant(), 753);
    assert_eq!(prepared.manifest.chain_discriminant(), 369);
    prepared
        .manifest
        .validate_mode_specific_consensus_parameters()
        .unwrap();
    assert_eq!(chain_discriminant(), 753);
    let chain = CertifiedTestChain::from_prepared(prepared)
        .expect("original foreign-context signed genesis executes");
    assert_eq!(chain_discriminant(), 753);
    let view = chain.state().view();
    assert_eq!(view.height(), 1);
    assert_eq!(view.world().parameters().staking_policy(), Some(&expected));
}

#[test]
fn foreign_staking_manifest_mismatch_refuses_before_execution_and_restores_caller() {
    use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
    let _caller = ChainDiscriminantGuard::enter(753);
    let mut wrong = {
        let _author = ChainDiscriminantGuard::enter(369);
        CertifiedTestChain::prepare(TestChainConfig::new(World::new(), 1_000))
            .expect("original foreign signed genesis")
    };
    assert_eq!(chain_discriminant(), 753);
    let original_state = Arc::clone(&wrong.state);
    let original_kura = Arc::clone(&wrong.kura);
    wrong.manifest = wrong.manifest.with_chain_discriminant(753);
    let refusal = CertifiedTestChain::from_prepared(wrong)
        .err()
        .expect("a substituted manifest cannot select the execution context");
    assert!(matches!(&refusal.error, TestChainError::Genesis(message)
        if message.contains("original prepared manifest")));
    assert!(Arc::ptr_eq(&refusal.state, &original_state));
    assert_eq!(refusal.state.view().height(), 0);
    assert_eq!(original_kura.blocks_count(), 0);
    assert_eq!(chain_discriminant(), 753);
}

#[test]
fn selected_fixture_staking_asset_preserves_bounds_and_typed_custody_across_authors() {
    use iroha_config::parameters::defaults::{governance, nexus::staking};
    use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
    let _caller = ChainDiscriminantGuard::enter(753);
    let asset = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::parse_fully_qualified("private.staking-fixture")
            .unwrap(),
        "gas".parse().unwrap(),
    );
    let policy = staking_fixture_policy(asset.clone());
    assert_eq!(policy.stake_asset_id, asset);
    assert_eq!(policy.min_validator_stake, staking::min_validator_stake());
    assert_eq!(
        policy.max_stake_shares_per_validator,
        staking::MAX_STAKE_SHARES_PER_VALIDATOR
    );
    assert_eq!(
        policy.max_pending_unbonds_per_share,
        staking::MAX_PENDING_UNBONDS_PER_SHARE
    );
    assert_eq!(
        u128::from(policy.unbonding_delay_ms),
        staking::UNBONDING_DELAY.as_millis()
    );
    assert_eq!(policy.max_slash_bps, staking::MAX_SLASH_BPS);
    assert_eq!(
        policy.stake_escrow_account_id,
        governance::bond_escrow_account_id()
    );
    assert_eq!(
        policy.slash_sink_account_id,
        governance::bond_escrow_account_id()
    );
    let Parameter::Custom(default) = authored_staking_fixture_parameter() else {
        unreachable!()
    };
    let mut expected = PublicLaneStakingPolicy::from_custom_parameter(&default).unwrap();
    assert_ne!(expected.stake_asset_id, asset);
    expected.stake_asset_id = asset.clone();
    assert_eq!(policy, expected);
    {
        let _author = ChainDiscriminantGuard::enter(369);
        let foreign = staking_fixture_policy(asset);
        assert_eq!(foreign, policy);
        assert_eq!(
            PublicLaneStakingPolicy::from_custom_parameter(
                &foreign.into_custom_parameter().unwrap()
            )
            .unwrap(),
            policy
        );
    }
    assert_eq!(chain_discriminant(), 753);
}
