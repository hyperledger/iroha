//! Explicit staking monetary policy authoring in the single signed parameter snapshot.

use super::*;
use iroha_data_model::block::consensus::PublicLaneStakingPolicy;

impl GenesisBuilder {
    /// Author the root's exact staking asset, custody accounts, minimum and resource bounds.
    ///
    /// This is the same canonical custom parameter emitted by the signed genesis.
    /// Building requires one explicit policy; repeated assignments are rejected even
    /// when equal. No node-local staking configuration supplies a missing value.
    ///
    /// # Errors
    /// Returns the original policy validation or canonical encoding failure.
    pub fn with_staking_policy(self, policy: PublicLaneStakingPolicy) -> Result<Self> {
        let parameter = policy.into_custom_parameter()?;
        Ok(self.append_parameter(Parameter::Custom(parameter)))
    }
}

#[cfg(test)]
pub(super) fn fixture_policy() -> PublicLaneStakingPolicy {
    use std::num::NonZeroU32;
    // A producer chooses this fixed fixture profile before any State exists.
    // It is never read by runtime policy admission or execution.
    PublicLaneStakingPolicy {
        min_validator_stake: 1_u64.into(),
        max_stake_shares_per_validator: NonZeroU32::new(256).unwrap(),
        max_pending_unbonds_per_share: NonZeroU32::new(8).unwrap(),
        unbonding_delay_ms: 0,
        max_slash_bps: 10_000,
        stake_asset_id: iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
            .parse()
            .expect("fixed fixture stake currency"),
        // Both fixed protocol custody identities share the known governance key.
        // Construct the identity, without decoding a network-specific address.
        stake_escrow_account_id:
            iroha_config::parameters::defaults::governance::bond_escrow_account_id(),
        slash_sink_account_id:
            iroha_config::parameters::defaults::governance::bond_escrow_account_id(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    include!("staking_source_template_tests.rs");

    fn builder() -> GenesisBuilder {
        init_instruction_registry();
        GenesisBuilder::new_without_executor(
            ChainId::from("explicit-staking-policy"),
            ".",
            CryptoAdmissionPolicyV1::new(vec![Algorithm::Ed25519, Algorithm::BlsNormal]).unwrap(),
        )
        .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
        .set_topology(deterministic_test_genesis_topology_entries())
    }

    #[test]
    fn staking_fixture_uses_declared_author_context_and_restores_caller() {
        use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
        let _caller = ChainDiscriminantGuard::enter(753);
        let expected = fixture_policy();
        let manifest = {
            let _author = ChainDiscriminantGuard::enter(369);
            assert_eq!(
                fixture_policy(),
                expected,
                "typed protocol identities are domainless"
            );
            builder()
                .with_staking_policy(fixture_policy())
                .unwrap()
                .build_raw()
                .unwrap()
        };
        assert_eq!(chain_discriminant(), 753);
        assert_eq!(manifest.chain_discriminant(), 369);
        let original = manifest.encode();
        manifest
            .validate_mode_specific_consensus_parameters()
            .unwrap();
        assert_eq!(manifest.encode(), original);
        assert_eq!(chain_discriminant(), 753);
        let serialized = norito::json::to_json(&manifest).unwrap();
        let decoded: RawGenesisTransaction = norito::json::from_str(&serialized).unwrap();
        assert_eq!(chain_discriminant(), 753);
        decoded
            .validate_mode_specific_consensus_parameters()
            .unwrap();
        assert_eq!(chain_discriminant(), 753);
        {
            let _author = ChainDiscriminantGuard::enter(369);
            assert_eq!(
                PublicLaneStakingPolicy::from_parameters(&decoded.effective_parameters().unwrap())
                    .unwrap(),
                expected
            );
        }
        assert_eq!(chain_discriminant(), 753);
        assert!(
            decoded
                .with_chain_discriminant(753)
                .validate_mode_specific_consensus_parameters()
                .is_err()
        );
        assert_eq!(chain_discriminant(), 753, "refusal restores caller context");
    }

    #[test]
    fn builder_requires_explicit_staking_policy_without_local_defaults() {
        let error = builder().build_raw().unwrap_err();
        assert!(matches!(
            error
                .downcast_ref::<iroha_data_model::block::consensus::PublicLaneStakingPolicyError>(),
            Some(
                iroha_data_model::block::consensus::PublicLaneStakingPolicyError::MissingParameter
            )
        ));
    }

    #[test]
    fn authored_staking_fields_survive_json_and_signed_original_parameter() -> Result<()> {
        let mut policy = fixture_policy();
        policy.min_validator_stake = 17_u64.into();
        policy.max_stake_shares_per_validator = 19_u32.try_into().unwrap();
        policy.max_pending_unbonds_per_share = 3_u32.try_into().unwrap();
        policy.unbonding_delay_ms = 123_456;
        policy.max_slash_bps = 4321;
        policy.stake_asset_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::parse_fully_qualified("staking.example").unwrap(),
            "bond".parse().unwrap(),
        );
        policy.stake_escrow_account_id = AccountId::new(
            KeyPair::from_seed(vec![0xB6; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        policy.slash_sink_account_id = AccountId::new(
            KeyPair::from_seed(vec![0xB7; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let raw = builder().with_staking_policy(policy.clone())?.build_raw()?;
        let decoded: RawGenesisTransaction = norito::json::from_str(&norito::json::to_json(&raw)?)?;
        let decoded = decoded.with_consensus_meta()?;
        assert_eq!(
            PublicLaneStakingPolicy::from_parameters(&decoded.effective_parameters()?)?,
            policy
        );
        let key = KeyPair::from_seed(vec![0xB8; 32], Algorithm::Ed25519);
        let block = decoded
            .clone()
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                &key, None, None, 1_000,
            )?
            .0;
        let slots = block
            .external_transactions()
            .flat_map(|transaction| {
                let Executable::Instructions(instructions) = transaction.instructions() else {
                    panic!("genesis source is explicit instructions");
                };
                instructions
                    .iter()
                    .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
            })
            .filter_map(|set| match set.inner() {
                Parameter::Custom(custom)
                    if custom.id() == &PublicLaneStakingPolicy::parameter_id() =>
                {
                    Some(custom)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(slots.len(), 1);
        assert_eq!(
            PublicLaneStakingPolicy::from_custom_parameter(slots[0])?,
            policy
        );
        validate_prepared_genesis_bundle(
            &block.encode_wire()?,
            &decoded,
            key.public_key(),
            block.hash(),
        )?;
        Ok(())
    }

    #[test]
    fn repeated_staking_assignment_is_invalid_even_when_equal() {
        let policy = fixture_policy();
        let error = builder()
            .with_staking_policy(policy.clone())
            .unwrap()
            .next_transaction()
            .append_parameter(Parameter::Custom(policy.into_custom_parameter().unwrap()))
            .build_raw()
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("repeated public_lane_staking_v1")
        );
    }

    #[test]
    fn raw_manifest_cannot_sign_after_its_required_staking_policy_is_removed() {
        let mut raw = builder()
            .with_staking_policy(fixture_policy())
            .unwrap()
            .build_raw()
            .unwrap();
        raw.transactions[0]
            .parameters
            .as_mut()
            .unwrap()
            .custom
            .remove(&PublicLaneStakingPolicy::parameter_id());
        assert!(raw.validate_mode_specific_consensus_parameters().is_err());
        let key = KeyPair::from_seed(vec![0xB9; 32], Algorithm::Ed25519);
        assert!(raw.build_and_sign(&key).is_err());
    }

    #[test]
    fn invalid_typed_policy_is_refused_before_it_enters_the_builder() {
        let mut policy = fixture_policy();
        policy.max_slash_bps = 10_001;
        assert!(builder().with_staking_policy(policy).is_err());
    }
}
