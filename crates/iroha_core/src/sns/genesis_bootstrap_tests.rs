//! Signed private-currency SNS initialization before ordinary State construction.

use super::*;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    block::{
        SignedBlock,
        consensus::{PrivateRootFeePolicy, SumeragiGenesisContextParameters, SumeragiRootScope},
    },
    nexus::DataSpaceCatalog,
    parameter::{Parameter, system::SumeragiConsensusMode},
};
use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry};

fn policy() -> PrivateRootFeePolicy {
    PrivateRootFeePolicy {
        asset_definition_id: AssetDefinitionId::derive_from_components(
            DomainId::parse_fully_qualified("app.private-bootstrap").unwrap(),
            "gas".parse().unwrap(),
        ),
        base_fee: 1_u32.into(),
        per_byte_fee: 0_u32.into(),
        per_instruction_fee: 1_u32.into(),
        per_gas_unit_fee: 1_u32.into(),
    }
}

fn genesis(scope: SumeragiRootScope, parameters: Vec<Parameter>) -> SignedBlock {
    iroha_genesis::init_instruction_registry();
    let validators = crate::sumeragi::test_chain::fixture_validators();
    let mut context = SumeragiGenesisContextParameters::recommended();
    context.root_scope = scope;
    let builder = GenesisBuilder::new_without_executor("sns-private-bootstrap".into(), ".")
        .set_topology(
            validators
                .into_iter()
                .map(|(peer, pop)| GenesisTopologyEntry::new(peer, pop))
                .collect(),
        )
        .with_sumeragi_context_parameters(context);
    let builder = parameters
        .into_iter()
        .fold(builder, GenesisBuilder::append_parameter);
    let raw = builder
        .build_raw()
        .unwrap()
        .with_consensus_mode(SumeragiConsensusMode::Permissioned)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
    let signer = KeyPair::from_seed(vec![75; 32], Algorithm::Ed25519);
    raw.build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
        &signer,
        None,
        Some(crate::state::default_genesis_confidential_policy_hash()),
        1_000,
    )
    .unwrap()
    .0
}

fn scope() -> SumeragiRootScope {
    SumeragiRootScope::Dataspace {
        parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"independent parent",
        ))),
        dataspace_id: DataSpaceId::new(u64::MAX - 10),
    }
}

#[test]
fn private_genesis_seeds_signed_namespace_currency_before_global_defaults_without_retargeting() {
    let policy = policy();
    let block = genesis(
        scope(),
        vec![Parameter::Custom(
            policy.clone().into_custom_parameter().unwrap(),
        )],
    );
    let mut world = World::default();
    seed_genesis_alias_bootstrap(&mut world, &block, &DataSpaceCatalog::default()).unwrap();
    // Exactly the ordinary State constructor's next initialization call: its fallback cannot
    // replace authoritative private policies that the original signed source installed.
    try_seed_default_namespace_policies(
        &mut world,
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap();
    ensure_default_namespace_policies_match_configured(
        &world.view(),
        &policy.asset_definition_id.to_string(),
    )
    .unwrap();
    let before = world
        .smart_contract_state
        .view()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<Vec<_>>();
    seed_genesis_alias_bootstrap(&mut world, &block, &DataSpaceCatalog::default()).unwrap();
    assert_eq!(
        before,
        world
            .smart_contract_state
            .view()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>()
    );

    let mut conflicting = World::default();
    let global = iroha_config::parameters::defaults::nexus::fees::fee_asset_id();
    let existing = default_namespace_policy(
        SnsNamespace::Domain,
        &bootstrap_steward_for_world(&conflicting.view()),
        &global,
    );
    let key = policy_storage_key(existing.suffix_id);
    let bytes = existing.encode();
    conflicting
        .smart_contract_state
        .insert(key.clone(), bytes.clone());
    assert!(
        seed_genesis_alias_bootstrap(&mut conflicting, &block, &DataSpaceCatalog::default())
            .is_err()
    );
    assert_eq!(conflicting.smart_contract_state.view().iter().count(), 1);
    assert_eq!(
        conflicting.smart_contract_state.view().get(&key),
        Some(&bytes)
    );
}

#[test]
fn missing_or_untrusted_private_fee_authority_cannot_seed_namespace_state() {
    let missing = genesis(scope(), vec![]);
    let global = genesis(SumeragiRootScope::Global, vec![]);
    let fee = policy().into_custom_parameter().unwrap();
    let valid = genesis(scope(), vec![Parameter::Custom(fee)]);
    let other = KeyPair::from_seed(vec![76; 32], Algorithm::Ed25519);
    let forged = SignedBlock::genesis(
        valid.external_transactions().cloned().collect(),
        other.private_key(),
        None,
        None,
    );
    for block in [&missing, &forged] {
        let mut world = World::default();
        assert!(
            seed_genesis_alias_bootstrap(&mut world, block, &DataSpaceCatalog::default()).is_err()
        );
        assert_eq!(world.smart_contract_state.view().iter().count(), 0);
    }
    let mut world = World::default();
    seed_genesis_alias_bootstrap(&mut world, &global, &DataSpaceCatalog::default()).unwrap();
    try_seed_default_namespace_policies(
        &mut world,
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap();
    ensure_default_namespace_policies_match_configured(
        &world.view(),
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap();
}
