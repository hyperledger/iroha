//! Signed private-currency SNS initialization before ordinary State construction.

use super::*;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    block::{
        SignedBlock,
        consensus::{RootFeePolicy, SumeragiGenesisContextParameters, SumeragiRootScope},
    },
    nexus::DataSpaceCatalog,
    parameter::{Parameter, system::SumeragiConsensusMode},
};
use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry};

fn policy() -> RootFeePolicy {
    RootFeePolicy {
        fee_asset_id: AssetDefinitionId::derive_from_components(
            DomainId::parse_fully_qualified("app.private-bootstrap").unwrap(),
            "gas".parse().unwrap(),
        ),
        base_fee: 1_u32.into(),
        per_byte_fee: 0_u32.into(),
        per_instruction_fee: 1_u32.into(),
        per_gas_unit_fee: 1_u32.into(),
        ..iroha_config::parameters::defaults::nexus::fees::genesis_policy()
    }
}

fn genesis(scope: SumeragiRootScope, parameters: Vec<Parameter>) -> SignedBlock {
    iroha_genesis::init_instruction_registry();
    let validators = crate::sumeragi::test_chain::fixture_validators();
    let mut context = SumeragiGenesisContextParameters::recommended();
    context.root_scope = scope;
    let builder = GenesisBuilder::new_without_executor(
        "sns-private-bootstrap".into(),
        ".",
        iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
            iroha_crypto::Algorithm::Ed25519,
            iroha_crypto::Algorithm::Secp256k1,
            iroha_crypto::Algorithm::BlsNormal,
        ])
        .expect("explicit canonical genesis producer policy"),
    )
    .with_staking_policy(crate::sumeragi::test_chain::staking_fixture_policy(
        match scope {
            SumeragiRootScope::Dataspace { .. } => policy().fee_asset_id,
            SumeragiRootScope::Global => {
                iroha_config::parameters::defaults::nexus::fees::genesis_policy().fee_asset_id
            }
        },
    ))
    .expect("explicit fixture staking author")
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
    for namespace in [
        SnsNamespace::AccountAlias,
        SnsNamespace::Domain,
        SnsNamespace::Dataspace,
    ] {
        let stored = policy_or_not_found(&world.view(), namespace.suffix_id()).unwrap();
        for literal in std::iter::once(stored.payment_asset_id.as_str()).chain(
            stored
                .pricing
                .iter()
                .map(|tier| tier.base_price.asset_id.as_str()),
        ) {
            assert_eq!(
                AssetDefinitionId::parse_address_literal(literal).unwrap(),
                policy.fee_asset_id,
            );
        }
    }
    // Exactly the ordinary State constructor's next initialization call: its fallback cannot
    // replace authoritative private policies that the original signed source installed.
    try_seed_default_namespace_policies(
        &mut world,
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap();
    ensure_default_namespace_policies_match_configured(
        &world.view(),
        &policy.fee_asset_id.to_string(),
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
    // The production builder rejects missing private monetary policy. Construct a genuinely
    // signed negative fixture through the native epoch fixture to exercise SNS admission itself.
    let missing = crate::sumeragi::epoch::tests::genesis_fixture_with_scope(
        SumeragiConsensusMode::Permissioned,
        10,
        false,
        scope(),
    );
    iroha_data_model::sumeragi_finality::authenticated_genesis(&missing)
        .expect("missing-policy fixture retains authenticated genesis authority");
    let mut missing_world = World::default();
    assert!(matches!(
        seed_genesis_alias_bootstrap(
            &mut missing_world,
            &missing,
            &DataSpaceCatalog::default(),
        ),
        Err(SnsError::BadRequest(message))
            if message == "private SNS bootstrap omits its signed fee policy"
    ));
    assert_eq!(missing_world.smart_contract_state.view().iter().count(), 0);
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
    let mut forged_world = World::default();
    assert!(
        seed_genesis_alias_bootstrap(&mut forged_world, &forged, &DataSpaceCatalog::default())
            .is_err()
    );
    assert_eq!(forged_world.smart_contract_state.view().iter().count(), 0);
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
