//! Explicit genesis staking authors survive generation and later profile additions.

use super::*;
use crate::genesis::CompleteTestGenesisBuilder as _;
use iroha_data_model::block::consensus::PublicLaneStakingPolicyError;
use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR;

fn builder() -> GenesisBuilder {
    GenesisBuilder::new_without_executor(
        ChainId::from("kagami-explicit-staking"),
        ".",
        CryptoAdmissionPolicyV1::new(vec![Algorithm::Ed25519, Algorithm::BlsNormal]).unwrap(),
    )
    .complete_for_test()
}

fn authored(manifest: &RawGenesisTransaction) -> PublicLaneStakingPolicy {
    PublicLaneStakingPolicy::from_parameters(&manifest.effective_parameters().unwrap()).unwrap()
}

fn assert_monetary_assets(manifest: &RawGenesisTransaction, asset: &AssetDefinitionId) {
    let parameters = manifest.effective_parameters().unwrap();
    let staking = PublicLaneStakingPolicy::from_parameters(&parameters).unwrap();
    let npos = parameters
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()
        .unwrap()
        .flatten()
        .unwrap();
    let fees = RootFeePolicy::from_parameters(&parameters)
        .unwrap()
        .unwrap();
    assert_eq!(&staking.stake_asset_id, asset);
    assert_eq!(&npos.xor_asset_definition_id, asset);
    assert_eq!(&fees.fee_asset_id, asset);
}

#[test]
fn policy_resolution_uses_selected_asset_typed_custody_and_liability_profile() {
    let _caller = ChainDiscriminantGuard::enter(753);
    let asset = AssetDefinitionId::parse_address_literal("61CtjvNd9T3THAR65GsMVHr82Bjc").unwrap();
    let ordinary = resolve_staking_policy(Some(&asset), false).unwrap();
    let liability = resolve_staking_policy(Some(&asset), true).unwrap();
    let custody = iroha_config::parameters::defaults::governance::bond_escrow_account_id();
    assert_eq!(ordinary.stake_asset_id, asset);
    assert_eq!(ordinary.stake_escrow_account_id, custody);
    assert_eq!(ordinary.slash_sink_account_id, custody);
    assert_eq!(ordinary.unbonding_delay_ms, 0);
    assert_eq!(
        liability.unbonding_delay_ms,
        iroha_deploy::genesis::sccp::UNBONDING_DELAY_MS
    );
    assert_eq!(
        liability.max_slash_bps,
        iroha_deploy::genesis::sccp::MAX_SLASH_BPS
    );
    let mut expected = ordinary.clone();
    expected.unbonding_delay_ms = liability.unbonding_delay_ms;
    expected.max_slash_bps = liability.max_slash_bps;
    assert_eq!(liability, expected);
    {
        let _author = ChainDiscriminantGuard::enter(369);
        assert_eq!(
            resolve_staking_policy(Some(&asset), false).unwrap(),
            ordinary
        );
        assert_eq!(
            resolve_staking_policy(Some(&asset), true).unwrap(),
            liability
        );
    }
    assert_eq!(
        iroha_data_model::account::address::chain_discriminant(),
        753
    );
    let fallback = resolve_staking_policy(None, false).unwrap();
    assert_eq!(
        fallback.stake_asset_id,
        iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
            .parse()
            .unwrap()
    );
}

#[test]
fn both_generation_modes_preserve_one_policy_through_public_xor_and_sccp() {
    for literal in [
        crate::genesis::TAIRA_XOR_ASSET_DEFINITION_ID,
        "61CtjvNd9T3THAR65GsMVHr82Bjc",
    ] {
        let asset = AssetDefinitionId::parse_address_literal(literal).unwrap();
        for mode in [
            Mode::Default,
            Mode::Synthetic {
                domains: 1,
                accounts_per_domain: 0,
                asset_definitions_per_domain: 1,
            },
        ] {
            for sccp in [false, true] {
                let policy = resolve_staking_policy(Some(&asset), sccp).unwrap();
                let generated = build_genesis_for_mode(
                    mode,
                    builder(),
                    SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
                    None,
                    SumeragiConsensusMode::Npos,
                    None,
                    Some([7; 32]),
                    policy.clone(),
                )
                .unwrap();
                assert_eq!(
                    authored(&generated),
                    policy,
                    "first build owns the exact policy"
                );
                assert_monetary_assets(&generated, &asset);
                let original_parameters = generated.effective_parameters().unwrap();
                let bound = append_public_xor_binding(generated, &asset).unwrap();
                assert_eq!(bound.effective_parameters().unwrap(), original_parameters);
                let rebound = append_public_xor_binding(bound, &asset).unwrap();
                assert_eq!(rebound.effective_parameters().unwrap(), original_parameters);
                assert_eq!(authored(&rebound), policy);
                let final_manifest = if sccp {
                    iroha_deploy::genesis::sccp::append_profile(rebound, [7; 32]).unwrap()
                } else {
                    rebound
                };
                assert_eq!(authored(&final_manifest), policy);
                assert_monetary_assets(&final_manifest, &asset);
                let error = final_manifest
                    .into_builder()
                    .with_staking_policy(policy)
                    .unwrap()
                    .build_raw()
                    .unwrap_err();
                assert!(
                    error.to_string().contains("staking"),
                    "an additional assignment must be rejected: {error}"
                );
            }
        }
    }
}

#[test]
fn public_xor_rejects_changing_the_original_staking_asset() {
    let policy = resolve_staking_policy(None, false).unwrap();
    let manifest = build_genesis_for_mode(
        Mode::Default,
        builder(),
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
        None,
        SumeragiConsensusMode::Npos,
        None,
        Some([7; 32]),
        policy.clone(),
    )
    .unwrap();
    let different =
        AssetDefinitionId::parse_address_literal("61CtjvNd9T3THAR65GsMVHr82Bjc").unwrap();
    assert_ne!(different, policy.stake_asset_id);
    let error = append_public_xor_binding(manifest.clone(), &different).unwrap_err();
    assert!(error.to_string().contains("staking asset authored before"));
    assert_eq!(authored(&manifest), policy);
}

#[test]
fn fixture_context_completion_does_not_supply_an_absent_staking_policy() {
    let error = builder().build_raw().unwrap_err();
    assert!(matches!(
        error.downcast_ref::<PublicLaneStakingPolicyError>(),
        Some(PublicLaneStakingPolicyError::MissingParameter)
    ));
    let policy = crate::genesis::test_staking_policy();
    let manifest = builder()
        .with_staking_policy(policy.clone())
        .unwrap()
        .build_raw()
        .unwrap();
    assert_eq!(authored(&manifest), policy);
}

#[test]
fn public_profile_generation_enters_author_context_and_restores_on_success_and_error() {
    let _caller = ChainDiscriminantGuard::enter(753);
    let args = Args {
        profile: Some(GenesisProfile::Iroha3Taira),
        chain_id: None,
        vrf_seed_hex: Some(hex::encode([7; 32])),
        xor_asset_definition_id: None,
        sccp_reset_history: None,
        executor: None,
        ivm_dir: ".".into(),
        genesis_public_key: SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone(),
        mode: Some(Mode::Default),
        ivm_gas_limit_per_block: None,
        consensus_mode: Some(ConsensusModeArg::Npos),
        lane_policy: None,
        crypto: CryptoArgs {
            allowed_signing: vec![Algorithm::Ed25519, Algorithm::BlsNormal],
        },
    };
    let mut output = BufWriter::new(Vec::new());
    args.clone().run(&mut output).unwrap();
    output.flush().unwrap();
    let manifest: RawGenesisTransaction =
        norito::json::from_slice(&output.into_inner().unwrap()).unwrap();
    assert_eq!(
        iroha_data_model::account::address::chain_discriminant(),
        753
    );
    assert_eq!(
        manifest.chain_discriminant(),
        crate::genesis::profile::TAIRA_CHAIN_DISCRIMINANT
    );
    {
        let _author = ChainDiscriminantGuard::enter(manifest.chain_discriminant());
        let asset =
            AssetDefinitionId::parse_address_literal(crate::genesis::TAIRA_XOR_ASSET_DEFINITION_ID)
                .unwrap();
        assert_eq!(
            authored(&manifest),
            resolve_staking_policy(Some(&asset), false).unwrap()
        );
        assert_monetary_assets(&manifest, &asset);
    }
    let mut invalid = args;
    invalid.crypto.allowed_signing = vec![Algorithm::Ed25519];
    let error = invalid.run(&mut BufWriter::new(Vec::new())).unwrap_err();
    assert!(error.to_string().contains("explicitly allowing bls_normal"));
    assert_eq!(
        iroha_data_model::account::address::chain_discriminant(),
        753
    );
}

#[test]
fn public_xor_refuses_mutated_npos_and_fee_authors_without_repairing_them() {
    let asset =
        AssetDefinitionId::parse_address_literal(crate::genesis::TAIRA_XOR_ASSET_DEFINITION_ID)
            .unwrap();
    let different =
        AssetDefinitionId::parse_address_literal("61CtjvNd9T3THAR65GsMVHr82Bjc").unwrap();
    let original = build_genesis_for_mode(
        Mode::Default,
        builder(),
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
        None,
        SumeragiConsensusMode::Npos,
        None,
        Some([7; 32]),
        resolve_staking_policy(Some(&asset), false).unwrap(),
    )
    .unwrap();
    assert_monetary_assets(&original, &asset);
    let parameters = original.effective_parameters().unwrap();
    let mut npos = parameters
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()
        .unwrap()
        .flatten()
        .unwrap();
    let mut fees = RootFeePolicy::from_parameters(&parameters)
        .unwrap()
        .unwrap();
    npos.xor_asset_definition_id = different.clone();
    fees.fee_asset_id = different;
    for (parameter, expected) in [
        (npos.into_custom_parameter(), "NPoS asset authored before"),
        (
            fees.into_custom_parameter().unwrap(),
            "fee asset authored before",
        ),
    ] {
        let altered = original
            .clone()
            .into_builder()
            .append_parameter(Parameter::Custom(parameter))
            .build_raw()
            .unwrap();
        let error = append_public_xor_binding(altered, &asset).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
        assert_monetary_assets(&original, &asset);
    }
}
