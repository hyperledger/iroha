//! Profile-default normalization and genesis-recipe parity with canonical Taira output.
//!
//! These tests verify the exact catalog and custody fields copied by normalization,
//! and compare the compiled profile recipe with a generated signed Taira manifest.

use super::*;
use iroha_config::profile::{KeylessRole, Profile, ProfileId};

/// Fixed peer, operator and genesis seed shared by both halves.
const SEED: &str = "sora-nexus-v1-golden-parity";
/// Nexus fields that make up "the catalog": lanes, dataspaces, routes, the lane-manifest registry
/// and the governance modules its restricted lanes name. They are copied from Kagami into the
/// profile render by [`copy_kagami_catalog`]; this list documents that exact set.
const CATALOG_FIELDS: &[&str] = &[
    "nexus.lane_catalog",
    "nexus.configured_lane_catalog",
    "nexus.lane_config",
    "nexus.dataspace_catalog",
    "nexus.configured_dataspace_catalog",
    "nexus.routing_policy",
    "nexus.registry",
    "nexus.governance",
];

/// Custody roles that name one keyless protocol account on both sides. They are copied from Kagami
/// into the profile render by [`copy_kagami_custody_account`] after both are checked.
const CUSTODY_ACCOUNT_FIELDS: &[&str] = &[
    "pipeline.gas.tech_account_id",
    "nexus.fees.fee_sink_account_id",
    "nexus.fees.sponsor_vault_custody_account_id",
    "nexus.staking.stake_escrow_account_id",
    "nexus.staking.slash_sink_account_id",
];

/// Governance roles that name the published sample key in Kagami's Taira and a keyless role
/// account in the profile, in [`KeylessRole::ALL`] order. They are copied from Kagami into the
/// profile render by [`copy_kagami_governance_accounts`] after both are checked.
const GOVERNANCE_ACCOUNT_FIELDS: &[&str] = &[
    "gov.citizenship_escrow_account",
    "gov.bond_escrow_account",
    "gov.slash_receiver_account",
    "gov.viral_incentives.incentive_pool_account",
    "gov.viral_incentives.escrow_account",
    "gov.sorafs_pin_fee_treasury_account",
];

/// Today's canonical Taira localnet, generated with the profile's cadence.
struct KagamiTaira {
    _dir: crate::localnet::localnet_test_helpers::PrivateTempDir,
    manifest: RawGenesisTransaction,
}

impl KagamiTaira {
    fn generate(block_cadence_ms: u64) -> Self {
        let dir = crate::localnet::localnet_test_helpers::private_tempdir()
            .expect("temporary Taira directory");
        let opts = LocalnetOptions {
            service_profile: crate::localnet::LocalnetServiceProfile::Standard,
            sora_profile: Some(SoraProfile::Nexus),
            perf_profile: None,
            peers: NonZeroU16::new(TAIRA_TESTNET_PEERS).expect("four peers"),
            seed: Some(SEED.to_owned()),
            bind_host: DEFAULT_BIND_HOST.to_owned(),
            public_host: DEFAULT_PUBLIC_HOST.to_owned(),
            base_api_port: 8_080,
            base_p2p_port: 1_337,
            out_dir: dir.path().to_path_buf(),
            extra_accounts: 0,
            assets: Vec::new(),
            block_cadence_ms: Some(block_cadence_ms),
            consensus_mode: SumeragiConsensusMode::Npos,
        };
        generate_localnet_with_chain(
            &opts,
            &mut BufWriter::new(Vec::new()),
            Some(PUBLIC_TAIRA_CHAIN_ID),
            None,
        )
        .expect("generate canonical Taira localnet");
        let _discriminant = ChainDiscriminantGuard::enter(taira_discriminant());
        let manifest = RawGenesisTransaction::from_path(dir.path().join("genesis.json"))
            .expect("bound Taira genesis manifest");
        read_signed_genesis(&dir.path().join("genesis.signed.nrt")).expect("signed Taira genesis");
        Self {
            _dir: dir,
            manifest,
        }
    }
}

fn taira_discriminant() -> u16 {
    known_chain_discriminant_for_chain_id(PUBLIC_TAIRA_CHAIN_ID).expect("Taira discriminant")
}

/// Replace exactly the [`CATALOG_FIELDS`] of the profile render with Kagami's.
fn copy_kagami_catalog(to: &mut actual::Nexus, from: &actual::Nexus) {
    to.lane_catalog = from.lane_catalog.clone();
    to.configured_lane_catalog = from.configured_lane_catalog.clone();
    to.lane_config = from.lane_config.clone();
    to.dataspace_catalog = from.dataspace_catalog.clone();
    to.configured_dataspace_catalog = from.configured_dataspace_catalog.clone();
    to.routing_policy = from.routing_policy.clone();
    to.registry = from.registry.clone();
    to.governance = from.governance.clone();
}

/// The account of every [`CUSTODY_ACCOUNT_FIELDS`] role, in that order.
fn custody_accounts(pipeline: &actual::Pipeline, nexus: &actual::Nexus) -> [AccountId; 5] {
    let _discriminant = ChainDiscriminantGuard::enter(taira_discriminant());
    let parse = |literal: &str| AccountId::parse_encoded(literal).expect("custody account literal");
    [
        parse(&pipeline.gas.tech_account_id),
        nexus.fees.fee_sink_account_id.clone(),
        nexus.fees.sponsor_vault_custody_account_id.clone(),
        parse(&nexus.staking.stake_escrow_account_id),
        parse(&nexus.staking.slash_sink_account_id),
    ]
}

/// Copy Kagami's [`CUSTODY_ACCOUNT_FIELDS`] values into the render, verbatim.
fn copy_kagami_custody_account(
    (pipeline, nexus): (&mut actual::Pipeline, &mut actual::Nexus),
    (from_pipeline, from_nexus): (&actual::Pipeline, &actual::Nexus),
) {
    pipeline.gas.tech_account_id = from_pipeline.gas.tech_account_id.clone();
    nexus.fees.fee_sink_account_id = from_nexus.fees.fee_sink_account_id.clone();
    nexus.fees.sponsor_vault_custody_account_id =
        from_nexus.fees.sponsor_vault_custody_account_id.clone();
    nexus.staking.stake_escrow_account_id = from_nexus.staking.stake_escrow_account_id.clone();
    nexus.staking.slash_sink_account_id = from_nexus.staking.slash_sink_account_id.clone();
}

/// The account of every [`GOVERNANCE_ACCOUNT_FIELDS`] role, in that order.
fn governance_accounts(gov: &actual::Governance) -> [AccountId; 6] {
    [
        gov.citizenship_escrow_account.clone(),
        gov.bond_escrow_account.clone(),
        gov.slash_receiver_account.clone(),
        gov.viral_incentives.incentive_pool_account.clone(),
        gov.viral_incentives.escrow_account.clone(),
        gov.sorafs_pin_fee_treasury_account.clone(),
    ]
}

/// Copy Kagami's [`GOVERNANCE_ACCOUNT_FIELDS`] values into the render, verbatim.
fn copy_kagami_governance_accounts(to: &mut actual::Governance, from: &actual::Governance) {
    to.citizenship_escrow_account = from.citizenship_escrow_account.clone();
    to.bond_escrow_account = from.bond_escrow_account.clone();
    to.slash_receiver_account = from.slash_receiver_account.clone();
    to.viral_incentives.incentive_pool_account =
        from.viral_incentives.incentive_pool_account.clone();
    to.viral_incentives.escrow_account = from.viral_incentives.escrow_account.clone();
    to.sorafs_pin_fee_treasury_account = from.sorafs_pin_fee_treasury_account.clone();
}

/// Line diff (longest common subsequence) of two pretty `Debug` renderings.
fn line_diff(left: &str, right: &str) -> Vec<String> {
    let left: Vec<&str> = left.lines().collect();
    let right: Vec<&str> = right.lines().collect();
    let mut lcs = vec![vec![0_u32; right.len() + 1]; left.len() + 1];
    for i in (0..left.len()).rev() {
        for j in (0..right.len()).rev() {
            lcs[i][j] = if left[i] == right[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < left.len() || j < right.len() {
        if i < left.len() && j < right.len() && left[i] == right[j] {
            i += 1;
            j += 1;
        } else if j < right.len() && (i == left.len() || lcs[i][j + 1] >= lcs[i + 1][j]) {
            out.push(format!("  + profile: {}", right[j].trim()));
            j += 1;
        } else {
            out.push(format!("  - kagami:  {}", left[i].trim()));
            i += 1;
        }
    }
    out
}

#[test]
fn line_diff_reports_only_changed_lines() {
    assert!(line_diff("a\nb\nc", "a\nb\nc").is_empty());
    assert_eq!(
        line_diff("a\nb\nc", "a\nx\nc"),
        vec!["  + profile: x".to_owned(), "  - kagami:  b".to_owned()]
    );
    assert_eq!(line_diff("a", "a\nb"), vec!["  + profile: b".to_owned()]);
    assert_eq!(line_diff("a\nb", "b"), vec!["  - kagami:  a".to_owned()]);
}

#[test]
fn catalog_normalization_copies_exactly_the_catalog_fields() {
    let mut kagami = actual::Nexus::default();
    kagami.routing_policy.default_lane = LaneId::new(3);
    kagami.staking.max_slash_bps = kagami.staking.max_slash_bps.wrapping_add(1);
    let mut profile = actual::Nexus::default();
    copy_kagami_catalog(&mut profile, &kagami);
    assert_eq!(profile.routing_policy, kagami.routing_policy);
    assert_eq!(
        profile.staking.max_slash_bps,
        actual::Nexus::default().staking.max_slash_bps,
        "a non-catalog field must not be copied"
    );
    assert_eq!(CATALOG_FIELDS.len(), 8);
    assert!(
        CATALOG_FIELDS
            .iter()
            .all(|field| field.starts_with("nexus."))
    );
}

#[test]
fn custody_normalization_sets_exactly_the_five_custody_roles() {
    let kagami = localnet_gas_account_id(KeyPair::random().public_key());
    let literal = kagami
        .to_i105_for_discriminant(taira_discriminant())
        .expect("I105 literal");
    let (mut from_pipeline, mut from_nexus) =
        (actual::Pipeline::default(), actual::Nexus::default());
    from_pipeline.gas.tech_account_id.clone_from(&literal);
    from_nexus.fees.fee_sink_account_id = kagami.clone();
    from_nexus.fees.sponsor_vault_custody_account_id = kagami.clone();
    from_nexus
        .staking
        .stake_escrow_account_id
        .clone_from(&literal);
    from_nexus
        .staking
        .slash_sink_account_id
        .clone_from(&literal);
    from_nexus.fees.fee_asset_id = AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::parse_fully_qualified("app.parity").unwrap(),
        "different".parse().unwrap(),
    );
    let (mut pipeline, mut nexus) = (actual::Pipeline::default(), actual::Nexus::default());
    let fee_asset = nexus.fees.fee_asset_id.clone();
    copy_kagami_custody_account((&mut pipeline, &mut nexus), (&from_pipeline, &from_nexus));
    let accounts = custody_accounts(&pipeline, &nexus);
    assert_eq!(accounts.len(), CUSTODY_ACCOUNT_FIELDS.len());
    assert!(accounts.iter().all(|account| *account == kagami));
    assert_eq!(
        nexus.fees.fee_asset_id, fee_asset,
        "a non-custody field must not change"
    );
}

#[test]
fn governance_normalization_sets_exactly_the_six_governance_roles() {
    let kagami = localnet_gas_account_id(KeyPair::random().public_key());
    let defaults = actual::Governance::default();
    let from = actual::Governance {
        citizenship_escrow_account: kagami.clone(),
        bond_escrow_account: kagami.clone(),
        slash_receiver_account: kagami.clone(),
        sorafs_pin_fee_treasury_account: kagami.clone(),
        viral_incentives: actual::ViralIncentives {
            incentive_pool_account: kagami.clone(),
            escrow_account: kagami.clone(),
            halt: !defaults.viral_incentives.halt,
            ..defaults.viral_incentives.clone()
        },
        ..defaults
    };
    let mut to = actual::Governance::default();
    let halt = to.viral_incentives.halt;
    copy_kagami_governance_accounts(&mut to, &from);
    let accounts = governance_accounts(&to);
    assert_eq!(accounts.len(), GOVERNANCE_ACCOUNT_FIELDS.len());
    assert_eq!(
        KeylessRole::ALL
            .iter()
            .filter(|role| role.is_static())
            .count(),
        GOVERNANCE_ACCOUNT_FIELDS.len()
    );
    assert!(accounts.iter().all(|account| *account == kagami));
    assert_eq!(
        to.viral_incentives.halt, halt,
        "a non-account field must not change"
    );
}

/// The profile's genesis recipe is Kagami's signed Taira genesis, except for the cadence.
#[test]
fn sora_nexus_v1_genesis_recipe_matches_kagami_taira_genesis() {
    let profile = Profile::compiled(ProfileId::SoraNexusV1).expect("compiled profile");
    let recipe = profile.genesis_recipe();
    let geometry = profile.derive(4).expect("derive(4)");
    let kagami = KagamiTaira::generate(recipe.block_cadence_ms);
    let _discriminant = ChainDiscriminantGuard::enter(taira_discriminant());
    let parameters = kagami
        .manifest
        .effective_parameters()
        .expect("Kagami genesis parameters");
    let signed_fees =
        iroha_data_model::block::consensus::RootFeePolicy::from_parameters(&parameters)
            .expect("canonical committed fee policy")
            .expect("explicit authored fee policy");
    let gas_literal: String = parameters
        .custom()
        .get(&localnet_custom_parameter_id("ivm_gas_tech_account_id"))
        .expect("signed generated gas custody")
        .payload()
        .try_into_any_norito()
        .unwrap();
    let generated_gas = AccountId::parse_encoded(&gas_literal).unwrap();
    assert_eq!(signed_fees.fee_sink_account_id, generated_gas);
    assert_eq!(signed_fees.sponsor_vault_custody_account_id, generated_gas);
    let mut expected_fees = recipe.root_fees.clone();
    // Localnet custody derives from its exact genesis key; the compiled recipe
    // names published sample custody, just as the other custody checks above.
    expected_fees.fee_sink_account_id = generated_gas.clone();
    expected_fees.sponsor_vault_custody_account_id = generated_gas;
    assert_eq!(
        signed_fees, expected_fees,
        "all other monetary terms match the signed recipe"
    );
    assert_eq!(
        kagami.manifest.consensus_mode(),
        SumeragiConsensusMode::Npos
    );
    assert_eq!(recipe.consensus_mode, "npos");
    assert_eq!(
        parameters.sumeragi().block_cadence_ms().get(),
        recipe.block_cadence_ms
    );
    let npos = parameters
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()
        .expect("valid fixture NPoS parameters")
        .flatten()
        .expect("signed NPoS parameters");
    assert_eq!(
        npos.epoch_length_blocks().get(),
        recipe.epoch_length_blocks,
        "epoch_length_blocks"
    );
    assert_eq!(npos.max_validators(), geometry.npos_max_validators);
    assert_eq!(
        npos.min_self_bond(),
        &Quantity::from(recipe.npos_min_self_bond)
    );
    assert_eq!(
        parameters.block().max_transactions().get(),
        recipe.block_max_transactions
    );
    let ivm_gas_limit_per_block: u64 = parameters
        .custom()
        .get(&localnet_custom_parameter_id("ivm_gas_limit_per_block"))
        .expect("signed IVM gas limit")
        .payload()
        .try_into_any_norito()
        .expect("IVM gas limit payload");
    assert_eq!(ivm_gas_limit_per_block, recipe.ivm_gas_limit_per_block);
}
