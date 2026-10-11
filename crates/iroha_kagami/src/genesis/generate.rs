use crate::{
    Outcome, RunArgs,
    genesis::profile::{
        GenesisProfile, PUBLIC_XOR_ALIAS, PUBLIC_XOR_DOMAIN, ProfileDefaults,
        TAIRA_XOR_ASSET_DEFINITION_ID, TAIRA_XOR_SCALE, known_chain_discriminant_for_chain_id,
        parse_vrf_seed_hex, profile_defaults, profile_requires_npos,
        reject_retired_public_chain_id, resolve_public_xor_asset_definition_id, resolve_vrf_seed,
    },
    tui,
};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use color_eyre::eyre::WrapErr as _;
use iroha_crypto::Algorithm;
#[cfg(test)]
use iroha_data_model::hijiri::HijiriParametersV1;
use iroha_data_model::{
    account::address::ChainDiscriminantGuard,
    asset::AssetDefinitionAlias,
    block::consensus::SumeragiGenesisContextParameters,
    parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameters},
    },
    prelude::*,
    sumeragi_lanes::SumeragiLanePolicy,
};
use iroha_deploy::genesis::{ConsensusPolicy, generate_default, validate_consensus_mode};
#[cfg(test)]
use iroha_executor_data_model::permission::{
    parameter::{CanSetHijiriParameters, CanSetParameters},
    query::CanReadAllLedgerData,
};
use iroha_genesis::{
    GenesisBuilder, ManifestCrypto, RawGenesisTransaction, validate_genesis_manifest_json,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
#[cfg(test)]
use iroha_test_samples::ALICE_ID;
use iroha_test_samples::gen_account_in;
use std::{
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
};

const LANE_POLICY_MAX_BYTES: u64 = 1024 * 1024;

/// Load and validate a Sumeragi lane policy (`specs/sumeragi_lanes.md`) from a JSON file: its
/// structure, pinned lane parameters and every fixed member's proof of possession.
pub(super) fn load_lane_policy(path: &std::path::Path) -> color_eyre::Result<SumeragiLanePolicy> {
    let metadata = fs::metadata(path)
        .wrap_err_with(|| format!("read lane policy metadata from {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > LANE_POLICY_MAX_BYTES {
        return Err(color_eyre::eyre::eyre!(
            "the lane policy must be a regular file no larger than {LANE_POLICY_MAX_BYTES} bytes"
        ));
    }
    let bytes =
        fs::read(path).wrap_err_with(|| format!("read lane policy from {}", path.display()))?;
    let policy: SumeragiLanePolicy =
        norito::json::from_slice(&bytes).wrap_err("decode the lane policy")?;
    iroha_core::sumeragi::lanes::step::validate_policy(&policy)
        .map_err(|error| color_eyre::eyre::eyre!("invalid lane policy: {error}"))?;
    Ok(policy)
}

/// Add the lane policy parameter to `genesis`.
fn append_lane_policy(
    genesis: RawGenesisTransaction,
    policy: SumeragiLanePolicy,
) -> color_eyre::Result<RawGenesisTransaction> {
    Ok(genesis
        .into_builder()
        .append_parameter(Parameter::Custom(policy.into_custom_parameter()))
        .build_raw()?
        .with_consensus_meta()?)
}

/// Generate a genesis configuration and standard-output in JSON format
#[derive(Parser, Debug, Clone)]
pub struct Args {
    /// Optional profile: picks Iroha3 chain, cadence, consensus, and VRF defaults for dev/taira/nexus.
    #[clap(long, value_name = "PROFILE")]
    profile: Option<GenesisProfile>,
    /// Optional explicit chain id. With a profile, it must equal that profile's pinned chain id.
    #[clap(long, value_name = "CHAIN_ID")]
    chain_id: Option<ChainId>,
    /// Optional VRF seed (hex, 32 bytes). Required for the public
    /// `iroha3-taira`/`iroha3-nexus` profiles.
    #[clap(long, value_name = "HEX")]
    vrf_seed_hex: Option<String>,
    /// Canonical public XOR asset definition id (Base58). Required for `iroha3-nexus`
    /// NPoS manifests; `iroha3-taira` defaults to its live XOR id.
    #[clap(long, value_name = "BASE58")]
    xor_asset_definition_id: Option<String>,
    /// Optional path (relative to output) to the executor bytecode file (.to).
    /// If omitted, no executor upgrade is included in genesis.
    #[clap(long, value_name = "PATH")]
    executor: Option<PathBuf>,
    /// Relative path from the directory of output file to the directory that contains IVM bytecode libraries
    #[clap(long, value_name = "PATH")]
    ivm_dir: PathBuf,
    #[clap(long, value_name = "MULTI_HASH")]
    genesis_public_key: PublicKey,
    #[clap(subcommand)]
    mode: Option<Mode>,
    /// Optional: set the custom parameter `ivm_gas_limit_per_block` (u64) in genesis so all peers agree on the block gas budget.
    /// If omitted, a sensible default (1,680,000) is applied.
    #[clap(long, value_name = "U64")]
    ivm_gas_limit_per_block: Option<u64>,
    /// Select the consensus mode snapshot to seed in the genesis parameters (default:
    /// permissioned; profiles that require NPoS select it themselves).
    #[clap(long, value_enum, value_name = "MODE")]
    consensus_mode: Option<ConsensusModeArg>,
    /// Optional path to a JSON Sumeragi lane policy (fixed lanes, routes, autoscale) to set in
    /// genesis. If omitted, the chain has lane 0 only until governance sets a policy.
    #[clap(long, value_name = "PATH")]
    lane_policy: Option<PathBuf>,
    /// Override cryptography snapshot fields in the generated manifest.
    #[clap(flatten)]
    crypto: CryptoArgs,
}
#[derive(ClapArgs, Debug, Clone, Default)]
struct CryptoArgs {
    /// Toggle the OpenSSL-backed SM preview helpers in the generated manifest.
    #[clap(long, value_name = "BOOL")]
    sm_openssl_preview: Option<bool>,
    /// Override the default hash advertised in the manifest.
    #[clap(long, value_name = "HASH")]
    default_hash: Option<String>,
    /// Replace the allowed signing algorithms (repeat flag to supply multiple values).
    #[clap(long = "allowed-signing", value_name = "ALGO", value_enum)]
    allowed_signing: Vec<AlgorithmArg>,
    /// Override the fallback SM2 distinguishing identifier.
    #[clap(long, value_name = "DISTID")]
    sm2_distid_default: Option<String>,
    /// Override the allowed curve identifiers (repeat flag to supply multiple values).
    #[clap(long = "allowed-curve-id", value_name = "CURVE_ID")]
    allowed_curve_ids: Vec<u8>,
}
impl CryptoArgs {
    fn into_manifest_crypto(self) -> color_eyre::Result<ManifestCrypto> {
        let mut crypto = ManifestCrypto::default();
        if !self.allowed_signing.is_empty() {
            crypto.allowed_signing = self
                .allowed_signing
                .into_iter()
                .map(Algorithm::from)
                .collect();
        }
        if let Some(flag) = self.sm_openssl_preview {
            crypto.sm_openssl_preview = flag;
        }
        if let Some(hash) = self.default_hash {
            crypto.default_hash = hash;
        }
        if let Some(distid) = self.sm2_distid_default {
            crypto.sm2_distid_default = distid;
        }
        if !self.allowed_curve_ids.is_empty() {
            crypto.allowed_curve_ids = self.allowed_curve_ids;
        }
        crypto.allowed_signing.sort();
        crypto.allowed_signing.dedup();
        if !crypto
            .allowed_signing
            .iter()
            .any(|algo| matches!(algo, Algorithm::Ed25519))
        {
            crypto.allowed_signing.insert(0, Algorithm::Ed25519);
        }
        crypto.validate()?;
        Ok(crypto)
    }
}
#[derive(ValueEnum, Clone, Debug)]
enum AlgorithmArg {
    Ed25519,
    Secp256k1,
    #[cfg(feature = "sm")]
    Sm2,
}
impl From<AlgorithmArg> for Algorithm {
    fn from(value: AlgorithmArg) -> Self {
        match value {
            AlgorithmArg::Ed25519 => Algorithm::Ed25519,
            AlgorithmArg::Secp256k1 => Algorithm::Secp256k1,
            #[cfg(feature = "sm")]
            AlgorithmArg::Sm2 => Algorithm::Sm2,
        }
    }
}
#[derive(Subcommand, Debug, Clone, Copy, Default)]
pub enum Mode {
    /// Generate default genesis
    #[default]
    Default,
    /// Generate synthetic genesis with the specified number of domains, accounts and assets.
    ///
    /// Synthetic mode is useful when we need a semi-realistic genesis for stress-testing
    /// Iroha's startup times as well as being able to just start an Iroha network and have
    /// instructions that represent a typical blockchain after migration.
    Synthetic {
        /// Number of domains in synthetic genesis.
        #[clap(long, default_value_t)]
        domains: u64,
        /// Number of accounts per domains in synthetic genesis.
        /// The total number of accounts would be `domains * accounts_per_domain`.
        #[clap(long, default_value_t)]
        accounts_per_domain: u64,
        /// Number of asset definitions per domain in synthetic genesis.
        /// The total number of asset definitions would be `domains * asset_definitions_per_domain`.
        #[clap(long, default_value_t)]
        asset_definitions_per_domain: u64,
    },
}
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum ConsensusModeArg {
    Permissioned,
    Npos,
}
impl From<ConsensusModeArg> for SumeragiConsensusMode {
    fn from(value: ConsensusModeArg) -> Self {
        match value {
            ConsensusModeArg::Permissioned => SumeragiConsensusMode::Permissioned,
            ConsensusModeArg::Npos => SumeragiConsensusMode::Npos,
        }
    }
}
#[derive(Debug)]
struct ResolvedGenesisSettings {
    chain: ChainId,
    consensus_mode: SumeragiConsensusMode,
    profile_vrf_seed: Option<[u8; 32]>,
    public_xor_asset_definition_id: Option<AssetDefinitionId>,
}
fn apply_profile_overrides(
    profile: GenesisProfile,
    chain_id: Option<&ChainId>,
    consensus_mode: SumeragiConsensusMode,
    vrf_seed_override: Option<[u8; 32]>,
    xor_asset_definition_id: Option<&str>,
    ivm_gas_limit_per_block: Option<u64>,
    defaults: &ProfileDefaults,
) -> color_eyre::Result<ResolvedGenesisSettings> {
    if let Some(explicit_chain) = chain_id
        && explicit_chain != &defaults.chain_id
    {
        return Err(color_eyre::eyre::eyre!(
            "profile {profile:?} expects chain id `{}`; drop or align the `--chain-id` override",
            defaults.chain_id
        ));
    }
    if profile_requires_npos(profile) && !matches!(consensus_mode, SumeragiConsensusMode::Npos) {
        return Err(color_eyre::eyre::eyre!(
            "profile {profile:?} targets the public dataspace; use `--consensus-mode npos`"
        ));
    }
    if let Some(gas_limit) = ivm_gas_limit_per_block
        && gas_limit != 1_680_000
    {
        return Err(color_eyre::eyre::eyre!(
            "profile {profile:?} pins `ivm_gas_limit_per_block` to 1_680_000; drop the override"
        ));
    }
    let chain = defaults.chain_id.clone();
    let wants_npos_seed = matches!(consensus_mode, SumeragiConsensusMode::Npos);
    let profile_vrf_seed = if wants_npos_seed {
        Some(resolve_vrf_seed(profile, &chain, vrf_seed_override)?)
    } else {
        None
    };
    Ok(ResolvedGenesisSettings {
        chain,
        consensus_mode,
        profile_vrf_seed,
        public_xor_asset_definition_id: resolve_public_xor_asset_definition_id(
            Some(profile),
            xor_asset_definition_id,
            wants_npos_seed,
        )?,
    })
}
fn resolve_profile_settings(
    profile: Option<GenesisProfile>,
    chain_id: Option<&ChainId>,
    profile_defaults: Option<&ProfileDefaults>,
    consensus_mode: SumeragiConsensusMode,
    vrf_seed_override: Option<[u8; 32]>,
    xor_asset_definition_id: Option<&str>,
    ivm_gas_limit_per_block: Option<u64>,
) -> color_eyre::Result<ResolvedGenesisSettings> {
    let mut chain = chain_id
        .cloned()
        .or_else(|| profile_defaults.map(|d| d.chain_id.clone()))
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "genesis generation requires either `--profile` or an explicit `--chain-id`"
            )
        })?;
    let mut consensus_mode = consensus_mode;
    let mut public_xor_asset_definition_id = None;
    let profile_vrf_seed = if let Some(profile) = profile {
        let defaults = profile_defaults.expect("profile defaults available when profile is set");
        let overrides = apply_profile_overrides(
            profile,
            chain_id,
            consensus_mode,
            vrf_seed_override,
            xor_asset_definition_id,
            ivm_gas_limit_per_block,
            defaults,
        )?;
        chain = overrides.chain;
        consensus_mode = overrides.consensus_mode;
        public_xor_asset_definition_id = overrides.public_xor_asset_definition_id;
        overrides.profile_vrf_seed
    } else {
        None
    };
    if profile.is_none() {
        let wants_npos = matches!(consensus_mode, SumeragiConsensusMode::Npos);
        public_xor_asset_definition_id =
            resolve_public_xor_asset_definition_id(profile, xor_asset_definition_id, wants_npos)?;
    }
    reject_retired_public_chain_id(chain.as_str())?;
    Ok(ResolvedGenesisSettings {
        chain,
        consensus_mode,
        profile_vrf_seed,
        public_xor_asset_definition_id,
    })
}
#[allow(clippy::too_many_arguments)]
fn build_genesis_for_mode(
    mode: Mode,
    builder: GenesisBuilder,
    genesis_public_key: &PublicKey,
    ivm_gas_limit_per_block: Option<u64>,
    consensus_mode: SumeragiConsensusMode,
    profile_defaults: Option<&ProfileDefaults>,
    resolved_vrf_seed: Option<[u8; 32]>,
) -> color_eyre::Result<RawGenesisTransaction> {
    let genesis = match mode {
        Mode::Default => generate_default(
            builder,
            genesis_public_key,
            ivm_gas_limit_per_block,
            consensus_mode,
            profile_defaults,
            resolved_vrf_seed,
        ),
        Mode::Synthetic {
            domains,
            accounts_per_domain,
            asset_definitions_per_domain,
        } => generate_synthetic(
            builder,
            genesis_public_key,
            ivm_gas_limit_per_block,
            consensus_mode,
            domains,
            accounts_per_domain,
            asset_definitions_per_domain,
            profile_defaults,
            resolved_vrf_seed,
        ),
    }?;
    apply_npos_crypto_overrides(genesis, consensus_mode)
}
fn apply_npos_crypto_overrides(
    genesis: RawGenesisTransaction,
    consensus_mode: SumeragiConsensusMode,
) -> color_eyre::Result<RawGenesisTransaction> {
    let npos_bootstrap = matches!(consensus_mode, SumeragiConsensusMode::Npos);
    if !npos_bootstrap {
        return Ok(genesis);
    }
    let mut crypto = genesis.crypto().clone();
    if !crypto
        .allowed_signing
        .iter()
        .any(|algo| matches!(algo, Algorithm::BlsNormal))
    {
        crypto.allowed_signing.push(Algorithm::BlsNormal);
    }
    crypto.allowed_signing.sort();
    crypto.allowed_signing.dedup();
    crypto.allowed_curve_ids = crypto
        .allowed_signing
        .iter()
        .filter_map(|algo| {
            iroha_data_model::account::curve::CurveId::try_from_algorithm(*algo).ok()
        })
        .map(iroha_data_model::account::curve::CurveId::as_u8)
        .collect();
    crypto.allowed_curve_ids.sort_unstable();
    crypto.allowed_curve_ids.dedup();
    genesis.into_builder().with_crypto(crypto).build_raw()
}
fn append_public_xor_binding(
    genesis: RawGenesisTransaction,
    asset_definition_id: &AssetDefinitionId,
) -> color_eyre::Result<RawGenesisTransaction> {
    let public_xor_domain = DomainId::parse_fully_qualified(PUBLIC_XOR_DOMAIN)?;
    let public_xor_alias: AssetDefinitionAlias = PUBLIC_XOR_ALIAS.parse()?;
    let mut has_domain = false;
    let mut has_asset_definition = false;
    let mut alias_bound = false;
    for instruction in genesis.instructions() {
        if let Some(register) = instruction.as_any().downcast_ref::<Register<Domain>>() {
            has_domain |= register.object.id == public_xor_domain;
            continue;
        }
        if let Some(register) = instruction
            .as_any()
            .downcast_ref::<Register<AssetDefinition>>()
        {
            if register.object.id == *asset_definition_id {
                ensure_public_xor_definition(&register.object, asset_definition_id)?;
                has_asset_definition = true;
            }
            continue;
        }
        if let Some(register) = instruction
            .as_any()
            .downcast_ref::<iroha_data_model::isi::register::RegisterBox>()
        {
            match register {
                iroha_data_model::isi::register::RegisterBox::Domain(register) => {
                    has_domain |= register.object.id == public_xor_domain;
                }
                iroha_data_model::isi::register::RegisterBox::AssetDefinition(register) => {
                    if register.object.id == *asset_definition_id {
                        ensure_public_xor_definition(&register.object, asset_definition_id)?;
                        has_asset_definition = true;
                    }
                }
                _ => {}
            }
            continue;
        }
        if let Some(bind) = instruction
            .as_any()
            .downcast_ref::<iroha_data_model::isi::asset_alias::SetAssetDefinitionAlias>(
        ) && bind.alias.as_ref() == Some(&public_xor_alias)
        {
            if bind.asset_definition_id != *asset_definition_id {
                return Err(color_eyre::eyre::eyre!(
                    "public XOR alias `{PUBLIC_XOR_ALIAS}` is already bound to `{}`, expected `{asset_definition_id}`",
                    bind.asset_definition_id
                ));
            }
            alias_bound = true;
        }
    }
    let parameters = genesis.effective_parameters()?;
    let mut npos = parameters
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .ok_or_else(|| color_eyre::eyre::eyre!("public XOR requires the signed NPoS snapshot"))?;
    npos.xor_asset_definition_id = asset_definition_id.clone();
    let mut builder = genesis
        .into_builder()
        .append_parameter(Parameter::Custom(npos.into_custom_parameter()));
    if has_domain && has_asset_definition && alias_bound {
        return Ok(builder.build_raw()?.with_consensus_meta()?);
    }
    builder = builder.next_transaction();
    if !has_domain {
        builder = builder.append_instruction(Register::domain(Domain::new(public_xor_domain)));
    }
    if !has_asset_definition {
        let definition = AssetDefinition::new(
            asset_definition_id.clone(),
            "xor".to_owned(),
            public_xor_numeric_spec(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .with_metadata(Metadata::default());
        builder = builder.append_instruction(Register::asset_definition(definition));
    }
    if !alias_bound {
        builder = builder.append_instruction(
            iroha_data_model::isi::asset_alias::SetAssetDefinitionAlias::bind(
                asset_definition_id.clone(),
                public_xor_alias,
                None,
            ),
        );
    }
    Ok(builder.build_raw()?.with_consensus_meta()?)
}
fn public_xor_numeric_spec() -> NumericSpec {
    NumericSpec::fractional(TAIRA_XOR_SCALE)
}
fn ensure_public_xor_definition(
    definition: &NewAssetDefinition,
    asset_definition_id: &AssetDefinitionId,
) -> color_eyre::Result<()> {
    let expected = public_xor_numeric_spec();
    if definition.spec != expected
        || definition.balance_scope_policy != iroha_data_model::asset::AssetBalancePolicy::Global
    {
        return Err(color_eyre::eyre::eyre!(
            "public XOR asset `{asset_definition_id}` requires global scope and numeric spec {expected:?}; found scope {:?}, spec {:?}",
            definition.balance_scope_policy,
            definition.spec
        ));
    }
    Ok(())
}
fn format_profile_summary(
    profile: GenesisProfile,
    summary_chain: &ChainId,
    profile_defaults: Option<&ProfileDefaults>,
    genesis: &RawGenesisTransaction,
    resolved_vrf_seed: Option<[u8; 32]>,
) -> String {
    let summary_fingerprint = genesis
        .consensus_fingerprint()
        .map_or_else(|| "n/a".to_owned(), |fingerprint| fingerprint.to_string());
    let vrf_seed_hex = resolved_vrf_seed.map_or_else(|| "n/a".to_string(), hex::encode_upper);
    format!(
        "kagami profile summary: profile={:?} chain_id={} block_cadence_ms={} vrf_seed={} consensus_fingerprint={} kagami_version={}",
        profile,
        summary_chain,
        profile_defaults
            .map_or_else(
                || SumeragiParameters::default().block_cadence_ms(),
                |defaults| defaults.block_cadence_ms,
            )
            .get(),
        vrf_seed_hex,
        summary_fingerprint,
        env!("CARGO_PKG_VERSION")
    )
}
fn validate_vrf_seed_usage(
    resolved_vrf_seed: Option<[u8; 32]>,
    consensus_mode: SumeragiConsensusMode,
) -> color_eyre::Result<()> {
    if resolved_vrf_seed.is_some() && !matches!(consensus_mode, SumeragiConsensusMode::Npos) {
        return Err(color_eyre::eyre::eyre!(
            "`--vrf-seed-hex` applies only to NPoS consensus manifests"
        ));
    }
    Ok(())
}
impl<T: Write> RunArgs<T> for Args {
    #[allow(clippy::too_many_lines)]
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let Self {
            profile,
            chain_id,
            vrf_seed_hex,
            xor_asset_definition_id,
            executor,
            ivm_dir,
            genesis_public_key,
            mode,
            ivm_gas_limit_per_block,
            consensus_mode,
            lane_policy,
            crypto,
        } = self;
        let mode = mode.unwrap_or_default();
        let mode_label = match &mode {
            Mode::Default => "default genesis manifest",
            Mode::Synthetic { .. } => "synthetic genesis manifest",
        };
        tui::status(format!("Building {mode_label}"));
        let profile_defaults = profile.map(profile_defaults);
        let vrf_seed_override = vrf_seed_hex
            .map(|hex| parse_vrf_seed_hex(&hex))
            .transpose()
            .wrap_err("invalid --vrf-seed-hex")?;
        let consensus_mode = consensus_mode.map_or(
            SumeragiConsensusMode::Permissioned,
            SumeragiConsensusMode::from,
        );
        let crypto = crypto.into_manifest_crypto()?;
        let resolved = resolve_profile_settings(
            profile,
            chain_id.as_ref(),
            profile_defaults.as_ref(),
            consensus_mode,
            vrf_seed_override,
            xor_asset_definition_id.as_deref(),
            ivm_gas_limit_per_block,
        )?;
        let chain = resolved.chain;
        let consensus_mode = resolved.consensus_mode;
        let profile_vrf_seed = resolved.profile_vrf_seed;
        let public_xor_asset_definition_id = resolved.public_xor_asset_definition_id;
        let resolved_vrf_seed = profile_vrf_seed.or(vrf_seed_override);
        validate_vrf_seed_usage(resolved_vrf_seed, consensus_mode)?;
        let summary_chain = chain.clone();
        let consensus_policy = match profile {
            Some(profile) if profile_requires_npos(profile) => ConsensusPolicy::PublicDataspace,
            _ => ConsensusPolicy::Any,
        };
        validate_consensus_mode(consensus_mode, consensus_policy)?;
        let builder = match executor {
            Some(path) => GenesisBuilder::new(chain, path, ivm_dir),
            None => GenesisBuilder::new_without_executor(chain, ivm_dir),
        }
        .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
        .with_crypto(crypto);
        let mut genesis = build_genesis_for_mode(
            mode,
            builder,
            &genesis_public_key,
            ivm_gas_limit_per_block,
            consensus_mode,
            profile_defaults.as_ref(),
            resolved_vrf_seed,
        )?;
        if let Some(asset_definition_id) = public_xor_asset_definition_id.as_ref() {
            genesis = append_public_xor_binding(genesis, asset_definition_id)?;
        }
        if let Some(path) = lane_policy {
            genesis = append_lane_policy(genesis, load_lane_policy(&path)?)?;
        }
        let chain_discriminant = profile_defaults
            .as_ref()
            .and_then(|defaults| defaults.chain_discriminant)
            .or_else(|| known_chain_discriminant_for_chain_id(summary_chain.as_str()))
            .unwrap_or_else(iroha_data_model::account::address::chain_discriminant);
        let genesis = genesis.with_chain_discriminant(chain_discriminant);
        let _chain_discriminant = ChainDiscriminantGuard::enter(chain_discriminant);
        let mut json = norito::json::to_json_pretty(&genesis)?;
        json.push('\n');
        validate_genesis_manifest_json(json.as_bytes())
            .wrap_err("generated genesis exceeds fixed resource bounds")?;
        writer
            .write_all(json.as_bytes())
            .wrap_err("failed to write serialized genesis to the buffer")?;
        if let Some(profile) = profile {
            let summary = format_profile_summary(
                profile,
                &summary_chain,
                profile_defaults.as_ref(),
                &genesis,
                resolved_vrf_seed,
            );
            eprintln!("{summary}");
        }
        tui::success("Genesis manifest generated");
        Ok(())
    }
}
#[cfg(test)]
mod consensus_manifest_tests {
    use super::*;
    use crate::genesis::CompleteTestGenesisBuilder as _;
    use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR;

    #[test]
    fn every_network_xor_is_generated_with_global_scale_nine() {
        for literal in [
            TAIRA_XOR_ASSET_DEFINITION_ID,
            "61CtjvNd9T3THAR65GsMVHr82Bjc",
        ] {
            let xor = AssetDefinitionId::parse_address_literal(literal).unwrap();
            let manifest = GenesisBuilder::new_without_executor(
                ChainId::from("canonical-xor-generation"),
                PathBuf::from("."),
            )
            .append_parameter(Parameter::Custom(
                SumeragiNposParameters {
                    xor_asset_definition_id: xor.clone(),
                    ..Default::default()
                }
                .into_custom_parameter(),
            ))
            .complete_for_test()
            .build_raw()
            .unwrap()
            .with_consensus_mode(SumeragiConsensusMode::Npos);
            let generated = append_public_xor_binding(manifest.clone(), &xor).unwrap();
            let definition = generated
                .instructions()
                .find_map(|instruction| {
                    if let Some(register) = instruction
                        .as_any()
                        .downcast_ref::<Register<AssetDefinition>>()
                    {
                        if register.object.id == xor {
                            return Some(&register.object);
                        }
                    }
                    instruction
                        .as_any()
                        .downcast_ref::<iroha_data_model::isi::register::RegisterBox>()
                        .and_then(|register| match register {
                            iroha_data_model::isi::register::RegisterBox::AssetDefinition(
                                register,
                            ) if register.object.id == xor => Some(&register.object),
                            _ => None,
                        })
                })
                .expect("generated canonical XOR definition");
            assert_eq!(definition.spec, NumericSpec::fractional(9));
            assert_eq!(
                definition.balance_scope_policy,
                iroha_data_model::asset::AssetBalancePolicy::Global
            );
            for (spec, scope) in [
                (
                    NumericSpec::default(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                ),
                (
                    NumericSpec::fractional(18),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                ),
                (
                    NumericSpec::fractional(9),
                    iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
                ),
            ] {
                let incompatible = manifest
                    .clone()
                    .into_builder()
                    .append_instruction(Register::asset_definition(AssetDefinition::new(
                        xor.clone(),
                        "XOR",
                        spec,
                        scope,
                        None,
                    )))
                    .build_raw()
                    .unwrap();
                let error = append_public_xor_binding(incompatible, &xor).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("requires global scope and numeric spec"),
                    "{error}"
                );
            }
        }
    }

    fn load_genesis_source_template_for_test(
        repository_root: &std::path::Path,
        relative_path: &str,
    ) -> RawGenesisTransaction {
        let path = repository_root.join(relative_path);
        // Public Nexus forbids the Taira XOR definition; match whole directory names so public
        // Taira under `configs/soranexus/` keeps the canonical Taira definition it requires.
        let nexus = std::path::Path::new(relative_path)
            .components()
            .any(|component| {
                matches!(
                    component.as_os_str().to_str(),
                    Some("nexus" | "iroha3-nexus")
                )
            });
        iroha_genesis::GenesisSourceTemplate::from_path(&path)
            .and_then(|template| {
                template.materialize(Some(if nexus {
                    AssetDefinitionId::derive_from_components(
                        DomainId::parse_fully_qualified("mainnet-fixture.universal")
                            .expect("fixture domain"),
                        "xor".parse().expect("fixture asset"),
                    )
                } else {
                    SumeragiNposParameters::default().xor_asset_definition_id
                }))
            })
            .unwrap_or_else(|error| panic!("complete {} for test: {error}", path.display()))
    }
    fn account_permission_grants(manifest: &RawGenesisTransaction) -> Vec<(AccountId, Permission)> {
        manifest
            .transactions()
            .iter()
            .flat_map(iroha_genesis::RawGenesisTx::instructions)
            .filter_map(|instruction| {
                let iroha_data_model::isi::GrantBox::Permission(grant) =
                    instruction
                        .as_any()
                        .downcast_ref::<iroha_data_model::isi::GrantBox>()?
                else {
                    return None;
                };
                Some((grant.destination().clone(), grant.object().clone()))
            })
            .collect()
    }
    fn grants_global_reader_to(
        manifest: &RawGenesisTransaction,
        expected_authority: &AccountId,
    ) -> bool {
        let expected_permission: Permission = CanReadAllLedgerData.into();
        account_permission_grants(manifest)
            .iter()
            .any(|(authority, permission)| {
                authority == expected_authority && permission == &expected_permission
            })
    }
    fn assert_first_release_hijiri_bootstrap(manifest: &RawGenesisTransaction, description: &str) {
        let parameters = manifest
            .effective_parameters()
            .unwrap_or_else(|error| panic!("derive parameters for {description}: {error}"));
        let custom = parameters
            .custom()
            .get(&HijiriParametersV1::parameter_id())
            .unwrap_or_else(|| panic!("{description} must seed global Hijiri parameters"));
        let actual = HijiriParametersV1::from_custom_parameter(custom)
            .unwrap_or_else(|error| panic!("decode Hijiri parameters for {description}: {error}"))
            .unwrap_or_else(|| panic!("{description} changed the reserved Hijiri identity"));
        assert_eq!(
            actual,
            HijiriParametersV1::first_release_genesis(),
            "{description} must seed the exact neutral first-release Hijiri snapshot"
        );
    }
    #[test]
    fn genesis_generation_requires_an_explicit_display_chain_without_a_profile() {
        let error = resolve_profile_settings(
            None,
            None,
            None,
            SumeragiConsensusMode::Permissioned,
            None,
            None,
            None,
        )
        .expect_err("unprofiled genesis generation must name its display chain");
        assert!(error.to_string().contains("--chain-id"));
    }

    #[test]
    fn taira_profile_rejects_every_noncanonical_chain_override() {
        let profile = GenesisProfile::Iroha3Taira;
        let defaults = profile_defaults(profile);
        for noncanonical in ["iroha3-taira", "taira-shadow"] {
            let chain = ChainId::from(noncanonical);
            let error = resolve_profile_settings(
                Some(profile),
                Some(&chain),
                Some(&defaults),
                SumeragiConsensusMode::Npos,
                Some([0xA5; 32]),
                None,
                None,
            )
            .expect_err("Taira profile must reject a substituted chain identity");
            assert!(error.to_string().contains("expects chain id"));
        }
        let resolved = resolve_profile_settings(
            Some(profile),
            Some(&defaults.chain_id),
            Some(&defaults),
            SumeragiConsensusMode::Npos,
            Some([0xA5; 32]),
            None,
            None,
        )
        .expect("canonical Taira chain override is an exact assertion");
        assert_eq!(resolved.chain, defaults.chain_id);
    }
    #[test]
    fn synthetic_npos_genesis_has_canonical_metadata() {
        let manifest = generate_synthetic(
            GenesisBuilder::new_without_executor(
                ChainId::from("synthetic-meta"),
                PathBuf::from("."),
            )
            .complete_for_test(),
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Npos,
            0,
            0,
            0,
            None,
            Some([7; 32]),
        )
        .expect("generate synthetic NPoS genesis");
        assert_eq!(manifest.consensus_mode(), SumeragiConsensusMode::Npos);
        assert!(manifest.consensus_fingerprint().is_some());
        assert_eq!(
            manifest.wire_protocol_version(),
            u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION)
        );
    }
    #[test]
    fn profile_cadence_and_seed_are_signed() {
        let defaults = profile_defaults(GenesisProfile::Iroha3Dev);
        let seed = [9; 32];
        let manifest = generate_default(
            GenesisBuilder::new_without_executor(defaults.chain_id.clone(), PathBuf::from("."))
                .complete_for_test(),
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Npos,
            Some(&defaults),
            Some(seed),
        )
        .expect("generate profiled NPoS genesis");
        let parameters = manifest
            .effective_parameters()
            .expect("generated manifest has one structured parameter block");
        let npos = parameters
            .custom()
            .get(&SumeragiNposParameters::parameter_id())
            .map(SumeragiNposParameters::from_custom_parameter)
            .transpose()
            .expect("valid fixture NPoS parameters")
            .flatten()
            .expect("signed NPoS parameters");
        assert_eq!(
            parameters.sumeragi().block_cadence_ms(),
            defaults.block_cadence_ms
        );
        assert_eq!(npos.epoch_seed(), seed);
        assert_eq!(
            npos.epoch_length_blocks(),
            parameters.sumeragi().epoch_length_blocks
        );
    }
    #[test]
    fn profile_summary_without_profile_defaults_reports_the_data_model_cadence() {
        let manifest = generate_default(
            GenesisBuilder::new_without_executor(
                ChainId::from("summary-default-cadence"),
                PathBuf::from("."),
            )
            .complete_for_test(),
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Permissioned,
            None,
            None,
        )
        .expect("generate unprofiled permissioned genesis");
        let signed_cadence = manifest
            .effective_parameters()
            .expect("generated manifest has one structured parameter block")
            .sumeragi()
            .block_cadence_ms();
        assert_eq!(
            signed_cadence,
            SumeragiParameters::default().block_cadence_ms()
        );
        let summary = format_profile_summary(
            GenesisProfile::Iroha3Dev,
            &ChainId::from("summary-default-cadence"),
            None,
            &manifest,
            None,
        );
        assert!(
            summary.contains(&format!(" block_cadence_ms={signed_cadence} ")),
            "{summary}"
        );
        assert!(summary.contains(" block_cadence_ms=1000 "), "{summary}");
        let defaults = profile_defaults(GenesisProfile::Iroha3Dev);
        let summary = format_profile_summary(
            GenesisProfile::Iroha3Dev,
            &defaults.chain_id,
            Some(&defaults),
            &manifest,
            None,
        );
        assert!(
            summary.contains(&format!(" block_cadence_ms={} ", defaults.block_cadence_ms)),
            "{summary}"
        );
    }
    #[test]
    fn npos_genesis_rejects_missing_seed() {
        let error = generate_default(
            GenesisBuilder::new_without_executor(
                ChainId::from("missing-npos-seed"),
                PathBuf::from("."),
            )
            .complete_for_test(),
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Npos,
            None,
            None,
        )
        .expect_err("NPoS genesis without a seed must fail closed");
        assert!(error.to_string().contains("VRF seed"));
    }
    #[test]
    fn a_lane_policy_file_becomes_the_genesis_lane_policy() {
        use iroha_data_model::sumeragi_lanes::{
            SumeragiFixedLane, SumeragiLaneMember, SumeragiLaneRoute,
        };
        let key = iroha_crypto::KeyPair::from_seed(vec![7; 32], Algorithm::BlsNormal);
        let policy = SumeragiLanePolicy {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            anchor_freshness: 16,
            max_merge_blocks: 32,
            stall_window: 256,
            lane_params: SumeragiParameters::default(),
            fixed: vec![SumeragiFixedLane {
                lane: iroha_model_base::topology::LaneId::new(2),
                dataspace: iroha_model_base::topology::DataSpaceId::new(0),
                committee: vec![SumeragiLaneMember {
                    peer: iroha_model_base::peer::PeerId::new(key.public_key().clone()),
                    pop: iroha_crypto::bls_normal_pop_prove(key.private_key()).expect("pop"),
                }],
            }],
            routes: vec![SumeragiLaneRoute {
                lane: iroha_model_base::topology::LaneId::new(2),
                account: None,
                instruction: Some("Log".to_owned()),
            }],
            autoscale: None,
        };
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("lanes.json");
        fs::write(&path, norito::json::to_json(&policy).expect("json")).expect("write");
        let loaded = load_lane_policy(&path).expect("a valid policy loads");
        assert_eq!(loaded, policy);
        let manifest = generate_default(
            GenesisBuilder::new_without_executor(ChainId::from("lanes"), PathBuf::from("."))
                .complete_for_test(),
            iroha_test_samples::ALICE_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Permissioned,
            None,
            None,
        )
        .expect("generate genesis");
        let manifest = append_lane_policy(manifest, loaded).expect("append the policy");
        let parameters = manifest.effective_parameters().expect("parameters");
        let custom = parameters
            .custom()
            .get(&SumeragiLanePolicy::parameter_id())
            .expect("the policy parameter");
        assert_eq!(
            SumeragiLanePolicy::from_custom_parameter(custom),
            Some(Ok(policy.clone()))
        );
        // A committee member whose proof of possession does not verify is refused.
        let mut forged = policy;
        forged.fixed[0].committee[0].pop = vec![0; 96];
        fs::write(&path, norito::json::to_json(&forged).expect("json")).expect("write");
        assert!(load_lane_policy(&path).is_err());
    }
    #[test]
    fn generated_genesis_does_not_reregister_its_preseeded_authority() {
        let manifest = generate_default(
            GenesisBuilder::new_without_executor(
                ChainId::from("authority-is-alice"),
                PathBuf::from("."),
            )
            .complete_for_test(),
            iroha_test_samples::ALICE_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Permissioned,
            None,
            None,
        )
        .expect("generate genesis with Alice as the genesis authority");
        assert!(
            !manifest
                .transactions()
                .iter()
                .flat_map(iroha_genesis::RawGenesisTx::instructions)
                .any(|instruction| {
                    instruction
                        .as_any()
                        .downcast_ref::<iroha_data_model::isi::RegisterBox>()
                        .is_some_and(|register| {
                            matches!(
                                register,
                                iroha_data_model::isi::RegisterBox::Account(account)
                                    if account.object().id() == &*ALICE_ID
                            )
                        })
                }),
            "the fresh-node world pre-seeds the genesis authority account"
        );
    }
    #[test]
    fn generated_default_grants_privileges_only_to_supplied_authority() {
        let manifest = generate_default(
            GenesisBuilder::new_without_executor(
                ChainId::from("default-global-reader"),
                PathBuf::from("."),
            )
            .complete_for_test(),
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Permissioned,
            None,
            None,
        )
        .expect("generate default genesis");
        assert!(
            grants_global_reader_to(
                &manifest,
                &AccountId::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone()),
            ),
            "the supplied bootstrap operator must receive the immutable global query root"
        );
        let authority = AccountId::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone());
        let grants = account_permission_grants(&manifest);
        assert_eq!(grants.len(), 6);
        assert!(grants.iter().all(|(account, _)| account == &authority));
        assert!(
            !manifest.instructions().any(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .is_some_and(|register| {
                        matches!(
                            register,
                            RegisterBox::Account(_) | RegisterBox::AssetDefinition(_)
                        )
                    })
            }),
            "default genesis must not inject fixture accounts or assets"
        );
        assert_first_release_hijiri_bootstrap(&manifest, "generated default genesis");
    }
    #[test]
    fn checked_in_first_release_source_templates_seed_neutral_hijiri() {
        let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for relative_path in [
            "defaults/genesis.template.json",
            "defaults/kagami/iroha3-dev/genesis.template.json",
            "defaults/kagami/iroha3-nexus/genesis.template.json",
            "defaults/nexus/genesis.template.json",
            "configs/soranexus/nexus/genesis.template.json",
            "configs/soranexus/taira/genesis.template.json",
            "crates/iroha_kagami/tests/fixtures/taira_nevo_v2/unsigned-genesis.template.json",
        ] {
            let path = repository_root.join(relative_path);
            let unbound = RawGenesisTransaction::from_path(&path)
                .expect("bounded source JSON must remain parseable before materialization");
            assert_eq!(unbound.consensus_fingerprint(), None);
            assert!(
                unbound
                    .validate_mode_specific_consensus_parameters()
                    .is_err(),
                "{relative_path} must require its explicit NPoS XOR selection"
            );
            assert!(
                iroha_genesis::GenesisSourceTemplate::from_path(&path)
                    .expect("read the original unbound source template")
                    .materialize(None)
                    .is_err(),
                "{relative_path} must not materialize without its NPoS XOR selection"
            );
            let manifest = load_genesis_source_template_for_test(&repository_root, relative_path);
            assert_first_release_hijiri_bootstrap(&manifest, relative_path);
        }
    }
    #[test]
    fn shipped_first_release_source_templates_name_an_intentional_global_reader() {
        let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for relative_path in [
            "defaults/genesis.template.json",
            "defaults/kagami/iroha3-dev/genesis.template.json",
            "defaults/kagami/iroha3-nexus/genesis.template.json",
            "defaults/nexus/genesis.template.json",
            "configs/soranexus/nexus/genesis.template.json",
            "configs/soranexus/taira/genesis.template.json",
        ] {
            let manifest = load_genesis_source_template_for_test(&repository_root, relative_path);
            let grants = account_permission_grants(&manifest);
            let set_parameters: Vec<_> = grants
                .iter()
                .filter(|(_, permission)| permission == &Permission::from(CanSetParameters))
                .collect();
            assert_eq!(
                set_parameters.len(),
                1,
                "{relative_path} must name exactly one bootstrap parameter operator"
            );
            let set_hijiri_parameters: Vec<_> = grants
                .iter()
                .filter(|(_, permission)| permission == &Permission::from(CanSetHijiriParameters))
                .collect();
            assert_eq!(
                set_hijiri_parameters.len(),
                1,
                "{relative_path} must name exactly one bootstrap Hijiri parameter operator"
            );
            assert_eq!(
                set_hijiri_parameters[0].0, set_parameters[0].0,
                "{relative_path} must preserve the existing parameter operator as the Hijiri bootstrap root"
            );
            let global_readers: Vec<_> = grants
                .iter()
                .filter(|(_, permission)| permission.name() == "CanReadAllLedgerData")
                .collect();
            assert_eq!(
                global_readers.len(),
                1,
                "{relative_path} must name exactly one global reader root"
            );
            assert_eq!(
                global_readers[0].1,
                Permission::from(CanReadAllLedgerData),
                "{relative_path} contains a malformed global reader grant"
            );
            assert_eq!(
                global_readers[0].0, set_parameters[0].0,
                "{relative_path} must grant global reads to its bootstrap parameter operator"
            );
        }
    }
    #[test]
    fn shipped_taira_xor_uses_the_pinned_decimal_scale() {
        let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let manifest = load_genesis_source_template_for_test(
            &repository_root,
            "configs/soranexus/taira/genesis.template.json",
        );
        let asset_definition_id =
            AssetDefinitionId::parse_address_literal(TAIRA_XOR_ASSET_DEFINITION_ID)
                .expect("parse pinned Taira XOR id");
        let spec = manifest.instructions().find_map(|instruction| {
            if let Some(register) = instruction
                .as_any()
                .downcast_ref::<Register<AssetDefinition>>()
                && register.object.id == asset_definition_id
            {
                return Some(register.object.spec);
            }
            if let Some(iroha_data_model::isi::register::RegisterBox::AssetDefinition(register)) =
                instruction
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::register::RegisterBox>()
                && register.object.id == asset_definition_id
            {
                return Some(register.object.spec);
            }
            None
        });

        assert_eq!(
            spec,
            Some(NumericSpec::fractional(TAIRA_XOR_SCALE)),
            "shipped Taira XOR must expose the same decimal scale consumed by wallets"
        );
    }
}
#[allow(clippy::too_many_arguments)]
fn generate_synthetic(
    builder: GenesisBuilder,
    genesis_public_key: &PublicKey,
    ivm_gas_limit_per_block: Option<u64>,
    consensus_mode: SumeragiConsensusMode,
    domains: u64,
    accounts_per_domain: u64,
    asset_definitions_per_domain: u64,
    profile_defaults: Option<&ProfileDefaults>,
    profile_vrf_seed: Option<[u8; 32]>,
) -> color_eyre::Result<RawGenesisTransaction> {
    // Synthetic genesis extends the default one with additional transactions
    // describing synthetic domains and assets.
    let default_genesis = generate_default(
        builder,
        genesis_public_key,
        ivm_gas_limit_per_block,
        consensus_mode,
        profile_defaults,
        profile_vrf_seed,
    )?;
    let mut builder = default_genesis.into_builder().next_transaction();
    for domain in 0..domains {
        let domain_id = DomainId::try_new(format!("domain_{domain}"), "universal")?;
        builder = builder.append_instruction(Register::domain(Domain::new(domain_id.clone())));
        let mut synthetic_asset_definitions = Vec::new();
        for asset_definition in 0..asset_definitions_per_domain {
            let asset_name_literal = format!("asset_{asset_definition}");
            let asset_name: Name = asset_name_literal.parse()?;
            let asset_definition_id =
                AssetDefinitionId::derive_from_components(domain_id.clone(), asset_name);
            synthetic_asset_definitions.push(asset_definition_id.clone());
            builder = builder.append_instruction(Register::asset_definition(AssetDefinition::new(
                asset_definition_id,
                asset_name_literal,
                NumericSpec::default(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )));
        }
        for _ in 0..accounts_per_domain {
            let (account_id, _account_keypair) = gen_account_in(&domain_id);
            builder =
                builder.append_instruction(Register::account(Account::new(account_id.clone())));
            for asset_definition_id in &synthetic_asset_definitions {
                let mint = Mint::asset_quantity(
                    13u32,
                    AssetId::new(asset_definition_id.clone(), account_id.clone()),
                );
                builder = builder.append_instruction(mint);
            }
        }
    }
    let manifest = builder.build_raw()?.with_consensus_mode(consensus_mode);
    Ok(manifest.with_consensus_meta()?)
}
