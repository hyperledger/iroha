//! Canonical operator-owned default genesis manifest construction.
use super::profile::ProfileDefaults;
use iroha_crypto::PublicKey;
use iroha_data_model::{
    hijiri::HijiriParametersV1,
    parameter::{
        Parameter, Parameters,
        custom::{CustomParameter, CustomParameterId},
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    },
    prelude::*,
};
use iroha_executor_data_model::permission::{
    account::CanRegisterAccount,
    parameter::{CanSetHijiriParameters, CanSetParameters},
    query::CanReadAllLedgerData,
};
use iroha_genesis::{GenesisBuilder, RawGenesisTransaction};
use iroha_model_base::domain::DomainId;
use iroha_primitives::json::Json;
/// Consensus restrictions selected by a generated dataspace profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusPolicy {
    /// Allow either permissioned or `NPoS` consensus.
    Any,
    /// Require `NPoS` (public dataspace rule).
    PublicDataspace,
}
/// Enforce the profile consensus restriction before creating artifacts.
///
/// # Errors
/// Returns an error when a public dataspace selects a consensus mode other than `NPoS`.
pub fn validate_consensus_mode(
    consensus_mode: SumeragiConsensusMode,
    policy: ConsensusPolicy,
) -> color_eyre::Result<()> {
    if matches!(policy, ConsensusPolicy::PublicDataspace)
        && consensus_mode != SumeragiConsensusMode::Npos
    {
        return Err(color_eyre::eyre::eyre!(
            "public dataspace requires `--consensus-mode npos` (permissioned is private-only)"
        ));
    }
    Ok(())
}
/// Build the canonical operator-owned genesis with explicit authority and consensus parameters.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
///
/// # Errors
/// Returns an error for invalid bootstrap identifiers, missing `NPoS` seed, invalid consensus parameters, or failed genesis construction.
pub fn generate_default(
    builder: GenesisBuilder,
    genesis_public_key: &PublicKey,
    ivm_gas_limit_per_block: Option<u64>,
    consensus_mode: SumeragiConsensusMode,
    profile_defaults: Option<&ProfileDefaults>,
    profile_vrf_seed: Option<[u8; 32]>,
) -> color_eyre::Result<RawGenesisTransaction> {
    let genesis_account_id = AccountId::new(genesis_public_key.clone());
    // Default genesis contains only operator-owned bootstrap state. Public test
    // identities and sample assets belong in explicitly synthetic fixtures.
    let bootstrap_domain = DomainId::parse_fully_qualified("universal.universal")?;
    let mut builder = builder.domain(bootstrap_domain.clone()).finish_domain();
    let bootstrap_permissions = [
        Permission::from(CanSetParameters),
        Permission::from(CanSetHijiriParameters),
        Permission::from(CanReadAllLedgerData),
        Permission::new("CanManageSoracloud".into(), Json::new(())),
        Permission::new("CanManageVerifyingKeys".into(), Json::new(())),
        Permission::from(CanRegisterAccount {
            domain: bootstrap_domain,
        }),
    ];
    let mut parameters = Parameters::default();
    parameters.set_parameter(Parameter::Custom(
        HijiriParametersV1::first_release_genesis().into_custom_parameter(),
    ));
    if let Some(defaults) = profile_defaults {
        builder = builder.with_block_cadence_ms(defaults.block_cadence_ms);
    }
    let active_npos = matches!(consensus_mode, SumeragiConsensusMode::Npos);
    if active_npos {
        let seed = profile_vrf_seed.ok_or_else(|| {
            color_eyre::eyre::eyre!("NPoS genesis requires an explicit or profile-derived VRF seed")
        })?;
        let mut defaults = SumeragiNposParameters::default().with_epoch_seed(seed);
        defaults.epoch_length_blocks = parameters.sumeragi().epoch_length_blocks;
        defaults
            .validate()
            .map_err(|error| color_eyre::eyre::eyre!(error))?;
        parameters.set_parameter(Parameter::Custom(defaults.into()));
    }
    // Pin block-level gas limit for IVM across peers via a custom parameter.
    // Name: "ivm_gas_limit_per_block", payload: JSON u64 (1_680_000)
    let gas_param_id = CustomParameterId::new("ivm_gas_limit_per_block".parse()?);
    let gas_param_val = ivm_gas_limit_per_block.unwrap_or(1_680_000u64);
    let gas_param = CustomParameter::new(gas_param_id, Json::new(gas_param_val));
    for parameter in parameters.parameters() {
        builder = builder.append_parameter(parameter);
    }
    // Persist overrides via structured parameters so manifests stay canonical.
    builder = builder.append_parameter(Parameter::Custom(gas_param));
    // The daemon pre-seeds this explicit genesis authority. Grant privileges
    // only after the domain registration, without registering a second owner.
    builder = builder.next_transaction();
    for permission in bootstrap_permissions {
        builder = builder.append_instruction(Grant::account_permission(
            permission,
            genesis_account_id.clone(),
        ));
    }
    // Enrich with consensus metadata and fingerprint for operator visibility.
    let manifest = builder
        .build_raw()?
        .with_consensus_mode(consensus_mode)
        .with_consensus_meta()?;
    manifest.validate_mode_specific_consensus_parameters()?;
    Ok(manifest)
}
