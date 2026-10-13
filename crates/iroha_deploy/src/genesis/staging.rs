//! Actual core execution used to bind and authenticate generated genesis artifacts.
use super::profile::{PUBLIC_XOR_ALIAS, public_xor_profile_for_chain_id};
use color_eyre::eyre::{WrapErr, eyre};
use iroha_config::parameters::{actual, defaults};
use iroha_core::{
    block::ValidBlock,
    compliance::LaneComplianceEngine,
    governance::manifest::LaneManifestRegistry,
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::isi::Registrable as _,
    state::{State, World, WorldReadOnly as _},
    sumeragi::network_topology::Topology,
};
use iroha_crypto::{Hash, KeyPair};
use iroha_data_model::{
    account::address::{AccountAddress, ChainDiscriminantGuard},
    asset::AssetDefinitionAlias,
    da::commitment::DaProofPolicyBundle,
    parameter::system::{ConsensusMode, SumeragiConsensusMode},
    prelude::*,
};
use iroha_genesis::{GenesisBlock, RawGenesisTransaction};
use iroha_model_base::domain::DomainId;
use iroha_primitives::time::TimeSource;
use std::{path::PathBuf, sync::Arc};
const RETIRED_SYNTHETIC_STAKE_DOMAIN: &str = "nexus.universal";
const RETIRED_SYNTHETIC_STAKE_ASSET_NAME: &str = "xor";
struct StagedGenesisProjection<T> {
    execution: StagedGenesisExecution,
    projection: T,
}
/// Exact local execution result used to bind or reverify a signed genesis artifact.
/// This preparation result is not authority for a committed chain state.
pub struct StagedGenesisExecution {
    /// Nexus and atomic-execution policy commitment derived by Core.
    pub nexus_amx_context_hash: Hash,
    /// Exact canonical preimage of [`Self::nexus_amx_context_hash`], published beside the
    /// signed genesis so light clients can decode the genesis-declared Nexus catalog.
    pub nexus_amx_context_preimage: Vec<u8>,
    /// Execution-policy commitment derived by Core.
    pub execution_policy_hash: Hash,
    /// Executed signed genesis with its authentic output commitments.
    pub executed_block: SignedBlock,
}
/// Identify the retired synthetic stake definition so real bootstrap rejects it.
pub fn retired_synthetic_stake_asset_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::parse_fully_qualified(RETIRED_SYNTHETIC_STAKE_DOMAIN)
            .expect("static stake asset domain must remain valid"),
        RETIRED_SYNTHETIC_STAKE_ASSET_NAME
            .parse()
            .expect("static stake asset name must remain valid"),
    )
}
fn resolve_npos_bootstrap_stake_asset_id(
    manifest: &RawGenesisTransaction,
    configured: &str,
) -> Result<AssetDefinitionId, color_eyre::eyre::Error> {
    if let Ok(asset_id) = configured.parse::<AssetDefinitionId>() {
        return Ok(asset_id);
    }
    let alias = configured.parse::<AssetDefinitionAlias>().map_err(|err| {
        eyre!(
            "invalid nexus.staking.stake_asset_id `{configured}`: {err}; expected canonical asset definition id or alias"
        )
    })?;
    let Some(asset_definition_id) = resolve_asset_definition_alias(manifest, &alias)? else {
        return Err(eyre!(
            "nexus.staking.stake_asset_id alias `{configured}` is not bound in genesis manifest"
        ));
    };
    Ok(asset_definition_id)
}
fn resolve_asset_definition_alias(
    manifest: &RawGenesisTransaction,
    alias: &AssetDefinitionAlias,
) -> Result<Option<AssetDefinitionId>, color_eyre::eyre::Error> {
    let mut target = None;
    for instruction in manifest.instructions() {
        if let Some(bind) = instruction
            .as_any()
            .downcast_ref::<iroha_data_model::isi::asset_alias::SetAssetDefinitionAlias>(
        ) && bind.alias.as_ref() == Some(alias)
        {
            if let Some(existing) = &target
                && existing != &bind.asset_definition_id
            {
                return Err(eyre!(
                    "asset definition alias `{alias}` is bound to multiple asset definitions"
                ));
            }
            target = Some(bind.asset_definition_id.clone());
        }
    }
    Ok(target)
}
fn public_xor_profile_for_manifest(
    manifest: &RawGenesisTransaction,
) -> Option<super::profile::GenesisProfile> {
    public_xor_profile_for_chain_id(manifest.chain_id().as_str())
}
/// Resolve and verify the committed canonical XOR definition against the exact configuration.
pub fn configured_npos_bootstrap_stake_asset_id(
    manifest: &RawGenesisTransaction,
    config: Option<&actual::Root>,
) -> Result<AssetDefinitionId, color_eyre::eyre::Error> {
    let public_profile = public_xor_profile_for_manifest(manifest);
    let parameters = manifest.effective_parameters()?;
    let pinned = parameters
        .custom()
        .get(&iroha_data_model::parameter::system::SumeragiNposParameters::parameter_id())
        .map(iroha_data_model::parameter::system::SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .ok_or_else(|| eyre!("NPoS bootstrap requires the committed XOR asset identity"))?
        .xor_asset_definition_id;
    let stake_asset_id = if let Some(config) = config {
        resolve_npos_bootstrap_stake_asset_id(manifest, &config.nexus.staking.stake_asset_id)
            .map_err(|err| eyre!("failed to resolve nexus.staking.stake_asset_id: {err}"))?
    } else {
        pinned.clone()
    };
    if stake_asset_id != pinned || stake_asset_id == retired_synthetic_stake_asset_id() {
        return Err(eyre!(
            "NPoS stake asset must equal the committed canonical XOR definition `{pinned}`; synthetic stake assets are forbidden"
        ));
    }
    if let Some(profile) = public_profile {
        let public_xor_alias: AssetDefinitionAlias = PUBLIC_XOR_ALIAS.parse()?;
        let public_xor_asset_id =
            resolve_asset_definition_alias(manifest, &public_xor_alias)?.ok_or_else(|| {
                eyre!(
                    "public NPoS bootstrap for {profile:?} requires `{PUBLIC_XOR_ALIAS}` to be bound to a canonical XOR asset in genesis"
                )
            })?;
        if profile == super::profile::GenesisProfile::Iroha3Taira
            && public_xor_asset_id.to_string() != super::profile::TAIRA_XOR_ASSET_DEFINITION_ID
        {
            return Err(eyre!(
                "public Taira NPoS bootstrap requires `{PUBLIC_XOR_ALIAS}` to bind to `{}`; found `{public_xor_asset_id}`",
                super::profile::TAIRA_XOR_ASSET_DEFINITION_ID
            ));
        }
        if profile == super::profile::GenesisProfile::Iroha3Nexus
            && public_xor_asset_id.to_string() == super::profile::TAIRA_XOR_ASSET_DEFINITION_ID
        {
            return Err(eyre!(
                "public Nexus cannot substitute the Taira XOR definition for its operator-provisioned mainnet asset"
            ));
        }
        if public_xor_asset_id == retired_synthetic_stake_asset_id() {
            return Err(eyre!(
                "public NPoS bootstrap for {profile:?} cannot use synthetic `{RETIRED_SYNTHETIC_STAKE_DOMAIN}/{RETIRED_SYNTHETIC_STAKE_ASSET_NAME}`; bind `{PUBLIC_XOR_ALIAS}` to the real XOR asset or configure a canonical stake asset id"
            ));
        }
        if stake_asset_id != public_xor_asset_id {
            return Err(eyre!(
                "public NPoS bootstrap for {profile:?} resolved stake asset `{stake_asset_id}`, but `{PUBLIC_XOR_ALIAS}` is bound to `{public_xor_asset_id}`; public stake asset must match the canonical XOR binding"
            ));
        }
    }
    Ok(stake_asset_id)
}
/// Reject a peer configuration with another manifest chain or address discriminant.
pub fn ensure_peer_config_matches_manifest(
    config: &actual::Root,
    manifest: &RawGenesisTransaction,
) -> Result<(), color_eyre::eyre::Error> {
    if config.common.chain != *manifest.chain_id() {
        return Err(eyre!(
            "peer config chain `{}` does not match genesis manifest chain `{}`",
            config.common.chain,
            manifest.chain_id()
        ));
    }
    let configured_discriminant = *config.common.chain_discriminant.value();
    if configured_discriminant != manifest.chain_discriminant() {
        return Err(eyre!(
            "peer config chain discriminant {configured_discriminant} does not match genesis manifest chain discriminant {}",
            manifest.chain_discriminant()
        ));
    }
    Ok(())
}
/// Build the canonical signed genesis proposal with explicit proof and confidentiality policies.
pub fn build_signed_genesis(
    genesis: RawGenesisTransaction,
    genesis_key_pair: &KeyPair,
    da_proof_policies: Option<DaProofPolicyBundle>,
    confidential_policy_hash: [u8; 32],
    creation_time_ms: Option<u64>,
) -> Result<GenesisBlock, color_eyre::eyre::Error> {
    match creation_time_ms {
        Some(creation_time_ms) => genesis
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                genesis_key_pair,
                da_proof_policies,
                Some(confidential_policy_hash),
                creation_time_ms,
            ),
        None => genesis.build_and_sign_with_da_proof_policies_and_confidential_policy_hash(
            genesis_key_pair,
            da_proof_policies,
            Some(confidential_policy_hash),
        ),
    }
}
/// Bind the staged consensus context and sign the exact resulting manifest.
///
/// Callers which publish both the manifest and signed block must persist the
/// returned manifest so prepared-bundle admission can compare every
/// instruction, including the derived consensus commitment.
pub fn bind_and_sign_staged_sumeragi_context(
    genesis: RawGenesisTransaction,
    genesis_key_pair: &KeyPair,
    config: Option<&actual::Root>,
    da_proof_policies: Option<DaProofPolicyBundle>,
    confidential_policy_hash: [u8; 32],
    creation_time_ms: Option<u64>,
) -> Result<(RawGenesisTransaction, GenesisBlock), color_eyre::eyre::Error> {
    bind_and_sign_staged_sumeragi_context_with_preimage(
        genesis,
        genesis_key_pair,
        config,
        da_proof_policies,
        confidential_policy_hash,
        creation_time_ms,
    )
    .map(|(manifest, block, _)| (manifest, block))
}
/// [`bind_and_sign_staged_sumeragi_context`], also returning the exact Nexus/AMX context
/// preimage whose hash the final signed genesis commits.
pub fn bind_and_sign_staged_sumeragi_context_with_preimage(
    genesis: RawGenesisTransaction,
    genesis_key_pair: &KeyPair,
    config: Option<&actual::Root>,
    da_proof_policies: Option<DaProofPolicyBundle>,
    confidential_policy_hash: [u8; 32],
    creation_time_ms: Option<u64>,
) -> Result<(RawGenesisTransaction, GenesisBlock, Vec<u8>), color_eyre::eyre::Error> {
    let mut parameters = genesis.sumeragi_context_parameters();
    let (nexus_amx_context_hash, execution_policy_hash) = staged_sumeragi_context_hashes(
        &genesis,
        genesis_key_pair,
        config,
        da_proof_policies.as_ref(),
        confidential_policy_hash,
        creation_time_ms,
    )?;
    parameters.nexus_amx_context_hash = nexus_amx_context_hash.into();
    parameters.execution_policy_hash = execution_policy_hash.into();
    let bound_manifest = genesis
        .with_sumeragi_context_parameters(parameters)
        .with_consensus_meta()?;
    let proposal = build_signed_genesis(
        bound_manifest.clone(),
        genesis_key_pair,
        da_proof_policies,
        confidential_policy_hash,
        creation_time_ms,
    )?;
    let StagedGenesisExecution {
        mut executed_block,
        nexus_amx_context_preimage,
        ..
    } = verify_final_signed_sumeragi_context(
        &bound_manifest,
        config,
        &proposal.0,
        nexus_amx_context_hash,
        execution_policy_hash,
    )?;
    let signature = BlockSignature::new(
        0,
        iroha_crypto::SignatureOf::try_from_hash(
            genesis_key_pair.private_key(),
            executed_block.hash(),
        )
        .wrap_err("sign fully executed genesis block")?,
    );
    executed_block
        .replace_signatures(iroha_data_model::block::BlockSignatures::try_from_iter([
            signature,
        ])?)
        .wrap_err("replace provisional genesis signature after execution")?;
    Ok((
        bound_manifest,
        GenesisBlock(executed_block),
        nexus_amx_context_preimage,
    ))
}
/// Reexecute the final signed identity and require the exact expected consensus policy hashes.
///
/// # Errors
/// Returns the concrete Core validation failure or an exact policy-commitment mismatch.
pub fn verify_final_signed_sumeragi_context(
    bound_manifest: &RawGenesisTransaction,
    config: Option<&actual::Root>,
    signed: &SignedBlock,
    signed_nexus_amx_context_hash: Hash,
    signed_execution_policy_hash: Hash,
) -> Result<StagedGenesisExecution, color_eyre::eyre::Error> {
    let staged = restage_signed_sumeragi_context_hashes(bound_manifest, config, signed)?;
    if staged.nexus_amx_context_hash != signed_nexus_amx_context_hash {
        return Err(eyre!(
            "final-NetworkId genesis restaging changed the signed Nexus/AMX context: signed {signed_nexus_amx_context_hash}, restaged {}",
            staged.nexus_amx_context_hash,
        ));
    }
    if staged.execution_policy_hash != signed_execution_policy_hash {
        return Err(eyre!(
            "final-NetworkId genesis restaging changed the signed execution policy: signed {signed_execution_policy_hash}, restaged {}",
            staged.execution_policy_hash,
        ));
    }
    Ok(staged)
}
/// Stage a raw genesis transaction and return its exact Nexus/AMX consensus and execution-policy
/// commitments without committing state or touching persistent node storage.
fn staged_sumeragi_context_hashes(
    genesis: &RawGenesisTransaction,
    genesis_key_pair: &KeyPair,
    config: Option<&actual::Root>,
    da_proof_policies: Option<&DaProofPolicyBundle>,
    confidential_policy_hash: [u8; 32],
    creation_time_ms: Option<u64>,
) -> Result<(iroha_crypto::Hash, iroha_crypto::Hash), color_eyre::eyre::Error> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("iroha-genesis-staging".to_owned())
            .stack_size(16 * 1024 * 1024)
            .spawn_scoped(scope, move || {
                staged_sumeragi_context_hashes_on_bounded_stack(
                    genesis,
                    genesis_key_pair,
                    config,
                    da_proof_policies,
                    confidential_policy_hash,
                    creation_time_ms,
                )
            })
            .wrap_err("spawn bounded genesis staging thread")?
            .join()
            .map_err(|_| eyre!("bounded genesis staging thread panicked"))?
    })
}
/// Re-stage an already authenticated signed genesis body against one effective
/// validator configuration.
///
/// Prepared-bundle admission uses this path so every runtime config must
/// reproduce the exact Nexus/AMX and execution-policy commitments signed into
/// genesis without requiring or reloading the retired genesis private key.
pub fn staged_signed_sumeragi_context_hashes(
    genesis: &RawGenesisTransaction,
    signed: &SignedBlock,
    config: &actual::Root,
) -> Result<(iroha_crypto::Hash, iroha_crypto::Hash), color_eyre::eyre::Error> {
    let staged = restage_signed_sumeragi_context_hashes(genesis, Some(config), signed)?;
    Ok((staged.nexus_amx_context_hash, staged.execution_policy_hash))
}
/// Original signed genesis and its exact native lane state produced by actual staging.
/// This receipt grants no signing capability and contains no retired lane catalog authority.
#[derive(Debug)]
pub struct StagedNativeGenesis {
    genesis: SignedBlock,
    epoch: iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1,
    lane_policy: Option<iroha_data_model::sumeragi_lanes::SumeragiLanePolicy>,
    lanes: iroha_data_model::sumeragi_lanes::SumeragiLaneState,
}
impl StagedNativeGenesis {
    /// Original authenticated signed genesis.
    pub fn genesis(&self) -> &SignedBlock {
        &self.genesis
    }
    /// Validator epoch authenticated by that original genesis.
    pub fn epoch(&self) -> &iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1 {
        &self.epoch
    }
    /// Committed lane policy produced by original genesis execution.
    pub fn lane_policy(&self) -> Option<&iroha_data_model::sumeragi_lanes::SumeragiLanePolicy> {
        self.lane_policy.as_ref()
    }
    /// Exact lane state produced by original genesis execution.
    pub fn lanes(&self) -> &iroha_data_model::sumeragi_lanes::SumeragiLaneState {
        &self.lanes
    }
}

/// Authenticate and execute the exact signed bundle with its independently retained config.
pub fn staged_signed_native_genesis(
    genesis: &RawGenesisTransaction,
    signed_wire: &[u8],
    config: &actual::Root,
) -> Result<StagedNativeGenesis, color_eyre::eyre::Error> {
    staged_signed_native_genesis_with_projection(genesis, signed_wire, config, |_, _| Ok(()))
        .map(|(authority, ())| authority)
}

/// Project owned values from the same actual staged StateBlock as the native lane receipt.
/// The caller cannot provide a replacement epoch, context, policy or poststate.
pub fn staged_signed_native_genesis_with_projection<T: Send>(
    genesis: &RawGenesisTransaction,
    signed_wire: &[u8],
    config: &actual::Root,
    project: impl FnOnce(
        &GenesisBlock,
        &iroha_core::state::StateBlock<'_>,
    ) -> Result<T, color_eyre::eyre::Error>
    + Send,
) -> Result<(StagedNativeGenesis, T), color_eyre::eyre::Error> {
    ensure_peer_config_matches_manifest(config, genesis)?;
    let validated = iroha_genesis::validate_prepared_genesis_bundle(
        signed_wire,
        genesis,
        &config.genesis.public_key,
        config.genesis.expected_hash,
    )
    .wrap_err("authenticate original signed native genesis")?;
    iroha_core::validate_genesis_block(
        validated.block(),
        &AccountId::new(validated.public_key().clone()),
    )
    .map_err(|error| eyre!("original genesis failed full core validation: {error}"))?;
    let authenticated = GenesisBlock(validated.block().clone());
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("iroha-native-genesis-state".to_owned())
            .stack_size(16 * 1024 * 1024)
            .spawn_scoped(scope, move || {
                let staged = staged_genesis_with_projection_on_bounded_stack(
                    genesis,
                    Some(config),
                    GenesisBlock(authenticated.0.clone()),
                    |staged| {
                        let epoch = iroha_data_model::sumeragi_finality::authenticated_genesis(
                            &authenticated.0,
                        )
                        .map(|genesis| genesis.into_parts().0)
                        .map_err(|error| eyre!(error))?;
                        let authority = StagedNativeGenesis {
                            genesis: authenticated.0.clone(),
                            epoch,
                            lane_policy: iroha_core::sumeragi::lanes::lane_policy(staged.world())
                                .wrap_err("read committed staged genesis lane policy")?,
                            lanes: staged.world().sumeragi_lanes().clone(),
                        };
                        let projection = project(&authenticated, staged)?;
                        Ok((authority, projection))
                    },
                )?;
                if staged.execution.executed_block.hash() != authenticated.0.hash() {
                    return Err(eyre!(
                        "original authenticated genesis changed during exact restaging"
                    ));
                }
                Ok(staged.projection)
            })
            .wrap_err("spawn bounded native genesis staging thread")?
            .join()
            .map_err(|_| eyre!("bounded native genesis staging thread panicked"))?
    })
}
/// Reexecute a signed genesis using its exact configuration, or canonical defaults when absent.
///
/// # Errors
/// Returns configuration, signature, execution or output-commitment validation failures.
pub fn restage_signed_sumeragi_context_hashes(
    genesis: &RawGenesisTransaction,
    config: Option<&actual::Root>,
    signed: &SignedBlock,
) -> Result<StagedGenesisExecution, color_eyre::eyre::Error> {
    let provisional = GenesisBlock(signed.clone());
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("iroha-prepared-genesis-staging".to_owned())
            .stack_size(16 * 1024 * 1024)
            .spawn_scoped(scope, move || {
                staged_sumeragi_context_hashes_from_provisional_on_bounded_stack(
                    genesis,
                    config,
                    provisional,
                )
            })
            .wrap_err("spawn bounded prepared-genesis staging thread")?
            .join()
            .map_err(|_| eyre!("bounded prepared-genesis staging thread panicked"))?
    })
}
fn staged_sumeragi_context_hashes_on_bounded_stack(
    genesis: &RawGenesisTransaction,
    genesis_key_pair: &KeyPair,
    config: Option<&actual::Root>,
    da_proof_policies: Option<&DaProofPolicyBundle>,
    confidential_policy_hash: [u8; 32],
    creation_time_ms: Option<u64>,
) -> Result<(iroha_crypto::Hash, iroha_crypto::Hash), color_eyre::eyre::Error> {
    // This worker is a new thread, so it does not inherit the caller's
    // thread-local I105 discriminant.
    let _chain_discriminant = staged_genesis_chain_discriminant(genesis);
    let provisional = build_signed_genesis(
        genesis.clone().with_consensus_meta()?,
        genesis_key_pair,
        da_proof_policies.cloned(),
        confidential_policy_hash,
        creation_time_ms,
    )?;
    match staged_sumeragi_context_hashes_from_provisional_on_bounded_stack(
        genesis,
        config,
        provisional,
    ) {
        Ok(staged) => Ok((staged.nexus_amx_context_hash, staged.execution_policy_hash)),
        // Staging preserves the concrete validation error through its report context.
        Err(error) => match error.downcast_ref::<iroha_core::block::BlockValidationError>() {
            Some(iroha_core::block::BlockValidationError::GenesisPolicyMismatch {
                actual_execution,
                actual_nexus,
                ..
            }) => {
                // Only the unpublished signing draft consumes the sole validator's exact
                // derived hashes. The newly signed final bundle must pass that validator
                // unchanged before it can be returned or published.
                Ok((*actual_nexus, *actual_execution))
            }
            _ => Err(error),
        },
    }
}
fn staged_sumeragi_context_hashes_from_provisional_on_bounded_stack(
    genesis: &RawGenesisTransaction,
    config: Option<&actual::Root>,
    provisional: GenesisBlock,
) -> Result<StagedGenesisExecution, color_eyre::eyre::Error> {
    staged_genesis_with_projection_on_bounded_stack(genesis, config, provisional, |_| Ok(()))
        .map(|staged| staged.execution)
}
fn staged_genesis_with_projection_on_bounded_stack<T>(
    genesis: &RawGenesisTransaction,
    config: Option<&actual::Root>,
    provisional: GenesisBlock,
    project: impl FnOnce(&iroha_core::state::StateBlock<'_>) -> Result<T, color_eyre::eyre::Error>,
) -> Result<StagedGenesisProjection<T>, color_eyre::eyre::Error> {
    let _chain_discriminant = staged_genesis_chain_discriminant(genesis);
    let signed_metadata = iroha_genesis::signed_genesis_consensus_metadata(&provisional.0)
        .wrap_err("read signed genesis consensus context before staging")?;
    if signed_metadata.mode != genesis.consensus_mode() {
        return Err(eyre!(
            "genesis manifest consensus mode differs from signed metadata"
        ));
    }
    let consensus_mode = match signed_metadata.mode {
        SumeragiConsensusMode::Permissioned => ConsensusMode::Permissioned,
        SumeragiConsensusMode::Npos => ConsensusMode::Npos,
    };
    let root_scope = signed_metadata.sumeragi_context.root_scope;
    let (state, _, authority) = configured_initial_genesis_state(genesis, config, &provisional)?;
    let voters = iroha_core::sumeragi::schedule::genesis_validators(&provisional)
        .map_err(|error| eyre!("invalid signed Sumeragi genesis roster: {error}"))?;
    if voters.is_empty() {
        return Err(eyre!(
            "Sumeragi genesis roster is empty; inject BLS topology entries and PoPs before signing"
        ));
    }
    let topology = Topology::new(voters.into_keys());
    let (valid, staged) = ValidBlock::validate_signed_genesis(
        provisional.0,
        &topology,
        &authority,
        &TimeSource::new_system(),
        &state,
        consensus_mode,
        root_scope,
    )
    .unpack(|_| {})
    .map_err(|(block, error)| {
        // Preserve the validator's concrete error through the report context. Only the
        // unpublished signing draft may consume its exact derived policy commitments.
        let error = *error;
        let transaction_errors = block
            .execution_outputs()
            .iter()
            .enumerate()
            .filter_map(|(output_index, output)| {
                use iroha_data_model::block::execution_output::ExecutionOutputV1;
                let reason = output.result().as_ref().err()?;
                let source = match output {
                    ExecutionOutputV1::Network(row) => format!("transaction[{}]", row.input_index),
                    ExecutionOutputV1::Pipeline(_) => format!("pipeline output[{output_index}]"),
                    ExecutionOutputV1::Time(_) => format!("time output[{output_index}]"),
                };
                Some(format!("{source}: {reason:?}"))
            })
            .collect::<Vec<_>>();
        if transaction_errors.is_empty() {
            color_eyre::Report::new(error).wrap_err(format!(
                "staged genesis execution failed ({} network inputs)",
                block.network_entrypoint_count()
            ))
        } else {
            color_eyre::Report::new(error).wrap_err(format!(
                "staged genesis execution failed; {}",
                transaction_errors.join("; ")
            ))
        }
    })?;
    let nexus_amx_context_preimage =
        iroha_core::sumeragi::staged_genesis_nexus_amx_context_preimage(&staged);
    let nexus_amx_context_hash = Hash::new(&nexus_amx_context_preimage);
    let execution_policy_hash = iroha_core::sumeragi::staged_genesis_execution_policy_hash(&staged)
        .map_err(|error| eyre!("derive staged genesis execution policy: {error}"))?;
    let projection = project(&staged)?;
    drop(staged);
    Ok(StagedGenesisProjection {
        execution: StagedGenesisExecution {
            nexus_amx_context_hash,
            nexus_amx_context_preimage,
            execution_policy_hash,
            executed_block: valid.into(),
        },
        projection,
    })
}
/// Build the original fresh-node State once, before any genesis instruction executes.
/// Both normal staging and the genuine native execution fixture use this configuration owner.
pub fn configured_initial_genesis_state(
    genesis: &RawGenesisTransaction,
    config: Option<&actual::Root>,
    provisional: &GenesisBlock,
) -> Result<(State, Arc<Kura>, AccountId), color_eyre::eyre::Error> {
    // Never inherit iroha_core's repository-wide test identity here. Signing stages the
    // unbound provisional block, while prepared-bundle admission stages the final signed block.
    // Generation-zero Nexus state is intentionally independent of this value, so both paths
    // reproduce the same signed commitments without requiring a genesis-hash fixed point.
    let staging_network_id = NetworkId::from_genesis_hash(provisional.0.hash());
    let authority = provisional
        .0
        .external_transactions()
        .next()
        .and_then(|transaction| transaction.authority().try_signatory())
        .cloned()
        .map(AccountId::new)
        .ok_or_else(|| {
            eyre!("prepared genesis authority must be one canonical single-key account")
        })?;
    // World storage and its State must retain this same original pool; equal limits
    // on a second pool cannot authorize the World's prepaid table acquisition.
    let execution_budget = iroha_core::state::AllocationBudget::new(
        config.map_or(defaults::pipeline::IVM_EXECUTION_MAX_BYTES, |config| {
            config.pipeline.ivm_execution_max_bytes
        }),
    );
    let mut world = World::try_with_execution_budget(
        [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&authority)],
        [Account::new(authority.clone()).build(&authority)],
        [],
        &execution_budget,
    )
    .wrap_err("initialize original World storage for staged genesis")?;
    let nexus = match config {
        Some(config) => config.nexus.clone(),
        None => staged_default_nexus(genesis)?,
    };
    // Match fresh-node and `iroha3d --check-config` semantics exactly: genesis aliases are
    // pre-seeded before the block executes so declarative EnsureAlias instructions repair
    // derived state without charging or depending on policy activation order.
    iroha_core::sns::seed_genesis_alias_bootstrap(
        &mut world,
        &provisional.0,
        &nexus.dataspace_catalog,
    )
    .map_err(|error| eyre!("initialize authenticated genesis SNS policies: {error}"))?;
    // Even the generic default profile needs an authenticated configured catalog.
    // A blank test Kura has no production network/geometry binding to restore.
    let kura_config = config.map_or_else(staged_default_kura, |config| config.kura.clone());
    let kura = Kura::new_temporary_with_configured_lane_catalog(
        &kura_config,
        &nexus.lane_config,
        &nexus.configured_lane_catalog,
    )
    .map_err(|error| eyre!("initialize isolated Kura for staged genesis: {error}"))?;
    let mut state = State::try_new_with_chain_and_network_id_with_default_telemetry(
        execution_budget,
        world,
        Arc::clone(&kura),
        LiveQueryStore::start_test(),
        genesis.chain_id().clone(),
        staging_network_id,
    )
    .map_err(|error| eyre!("initialize isolated State for staged genesis: {error}"))?;
    configure_staged_genesis_state(&mut state, genesis, config, nexus)?;
    Ok((state, kura, authority))
}

/// Scope literal parsing and rendering to the manifest address discriminant.
pub fn staged_genesis_chain_discriminant(
    genesis: &RawGenesisTransaction,
) -> ChainDiscriminantGuard {
    ChainDiscriminantGuard::enter(genesis.chain_discriminant())
}
/// Materialize and validate active lane governance coverage for genesis staging.
pub fn staged_lane_manifest_registry(
    genesis: &RawGenesisTransaction,
    nexus: &actual::Nexus,
) -> Result<LaneManifestRegistry, color_eyre::eyre::Error> {
    // Genesis construction can enter additional I105 scopes. Reassert the manifest
    // discriminant at the exact filesystem-parse boundary so validator accounts
    // cannot fall back to the process-global SORA prefix.
    let _chain_discriminant = staged_genesis_chain_discriminant(genesis);
    let registry =
        LaneManifestRegistry::from_config(&nexus.lane_catalog, &nexus.governance, &nexus.registry);
    registry
        .validate_active_coverage_for_catalog(&nexus.lane_catalog)
        .map_err(|error| eyre!("invalid lane manifest registry for staged genesis: {error}"))?;
    Ok(registry)
}
fn staged_genesis_pipeline(mut pipeline: actual::Pipeline) -> actual::Pipeline {
    // Keep offline genesis execution on the guarded staging worker so nested
    // account parsing cannot fall back to the process-global discriminant.
    pipeline.workers = 1;
    pipeline
}
/// Render a built-in account for the exact staged chain discriminant.
pub fn staged_default_account_literal(
    literal: &str,
    target_discriminant: u16,
    label: &'static str,
) -> Result<String, color_eyre::eyre::Error> {
    let address = AccountAddress::from_i105_for_discriminant(
        literal,
        Some(defaults::common::chain_discriminant()),
    )
    .map_err(|error| eyre!("invalid built-in {label}: {error}"))?;
    address
        .to_i105_for_discriminant(target_discriminant)
        .map_err(|error| eyre!("re-encode built-in {label} for staged genesis: {error}"))
}
/// Resolve generic node defaults against the manifest canonical public asset binding.
pub fn staged_default_nexus(
    genesis: &RawGenesisTransaction,
) -> Result<actual::Nexus, color_eyre::eyre::Error> {
    let discriminant = genesis.chain_discriminant();
    let mut nexus = actual::Nexus::default();
    if public_xor_profile_for_manifest(genesis).is_some() {
        // The public bootstrap and the State that executes it must select the same
        // signed XOR binding and immutable NPoS asset identity.
        let public_xor = configured_npos_bootstrap_stake_asset_id(genesis, None)?.to_string();
        nexus.staking.stake_asset_id = public_xor.clone();
        nexus.fees.fee_asset_id = public_xor;
    }
    nexus.staking.stake_escrow_account_id = staged_default_account_literal(
        &nexus.staking.stake_escrow_account_id,
        discriminant,
        "nexus.staking.stake_escrow_account_id",
    )?;
    nexus.staking.slash_sink_account_id = staged_default_account_literal(
        &nexus.staking.slash_sink_account_id,
        discriminant,
        "nexus.staking.slash_sink_account_id",
    )?;
    nexus.fees.fee_sink_account_id = staged_default_account_literal(
        &nexus.fees.fee_sink_account_id,
        discriminant,
        "nexus.fees.fee_sink_account_id",
    )?;
    if let Some(authority) = nexus.relay_worker.authority_account_id.as_mut() {
        *authority = staged_default_account_literal(
            authority,
            discriminant,
            "nexus.relay_worker.authority_account_id",
        )?;
    }
    if genesis.consensus_mode() == SumeragiConsensusMode::Npos {
        // Bootstrap and the offline execution that authenticates it must use
        // the same manifest-selected asset, including public XOR alias bindings.
        let xor_asset = configured_npos_bootstrap_stake_asset_id(genesis, None)?.to_string();
        nexus.staking.stake_asset_id = xor_asset.clone();
        nexus.fees.fee_asset_id = xor_asset;
    }
    Ok(nexus)
}
/// Resolve generic pipeline defaults for deterministic single-worker genesis staging.
pub fn staged_default_pipeline(
    genesis: &RawGenesisTransaction,
) -> Result<actual::Pipeline, color_eyre::eyre::Error> {
    let mut pipeline = actual::Pipeline::default();
    pipeline.gas.tech_account_id = staged_default_account_literal(
        &pipeline.gas.tech_account_id,
        genesis.chain_discriminant(),
        "pipeline.gas.tech_account_id",
    )?;
    Ok(staged_genesis_pipeline(pipeline))
}
fn staged_default_kura() -> actual::Kura {
    actual::Kura {
        init_mode: iroha_config::kura::InitMode::Strict,
        // The temporary constructor substitutes its own owned directory before opening storage.
        store_dir: iroha_config::base::WithOrigin::inline(PathBuf::from(defaults::kura::STORE_DIR)),
        max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
        blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
        native_context_archive_max_bytes:
            iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
        history_checkpoint_cache_capacity:
            iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
        block_hash_history_bytes:
            iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
        transaction_history_bytes:
            iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
        membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
        fastpq_artifacts: defaults::kura::FASTPQ_ARTIFACT_POLICY,
        debug_output_new_blocks: false,
        fsync_mode: defaults::kura::FSYNC_MODE,
        fsync_interval: defaults::kura::FSYNC_INTERVAL,
    }
}
fn configure_staged_genesis_state(
    state: &mut State,
    genesis: &RawGenesisTransaction,
    config: Option<&actual::Root>,
    nexus: actual::Nexus,
) -> Result<(), color_eyre::eyre::Error> {
    // Every governed runtime projection requires its validated manifest baseline, including
    // the views taken while configuring and reconciling the pre-genesis lane catalog.
    install_staged_nexus_policies(state, genesis, &nexus)?;
    if let Some(config) = config {
        // Execution limits are committed chain policy too: a genesis that needs
        // non-default ones carries the `pipeline_validity_policy_v1` parameter.
        state
            .install_node_pipeline(staged_genesis_pipeline(config.pipeline.clone()))
            .map_err(|error| eyre!("invalid pipeline config for staged genesis: {error}"))?;
        state.set_oracle(config.oracle.clone());
        state.install_node_fraud_monitoring(config.fraud_monitoring.clone());
        state.set_gov(config.gov.clone());
        state.content = config.content.clone();
        state.set_settlement(config.settlement);
        // ZK validity values are committed chain policy: a genesis that needs
        // non-default ones carries the `zk_validity_policy_v1` parameter. The
        // staging configuration supplies local resource settings only.
        state
            .install_node_zk(config.zk.clone())
            .map_err(|error| eyre!("invalid ZK config for staged genesis: {error}"))?;
    } else {
        state
            .install_node_pipeline(staged_default_pipeline(genesis)?)
            .map_err(|error| eyre!("invalid pipeline config for staged genesis: {error}"))?;
    }
    state
        .prepare_configured_primary_geometry_anchor(&nexus.configured_lane_catalog)
        .map_err(|error| eyre!("invalid primary Nexus geometry for staged genesis: {error}"))?;
    state
        .restore_kura_lane_segments_before_startup_replay()
        .map_err(|error| eyre!("restore staged genesis primary Nexus geometry: {error}"))?;
    state
        .set_nexus_from_config(nexus)
        .map_err(|error| eyre!("invalid Nexus config for staged genesis: {error}"))?;
    state.set_crypto(config.map_or_else(actual::Crypto::default, |config| config.crypto.clone()));
    Ok(())
}
fn install_staged_nexus_policies(
    state: &mut State,
    genesis: &RawGenesisTransaction,
    nexus: &actual::Nexus,
) -> Result<(), color_eyre::eyre::Error> {
    let lane_manifests = staged_lane_manifest_registry(genesis, nexus)?;
    let lane_compliance = if nexus.compliance.enabled {
        let policy_dir =
            nexus.compliance.policy_dir.as_ref().ok_or_else(|| {
                eyre!("lane compliance is enabled but no policy_dir is configured")
            })?;
        let engine = LaneComplianceEngine::from_directory(policy_dir, nexus.compliance.audit_only)
            .map_err(|error| eyre!("load staged genesis lane compliance policies: {error}"))?;
        engine
            .validate_active_catalog(&nexus.lane_catalog)
            .map_err(|error| eyre!("validate staged genesis lane compliance policies: {error}"))?;
        Some(Arc::new(engine))
    } else {
        None
    };
    // Load and validate both policy owners before changing the installed projections.
    state
        .install_materialized_lane_manifests_for_catalog(
            &Arc::new(lane_manifests),
            &nexus.lane_catalog,
            &nexus.governance,
        )
        .map_err(|error| eyre!("install staged genesis lane manifests: {error}"))?;
    state.install_lane_compliance_engine(lane_compliance);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, bls_normal_pop_prove};
    use iroha_data_model::block::consensus::SumeragiGenesisContextParameters;
    use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry};
    use iroha_model_base::{chain::ChainId, peer::PeerId};

    fn default_test_topology() -> Vec<GenesisTopologyEntry> {
        let mut entries = (0x40..=0x43)
            .map(|seed| {
                let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                    .expect("derive deterministic default staging validator");
                let pop = bls_normal_pop_prove(key.private_key()).expect("checked topology proof");
                GenesisTopologyEntry::new(PeerId::new(key.public_key().clone()), pop)
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.peer.cmp(&right.peer));
        entries
    }

    #[test]
    fn configured_genesis_world_retains_original_state_pool_across_pipeline_installation() {
        let key = KeyPair::try_from_seed(vec![0x6D; 32], Algorithm::Ed25519)
            .expect("deterministic staging authority");
        let raw = GenesisBuilder::new_without_executor(ChainId::from("genesis-original-pool"), ".")
            .set_topology(default_test_topology())
            .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
            .build_raw()
            .unwrap()
            .with_consensus_mode(SumeragiConsensusMode::Permissioned)
            .with_consensus_meta()
            .unwrap();
        let provisional = build_signed_genesis(
            raw.clone(),
            &key,
            None,
            iroha_core::state::default_genesis_confidential_policy_hash(),
            Some(1_700_000_000_000),
        )
        .unwrap();
        let (mut state, _, _) = configured_initial_genesis_state(&raw, None, &provisional)
            .expect("construct the actual fresh-node World and State");
        let original = state.ivm_execution_budget();
        let reserved = original.reserved_bytes();
        assert!(
            reserved > 0,
            "the original pool funds real retained storage"
        );
        drop(
            state
                .world
                .try_block(&original)
                .expect("original World acquisition"),
        );
        assert_eq!(original.reserved_bytes(), reserved);

        let mut pipeline = staged_default_pipeline(&raw).unwrap();
        pipeline.ivm_execution_max_bytes = original.limit_bytes() - 1;
        state.install_node_pipeline(pipeline).unwrap();
        assert!(original.same_pool(&state.ivm_execution_budget()));
        let before = original.reserved_bytes();
        let foreign = iroha_core::state::AllocationBudget::new(original.limit_bytes());
        assert!(matches!(
            state.world.try_block(&foreign),
            Err(mv::storage::AdmittedStorageError::ScopeIdentity)
        ));
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(original.reserved_bytes(), before);
        drop(
            state
                .world
                .try_block(&original)
                .expect("retry with original pool"),
        );
        assert_eq!(original.reserved_bytes(), before);
    }

    #[test]
    fn default_genesis_staging_authenticates_catalog_and_reproduces_signed_context() {
        let genesis_key_pair = KeyPair::try_from_seed(vec![0x6E; 32], Algorithm::Ed25519)
            .expect("derive deterministic default staging key");
        let topology = default_test_topology();
        let raw =
            GenesisBuilder::new_without_executor(ChainId::from("default-genesis-staging"), ".")
                .set_topology(topology.clone())
                .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
                .build_raw()
                .expect("complete generic four-validator genesis")
                .with_consensus_mode(SumeragiConsensusMode::Permissioned)
                .with_consensus_meta()
                .expect("valid fixture consensus parameters");
        let (bound_manifest, signed) = bind_and_sign_staged_sumeragi_context(
            raw,
            &genesis_key_pair,
            None,
            None,
            iroha_core::state::default_genesis_confidential_policy_hash(),
            Some(1_700_000_000_000),
        )
        .expect("no-config signing must authenticate default storage before executing genesis");
        let epoch = iroha_data_model::sumeragi_finality::authenticated_genesis(&signed.0)
            .map(|genesis| genesis.into_parts().0)
            .expect("signed topology establishes the exact BLS generation zero");
        assert_eq!(epoch.authorization.authority_generation, 0);
        assert_eq!(
            epoch.generation().validators,
            topology
                .iter()
                .map(|entry| entry.peer.clone())
                .collect::<Vec<_>>()
        );
        epoch
            .authorization
            .validate_against_generation(&epoch.generation())
            .expect("original genesis authorization");
        assert!(signed.0.network_entrypoint_count() > 0);
        assert!(signed.0.has_results());
        assert!(
            signed
                .0
                .output_results()
                .all(|result| result.as_ref().is_ok())
        );
        signed
            .0
            .validate_output_merkle_cache()
            .expect("complete executed genesis outputs");
        assert!(signed.0.external_transactions().next().is_some());
        for transaction in signed.0.external_transactions() {
            transaction
                .verify_signature()
                .expect("original transaction signature");
        }
        assert!(signed.0.signatures().next().is_some());
        for signature in signed.0.signatures() {
            signature
                .signature()
                .verify_hash(genesis_key_pair.public_key(), signed.0.hash())
                .expect("original final genesis signature");
        }
        let restaged = restage_signed_sumeragi_context_hashes(&bound_manifest, None, &signed.0)
            .expect("default staging must also accept the final signed network identity");
        let parameters = bound_manifest.sumeragi_context_parameters();
        assert_eq!(
            restaged.nexus_amx_context_hash,
            Hash::prehashed(parameters.nexus_amx_context_hash)
        );
        assert_eq!(
            restaged.execution_policy_hash,
            Hash::prehashed(parameters.execution_policy_hash)
        );
        assert_eq!(restaged.executed_block.hash(), signed.0.hash());
        assert_eq!(
            Hash::new(&restaged.nexus_amx_context_preimage),
            restaged.nexus_amx_context_hash,
            "the published preimage hashes to the signed Nexus/AMX context"
        );
        iroha_data_model::nexus::decode_nexus_amx_context_v1(&restaged.nexus_amx_context_preimage)
            .expect("the staged preimage is a canonical Nexus/AMX context");
        let different_mode = bound_manifest.with_consensus_mode(SumeragiConsensusMode::Npos);
        let mismatch = restage_signed_sumeragi_context_hashes(&different_mode, None, &signed.0)
            .err()
            .expect("a manifest cannot replace the signed consensus mode");
        assert!(
            mismatch
                .to_string()
                .contains("genesis manifest consensus mode differs from signed metadata")
        );
    }
    #[test]
    fn committed_fraud_genesis_staging_signs_and_restages_authored_policy() {
        use iroha_data_model::{
            fraud::{FraudAdmissionPolicyV1, FraudRiskBandV1},
            parameter::Parameter,
        };
        let key = KeyPair::try_from_seed(vec![0x6F; 32], Algorithm::Ed25519).unwrap();
        let mut hashes = Vec::new();
        for band in [FraudRiskBandV1::Low, FraudRiskBandV1::High] {
            let policy = FraudAdmissionPolicyV1 {
                enabled: true,
                required_minimum_band: Some(band),
                missing_assessment_permitted: false,
                ..FraudAdmissionPolicyV1::protocol_default()
            };
            let raw =
                GenesisBuilder::new_without_executor(ChainId::from("fraud-genesis-staging"), ".")
                    .set_topology(default_test_topology())
                    .with_sumeragi_context_parameters(
                        SumeragiGenesisContextParameters::recommended(),
                    )
                    .append_parameter(Parameter::Custom(policy.into_custom_parameter()))
                    .build_raw()
                    .unwrap()
                    .with_consensus_mode(SumeragiConsensusMode::Permissioned)
                    .with_consensus_meta()
                    .unwrap();
            let (manifest, signed) = bind_and_sign_staged_sumeragi_context(
                raw,
                &key,
                None,
                None,
                iroha_core::state::default_genesis_confidential_policy_hash(),
                Some(1_700_000_000_000),
            )
            .unwrap();
            assert!(
                signed
                    .0
                    .output_results()
                    .all(|result| result.as_ref().is_ok()),
                "H1 admission remains the fixed predecessor while its policy is authored"
            );
            let restaged =
                restage_signed_sumeragi_context_hashes(&manifest, None, &signed.0).unwrap();
            assert_eq!(restaged.executed_block.hash(), signed.0.hash());
            assert_eq!(
                restaged.execution_policy_hash,
                Hash::prehashed(manifest.sumeragi_context_parameters().execution_policy_hash)
            );
            hashes.push(restaged.execution_policy_hash);
        }
        assert_ne!(
            hashes[0], hashes[1],
            "the signed fingerprint binds the authored band, not default transport"
        );
    }
}
