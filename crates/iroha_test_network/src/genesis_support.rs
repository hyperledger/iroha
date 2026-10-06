//! Shared orchestration helpers for preparing and validating local genesis artifacts.
use color_eyre::eyre::{Result, WrapErr, eyre};
use iroha_config::{base::toml::TomlSource, parameters::actual};
use iroha_crypto::{Hash, HashOf, KeyPair, PublicKey};
use iroha_data_model::{
    account::AccountId,
    block::{BlockHeader, SignedBlock},
    da::commitment::DaProofPolicyBundle,
    parameter::system::SumeragiConsensusMode,
};
use iroha_genesis::{RawGenesisTransaction, ValidatedGenesisBundle};
use iroha_model_base::chain::ChainId;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
/// Exact placeholder accepted while a genesis hash is not yet known.
///
/// The placeholder is replaced only in memory by the explicit preparation helpers
/// [`prepare_unpublished_genesis_from_config`] and [`sign_prepared_genesis_from_config`].
/// Persisted node configurations still require the exact hash before normal startup validation.
pub const UNRESOLVED_GENESIS_EXPECTED_HASH: &str = "REPLACE_WITH_GENESIS_EXPECTED_HASH";
/// Filesystem paths controlled by a local node-generation orchestrator.
///
/// Every path is owned and detached from `iroha_config`'s origin wrappers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedNodePaths {
    /// Resolved Kura block-store directory.
    pub kura_store_dir: PathBuf,
    /// Resolved snapshot-store directory.
    pub snapshot_store_dir: PathBuf,
    /// Torii's persistent data directory.
    pub torii_data_dir: PathBuf,
    /// Torii's persistent DA replay-cache directory.
    pub torii_da_replay_cache_store_dir: PathBuf,
    /// Torii's persistent DA manifest-spool directory.
    pub torii_da_manifest_store_dir: PathBuf,
    /// Torii's SoraFS storage directory.
    pub torii_sorafs_storage_data_dir: PathBuf,
    /// Streaming session-store directory.
    pub streaming_session_store_dir: PathBuf,
    /// Streaming codec's signed rANS-table path.
    pub streaming_rans_tables_path: PathBuf,
    /// SoraNet proof-of-work ticket-revocation store path.
    pub soranet_pow_revocation_store_path: PathBuf,
}
/// Owned projection of the node configuration bindings needed by genesis orchestration.
///
/// This deliberately exposes domain types and owned values rather than any
/// `iroha_config` representation. Parsing therefore remains centralized and
/// canonical while callers cannot depend on configuration-layer internals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedNodeConfig {
    /// Configured chain identifier.
    pub chain_id: ChainId,
    /// Configured I105 chain discriminant.
    pub chain_discriminant: u16,
    /// Public key of the configured local node.
    pub local_public_key: PublicKey,
    /// Trusted validator proof-of-possession roster.
    pub trusted_peer_pops: BTreeMap<PublicKey, Vec<u8>>,
    /// Public key authorized to sign genesis.
    pub genesis_public_key: PublicKey,
    /// Exact configured genesis block-header hash.
    pub genesis_expected_hash: HashOf<BlockHeader>,
    /// Resolved path to the signed genesis block.
    pub genesis_block_path: PathBuf,
    /// Resolved path to the raw genesis manifest.
    pub genesis_manifest_path: PathBuf,
    /// Exact DA proof-policy bundle derived from the node configuration.
    pub da_proof_policies: DaProofPolicyBundle,
    /// Exact confidential-policy hash derived from the node configuration.
    pub genesis_confidential_policy_hash: [u8; 32],
    /// Filesystem paths managed by local node generation.
    pub managed_paths: ManagedNodePaths,
}
impl ManagedNodeConfig {
    /// Parse a node configuration through `iroha_config` and project the
    /// genesis bindings needed by local orchestration.
    ///
    /// Relative Kura, snapshot, genesis-block, and genesis-manifest paths are
    /// resolved against the configuration file which introduced them.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, canonical configuration
    /// parsing fails, or either required genesis artifact path is absent.
    pub fn from_path(path: &Path) -> Result<Self> {
        let (config, _) = load_node_config(path, false)?;
        Self::from_root(config)
    }
    fn from_root(config: actual::Root) -> Result<Self> {
        let genesis_block_path = config
            .genesis
            .file
            .as_ref()
            .ok_or_else(|| eyre!("node configuration omits required `genesis.file`"))?
            .resolve_relative_path();
        let genesis_manifest_path = config
            .genesis
            .manifest_json
            .as_ref()
            .ok_or_else(|| eyre!("node configuration omits required `genesis.manifest_json`"))?
            .resolve_relative_path();
        let managed_paths = ManagedNodePaths {
            kura_store_dir: config.kura.store_dir.resolve_relative_path(),
            snapshot_store_dir: config.snapshot.store_dir.resolve_relative_path(),
            torii_data_dir: config.torii.data_dir.clone(),
            torii_da_replay_cache_store_dir: config.torii.da_ingest.replay_cache_store_dir.clone(),
            torii_da_manifest_store_dir: config.torii.da_ingest.manifest_store_dir.clone(),
            torii_sorafs_storage_data_dir: config.torii.sorafs_storage.data_dir.clone(),
            streaming_session_store_dir: config.streaming.session_store_dir.clone(),
            streaming_rans_tables_path: config.streaming.codec.rans_tables_path.clone(),
            soranet_pow_revocation_store_path: PathBuf::from(
                config
                    .network
                    .soranet_handshake
                    .pow
                    .revocation_store_path
                    .as_ref(),
            ),
        };
        Ok(Self {
            chain_id: config.common.chain.clone(),
            chain_discriminant: *config.common.chain_discriminant.value(),
            local_public_key: config.common.key_pair.public_key().clone(),
            trusted_peer_pops: config.common.trusted_peers.value().pops.clone(),
            genesis_public_key: config.genesis.public_key.clone(),
            genesis_expected_hash: config.genesis.expected_hash,
            genesis_block_path,
            genesis_manifest_path,
            da_proof_policies: iroha_core::da::proof_policy_bundle(&config.nexus.lane_config),
            genesis_confidential_policy_hash:
                iroha_core::state::default_genesis_confidential_policy_hash(),
            managed_paths,
        })
    }
}
/// Build and sign a prepared genesis manifest using the policies selected by a
/// canonical node configuration.
///
/// The manifest chain, chain discriminant, optional expected consensus mode, signing key, and
/// canonical manifest path are bound to the parsed configuration before signing. The unresolved
/// expected-hash sentinel is accepted only for this preparation step and is replaced in memory
/// before canonical configuration parsing. If the configuration already selects an exact hash, the
/// newly produced block must match it.
///
/// # Errors
///
/// Returns an error when either input cannot be parsed, a binding differs, or
/// canonical genesis construction or signing fails.
pub fn sign_prepared_genesis_from_config(
    manifest_path: &Path,
    config_path: &Path,
    key_pair: &KeyPair,
    expected_consensus_mode: Option<SumeragiConsensusMode>,
) -> Result<SignedBlock> {
    let (manifest, parsed_config, config, unresolved_hash_replaced) = load_selected_genesis(
        manifest_path,
        config_path,
        key_pair,
        expected_consensus_mode,
    )?;
    let proposal = manifest
        .build_and_sign_with_da_proof_policies_and_confidential_policy_hash(
            key_pair,
            Some(config.da_proof_policies),
            Some(config.genesis_confidential_policy_hash),
        )
        .wrap_err("build and sign canonical prepared genesis")?;
    let topology = iroha_core::sumeragi::startup::genesis_committee_peers(&proposal.0)
        .map_err(|error| eyre!("derive prepared genesis voting roster: {error}"))?;
    let genesis_account = AccountId::new(key_pair.public_key().clone());
    let (block, _) = crate::config::preexecute_genesis_with_runtime_config(
        &proposal,
        &genesis_account,
        &topology,
        key_pair,
        None,
        None,
        None,
        Some(&parsed_config),
    )
    .wrap_err("pre-execute canonical prepared genesis")?;
    if !unresolved_hash_replaced && block.hash() != config.genesis_expected_hash {
        return Err(eyre!(
            "prepared genesis hashes to {}, but configuration requires {}",
            block.hash(),
            config.genesis_expected_hash
        ));
    }
    Ok(block)
}
/// Prepare and execute a new unpublished genesis against its selected node configuration.
///
/// The configuration must select the exact unresolved network-identity sentinel, and a draft
/// must not carry an already-bound consensus fingerprint. Only the recommended
/// provisional execution and Nexus commitments permit one native policy binding; explicit
/// commitments take the strict execution path. The maintained builder binds the exact typed
/// native result and strictly re-executes the same input before any output can be published.
/// Original manifest and configuration files remain unchanged. Reviewed manifests must instead
/// use [`sign_prepared_genesis_from_config`], which never rebinds their policy.
///
/// # Errors
///
/// Returns an error for a resolved network identity, mismatched selected inputs, already-bound
/// metadata, invalid execution, or noncanonical genesis output.
pub fn prepare_unpublished_genesis_from_config(
    manifest_path: &Path,
    config_path: &Path,
    key_pair: &KeyPair,
    expected_consensus_mode: Option<SumeragiConsensusMode>,
) -> Result<(RawGenesisTransaction, SignedBlock)> {
    let (manifest, parsed_config, config, unresolved_hash_replaced) = load_selected_genesis(
        manifest_path,
        config_path,
        key_pair,
        expected_consensus_mode,
    )?;
    if !unresolved_hash_replaced {
        return Err(eyre!(
            "unpublished genesis preparation requires the unresolved network identity"
        ));
    }
    if manifest.consensus_fingerprint().is_some() {
        return Err(eyre!(
            "unpublished genesis already carries a bound consensus fingerprint"
        ));
    }
    let context = manifest.sumeragi_context_parameters();
    let provisional =
        iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended();
    let bind_provisional = context.execution_policy_hash == provisional.execution_policy_hash
        && context.nexus_amx_context_hash == provisional.nexus_amx_context_hash;
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        config.chain_discriminant,
    );
    let proposal = manifest
        .clone()
        .build_and_sign_with_da_proof_policies_and_confidential_policy_hash(
            key_pair,
            Some(config.da_proof_policies),
            Some(config.genesis_confidential_policy_hash),
        )
        .wrap_err("build unpublished genesis proposal")?;
    let topology = iroha_core::sumeragi::startup::genesis_committee_peers(&proposal.0)
        .map_err(|error| eyre!("derive unpublished genesis voting roster: {error}"))?;
    let account = AccountId::new(key_pair.public_key().clone());
    let (executed, _, bound_manifest) = crate::config::execute_generated_genesis(
        proposal,
        manifest,
        key_pair,
        bind_provisional,
        |candidate| {
            crate::config::preexecute_genesis_with_runtime_config(
                candidate,
                &account,
                &topology,
                key_pair,
                None,
                None,
                None,
                Some(&parsed_config),
            )
        },
    )
    .wrap_err("prepare unpublished genesis with native execution")?;
    let bound_manifest = bound_manifest.with_consensus_meta()?;
    let block = executed.0;
    let wire = block
        .encode_wire()
        .wrap_err("encode prepared unpublished genesis")?;
    validate_prepared_genesis_for_startup(
        &wire,
        &bound_manifest,
        key_pair.public_key(),
        block.hash(),
        &config.chain_id,
    )
    .wrap_err("validate prepared unpublished genesis before publication")?;
    Ok((bound_manifest, block))
}

fn load_selected_genesis(
    manifest_path: &Path,
    config_path: &Path,
    key_pair: &KeyPair,
    expected_consensus_mode: Option<SumeragiConsensusMode>,
) -> Result<(RawGenesisTransaction, actual::Root, ManagedNodeConfig, bool)> {
    iroha_genesis::init_instruction_registry();
    let (parsed_config, unresolved_hash_replaced) = load_node_config(config_path, true)?;
    let config = ManagedNodeConfig::from_root(parsed_config.clone())?;
    let selected_manifest = config
        .genesis_manifest_path
        .canonicalize()
        .wrap_err_with(|| {
            format!(
                "resolve configured genesis manifest `{}`",
                config.genesis_manifest_path.display()
            )
        })?;
    let supplied_manifest = manifest_path.canonicalize().wrap_err_with(|| {
        format!(
            "resolve supplied genesis manifest `{}`",
            manifest_path.display()
        )
    })?;
    if supplied_manifest != selected_manifest {
        return Err(eyre!(
            "supplied genesis manifest `{}` differs from configured manifest `{}`",
            supplied_manifest.display(),
            selected_manifest.display()
        ));
    }
    let manifest =
        RawGenesisTransaction::from_path(&config.genesis_manifest_path).wrap_err_with(|| {
            format!(
                "parse prepared genesis manifest `{}`",
                config.genesis_manifest_path.display()
            )
        })?;
    if manifest.chain_id() != &config.chain_id {
        return Err(eyre!(
            "genesis manifest chain `{}` differs from configured chain `{}`",
            manifest.chain_id(),
            config.chain_id
        ));
    }
    if manifest.chain_discriminant() != config.chain_discriminant {
        return Err(eyre!(
            "genesis manifest chain discriminant {} differs from configured discriminant {}",
            manifest.chain_discriminant(),
            config.chain_discriminant
        ));
    }
    if key_pair.public_key() != &config.genesis_public_key {
        return Err(eyre!(
            "genesis signing key `{}` differs from configured genesis key `{}`",
            key_pair.public_key(),
            config.genesis_public_key
        ));
    }
    if let Some(expected_mode) = expected_consensus_mode
        && manifest.consensus_mode() != expected_mode
    {
        return Err(eyre!(
            "genesis manifest consensus mode {:?} differs from expected mode {:?}",
            manifest.consensus_mode(),
            expected_mode
        ));
    }
    Ok((manifest, parsed_config, config, unresolved_hash_replaced))
}

/// Validate a canonical prepared-genesis bundle for node startup.
///
/// This composes the independent manifest/wire validator with Core's complete
/// genesis-block invariant check. The expected chain is bound explicitly
/// before either validated result is returned.
///
/// # Errors
///
/// Returns an error when the manifest selects another chain, canonical bundle
/// validation fails, or Core rejects the genesis block.
pub fn validate_prepared_genesis_for_startup(
    signed_wire: &[u8],
    manifest: &RawGenesisTransaction,
    public_key: &PublicKey,
    expected_hash: HashOf<BlockHeader>,
    expected_chain_id: &ChainId,
) -> Result<ValidatedGenesisBundle> {
    if manifest.chain_id() != expected_chain_id {
        return Err(eyre!(
            "genesis manifest chain `{}` differs from expected chain `{}`",
            manifest.chain_id(),
            expected_chain_id
        ));
    }
    let validated = iroha_genesis::validate_prepared_genesis_bundle(
        signed_wire,
        manifest,
        public_key,
        expected_hash,
    )
    .wrap_err("validate canonical prepared genesis bundle")?;
    iroha_core::validate_genesis_block(validated.block(), &AccountId::new(public_key.clone()))
        .map_err(|error| eyre!("validate prepared genesis with Core: {error}"))?;
    Ok(validated)
}
fn load_node_config(path: &Path, allow_unresolved_hash: bool) -> Result<(actual::Root, bool)> {
    let mut source = TomlSource::from_file(path)
        .map_err(|error| eyre!("read node configuration `{}`: {error:?}", path.display()))?;
    let unresolved_hash_replaced = allow_unresolved_hash
        && source
            .table_mut()
            .get_mut("genesis")
            .and_then(toml::Value::as_table_mut)
            .and_then(|genesis| genesis.get_mut("expected_hash"))
            .is_some_and(|expected_hash| {
                expected_hash.as_str() == Some(UNRESOLVED_GENESIS_EXPECTED_HASH)
            });
    if unresolved_hash_replaced {
        let expected_hash = source
            .table_mut()
            .get_mut("genesis")
            .and_then(toml::Value::as_table_mut)
            .and_then(|genesis| genesis.get_mut("expected_hash"))
            .expect("sentinel location was just verified");
        let hash_body = Hash::new(b"unresolved genesis hash used only for policy derivation")
            .to_string()
            .to_ascii_uppercase();
        *expected_hash = toml::Value::String(norito::literal::format("hash", hash_body.as_str()));
    }
    let config = actual::Root::from_toml_source(source)
        .map_err(|error| eyre!("parse node configuration `{}`: {error:?}", path.display()))?;
    Ok((config, unresolved_hash_replaced))
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, bls_normal_pop_prove};
    use iroha_data_model::{
        block::consensus::{SumeragiGenesisContextParameters, is_valid_committee_size},
        isi::kagemusha_v1::{
            KAGEMUSHA_CHAIN_VERSION_V1, KagemushaMintFinalityAuthorityGenerationTemplateV1,
            KagemushaMintFinalityGenesisParametersV1,
        },
    };
    use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry};
    use iroha_model_base::peer::PeerId;
    use std::fs;
    const CONFIGURED_HASH: &str =
        "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E";
    const FIXTURE_GENESIS_PUBLIC_KEY: &str =
        "ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4";
    fn complete_test_builder_for_topology(
        builder: GenesisBuilder,
        mut topology: Vec<GenesisTopologyEntry>,
    ) -> GenesisBuilder {
        topology.sort_by(|left, right| left.peer.cmp(&right.peer));
        assert!(
            is_valid_committee_size(topology.len()),
            "genesis-support fixtures require an exact supported 3f + 1 topology"
        );
        assert!(
            !topology.windows(2).any(|pair| pair[0].peer == pair[1].peer),
            "genesis-support fixture topology must not repeat validators"
        );
        for entry in &topology {
            let pop = entry
                .pop_bytes()
                .expect("decode genesis-support validator proof of possession")
                .expect("genesis-support validator must carry a proof of possession");
            iroha_crypto::bls_normal_pop_verify(entry.peer.public_key(), &pop)
                .expect("verify genesis-support validator proof of possession");
        }
        let validators = topology
            .iter()
            .map(|entry| entry.peer.clone())
            .collect::<Vec<_>>();
        let validators = validators
            .into_iter()
            .enumerate()
            .map(|(index, validator)| {
                iroha_core_zk::kagemusha_v1_recursion::derive_kagemusha_mint_finality_validator_keys_v1(
                    &[0xA0_u8.wrapping_add(u8::try_from(index).expect("small test roster")); 32],
                    0,
                    validator,
                )
                .expect("derive deterministic test mint-finality keys")
            })
            .collect();
        let parameters = KagemushaMintFinalityGenesisParametersV1 {
            authority_generation: KagemushaMintFinalityAuthorityGenerationTemplateV1 {
                version: KAGEMUSHA_CHAIN_VERSION_V1,
                generation: 0,
                validators,
            },
        };
        parameters
            .validate()
            .expect("genesis-support test authority must be canonical");
        builder
            .set_topology(topology)
            .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
            .with_kagemusha_mint_finality_genesis_parameters(parameters)
    }
    fn prepared_manifest(chain_id: ChainId) -> (RawGenesisTransaction, KeyPair) {
        let topology = (0..4)
            .map(|_| {
                let validator = KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
                    .expect("generate validator key");
                let pop = bls_normal_pop_prove(validator.private_key())
                    .expect("generate validator proof of possession");
                GenesisTopologyEntry::new(PeerId::new(validator.public_key().clone()), pop)
            })
            .collect::<Vec<_>>();
        let manifest = complete_test_builder_for_topology(
            GenesisBuilder::new_without_executor(chain_id, "."),
            topology,
        )
        .build_raw()
        .expect("complete prepared-manifest fixture");
        let genesis_key = KeyPair::try_random().expect("generate genesis key");
        (manifest, genesis_key)
    }
    /// Prepare this test-owned manifest before exercising the strict signing boundary.
    fn bind_fixture_policy(
        manifest: RawGenesisTransaction,
        key: &KeyPair,
        config_path: &Path,
    ) -> RawGenesisTransaction {
        let (config, _) = load_node_config(config_path, true).expect("parse fixture config");
        let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
            *config.common.chain_discriminant.value(),
        );
        let da = Some(iroha_core::da::proof_policy_bundle(
            &config.nexus.lane_config,
        ));
        let confidential = Some(iroha_core::state::default_genesis_confidential_policy_hash());
        let proposal = manifest
            .clone()
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash(
                key,
                da.clone(),
                confidential,
            )
            .expect("sign unpublished fixture proposal");
        let topology = iroha_core::sumeragi::startup::genesis_committee_peers(&proposal.0)
            .expect("canonical four-validator fixture roster");
        assert_eq!(topology.len(), 4);
        let account = AccountId::new(key.public_key().clone());
        let staged = crate::config::discover_generated_policy_hashes(
            crate::config::staged_genesis_policy_hashes(
                &proposal,
                &account,
                &topology,
                key,
                None,
                None,
                None,
                Some(&config),
            ),
        )
        .expect("derive actual fixture commitments from native execution");
        let mut context = manifest.sumeragi_context_parameters();
        context.nexus_amx_context_hash = staged.nexus_amx.into();
        context.execution_policy_hash = staged.execution_policy.into();
        let manifest = manifest
            .with_sumeragi_context_parameters(context)
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        let proposal = manifest
            .clone()
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash(
                key,
                da,
                confidential,
            )
            .expect("sign policy-bound fixture proposal");
        let actual = crate::config::staged_genesis_policy_hashes(
            &proposal,
            &account,
            &topology,
            key,
            None,
            None,
            None,
            Some(&config),
        )
        .expect("final fixture must pass the strict native validator without rebinding");
        assert_eq!(actual, staged);
        manifest
    }
    fn write_node_config(
        directory: &Path,
        chain_id: &ChainId,
        chain_discriminant: u16,
        genesis_public_key: &PublicKey,
        expected_hash: &str,
    ) -> PathBuf {
        let managed_directory = directory.join("managed");
        fs::create_dir_all(&managed_directory).expect("create managed fixture directory");
        let rans_tables_path = managed_directory.join("rans_tables.toml");
        fs::write(
            &rans_tables_path,
            include_bytes!("../../../codec/rans/tables/rans_seed0.toml"),
        )
        .expect("write signed rANS tables fixture");
        let rans_tables_literal = rans_tables_path.to_string_lossy().replace('\\', "\\\\");
        let mut config = include_str!("../../iroha_config/iroha_test_config.toml").to_owned();
        config = config.replacen(
            "chain = \"00000000-0000-0000-0000-000000000000\"",
            &format!("chain = \"{chain_id}\"\nchain_discriminant = {chain_discriminant}"),
            1,
        );
        config = config.replacen(
            &format!("[genesis]\npublic_key = \"{FIXTURE_GENESIS_PUBLIC_KEY}\""),
            &format!("[genesis]\npublic_key = \"{genesis_public_key}\""),
            1,
        );
        config = config.replacen(
            "file = \"./genesis.signed.nrt\"",
            "file = \"managed/genesis.signed.nrt\"\nmanifest_json = \"genesis.json\"",
            1,
        );
        config = config.replacen(CONFIGURED_HASH, expected_hash, 1);
        config.push_str(
            r#"

[kura]
store_dir = "managed/kura"

[snapshot]
store_dir = "managed/snapshot"

[torii.da_ingest]
replay_cache_store_dir = "managed/torii/da-replay"
manifest_store_dir = "managed/torii/da-manifests"

[sorafs.storage]
data_dir = "managed/sorafs"

[streaming.codec]
cabac_mode = "disabled"
trellis_blocks = []
rans_tables_path = "__RANS_TABLES_PATH__"
entropy_mode = "rans_bundled"
bundle_width = 2
bundle_accel = "none"

[network.soranet_handshake.pow]
revocation_store_path = "managed/soranet/revocations.norito"
"#,
        );
        config = config.replacen("__RANS_TABLES_PATH__", &rans_tables_literal, 1);
        config = config.replacen(
            "session_store_dir = \"./storage/streaming\"",
            "session_store_dir = \"managed/streaming\"",
            1,
        );
        config = config.replacen(
            "[torii]\naddress = \"addr:127.0.0.1:8080#8942\"",
            "[torii]\naddress = \"addr:127.0.0.1:8080#8942\"\ndata_dir = \"managed/torii\"",
            1,
        );
        let path = directory.join("config.toml");
        fs::write(&path, config).expect("write node config");
        path
    }
    fn unpublished_fixture() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        RawGenesisTransaction,
        KeyPair,
    ) {
        let directory = tempfile::tempdir().expect("create unpublished fixture directory");
        let chain = ChainId::from("unpublished-genesis-fixture");
        let (manifest, key) = prepared_manifest(chain.clone());
        let config = write_node_config(
            directory.path(),
            &chain,
            manifest.chain_discriminant(),
            key.public_key(),
            UNRESOLVED_GENESIS_EXPECTED_HASH,
        );
        let path = directory.path().join("genesis.json");
        fs::write(
            &path,
            norito::json::to_vec_pretty(&manifest).expect("encode unpublished fixture"),
        )
        .expect("write unpublished fixture");
        let manifest = RawGenesisTransaction::from_path(&path)
            .expect("read canonical selected unpublished fixture");
        (directory, path, config, manifest, key)
    }
    #[test]
    fn unpublished_preparation_preserves_inputs_and_passes_strict_prepared_signing() {
        let (_directory, path, config, original, key) = unpublished_fixture();
        let input = fs::read(&path).expect("original unpublished manifest");
        let config_bytes = fs::read(&config).expect("original selected config");
        let (bound, block) = prepare_unpublished_genesis_from_config(
            &path,
            &config,
            &key,
            Some(SumeragiConsensusMode::Permissioned),
        )
        .expect("prepare actual config-bound genesis");
        assert_eq!(fs::read(&path).unwrap(), input);
        assert_eq!(fs::read(&config).unwrap(), config_bytes);
        assert!(bound.consensus_fingerprint().is_some());
        assert!(block.has_results());
        let mut expected_context = original.sumeragi_context_parameters();
        let actual_context = bound.sumeragi_context_parameters();
        expected_context.execution_policy_hash = actual_context.execution_policy_hash;
        expected_context.nexus_amx_context_hash = actual_context.nexus_amx_context_hash;
        let expected = original
            .with_sumeragi_context_parameters(expected_context)
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        assert_eq!(
            norito::json::to_value(&bound).unwrap(),
            norito::json::to_value(&expected).unwrap(),
            "only derived policy commitments and their consensus metadata may change"
        );
        fs::write(&path, norito::json::to_vec_pretty(&bound).unwrap())
            .expect("publish prepared manifest fixture");
        let prepared_bytes = fs::read(&path).unwrap();
        let signed = sign_prepared_genesis_from_config(
            &path,
            &config,
            &key,
            Some(SumeragiConsensusMode::Permissioned),
        )
        .expect("unchanged strict signer must accept prepared manifest");
        assert!(signed.has_results());
        assert_eq!(fs::read(&path).unwrap(), prepared_bytes);
        validate_prepared_genesis_for_startup(
            &signed.encode_wire().unwrap(),
            &bound,
            key.public_key(),
            signed.hash(),
            bound.chain_id(),
        )
        .expect("strict final bundle passes Core startup validation");
    }
    #[test]
    fn unpublished_preparation_rejects_already_bound_metadata() {
        let (_directory, path, config, manifest, key) = unpublished_fixture();
        let bound = norito::json::to_vec_pretty(
            &manifest
                .with_consensus_meta()
                .expect("valid fixture consensus parameters"),
        )
        .unwrap();
        fs::write(&path, &bound).unwrap();
        let error = prepare_unpublished_genesis_from_config(&path, &config, &key, None)
            .expect_err("reviewed metadata cannot be rebound through unpublished preparation");
        assert!(
            error
                .to_string()
                .contains("already carries a bound consensus fingerprint")
        );
        assert_eq!(fs::read(&path).unwrap(), bound);
    }
    #[test]
    fn unpublished_preparation_never_rebinds_explicit_stale_policy() {
        let (_directory, path, config, manifest, key) = unpublished_fixture();
        let mut context = manifest.sumeragi_context_parameters();
        context.execution_policy_hash = Hash::new(b"explicit stale unpublished policy").into();
        let explicit =
            norito::json::to_vec_pretty(&manifest.with_sumeragi_context_parameters(context))
                .unwrap();
        fs::write(&path, &explicit).unwrap();
        let error = prepare_unpublished_genesis_from_config(&path, &config, &key, None)
            .expect_err("explicit policy commitment must remain an exact strict contract");
        assert!(
            matches!(
                error
                    .downcast_ref::<Box<iroha_core::block::BlockValidationError>>()
                    .map(Box::as_ref),
                Some(iroha_core::block::BlockValidationError::GenesisPolicyMismatch { .. })
            ),
            "unexpected native refusal: {error:#}"
        );
        assert_eq!(fs::read(&path).unwrap(), explicit);
    }
    #[test]
    fn managed_projection_owns_exact_genesis_bindings_and_paths() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let chain_id = ChainId::from("managed-projection-fixture");
        let genesis_key = KeyPair::try_random().expect("generate genesis key");
        let chain_discriminant = iroha_config::parameters::defaults::common::chain_discriminant();
        let config_path = write_node_config(
            directory.path(),
            &chain_id,
            chain_discriminant,
            genesis_key.public_key(),
            CONFIGURED_HASH,
        );
        let projected = ManagedNodeConfig::from_path(&config_path).expect("project config");
        assert_eq!(projected.chain_id, chain_id);
        assert_eq!(projected.chain_discriminant, chain_discriminant);
        assert_eq!(
            projected.genesis_public_key,
            genesis_key.public_key().clone()
        );
        assert_eq!(projected.trusted_peer_pops.len(), 4);
        assert_eq!(
            projected.genesis_block_path,
            directory.path().join("managed/genesis.signed.nrt")
        );
        assert_eq!(
            projected.genesis_manifest_path,
            directory.path().join("genesis.json")
        );
        assert_eq!(
            projected.managed_paths.kura_store_dir,
            directory.path().join("managed/kura")
        );
        assert_eq!(
            projected.managed_paths.snapshot_store_dir,
            directory.path().join("managed/snapshot")
        );
        assert_eq!(
            projected.managed_paths.torii_data_dir,
            PathBuf::from("managed/torii")
        );
        assert_eq!(
            projected.managed_paths.torii_da_replay_cache_store_dir,
            PathBuf::from("managed/torii/da-replay")
        );
        assert_eq!(
            projected.managed_paths.torii_da_manifest_store_dir,
            PathBuf::from("managed/torii/da-manifests")
        );
        assert_eq!(
            projected.managed_paths.torii_sorafs_storage_data_dir,
            PathBuf::from("managed/sorafs")
        );
        assert_eq!(
            projected.managed_paths.streaming_session_store_dir,
            PathBuf::from("managed/streaming")
        );
        assert_eq!(
            projected.managed_paths.streaming_rans_tables_path,
            directory.path().join("managed/rans_tables.toml")
        );
        assert_eq!(
            projected.managed_paths.soranet_pow_revocation_store_path,
            PathBuf::from("managed/soranet/revocations.norito")
        );
        let (parsed, replaced) = load_node_config(&config_path, false).expect("parse config");
        assert!(!replaced);
        assert_eq!(
            projected.da_proof_policies,
            iroha_core::da::proof_policy_bundle(&parsed.nexus.lane_config)
        );
        assert_eq!(
            projected.genesis_confidential_policy_hash,
            iroha_core::state::default_genesis_confidential_policy_hash()
        );
    }
    #[test]
    fn signing_accepts_only_selected_manifest_and_exact_unresolved_sentinel() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let chain_id = ChainId::from("managed-signing-fixture");
        let (manifest, genesis_key) = prepared_manifest(chain_id.clone());
        let manifest_path = directory.path().join("genesis.json");
        let config_path = write_node_config(
            directory.path(),
            &chain_id,
            manifest.chain_discriminant(),
            genesis_key.public_key(),
            UNRESOLVED_GENESIS_EXPECTED_HASH,
        );
        let manifest = bind_fixture_policy(manifest, &genesis_key, &config_path);
        fs::write(
            &manifest_path,
            norito::json::to_json_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");
        let (parsed, replaced) =
            load_node_config(&config_path, true).expect("parse sentinel config");
        assert!(replaced);
        let expected_da = iroha_core::da::proof_policy_bundle(&parsed.nexus.lane_config);
        let expected_confidential = iroha_core::state::default_genesis_confidential_policy_hash();
        let error = sign_prepared_genesis_from_config(
            &manifest_path,
            &config_path,
            &genesis_key,
            Some(SumeragiConsensusMode::Npos),
        )
        .expect_err("unexpected consensus mode must fail closed");
        assert!(error.to_string().contains("differs from expected mode"));
        let block = sign_prepared_genesis_from_config(
            &manifest_path,
            &config_path,
            &genesis_key,
            Some(SumeragiConsensusMode::Permissioned),
        )
        .expect("sign selected manifest");
        assert!(
            fs::read_to_string(&config_path)
                .expect("read original config")
                .contains(UNRESOLVED_GENESIS_EXPECTED_HASH),
            "signing must not rewrite the unresolved sentinel on disk"
        );
        assert_eq!(block.da_proof_policies(), Some(&expected_da));
        assert_eq!(
            block
                .header()
                .confidential_features()
                .and_then(|features| features.zk_policy_hash),
            Some(expected_confidential)
        );
        let wire = block.encode_wire().expect("encode signed block");
        let validated = validate_prepared_genesis_for_startup(
            &wire,
            &manifest,
            genesis_key.public_key(),
            block.hash(),
            &chain_id,
        )
        .expect("run composed startup validation");
        assert_eq!(validated.block(), &block);
        let other_manifest = directory.path().join("other-genesis.json");
        fs::copy(&manifest_path, &other_manifest).expect("copy manifest");
        let error = sign_prepared_genesis_from_config(
            &other_manifest,
            &config_path,
            &genesis_key,
            Some(SumeragiConsensusMode::Permissioned),
        )
        .expect_err("unselected manifest path must fail closed");
        assert!(
            error
                .to_string()
                .contains("differs from configured manifest")
        );
    }
    #[test]
    fn generated_preparation_binds_policy_once_without_weakening_prepared_signing() {
        let directory = tempfile::tempdir().expect("temporary generation");
        let chain_id = ChainId::from("generated-policy-fixture");
        let (manifest, key) = prepared_manifest(chain_id.clone());
        let provisional = manifest.sumeragi_context_parameters();
        assert!(manifest.consensus_fingerprint().is_none());
        let manifest_path = directory.path().join("genesis.json");
        let original = norito::json::to_json_pretty(&manifest).unwrap();
        fs::write(&manifest_path, &original).unwrap();
        let config_path = write_node_config(
            directory.path(),
            &chain_id,
            manifest.chain_discriminant(),
            key.public_key(),
            UNRESOLVED_GENESIS_EXPECTED_HASH,
        );
        let mode = Some(SumeragiConsensusMode::Permissioned);
        let strict = sign_prepared_genesis_from_config(&manifest_path, &config_path, &key, mode)
            .unwrap_err();
        assert!(matches!(
            strict
                .downcast_ref::<Box<iroha_core::block::BlockValidationError>>()
                .map(Box::as_ref),
            Some(iroha_core::block::BlockValidationError::GenesisPolicyMismatch { .. })
        ));
        let (bound, block) =
            prepare_unpublished_genesis_from_config(&manifest_path, &config_path, &key, mode)
                .unwrap();
        assert_ne!(
            bound.sumeragi_context_parameters().execution_policy_hash,
            provisional.execution_policy_hash
        );
        assert_ne!(
            bound.sumeragi_context_parameters().nexus_amx_context_hash,
            provisional.nexus_amx_context_hash
        );
        assert_eq!(fs::read_to_string(&manifest_path).unwrap(), original);
        validate_prepared_genesis_for_startup(
            &block.encode_wire().unwrap(),
            &bound,
            key.public_key(),
            block.hash(),
            &chain_id,
        )
        .unwrap();

        // Publication of the exact generated manifest enables the unchanged strict signer.
        fs::write(
            &manifest_path,
            norito::json::to_json_pretty(&bound).unwrap(),
        )
        .unwrap();
        sign_prepared_genesis_from_config(&manifest_path, &config_path, &key, mode).unwrap();
        let resolved = write_node_config(
            directory.path(),
            &chain_id,
            manifest.chain_discriminant(),
            key.public_key(),
            CONFIGURED_HASH,
        );
        let error = prepare_unpublished_genesis_from_config(&manifest_path, &resolved, &key, mode)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires the unresolved network identity")
        );
    }

    #[test]
    fn resolved_hash_and_expected_chain_are_enforced() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let chain_id = ChainId::from("managed-binding-fixture");
        let (manifest, genesis_key) = prepared_manifest(chain_id.clone());
        let manifest_path = directory.path().join("genesis.json");
        let config_path = write_node_config(
            directory.path(),
            &chain_id,
            manifest.chain_discriminant(),
            genesis_key.public_key(),
            CONFIGURED_HASH,
        );
        let manifest = bind_fixture_policy(manifest, &genesis_key, &config_path);
        fs::write(
            &manifest_path,
            norito::json::to_json_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");
        let error = sign_prepared_genesis_from_config(
            &manifest_path,
            &config_path,
            &genesis_key,
            Some(SumeragiConsensusMode::Permissioned),
        )
        .expect_err("resolved hash must bind the produced block");
        assert!(error.to_string().contains("configuration requires"));
        let near_miss = format!("{UNRESOLVED_GENESIS_EXPECTED_HASH} ");
        let config_path = write_node_config(
            directory.path(),
            &chain_id,
            manifest.chain_discriminant(),
            genesis_key.public_key(),
            &near_miss,
        );
        let error = sign_prepared_genesis_from_config(
            &manifest_path,
            &config_path,
            &genesis_key,
            Some(SumeragiConsensusMode::Permissioned),
        )
        .expect_err("a near-miss unresolved sentinel must not be substituted");
        assert!(error.to_string().contains("parse node configuration"));
        let error = validate_prepared_genesis_for_startup(
            &[],
            &manifest,
            genesis_key.public_key(),
            HashOf::from_untyped_unchecked(Hash::new(b"unused expected hash")),
            &ChainId::from("other-chain"),
        )
        .expect_err("wrong chain must fail before bundle decoding");
        assert!(error.to_string().contains("differs from expected chain"));
    }
}
