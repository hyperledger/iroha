//! Independently signed, owner-operated private-root preparation.

use super::*;
use crate::managed::{Error, LocalnetPorts, ManagedContext, ManagedPeer, PreparedLocalnet};
use iroha_data_model::{
    NetworkId,
    block::consensus::{PrivateRootFeePolicy, SumeragiRootScope},
    hijiri::HijiriParametersV1,
    parameter::{Parameter, Parameters},
    sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1},
};
use norito::{JsonDeserialize, JsonSerialize};

const PREPARED: &str = "private-root-prepared.json";

/// Exact parent SNS identity for an independently operated private ledger.
///
/// The caller must authenticate parent SNS ownership and admission before claiming attachment.
/// Local preparation may precede that reservation; decoding or validating this value proves
/// structural identity only. The canonical SNS name hash derives the child dataspace identifier;
/// no physical parent lane or catalog entry is created. The child's own catalog uses that exact
/// name hash independently of child genesis.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct PrivateRootSpec {
    /// Genesis-bound identity of the parent network.
    pub parent_network_id: NetworkId,
    /// Full-width identifier derived from the canonical parent SNS alias name hash.
    pub dataspace_id: DataSpaceId,
    /// Canonical namespace to reserve in parent SNS before registration.
    pub dataspace_alias: String,
}

impl PrivateRootSpec {
    /// Validate the exact parent SNS alias/hash/identifier binding.
    ///
    /// # Errors
    /// Rejects reserved identity, malformed aliases and a hash deriving a different identifier.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            DataSpaceId::from_hash(&self.name_hash()?) == self.dataspace_id,
            "private-root dataspace identifier differs from its canonical SNS alias"
        );
        DomainId::parse_fully_qualified(&format!("app.{}", self.dataspace_alias))?;
        self.scope().validate()?;
        Ok(())
    }

    fn name_hash(&self) -> Result<[u8; 32]> {
        let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, &self.dataspace_alias)?;
        ensure!(
            selector.normalized_label() == self.dataspace_alias
                && self.dataspace_alias != "universal",
            "private-root alias must be canonical and cannot be universal"
        );
        Ok(selector.name_hash())
    }

    /// Immutable native root identity embedded in the signed child genesis.
    #[must_use]
    pub const fn scope(&self) -> SumeragiRootScope {
        SumeragiRootScope::Dataspace {
            parent_network_id: self.parent_network_id,
            dataspace_id: self.dataspace_id,
        }
    }
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RetainedPrivateRoot {
    spec: PrivateRootSpec,
    prepared: PreparedLocalnet,
}

impl PreparedLocalnet {
    /// Derive the public child registration from the original retained signed private genesis.
    ///
    /// This authenticates the generated manifest, scope, owner and validator configuration,
    /// then executes genesis through the native startup path in isolated temporary storage.
    /// The result commitment comes from that original local execution, without trusting a
    /// Torii response or touching the running validators' storage. Parent authorization and
    /// independently verified parent inclusion remain separate requirements.
    ///
    /// # Errors
    /// Rejects a global generation, changed retained artifacts, invalid signed genesis or any
    /// failure to reproduce its native execution and compact registration.
    pub fn load_private_registration(
        &self,
    ) -> crate::managed::Result<iroha_data_model::private_dataspace::PrivateDataspaceRegistration>
    {
        let invalid = || Error::Invalid("retained private registration binding is invalid".into());
        let root = iroha_fs::PrivateDirectory::open(
            self.context.client_config.parent().ok_or_else(invalid)?,
        )?;
        let retained: RetainedPrivateRoot =
            norito::json::from_slice(&root.read(PREPARED, 1024 * 1024)?).map_err(|_| invalid())?;
        if retained.prepared != *self {
            return Err(invalid());
        }
        retained.spec.validate().map_err(|_| invalid())?;
        verify_retained(root.path(), self, &retained.spec)?;
        let manifest_bytes = root.read(
            "genesis.json",
            iroha_genesis::GENESIS_MANIFEST_JSON_MAX_BYTES_V1,
        )?;
        validate_genesis_manifest_json(&manifest_bytes).map_err(|_| invalid())?;
        let manifest = RawGenesisTransaction::from_json_slice_at_path(
            &manifest_bytes,
            root.path().join("genesis.json"),
        )
        .map_err(|_| invalid())?;
        let signed = root.read("genesis.signed.nrt", SIGNED_GENESIS_MAX_BYTES_V1)?;
        let config_bytes = root.read("peer0.toml", 1024 * 1024)?;
        let config = parse_private_peer_config(
            std::str::from_utf8(&config_bytes).map_err(|_| invalid())?,
            Some(&root.path().join("peer0.toml")),
        )
        .map_err(|_| invalid())?;
        let registration = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("iroha-private-registration".into())
                .stack_size(16 * 1024 * 1024)
                .spawn_scoped(scope, || -> Result<_> {
                    use crate::genesis::staging::{
                        configured_initial_genesis_state, ensure_peer_config_matches_manifest,
                        staged_genesis_chain_discriminant,
                    };
                    let _discriminant = staged_genesis_chain_discriminant(&manifest);
                    ensure_peer_config_matches_manifest(&config, &manifest)?;
                    let validated = iroha_genesis::validate_prepared_genesis_bundle(
                        &signed,
                        &manifest,
                        &config.genesis.public_key,
                        config.genesis.expected_hash,
                    )?;
                    let genesis = iroha_genesis::GenesisBlock(validated.block().clone());
                    let (state, _storage, authority) =
                        configured_initial_genesis_state(&manifest, Some(&config), &genesis)?;
                    iroha_core::sumeragi::startup::apply_genesis(
                        &state,
                        genesis.0,
                        &authority,
                        iroha_data_model::parameter::system::ConsensusMode::Permissioned,
                        None,
                    )?;
                    Ok(
                        iroha_core::sumeragi::private_dataspace_export::registration(
                            &state.view(),
                        )?,
                    )
                })?
                .join()
                .map_err(|_| invalid())?
                .map_err(|error| {
                    Error::Invalid(format!(
                        "retained private genesis execution failed: {error:#}"
                    ))
                })
        })?;
        if registration.scope != retained.spec.scope()
            || registration.child_network_id.to_string() != self.context.network_id
            || registration.child_chain_id.to_string() != self.context.chain_id
        {
            return Err(invalid());
        }
        root.revalidate()?;
        Ok(registration)
    }
}

/// Prepare four loopback validators for an independent, owner-operated private root.
///
/// This only prepares local artifacts. It neither registers with the parent nor starts a node.
/// The generated ledger owner is returned in the context and retained for parent registration.
/// Reopening a completed generation returns that exact identity. An interrupted incomplete
/// generation is retained and rejected; it is never silently replaced with new signing keys.
/// The managed engine wraps this low-level renderer in whole-generation atomic publication,
/// discarding only its unpublished staging directory before another preparation attempt.
///
/// # Errors
/// Rejects unsafe custody, conflicting identity, incomplete preparation or genuine Core genesis
/// execution failure. Parent admission and runtime readiness remain separate required steps.
pub fn prepare_private_root(
    name: &str,
    directory: &Path,
    ports: &LocalnetPorts,
    spec: &PrivateRootSpec,
) -> crate::managed::Result<PreparedLocalnet> {
    prepare_private_root_at(name, directory, ports, spec, None)
}

pub(crate) fn prepare_private_root_at(
    name: &str,
    directory: &Path,
    ports: &LocalnetPorts,
    spec: &PrivateRootSpec,
    publication_root: Option<&Path>,
) -> crate::managed::Result<PreparedLocalnet> {
    prepare_private_root_selected(name, directory, ports, spec, publication_root, None)
}

pub(crate) fn prepare_private_root_with_amx_at(
    name: &str,
    directory: &Path,
    ports: &LocalnetPorts,
    spec: &PrivateRootSpec,
    publication_root: Option<&Path>,
    sources: &crate::bootstrap::ParentBootstrapSources,
) -> crate::managed::Result<PreparedLocalnet> {
    prepare_private_root_selected(
        name,
        directory,
        ports,
        spec,
        publication_root,
        Some(sources),
    )
}

fn prepare_private_root_selected(
    name: &str,
    directory: &Path,
    ports: &LocalnetPorts,
    spec: &PrivateRootSpec,
    publication_root: Option<&Path>,
    amx: Option<&crate::bootstrap::ParentBootstrapSources>,
) -> crate::managed::Result<PreparedLocalnet> {
    spec.validate().map_err(|error| {
        Error::Invalid(format!("private-root SNS identity is invalid: {error}"))
    })?;
    if directory.exists() {
        let root = iroha_fs::PrivateDirectory::open(directory)?;
        match root.read_optional(PREPARED, 1024 * 1024)? {
            Some(bytes) => {
                if publication_root.is_some() {
                    return Err(Error::Invalid(
                        "publication stage already contains a prepared identity".into(),
                    ));
                }
                let retained: RetainedPrivateRoot = norito::json::from_slice(&bytes)
                    .map_err(|_| Error::Invalid("retained private root is invalid".into()))?;
                if retained.spec != *spec || retained.prepared.context.name != name {
                    return Err(Error::Invalid(
                        "retained private-root identity differs".into(),
                    ));
                }
                verify_retained(root.path(), &retained.prepared, spec)?;
                if let Some(sources) = amx {
                    sources
                        .require_signed_generation(&retained.prepared)
                        .map_err(|error| Error::Invalid(error.to_string()))?;
                }
                return Ok(retained.prepared);
            }
            None => {}
        }
    }
    let mut prepared = prepare_fresh(name, directory, ports, spec, publication_root, amx)
        .map_err(|error| Error::Invalid(format!("private-root preparation failed: {error:#}")))?;
    verify_retained(&directory.canonicalize()?, &prepared, spec)?;
    if let Some(root) = publication_root {
        prepared.context.client_config = root.join("client.toml");
        for (index, peer) in prepared.peers.iter_mut().enumerate() {
            peer.config_path = root.join(format!("peer{index}.toml"));
        }
    }
    let retained = RetainedPrivateRoot {
        spec: spec.clone(),
        prepared: prepared.clone(),
    };
    let root = iroha_fs::PrivateDirectory::open(directory)?;
    root.write_atomic(
        PREPARED,
        norito::json::to_json(&retained)
            .map_err(|_| Error::Invalid("cannot encode prepared private root".into()))?
            .as_bytes(),
        iroha_fs::PublishMode::CreateNew,
    )?;
    Ok(prepared)
}

pub(crate) fn verify_retained(
    root: &Path,
    prepared: &PreparedLocalnet,
    spec: &PrivateRootSpec,
) -> crate::managed::Result<()> {
    // Reopening through a desktop or library entry point may precede fresh generation.
    // The shared loader owns the built-in instruction registry required by signed decoding.
    init_instruction_registry();
    let invalid = || Error::Invalid("retained private-root artifact binding differs".into());
    if prepared.service_profile != LocalnetServiceProfile::Standard
        || prepared.context.client_config != root.join("client.toml")
        || prepared.context.dataspace_id != spec.dataspace_id.as_u64()
        || prepared.context.dataspace_alias != spec.dataspace_alias
        || prepared.peers.len() != 4
        || prepared
            .peers
            .iter()
            .enumerate()
            .any(|(index, peer)| peer.config_path != root.join(format!("peer{index}.toml")))
    {
        return Err(invalid());
    }
    let client = prepared.context.load_client_config()?;
    prepared.load_operator_key_pair()?;
    verify_private_credentials(prepared, spec)?;
    let bytes = iroha_fs::read_private(
        &root.join("genesis.signed.nrt"),
        SIGNED_GENESIS_MAX_BYTES_V1,
    )?;
    let block =
        iroha_data_model::block::decode_framed_signed_block(&bytes).map_err(|_| invalid())?;
    let metadata = iroha_data_model::sumeragi_finality::authenticated_genesis(&block)
        .map_err(|_| invalid())?
        .metadata();
    service_authorities::validate_signed_profile(prepared, &block, &metadata)?;
    if metadata.sumeragi_context.root_scope != spec.scope()
        || NetworkId::from_genesis_hash(block.hash()).to_string() != prepared.context.network_id
    {
        return Err(invalid());
    }
    let management = Permission::from(CanManageSmartContractCode);
    let mut found_owner = false;
    let mut found_fees = false;
    let mut found_gas_custody = false;
    // The signed child account literal belongs to its retained client profile, even when a
    // parent-network caller carries a different ambient I105 discriminant.
    let expected_gas = localnet_gas_account_id(client.key_pair.public_key())
        .to_i105_for_discriminant(client.account_chain_discriminant)
        .map_err(|_| invalid())?;
    let expected_fees = private_fee_policy(spec).map_err(|_| invalid())?;
    for transaction in block.external_transactions() {
        if transaction.authority() != &client.account {
            return Err(invalid());
        }
        for instruction in transaction.instructions().explicit_instructions() {
            if let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>()
                && let Parameter::Custom(parameter) = set_parameter.inner()
                && parameter.id() == &localnet_custom_parameter_id("ivm_gas_tech_account_id")
            {
                let literal: String = parameter
                    .payload()
                    .try_into_any_norito()
                    .map_err(|_| invalid())?;
                if found_gas_custody || literal != expected_gas {
                    return Err(invalid());
                }
                found_gas_custody = true;
            }
            if let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>()
                && let Parameter::Custom(parameter) = set_parameter.inner()
                && parameter.id() == &PrivateRootFeePolicy::parameter_id()
            {
                let policy = PrivateRootFeePolicy::from_custom_parameter(parameter)
                    .map_err(|_| invalid())?;
                if found_fees || policy != expected_fees {
                    return Err(invalid());
                }
                found_fees = true;
            }
            if let Some(GrantBox::Permission(grant)) =
                instruction.as_any().downcast_ref::<GrantBox>()
                && grant.object() == &management
            {
                if found_owner || grant.destination() != &client.account {
                    return Err(invalid());
                }
                found_owner = true;
            }
        }
    }
    if !found_owner || !found_fees || !found_gas_custody {
        return Err(invalid());
    }
    Ok(())
}

fn verify_private_credentials(
    prepared: &PreparedLocalnet,
    spec: &PrivateRootSpec,
) -> crate::managed::Result<()> {
    let invalid = || Error::Invalid("private-root listener credential binding is invalid".into());
    let client = iroha_fs::read_private(&prepared.context.client_config, 1024 * 1024)?;
    let client = crate::secret_toml::Table::new(
        crate::secret_toml::parse_table(
            std::str::from_utf8(&client).map_err(|_| invalid())?,
            "private-root client",
        )
        .map_err(|_| invalid())?,
    );
    let token = client
        .get("api_token")
        .and_then(toml::Value::as_str)
        .ok_or_else(invalid)?;
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid());
    }
    for peer in &prepared.peers {
        let bytes = iroha_fs::read_private(&peer.config_path, 1024 * 1024)?;
        let table = crate::secret_toml::Table::new(
            crate::secret_toml::parse_table(
                std::str::from_utf8(&bytes).map_err(|_| invalid())?,
                "private-root validator",
            )
            .map_err(|_| invalid())?,
        );
        let genesis_public: iroha_crypto::PublicKey = table
            .get("genesis")
            .and_then(|value| value.get("public_key"))
            .and_then(toml::Value::as_str)
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let gas_account = localnet_gas_account_id(&genesis_public)
            .to_i105_for_discriminant(
                iroha_config::parameters::defaults::common::chain_discriminant(),
            )
            .map_err(|_| invalid())?;
        let expected = private_fee_configuration(
            &private_fee_policy(spec).map_err(|_| invalid())?,
            &gas_account,
        );
        if table.get("nexus").and_then(|value| value.get("fees"))
            != Some(&toml::Value::Table(expected))
        {
            return Err(invalid());
        }
        let torii = table
            .get("torii")
            .and_then(toml::Value::as_table)
            .ok_or_else(invalid)?;
        if torii
            .get("require_api_token")
            .and_then(toml::Value::as_bool)
            != Some(true)
            || !matches!(torii.get("api_tokens").and_then(toml::Value::as_array), Some(tokens) if tokens.len() == 1 && tokens[0].as_str() == Some(token))
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn prepare_fresh(
    name: &str,
    directory: &Path,
    ports: &LocalnetPorts,
    spec: &PrivateRootSpec,
    publication_root: Option<&Path>,
    amx: Option<&crate::bootstrap::ParentBootstrapSources>,
) -> Result<PreparedLocalnet> {
    init_instruction_registry();
    // Parent SDK work can carry a different address-rendering scope on this thread. A fresh
    // local child owns its default node profile and must not inherit the parent's I105 prefix.
    let _discriminant = ChainDiscriminantGuard::enter(
        iroha_config::parameters::defaults::common::chain_discriminant(),
    );
    let root = custody::prepare_empty_private_directory(directory)?;
    let chain = resolve_localnet_chain_id(None)?;
    let hosts = CanonicalHost::parse("127.0.0.1", "private-root loopback")?;
    let peers = build_peers(4, None, ports.base_api, ports.base_p2p)?;
    let owner = localnet_ephemeral_identity(None, b"private-root-owner")?;
    let operator = localnet_ephemeral_identity(None, b"private-root-http-operator")?;
    let mut token_bytes = Zeroizing::new([0_u8; 32]);
    OsRng
        .try_fill_bytes(token_bytes.as_mut())
        .map_err(|error| eyre!("private-root token generation failed: {error}"))?;
    let api_token = Zeroizing::new(hex::encode(&*token_bytes));
    let runtime = root.join(LOCALNET_RUNTIME_DIRECTORY);
    custody::create_directory(&runtime)?;
    custody::write(
        &runtime.join(LOCALNET_OPERATOR_SIGNER_KEY_FILE),
        Zeroizing::new(format!("{}\n", operator.private_key.as_str())).as_bytes(),
    )?;
    custody::write(
        &runtime.join(LOCALNET_LEDGER_SIGNER_KEY_FILE),
        Zeroizing::new(format!("{}\n", owner.private_key.as_str())).as_bytes(),
    )?;
    prepare_managed_node_directories(&root, peers.len())?;
    // This owner creates the private domain and its restricted assets in original genesis.
    // Retain one identity for genesis, later private transactions and parent registration;
    // assigning the domain to another signer would violate ordinary asset ownership checks.
    let genesis_public = owner.public_key.clone();
    let genesis_private: ExposedPrivateKey = owner
        .private_key
        .parse()
        .map_err(|_| eyre!("generated private owner key is invalid"))?;
    write_genesis_key_files(
        &root.join(GENESIS_PUBLIC_KEY_FILE),
        &root.join(GENESIS_PRIVATE_KEY_FILE),
        &genesis_public,
        &genesis_private,
    )?;
    let gas = localnet_gas_account_id(&genesis_public);
    let genesis = private_genesis(
        spec,
        &chain,
        &genesis_public,
        &owner.account_id,
        &gas,
        &peers,
    )?;
    let genesis = service_authorities::append_profile(
        genesis,
        LocalnetServiceProfile::Standard,
        &owner.account_id,
    )?;
    let genesis = match amx {
        Some(sources) => sources.append_to(genesis)?,
        None => genesis,
    };
    copy_rans_tables(&root)?;
    let signed_path = root.join("genesis.signed.nrt");
    let trusted = peers
        .iter()
        .map(|peer| format!("{}@{}", peer.public_key, hosts.addr_literal(peer.p2p_port)))
        .collect::<Vec<_>>();
    let urls = peers
        .iter()
        .map(|peer| hosts.torii_url(peer.api_port))
        .collect::<Vec<_>>();
    let bls = peers
        .iter()
        .map(|peer| BlsEntry {
            bls_pk: peer.bls_public_key.to_string(),
            pop_hex: format!("0x{}", hex::encode(&peer.bls_pop)),
        })
        .collect::<Vec<_>>();
    let owner_literal = owner.account_id.to_string();
    let gas_literal = gas.to_string();
    let render = |render_root: &Path, index: usize, identity| -> Result<Zeroizing<String>> {
        let paths = LocalnetPeerStoragePaths::new(render_root, index);
        let raw = render_peer_config(
            &peers[index],
            &trusted,
            // Peer telemetry performs anonymous HTTP reads. A private listener requires owner
            // credentials on every route, so leave that optional public monitor unconfigured.
            &[],
            &genesis_public,
            &render_root.join("genesis.signed.nrt"),
            identity,
            &bls,
            &paths,
            Some(&render_root.join(LOCALNET_RANS_TABLE_RELATIVE_PATH)),
            &chain,
            None,
            (&hosts, &hosts),
            RenderPeerFeatures {
                mcp_enabled: false,
                npos_bootstrap: false,
                taira: false,
                operator_account: &owner_literal,
                operator_public_key: &operator.public_key,
                onboarding_account: &owner_literal,
                runtime: None,
            },
            None,
            None,
            None,
            &gas_literal,
            localnet_tx_gossip_overrides(LOCALNET_PIPELINE_TIME_MS),
            None,
            None,
            LOCALNET_QUEUE_CAPACITY,
        );
        let configured = private_peer_config(&raw, spec, &api_token, &gas_literal)?;
        managed_peer_config(&configured, &managed_node_dir(render_root, index))
    };
    let bootstrap = render(
        &root,
        0,
        LocalnetGenesisIdentitySource::BootstrapInline(HashOf::from_untyped_unchecked(Hash::new(
            b"private-root staged policy binding",
        ))),
    )?;
    let config = parse_private_peer_config(&bootstrap, Some(&root.join("peer0.toml")))?;
    let expected = write_genesis(GenesisWriteContext {
        creation_time_ms: None,
        manifest: &genesis,
        public_key: &genesis_public,
        private_key: genesis_private,
        config: &config,
        chain_discriminant: None,
        json_path: &root.join("genesis.json"),
        signed_path: &signed_path,
        policies: GenesisConsensusPolicies {
            da_proof_policies: Some(resolve_localnet_da_proof_policies(&config)),
            confidential_policy_hash: iroha_core::state::default_genesis_confidential_policy_hash(),
        },
    })?;
    write_and_validate_genesis_expected_hash(
        &root.join(GENESIS_EXPECTED_HASH_FILE),
        &signed_path,
        expected,
    )?;
    for index in 0..4 {
        let paths = LocalnetPeerStoragePaths::new(&root, index);
        for path in [
            &paths.kura,
            &paths.state,
            &paths.tiered_state,
            &paths.da_store,
        ] {
            custody::ensure_directory(path)?;
        }
        let path = root.join(format!("peer{index}.toml"));
        let rendered = render(&root, index, LocalnetGenesisIdentitySource::PublishedFile)?;
        let parsed = parse_private_peer_config(&rendered, Some(&path))?;
        ensure!(
            parsed.genesis.expected_hash == expected,
            "private-root genesis binding changed"
        );
        let rendered = match publication_root {
            Some(root) => render(root, index, LocalnetGenesisIdentitySource::PublishedFile)?,
            None => rendered,
        };
        custody::write(&path, rendered.as_bytes())?;
    }
    write_client_config(&root, ports.base_api, &hosts, &chain, None, &owner, None)?;
    let client_path = root.join("client.toml");
    let client = iroha_fs::read_private(&client_path, 1024 * 1024)?;
    let mut table = crate::secret_toml::Table::new(crate::secret_toml::parse_table(
        std::str::from_utf8(&client)?,
        "private-root client",
    )?);
    table.remove("basic_auth");
    table.insert(
        "api_token".into(),
        toml::Value::String(api_token.as_str().into()),
    );
    custody::replace(
        &client_path,
        Zeroizing::new(toml::to_string(&*table)?).as_bytes(),
    )?;
    custody::validate_private_tree(&root, &[])?;
    Ok(PreparedLocalnet {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        context: ManagedContext {
            name: name.into(),
            chain_id: chain,
            network_id: NetworkId::from_genesis_hash(expected).to_string(),
            account_id: owner_literal,
            dataspace_id: spec.dataspace_id.as_u64(),
            dataspace_alias: spec.dataspace_alias.clone(),
            torii_url: urls[0].clone(),
            client_config: client_path,
        },
        peers: (0..4)
            .map(|index| ManagedPeer {
                config_path: root.join(format!("peer{index}.toml")),
                torii_url: urls[index].clone(),
                log_name: format!("peer{index}.log"),
            })
            .collect(),
    })
}

fn parse_private_peer_config(rendered: &str, path: Option<&Path>) -> Result<actual::Root> {
    let mut config = parse_localnet_peer_config(rendered, path)?;
    // Match the native worker's required `--sora` launch profile before deriving any signed
    // execution-policy commitment. Explicit private geometry is preserved by this owner.
    let table = crate::secret_toml::Table::new(crate::secret_toml::parse_table(
        rendered,
        "private-root validator",
    )?);
    iroha_config::sora_profile::SoraProfileSelection::from_table(&table).apply(&mut config);
    Ok(config)
}

fn private_peer_config(
    raw: &str,
    spec: &PrivateRootSpec,
    api_token: &str,
    gas_account: &str,
) -> Result<Zeroizing<String>> {
    use toml::{Table, Value};
    let mut root = crate::secret_toml::Table::new(crate::secret_toml::parse_table(
        raw,
        "private-root validator",
    )?);
    let nexus = root
        .get_mut("nexus")
        .and_then(Value::as_table_mut)
        .ok_or_else(|| eyre!("private-root Nexus config absent"))?;
    let mut dataspace = Table::new();
    dataspace.insert("alias".into(), Value::String(spec.dataspace_alias.clone()));
    // The child's physical catalog uses the genuine canonical SNS name hash. Passing the
    // complete hash avoids signed TOML integer conversion truncating the full-width ID.
    dataspace.insert(
        "manifest_hash".into(),
        Value::String(hex::encode(spec.name_hash()?)),
    );
    dataspace.insert("fault_tolerance".into(), Value::Integer(1));
    nexus.insert(
        "dataspace_catalog".into(),
        Value::Array(vec![Value::Table(dataspace)]),
    );
    let mut lane = Table::new();
    lane.insert("index".into(), Value::Integer(0));
    lane.insert("alias".into(), Value::String(spec.dataspace_alias.clone()));
    lane.insert(
        "dataspace".into(),
        Value::String(spec.dataspace_alias.clone()),
    );
    lane.insert("visibility".into(), Value::String("restricted".into()));
    lane.insert("storage".into(), Value::String("full_replica".into()));
    nexus.insert("lane_count".into(), Value::Integer(1));
    nexus.insert(
        "lane_catalog".into(),
        Value::Array(vec![Value::Table(lane)]),
    );
    let mut routing = Table::new();
    routing.insert("default_lane".into(), Value::Integer(0));
    routing.insert(
        "default_dataspace".into(),
        Value::String(spec.dataspace_alias.clone()),
    );
    nexus.insert("routing_policy".into(), Value::Table(routing));
    nexus.insert(
        "fees".into(),
        Value::Table(private_fee_configuration(
            &private_fee_policy(spec)?,
            gas_account,
        )),
    );
    let torii = root
        .entry("torii")
        .or_insert_with(|| Value::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| eyre!("private-root Torii config is invalid"))?;
    torii.insert("require_api_token".into(), Value::Boolean(true));
    torii.insert(
        "api_tokens".into(),
        Value::Array(vec![Value::String(api_token.into())]),
    );
    Ok(Zeroizing::new(toml::to_string(&*root)?))
}

pub(crate) fn private_fee_policy(spec: &PrivateRootSpec) -> Result<PrivateRootFeePolicy> {
    let policy = PrivateRootFeePolicy {
        asset_definition_id: AssetDefinitionId::derive_from_components(
            DomainId::parse_fully_qualified(&format!("app.{}", spec.dataspace_alias))?,
            "gas".parse()?,
        ),
        base_fee: "0.001".parse()?,
        per_byte_fee: Quantity::zero(),
        per_instruction_fee: "0.001".parse()?,
        per_gas_unit_fee: "0.00005".parse()?,
    };
    policy.validate()?;
    Ok(policy)
}

fn private_fee_configuration(policy: &PrivateRootFeePolicy, gas_account: &str) -> toml::Table {
    use toml::Value;
    // Private execution burns the signed scoped fee. These required node-local sink fields
    // retain the generated local account, never a public-network treasury or owner credential.
    [
        ("fee_asset_id", policy.asset_definition_id.to_string()),
        ("base_fee", policy.base_fee.to_string()),
        ("per_byte_fee", policy.per_byte_fee.to_string()),
        (
            "per_instruction_fee",
            policy.per_instruction_fee.to_string(),
        ),
        ("per_gas_unit_fee", policy.per_gas_unit_fee.to_string()),
        ("settlement_mode", "direct".into()),
        ("fee_sink_account_id", gas_account.into()),
        ("sponsor_vault_custody_account_id", gas_account.into()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), Value::String(value)))
    .collect()
}

fn private_genesis(
    spec: &PrivateRootSpec,
    chain: &str,
    genesis_key: &iroha_crypto::PublicKey,
    owner: &AccountId,
    gas: &AccountId,
    peers: &[Peer],
) -> Result<RawGenesisTransaction> {
    let genesis_authority = AccountId::new(genesis_key.clone());
    ensure!(
        &genesis_authority == owner,
        "private genesis signer must be the retained private owner"
    );
    let domain = DomainId::parse_fully_qualified(&format!("app.{}", spec.dataspace_alias))?;
    let mut context = SumeragiGenesisContextParameters::recommended();
    context.root_scope = spec.scope();
    let mut builder = GenesisBuilder::new_without_executor(chain.parse()?, PathBuf::from("."))
        .with_sumeragi_context_parameters(context);
    let mut parameters = Parameters::default();
    parameters.set_parameter(localnet_gas_custody_parameter(gas));
    parameters.set_parameter(Parameter::Custom(
        private_fee_policy(spec)?.into_custom_parameter()?,
    ));
    parameters.set_parameter(Parameter::Custom(
        HijiriParametersV1::first_release_genesis().into_custom_parameter(),
    ));
    for parameter in parameters.parameters() {
        builder = builder.append_parameter(parameter);
    }
    // The canonical initial genesis state already registers its signing authority.
    builder = builder.append_instruction(Register::account(Account::new(gas.clone())));
    for peer in peers {
        builder = builder.append_instruction(Register::account(Account::new(
            peer.validator_account_id(false),
        )));
    }
    let temporary_role: RoleId = "private_root_genesis_alias_setup".parse()?;
    builder = builder
        .next_transaction()
        .append_instruction(Register::role(
            Role::new(temporary_role.clone(), genesis_authority)
                .add_permission(CanManageAccountAlias {
                    scope: AccountAliasPermissionScope::Dataspace(spec.dataspace_id),
                })
                .add_permission(CanManageAccountAlias {
                    scope: AccountAliasPermissionScope::Domain(domain.clone()),
                }),
        ));
    let quote = AliasQuoteGuardV1 {
        expected_policy_version: LOCALNET_ALIAS_SETUP_POLICY_VERSION,
        expected_payment_asset: AssetDefinitionId::derive_from_components(
            domain.clone(),
            "gas".parse()?,
        ),
        max_amount: LOCALNET_PRIVATE_SNS_LEASE_PAYMENT
            .parse()
            .map_err(|error| eyre!("private bootstrap quote: {error}"))?,
        valid_until_ms: u64::MAX,
    };
    for intent in [
        AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new(spec.dataspace_alias.parse()?, spec.dataspace_id),
            owner: owner.clone(),
        }),
        AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(domain.clone(), spec.dataspace_id),
            owner: owner.clone(),
        }),
    ] {
        builder = builder.append_instruction(EnsureAlias::new(
            intent,
            AliasLeaseAcquisitionV1::new(1, None),
            quote.clone(),
        ));
    }
    builder = builder
        .append_instruction(Unregister::role(temporary_role))
        .next_transaction();
    // Sample holdings belong to this root's sole dataspace. No global balance bucket or
    // public-network fee asset is created by the private development recipe.
    for name in ["sample", "gas"] {
        let definition = AssetDefinitionId::derive_from_components(domain.clone(), name.parse()?);
        builder = builder
            .append_instruction(Register::asset_definition(AssetDefinition::new(
                definition.clone(),
                name.to_owned(),
                NumericSpec::fractional(LOCALNET_FEE_ASSET_SCALE),
                iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
                Some(domain.clone()),
            )))
            .append_instruction(SetAssetDefinitionAlias::bind(
                definition.clone(),
                format!("{name}#app.{}", spec.dataspace_alias).parse()?,
                None,
            ))
            .append_instruction(Mint::asset_quantity(
                LOCALNET_REQUESTED_ASSET_INITIAL_QUANTITY,
                AssetId::with_scope(
                    definition.clone(),
                    owner.clone(),
                    iroha_data_model::asset::AssetBalanceScope::Dataspace(spec.dataspace_id),
                ),
            ));
    }
    builder = builder.next_transaction();
    for permission in [
        Permission::from(CanManageSmartContractCode),
        Permission::from(CanGrantSmartContractCodeManagement),
        Permission::from(CanReadAllLedgerData),
        Permission::from(CanReadRestrictedDataspace {
            dataspace: spec.dataspace_id,
        }),
        Permission::from(CanRegisterAccount { domain }),
        Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(spec.dataspace_id),
        }),
        Permission::from(CanPublishSpaceDirectoryManifest {
            dataspace: spec.dataspace_id,
        }),
    ] {
        builder = builder.append_instruction(Grant::account_permission(permission, owner.clone()));
    }
    let genesis = builder
        .build_raw()?
        .with_consensus_mode(SumeragiConsensusMode::Permissioned);
    let genesis = apply_parameter_overrides(
        genesis,
        NonZeroU16::new(4).unwrap(),
        Some(LOCALNET_PIPELINE_TIME_MS),
        LOCALNET_BLOCK_MAX_TRANSACTIONS,
        SumeragiConsensusMode::Permissioned,
    )?;
    let genesis = append_peer_pop(genesis, peers)?;
    Ok(apply_localnet_crypto_overrides(genesis)?.with_consensus_meta()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> PrivateRootSpec {
        let alias = "privateapp";
        let name_hash = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias)
            .unwrap()
            .name_hash();
        PrivateRootSpec {
            parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"private-root parent fixture"),
            )),
            dataspace_id: DataSpaceId::from_hash(&name_hash),
            dataspace_alias: alias.into(),
        }
    }

    #[test]
    fn exact_sns_identity_and_scope_bind_alias_and_full_width_identifier() {
        let spec = spec();
        spec.validate().unwrap();
        assert_eq!(spec.scope().dataspace_id(), spec.dataspace_id);
        let encoded = norito::json::to_json(&spec).unwrap();
        assert_eq!(
            norito::json::from_str::<PrivateRootSpec>(&encoded).unwrap(),
            spec
        );
        let mut wrong = spec.clone();
        wrong.dataspace_id = DataSpaceId::new(spec.dataspace_id.as_u64() ^ 1);
        assert!(wrong.validate().is_err());
        wrong = spec.clone();
        wrong.dataspace_alias = "differentapp".into();
        assert!(wrong.validate().is_err());
        wrong = spec.clone();
        wrong.dataspace_alias = "PrivateApp".into();
        assert!(wrong.validate().is_err());
        wrong = spec.clone();
        wrong.dataspace_alias = "universal".into();
        assert!(wrong.validate().is_err());
        wrong = spec;
        wrong.dataspace_id = DataSpaceId::UNIVERSAL;
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn private_config_has_one_restricted_lane_and_the_canonical_sns_name_hash() {
        let spec = spec();
        let gas_account = ALICE_ID.to_string();
        let raw = "[pipeline]\n[nexus]\n";
        let config =
            private_peer_config(raw, &spec, "private-fixture-token", &gas_account).unwrap();
        let parsed: toml::Table = config.parse().unwrap();
        let nexus = parsed["nexus"].as_table().unwrap();
        let policy = private_fee_policy(&spec).unwrap();
        assert_eq!(
            nexus["fees"].as_table().unwrap(),
            &private_fee_configuration(&policy, &gas_account)
        );
        assert!(!policy.base_fee.is_zero() && !policy.per_gas_unit_fee.is_zero());
        assert_ne!(
            policy.asset_definition_id,
            localnet_xor_asset_definition_id()
        );
        let dataspaces = nexus["dataspace_catalog"].as_array().unwrap();
        assert_eq!(dataspaces.len(), 1);
        assert!(dataspaces[0].get("id").is_none());
        assert_eq!(
            dataspaces[0]["manifest_hash"].as_str(),
            Some(hex::encode(spec.name_hash().unwrap()).as_str())
        );
        let lanes = nexus["lane_catalog"].as_array().unwrap();
        assert_eq!(lanes.len(), 1);
        assert_eq!(lanes[0]["index"].as_integer(), Some(0));
        assert_eq!(lanes[0]["visibility"].as_str(), Some("restricted"));
        assert_eq!(
            lanes[0]["dataspace"].as_str(),
            Some(spec.dataspace_alias.as_str())
        );
        assert_eq!(
            nexus["routing_policy"]["default_dataspace"].as_str(),
            Some(spec.dataspace_alias.as_str())
        );
        assert_eq!(parsed["torii"]["require_api_token"].as_bool(), Some(true));
        assert_eq!(
            parsed["torii"]["api_tokens"][0].as_str(),
            Some("private-fixture-token")
        );
    }

    #[test]
    fn private_root_preparation_executes_signed_genesis_and_retains_owner_on_reopen() {
        let _parent_profile = ChainDiscriminantGuard::enter(369);
        let _guard = crate::managed::native_test_guard();
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("private-root");
        let ports = LocalnetPorts::reserve().unwrap();
        let spec = spec();
        let prepared = prepare_private_root("private", &directory, &ports, &spec).unwrap();
        assert_eq!(prepared.context.dataspace_id, spec.dataspace_id.as_u64());
        assert_eq!(
            prepared.build_cache_root(),
            directory
                .canonicalize()
                .unwrap()
                .join("runtime/build-cache")
        );
        assert!(!prepared.build_cache_root().exists());
        assert_eq!(prepared.peers.len(), 4);
        verify_retained(&directory.canonicalize().unwrap(), &prepared, &spec).unwrap();
        let registration = prepared.load_private_registration().unwrap();
        assert_eq!(registration.scope, spec.scope());
        assert_eq!(registration.genesis_cursor.height, 1);
        assert_eq!(
            registration.child_network_id.to_string(),
            prepared.context.network_id
        );
        registration.validate().unwrap();
        let client = prepared.context.load_client_config().unwrap();
        assert_eq!(
            client.account_chain_discriminant,
            iroha_config::parameters::defaults::common::chain_discriminant(),
            "parent address rendering cannot change the independently generated child profile"
        );
        assert_ne!(
            client.account_chain_discriminant,
            iroha_data_model::account::address::chain_discriminant(),
            "the retained child is verified while the original parent profile remains active",
        );
        let owner = client.account;
        let mut expected_roster = Vec::new();
        for peer in &prepared.peers {
            let bytes = iroha_fs::read_private(&peer.config_path, 1024 * 1024).unwrap();
            let table: toml::Table = std::str::from_utf8(&bytes).unwrap().parse().unwrap();
            assert!(table["torii"].get("faucet").is_none());
            assert!(table["torii"].get("account_onboarding").is_none());
            let config = parse_private_peer_config(
                std::str::from_utf8(&bytes).unwrap(),
                Some(&peer.config_path),
            )
            .unwrap();
            // Proof validity is committed chain policy; generated node settings must
            // neither select a backend nor preserve a retired compatibility setting.
            let local_zk = table.get("zk").and_then(toml::Value::as_table);
            assert!(local_zk.is_none_or(|zk| !zk.contains_key("pipa_r")));
            assert!(local_zk.is_none_or(|zk| !zk.contains_key("halo2")));
            assert!(config.zk.pipa_r.enabled);
            for enabled in [true, false] {
                let node_validity = Zeroizing::new(format!(
                    "{}\n[zk.pipa_r]\nenabled = {enabled}\n",
                    std::str::from_utf8(&bytes).unwrap(),
                ));
                assert!(parse_private_peer_config(&node_validity, Some(&peer.config_path)).is_err());
            }
            let retired = Zeroizing::new(format!(
                "{}\n[zk.halo2]\nenabled = true\n",
                std::str::from_utf8(&bytes).unwrap()
            ));
            assert!(parse_private_peer_config(&retired, Some(&peer.config_path)).is_err());
            assert!(table["pipeline"].get("gas").is_none());
            let retired_gas = Zeroizing::new(format!(
                "{}\n[pipeline.gas]\ntech_account_id = {:?}\n",
                std::str::from_utf8(&bytes).unwrap(),
                owner.to_string(),
            ));
            assert!(parse_private_peer_config(&retired_gas, Some(&peer.config_path)).is_err());
            assert_eq!(
                parse_private_peer_config(
                    std::str::from_utf8(&bytes).unwrap(),
                    Some(&peer.config_path),
                )
                .map(|retry| retry.genesis.expected_hash)
                .unwrap(),
                config.genesis.expected_hash,
                "the same original generated config remains admissible after retired-field refusal"
            );
            expected_roster.push(config.common.peer.id().clone());
            assert_eq!(&config.genesis.public_key, client.key_pair.public_key());
            assert_eq!(
                config.network.connect_startup_delay,
                std::time::Duration::ZERO
            );
            assert_eq!(
                (config.network.dial_timeout, config.network.preauth_timeout),
                (
                    iroha_config::parameters::defaults::network::DIAL_TIMEOUT,
                    iroha_config::parameters::defaults::network::PREAUTH_TIMEOUT,
                )
            );
            managed_puzzle::assert_managed_profile(&table, &config.network.soranet_handshake.pow);
            assert!(config.torii.peer_telemetry_urls.is_empty());
            assert_eq!(config.nexus.dataspace_catalog.entries().len(), 1);
            assert_eq!(
                config.nexus.dataspace_catalog.entries()[0].id,
                spec.dataspace_id
            );
            assert_eq!(
                config.nexus.dataspace_catalog,
                config.nexus.configured_dataspace_catalog
            );
            assert_eq!(config.nexus.lane_catalog.lanes().len(), 1);
            assert_eq!(
                config.nexus.lane_catalog.lanes()[0].dataspace_id,
                spec.dataspace_id
            );
        }
        let signed = read_signed_genesis(&directory.join("genesis.signed.nrt")).unwrap();
        let authenticated =
            iroha_data_model::sumeragi_finality::authenticated_genesis(&signed).unwrap();
        let metadata = authenticated.metadata();
        let epoch = authenticated.into_parts().0;
        // Derive only the mandatory account/profile value work from their canonical
        // constructors, independently of the profile validator or metadata decoder.
        // A DEP7 metadata replay cannot enlarge its own successful allowance.
        let profile_limits = |allocated| {
            norito::DecodeLimits::new(1_000_000, 48 * 1024 * 1024, 1_000_000, allocated, 64)
        };
        let reference = norito::core::DecodeBudgetContext::new(profile_limits(usize::MAX));
        let mut identity_debit = 0;
        reference.with(|| {
            let discriminant =
                iroha_data_model::account::address::AccountAddress::i105_discriminant(
                    &prepared.context.account_id,
                )
                .unwrap();
            let _address_profile = ChainDiscriminantGuard::enter(discriminant);
            assert_eq!(
                AccountId::parse_encoded(&prepared.context.account_id).unwrap(),
                owner
            );
            identity_debit = reference.consumed_allocated_bytes();
            iroha_primitives::json::Json::try_new(prepared.service_profile).unwrap();
        });
        let profile_debit = reference.consumed_allocated_bytes();
        assert!(identity_debit > 0 && profile_debit > identity_debit);
        // The already authenticated metadata must consume no additional allowance;
        // normal identity and expected-profile validation still execute in full.
        let profile_context = norito::core::DecodeBudgetContext::new(profile_limits(
            usize::try_from(profile_debit).unwrap(),
        ));
        profile_context.with(|| {
            service_authorities::validate_signed_profile(&prepared, &signed, &metadata)
        }).expect("original private-root signed profile must reuse completed authenticated metadata without another codec decode");
        assert_eq!(profile_context.consumed_allocated_bytes(), profile_debit);
        let empty = norito::core::DecodeBudgetContext::new(profile_limits(0));
        assert!(
            empty
                .with(|| service_authorities::validate_signed_profile(
                    &prepared, &signed, &metadata
                ))
                .is_err(),
            "an empty allowance must still refuse the original account validation"
        );
        // Complete the same required identity read, then refuse the actual JSON
        // constructor. The production validator must return its error, not unwind.
        let partial = norito::core::DecodeBudgetContext::new(profile_limits(
            usize::try_from(identity_debit).unwrap(),
        ));
        assert!(
            partial
                .with(|| service_authorities::validate_signed_profile(
                    &prepared, &signed, &metadata
                ))
                .is_err(),
            "signed profile JSON construction refusal must return without panicking"
        );
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            369
        );
        service_authorities::validate_signed_profile(&prepared, &signed, &metadata)
            .expect("a separate pristine profile attempt must still validate its original source");
        assert_eq!(epoch.authorization.authority_generation, 0);
        assert_eq!(epoch.committee.len(), 4);
        epoch
            .authorization
            .validate_against_generation(&epoch.generation())
            .unwrap();
        expected_roster.sort();
        assert_eq!(epoch.generation().validators, expected_roster);
        for index in 0..prepared.peers.len() {
            assert!(
                !managed_node_dir(&directory, index)
                    .join("secrets/mint_finality.seed")
                    .exists()
            );
        }
        let manifest = RawGenesisTransaction::from_path(&directory.join("genesis.json")).unwrap();
        let projected =
            iroha_core::state::StateParameters::try_from(manifest.effective_parameters().unwrap())
                .unwrap();
        assert_eq!(
            projected.gas().tech_account_id,
            localnet_gas_account_id(client.key_pair.public_key())
                .to_i105_for_discriminant(client.account_chain_discriminant)
                .unwrap(),
            "private genesis retains its original deterministic fee receiver in the child profile",
        );
        assert_eq!(
            manifest.sumeragi_context_parameters().root_scope,
            spec.scope()
        );
        assert_eq!(
            PrivateRootFeePolicy::from_parameters(&manifest.effective_parameters().unwrap())
                .unwrap(),
            Some(private_fee_policy(&spec).unwrap())
        );
        assert!(
            !manifest
                .effective_parameters()
                .unwrap()
                .custom()
                .contains_key(&PrivateDataspaceAdmissionPolicy::parameter_id()),
            "a private root cannot enable the parent admission registry"
        );
        let code_grants = manifest
            .instructions()
            .filter_map(|instruction| {
                let GrantBox::Permission(grant) =
                    instruction.as_any().downcast_ref::<GrantBox>()?
                else {
                    return None;
                };
                (grant.object() == &Permission::from(CanManageSmartContractCode))
                    .then(|| grant.destination().clone())
            })
            .collect::<Vec<_>>();
        assert_eq!(code_grants, vec![owner.clone()]);
        let definitions = manifest
            .instructions()
            .filter_map(|instruction| {
                let RegisterBox::AssetDefinition(registration) =
                    instruction.as_any().downcast_ref::<RegisterBox>()?
                else {
                    return None;
                };
                Some(registration.object())
            })
            .collect::<Vec<_>>();
        assert_eq!(definitions.len(), 2);
        assert_eq!(
            definitions
                .iter()
                .map(|definition| definition.name.as_str())
                .collect::<Vec<_>>(),
            ["sample", "gas"],
            "private asset names must match their canonical alias stems"
        );
        for definition in definitions {
            assert_eq!(
                definition.balance_scope_policy,
                iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted
            );
            assert_eq!(
                definition.owning_domain.as_ref(),
                Some(
                    &DomainId::parse_fully_qualified(&format!("app.{}", spec.dataspace_alias))
                        .unwrap()
                )
            );
        }
        let mints = manifest
            .instructions()
            .filter_map(|instruction| {
                let MintBox::Asset(mint) = instruction.as_any().downcast_ref::<MintBox>()? else {
                    return None;
                };
                Some(mint.destination())
            })
            .collect::<Vec<_>>();
        assert_eq!(mints.len(), 2);
        for destination in mints {
            assert_eq!(destination.account(), &owner);
            assert_eq!(
                destination.scope(),
                &iroha_data_model::asset::AssetBalanceScope::Dataspace(spec.dataspace_id)
            );
        }
        let repeated = prepare_private_root("private", &directory, &ports, &spec).unwrap();
        assert_eq!(repeated, prepared);
        assert_eq!(repeated.build_cache_root(), prepared.build_cache_root());
        assert!(!repeated.build_cache_root().exists());
        assert_eq!(repeated.load_private_registration().unwrap(), registration);
        let original_manifest = iroha_fs::read_private(
            &directory.join("genesis.json"),
            iroha_genesis::GENESIS_MANIFEST_JSON_MAX_BYTES_V1,
        )
        .unwrap();
        custody::replace(&directory.join("genesis.json"), b"{}").unwrap();
        assert!(prepared.load_private_registration().is_err());
        custody::replace(
            &directory.join("genesis.json"),
            original_manifest.as_slice(),
        )
        .unwrap();
        let peer_path = &prepared.peers[0].config_path;
        let bytes = iroha_fs::read_private(peer_path, 1024 * 1024).unwrap();
        let mut table = crate::secret_toml::Table::new(
            crate::secret_toml::parse_table(
                std::str::from_utf8(&bytes).unwrap(),
                "test private validator",
            )
            .unwrap(),
        );
        table["torii"]
            .as_table_mut()
            .unwrap()
            .insert("require_api_token".into(), toml::Value::Boolean(false));
        custody::replace(
            peer_path,
            Zeroizing::new(toml::to_string(&*table).unwrap()).as_bytes(),
        )
        .unwrap();
        assert!(verify_private_credentials(&prepared, &spec).is_err());
        custody::replace(peer_path, bytes.as_slice()).unwrap();
        table["torii"]
            .as_table_mut()
            .unwrap()
            .insert("require_api_token".into(), toml::Value::Boolean(true));
        table["nexus"]["fees"]
            .as_table_mut()
            .unwrap()
            .insert("base_fee".into(), toml::Value::String("0".into()));
        custody::replace(
            peer_path,
            Zeroizing::new(toml::to_string(&*table).unwrap()).as_bytes(),
        )
        .unwrap();
        assert!(
            verify_private_credentials(&prepared, &spec).is_err(),
            "a node-local zero-fee rewrite cannot replace the signed private fee policy"
        );
        custody::replace(peer_path, bytes.as_slice()).unwrap();
        let mut foreign = spec;
        foreign.parent_network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"foreign parent"),
        ));
        assert!(prepare_private_root("private", &directory, &ports, &foreign).is_err());
    }

    #[test]
    fn incomplete_private_generation_never_overwrites_retained_keys() {
        let _guard = crate::managed::native_test_guard();
        let parent = tempfile::tempdir().unwrap();
        let directory =
            iroha_fs::PrivateDirectory::open_or_create(parent.path().join("private-root")).unwrap();
        directory
            .write_atomic(
                "retained-key",
                b"already-created",
                iroha_fs::PublishMode::CreateNew,
            )
            .unwrap();
        let ports = LocalnetPorts::reserve().unwrap();
        assert!(prepare_private_root("private", directory.path(), &ports, &spec()).is_err());
        assert_eq!(
            &*directory.read("retained-key", 32).unwrap(),
            b"already-created"
        );
    }
}
