//! Exact signed-genesis custody for disposable real-peer networks.
//!
//! Admission reuses the ordinary signed-genesis and native runtime validators.
//! This owner never normalizes, extends, or re-signs its retained originals.
use super::*;
use color_eyre::eyre::ensure;
use std::collections::BTreeMap;

/// Exact authenticated public genesis inputs and the matching validator owners.
///
/// This type owns no genesis signing key. Construct it before allocating peers;
/// invalid wire, manifest, trust anchor, roster or owner custody is rejected there.
/// It is independent of the KAGEMUSHA catalog: callers must still qualify the
/// selected node, native wallet and installed verifier graph together.
#[derive(Clone)]
pub struct RetainedNetworkGenesis {
    genesis: RetainedGenesis,
    validator_keys: Vec<KeyPair>,
}

#[derive(Clone)]
pub(super) struct RetainedGenesis {
    originals: NativeGenesisProvisioningBundle,
    validated: iroha_genesis::ValidatedGenesisBundle,
    manifest: RawGenesisTransaction,
}

impl RetainedNetworkGenesis {
    /// Validate retained originals and consume one distinct owner for every voter.
    ///
    /// Keys may arrive in any order; the returned owner follows the signed roster.
    /// `originals` must carry independently selected verifier/hash trust anchors.
    /// Relative executor/trigger paths in its manifest retain their ordinary native
    /// interpretation; no replacement artifact or generated instruction is supplied.
    ///
    /// # Errors
    /// Rejects any original mismatch, invalid signature/PoP, missing, extra,
    /// duplicated or foreign validator owner, or a non-canonical signed profile.
    pub fn new(
        originals: NativeGenesisProvisioningBundle,
        validator_keys: Vec<KeyPair>,
    ) -> Result<Self> {
        init_instruction_registry();
        ensure!(
            sha256(&originals.manifest_json) == originals.manifest_sha256,
            "retained manifest bytes differ from their selected digest"
        );
        let manifest: RawGenesisTransaction = norito::json::from_slice(&originals.manifest_json)?;
        ensure!(
            manifest.chain_discriminant() == originals.chain_discriminant,
            "retained manifest address profile differs"
        );
        let validated = iroha_genesis::validate_prepared_genesis_bundle(
            &originals.signed_wire,
            &manifest,
            &originals.public_key,
            originals.block_hash,
        )?;
        let roster = genesis_committee_peers(validated.block())?;
        ensure!(
            validator_keys.len() == roster.len(),
            "retained voter owner count differs"
        );
        let mut owners = BTreeMap::new();
        for key in validator_keys {
            let peer = PeerId::new(key.public_key().clone());
            let expected_pop = validated
                .validator_pops()
                .get(key.public_key())
                .ok_or_else(|| eyre!("retained voter owner is foreign"))?;
            let actual_pop = iroha_crypto::bls_normal_pop_prove(key.private_key())
                .map_err(|error| eyre!("retained voter custody is not BLS: {error}"))?;
            ensure!(
                &actual_pop == expected_pop,
                "retained voter custody differs from signed PoP"
            );
            ensure!(
                owners.insert(peer, key).is_none(),
                "duplicate retained voter owner"
            );
        }
        let validator_keys = roster
            .iter()
            .map(|peer| {
                owners
                    .remove(peer)
                    .ok_or_else(|| eyre!("missing retained voter owner"))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(owners.is_empty(), "extra retained voter owner");
        let genesis = RetainedGenesis {
            originals,
            validated,
            manifest,
        };
        genesis.profile()?;
        Ok(Self {
            genesis,
            validator_keys,
        })
    }
}

impl RetainedGenesis {
    pub(super) fn originals(&self) -> NativeGenesisProvisioningBundle {
        self.originals.clone()
    }

    fn block(&self) -> GenesisBlock {
        GenesisBlock(self.validated.block().clone())
    }

    fn profile(&self) -> Result<ConsensusBootstrapProfile> {
        let metadata = self.validated.consensus_metadata();
        let mode = match metadata.mode {
            SumeragiConsensusMode::Permissioned => ConsensusMode::Permissioned,
            SumeragiConsensusMode::Npos => ConsensusMode::Npos,
        };
        let mut parameter_state = consensus_parameters_from_genesis(&self.block());
        // Cadence is carried by the authenticated handshake, not a Sumeragi SetParameter.
        // Reconstruct the same effective inputs as native signed-genesis validation.
        parameter_state.sumeragi.block_cadence_ms = metadata.block_cadence_ms;
        let params = iroha_core::sumeragi::consensus::consensus_genesis_params_from_parameters(
            mode,
            &parameter_state,
            metadata.sumeragi_context.clone(),
        )
        .map_err(|error| eyre!(error))?;
        let profile = ConsensusBootstrapProfile {
            params,
            mode_tag: if mode == ConsensusMode::Permissioned {
                PERMISSIONED_TAG
            } else {
                NPOS_TAG
            },
            bls_domain: if mode == ConsensusMode::Permissioned {
                PERMISSIONED_BLS_DOMAIN
            } else {
                NPOS_BLS_DOMAIN
            },
            chain_id: self.manifest.chain_id().clone(),
            wire_protocol_version: metadata.wire_protocol_version,
        };
        ensure!(
            genesis_has_exactly_one_consensus_handshake(
                &self.block(),
                &consensus_handshake_parameter(&profile)
            ),
            "retained signed consensus profile differs from committed parameters"
        );
        Ok(profile)
    }

    fn validate_peer_owner(
        &self,
        config: &iroha_config::parameters::actual::Root,
        peer: &NetworkPeer,
    ) -> Result<()> {
        ensure!(
            config.common.key_pair == peer.key_pair
                && config.common.peer.id() == &peer.id()
                && config.sumeragi.role == iroha_config::parameters::actual::NodeRole::Validator,
            "retained final validator identity or role differs from its supplied owner"
        );
        let trusted = config.common.trusted_peers.value();
        let configured = std::iter::once(&trusted.myself)
            .chain(trusted.others.iter())
            .map(|peer| peer.id().clone())
            .collect::<BTreeSet<_>>();
        let signed = self
            .validated
            .validator_pops()
            .keys()
            .cloned()
            .map(PeerId::new)
            .collect::<BTreeSet<_>>();
        ensure!(
            configured == signed && trusted.pops == *self.validated.validator_pops(),
            "retained final trusted roster or PoPs differ from signed genesis"
        );
        Ok(())
    }

    fn validate_runtime(
        &self,
        config: &iroha_config::parameters::actual::Root,
        topology: &[PeerId],
    ) -> Result<ValidatedNetworkGenesis> {
        ensure!(
            config.common.chain == *self.manifest.chain_id()
                && *config.common.chain_discriminant.value() == self.originals.chain_discriminant
                && config.genesis.public_key == self.originals.public_key
                && config.genesis.expected_hash == self.originals.block_hash,
            "retained genesis runtime trust anchor or address profile differs"
        );
        let original = self.block();
        assert_genesis_voting_roster_matches_network(&original, topology);
        let (executed, hashes) = config::validate_genesis_with_runtime_config(
            &original,
            &AccountId::new(self.originals.public_key.clone()),
            topology,
            Some(&config.pipeline),
            Some(&config.nexus),
            Some(&config.zk),
            Some(config),
        )?;
        // Native validation authenticates the proposal and computes its outputs.
        // Outputs are secondary state, not signed proposal content: a valid
        // resultless genesis necessarily gains them during this execution.
        ensure!(
            original.0.checked_resultless_proposal_eq(&executed)?,
            "native validation changed the retained signed proposal"
        );
        let profile = self.profile()?;
        ensure!(
            hashes.nexus_amx
                == CryptoHash::prehashed(profile.params.sumeragi_context.nexus_amx_context_hash)
                && hashes.execution_policy
                    == CryptoHash::prehashed(profile.params.sumeragi_context.execution_policy_hash),
            "retained signed policy differs from native runtime staging"
        );
        ensure!(
            original.0.encode_wire()? == self.originals.signed_wire,
            "native admission changed the retained signed original"
        );
        Ok(ValidatedNetworkGenesis::new(
            original,
            hashes,
            Some(self.manifest.clone()),
            &profile,
            topology,
        ))
    }
}

impl NetworkBuilder {
    /// Start a recipe owned by an already signed genesis and exact validator keys.
    ///
    /// Only node-local configuration and lifecycle settings may be added. Genesis
    /// instructions, replacement signing owners, added participants and signed
    /// parameter overrides are refused before allocating peer directories or ports.
    /// The ordinary generated-genesis recipe remains available through [`Self::new`].
    pub fn from_retained_genesis(input: RetainedNetworkGenesis) -> Self {
        let mut builder = Self::new();
        builder.n_peers = input.validator_keys.len();
        builder.block_cadence = None;
        builder.ivm_fuel = IvmFuelConfig::Unset;
        builder.npos_genesis_bootstrap_stake = None;
        builder.consensus_mode = match input.genesis.validated.consensus_metadata().mode {
            SumeragiConsensusMode::Permissioned => ConsensusMode::Permissioned,
            SumeragiConsensusMode::Npos => ConsensusMode::Npos,
        };
        builder.retained_genesis = Some(input);
        builder
    }

    fn validate_retained_recipe(&self, input: &RetainedNetworkGenesis) -> Result<()> {
        ensure!(
            self.n_peers == input.validator_keys.len()
                && self.committee_validator_p2p_bootstrap.is_none()
                && self.observer_p2p_bootstrap.is_none()
                && self.observer_slow_reader_relays.is_none()
                && self.custom_genesis.is_none()
                && self.genesis_isi.iter().all(Vec::is_empty)
                && self.genesis_post_topology_isi.iter().all(Vec::is_empty)
                && self.genesis_post_bootstrap_isi.iter().all(Vec::is_empty)
                && self.topology_genesis_isi.is_empty()
                && !self.genesis_committee_keys_for_global_peers
                && self.npos_genesis_bootstrap_stake.is_none()
                && matches!(self.ivm_fuel, IvmFuelConfig::Unset)
                && self.genesis_key_pair == *SAMPLE_GENESIS_ACCOUNT_KEYPAIR
                && !self.private_settlement_route_control
                && self.parliament_test_signers.is_none()
                && self.auto_populate_trusted_peer_pops,
            "retained genesis owns its exact instructions, participants and signer"
        );
        let metadata = input.genesis.validated.consensus_metadata();
        let mode = match metadata.mode {
            SumeragiConsensusMode::Permissioned => ConsensusMode::Permissioned,
            SumeragiConsensusMode::Npos => ConsensusMode::Npos,
        };
        ensure!(
            self.consensus_mode == mode
                && self.block_cadence.is_none_or(
                    |cadence| cadence == Duration::from_millis(metadata.block_cadence_ms.get())
                ),
            "retained signed consensus parameters cannot be overridden"
        );
        Ok(())
    }

    pub(super) fn build_retained_with_permit(
        self,
        input: RetainedNetworkGenesis,
        permit: NetworkPermit,
    ) -> Result<Network> {
        self.validate_retained_recipe(&input)?;
        let RetainedNetworkGenesis {
            genesis,
            validator_keys,
        } = input;
        let profile = genesis.profile()?;
        let discriminant = genesis.originals.chain_discriminant;
        let _scope =
            iroha_data_model::account::address::ChainDiscriminantGuard::enter(discriminant);
        let max_validator_capacity = self.max_validator_capacity.unwrap_or(self.n_peers);
        let env = Environment::new();
        let peers = validator_keys
            .into_iter()
            .enumerate()
            .map(|(index, key)| {
                let seed = self
                    .seed
                    .as_ref()
                    .map(|seed| format!("{seed}-peer-{index}"));
                NetworkPeerBuilder::new()
                    .with_seed(seed.as_ref().map(|seed| seed.as_bytes()))
                    .with_validator_key(key)
                    .build_with_program(&env, Program::Irohad)
            })
            .collect::<Vec<_>>();
        let topology_entries = peers
            .iter()
            .filter_map(NetworkPeer::genesis_pop)
            .collect::<Vec<_>>();
        ensure!(
            topology_entries.len() == peers.len(),
            "retained peer omitted its signed PoP"
        );
        let gossip_ms = i64::try_from(self.block_sync_gossip_period.as_millis())?;
        let mut base_layer = config::base_iroha_config()
            .write("chain", genesis.manifest.chain_id().to_string())
            .write("chain_discriminant", i64::from(discriminant))
            .write(
                ["genesis", "public_key"],
                genesis.originals.public_key.to_string(),
            )
            .write(
                ["genesis", "expected_hash"],
                genesis_expected_hash_config_literal(&genesis.originals.block_hash.to_string()),
            )
            .write(["network", "block_gossip_period_ms"], gossip_ms)
            .write(
                ["network", "block_gossip_size"],
                i64::try_from(peers.len())?,
            )
            .write(["pipeline", "signature_batch_max_bls"], 4_i64)
            .write(["torii", "transport", "norito_rpc", "stage"], "ga")
            .write(["torii", "transport", "norito_rpc", "enabled"], true);
        // These are ordinary runtime defaults only. Native staging must match the
        // signed policy after all caller layers; no genesis instruction is added.
        let genesis_account = AccountId::new(genesis.originals.public_key.clone())
            .to_i105_for_discriminant(discriminant)?;
        for path in [
            ["nexus", "fees", "fee_sink_account_id"],
            ["nexus", "staking", "stake_escrow_account_id"],
            ["nexus", "staking", "slash_sink_account_id"],
        ] {
            base_layer = base_layer.write(path, genesis_account.clone());
        }
        let network = Network {
            env,
            peers,
            committee_validators: Vec::new(),
            observers: Vec::new(),
            observer_advertised_p2p_addresses: HashMap::new(),
            observer_slow_reader_relays: None,
            next_peer_index: AtomicUsize::new(0),
            block_cadence: Duration::from_millis(profile.params.block_cadence_ms.get()),
            block_sync_gossip_period: self.block_sync_gossip_period,
            sync_timeout_override: self.sync_timeout,
            peer_startup_timeout_override: self.peer_startup_timeout,
            consensus_profile: profile,
            genesis_key_pair: None,
            genesis_isi: Vec::new(),
            genesis_post_topology_isi: Vec::new(),
            cached_genesis: OnceLock::new(),
            generated_genesis_manifest: OnceLock::new(),
            retained_genesis: Some(genesis),
            validated_genesis: None,
            config_layers: std::iter::once(base_layer)
                .chain(self.config_layers)
                .collect(),
            topology_entries,
            auto_populate_trusted_peer_pops: true,
            max_validator_capacity,
            _permit: permit,
        };
        network.validate_retained_genesis(
            network.retained_genesis.as_ref().expect("retained owner"),
        )?;
        let client_config = PeerClientConfig {
            chain: network.chain_id(),
            network_id: NetworkId::from_genesis_hash(
                network
                    .retained_genesis
                    .as_ref()
                    .expect("retained owner")
                    .originals
                    .block_hash,
            ),
            chain_discriminant: discriminant,
            policy: PeerClientPolicy::from_env(),
            api_token: self.client_api_token,
        };
        for peer in network.all_peers() {
            peer.client_config
                .set(client_config.clone())
                .map_err(|_| eyre!("retained peer client identity was already initialized"))?;
        }
        Ok(network)
    }
}

impl Network {
    pub(super) fn validate_retained_genesis(
        &self,
        retained: &RetainedGenesis,
    ) -> Result<ValidatedNetworkGenesis> {
        let layers = self
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let topology = self.peers.iter().map(NetworkPeer::id).collect::<Vec<_>>();
        let mut result = None;
        for peer in &self.peers {
            let actual = resolve_actual_config_result(peer, &layers)?;
            retained.validate_peer_owner(&actual, peer)?;
            validate_planned_validator_capacity(&actual, self.max_validator_capacity)?;
            let validated = retained.validate_runtime(&actual, &topology)?;
            if result.is_none() {
                result = Some(validated);
            }
        }
        result.ok_or_else(|| eyre!("retained signed network has no validator owners"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_fixture() -> (Network, NativeGenesisProvisioningBundle, Vec<KeyPair>) {
        let generated =
            crate::tests::build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        let mut originals = generated.native_genesis_provisioning_bundle().unwrap();
        let proposal = generated
            .genesis()
            .0
            .canonical_resultless_proposal()
            .unwrap();
        assert!(proposal.is_resultless_proposal());
        assert_eq!(proposal.hash(), originals.block_hash);
        originals.signed_wire = proposal.encode_wire().unwrap();
        // JSON whitespace is semantically inert but belongs to retained original custody.
        // Re-serializing the parsed manifest would lose this exact input.
        originals.manifest_json.extend_from_slice(b"\n  \n");
        originals.manifest_sha256 = sha256(&originals.manifest_json);
        let owners = generated
            .peers
            .iter()
            .map(|peer| peer.key_pair.clone())
            .collect();
        (generated, originals, owners)
    }

    fn recipe_with_same_runtime(
        generated: &Network,
        input: RetainedNetworkGenesis,
    ) -> NetworkBuilder {
        let mut recipe = NetworkBuilder::from_retained_genesis(input);
        // Carry the same runtime policies that authored the original. The dynamic
        // trusted-peer/address layer belongs to the new peer owners, not this copy.
        recipe.config_layers.extend(generated.config_layers.clone());
        recipe
    }

    #[test]
    fn retained_owner_preserves_originals_and_four_peer_restart_files_without_signing() -> Result<()>
    {
        let (generated, originals, mut owners) = retained_fixture();
        owners.reverse();
        let signatures = originals.signed_wire.clone();
        let signs_before = config::genesis_signing_count();
        let input = RetainedNetworkGenesis::new(originals.clone(), owners)?;
        let expected_roster = genesis_committee_peers(input.genesis.validated.block())?;
        let network =
            crate::tests::build_with_isolated_permit(recipe_with_same_runtime(&generated, input));
        assert!(
            network.genesis_key_pair.is_none(),
            "retained network has no genesis signing owner"
        );
        assert_eq!(
            network
                .peers
                .iter()
                .map(NetworkPeer::id)
                .collect::<Vec<_>>(),
            expected_roster
        );
        for _ in 0..2 {
            assert_eq!(network.genesis().0.encode_wire()?, signatures);
            let returned = network.native_genesis_provisioning_bundle()?;
            assert_eq!(returned.signed_wire, originals.signed_wire);
            assert_eq!(returned.manifest_json, originals.manifest_json);
            assert_eq!(returned.public_key, originals.public_key);
        }
        // Fixture builders take the synchronous permit guard before entering Tokio.
        // Keep the thread-local no-signing observation on this same test thread.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let prepared = runtime.block_on(PreparedPeerGenesis::prepare(network.genesis()))?;
        assert_eq!(prepared.bytes.as_ref(), originals.signed_wire.as_slice());
        let layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        for peer in &network.peers {
            runtime.block_on(peer.write_run_config(
                layers.iter().map(Cow::Borrowed),
                Some(&prepared),
                None,
                1,
            ))?;
            let first = peer.dir.join("run-1-genesis.nrt");
            assert_eq!(fs::read(&first)?, originals.signed_wire);
            let retained_path = peer.restart_genesis_file(false).expect("restart original");
            assert_eq!(retained_path, first);
            runtime.block_on(peer.write_run_config(
                layers.iter().map(Cow::Borrowed),
                None,
                Some(&retained_path),
                2,
            ))?;
            assert_eq!(fs::read(&retained_path)?, originals.signed_wire);
            assert!(!peer.dir.join("run-2-genesis.nrt").exists());
            assert!(!peer.is_running());
        }
        assert_eq!(
            config::genesis_signing_count(),
            signs_before,
            "retained path must never sign"
        );
        Ok(())
    }

    #[test]
    fn retained_input_refuses_wrong_originals_and_non_exact_owner_sets() {
        let (generated, originals, owners) = retained_fixture();
        let signs_before = config::genesis_signing_count();
        let admitted = RetainedNetworkGenesis::new(originals.clone(), owners.clone())
            .expect("unchanged signed originals and exact owners must be admitted");
        let profile = admitted.genesis.profile().unwrap();
        assert_eq!(profile.params, generated.consensus_profile.params);
        assert_ne!(
            profile.params.block_cadence_ms,
            consensus_parameters_from_genesis(&admitted.genesis.block())
                .sumeragi
                .block_cadence_ms,
            "fixture must exercise signed cadence distinct from the raw parameter projection"
        );
        assert_eq!(config::genesis_signing_count(), signs_before);
        let attempt = |source, keys| RetainedNetworkGenesis::new(source, keys).is_err();
        let mut source = originals.clone();
        *source.signed_wire.last_mut().unwrap() ^= 1;
        assert!(attempt(source, owners.clone()));
        let mut source = originals.clone();
        source.manifest_json.push(b' ');
        assert!(attempt(source, owners.clone()));
        let mut source = originals.clone();
        source.public_key = ALICE_KEYPAIR.public_key().clone();
        assert!(attempt(source, owners.clone()));
        let mut source = originals.clone();
        source.block_hash =
            iroha_crypto::HashOf::from_untyped_unchecked(CryptoHash::new(b"foreign genesis"));
        assert!(attempt(source, owners.clone()));
        let mut source = originals.clone();
        source.chain_discriminant ^= 1;
        assert!(attempt(source, owners.clone()));
        let mut missing = owners.clone();
        missing.pop();
        assert!(attempt(originals.clone(), missing));
        let mut extra = owners.clone();
        extra.push(owners[0].clone());
        assert!(attempt(originals.clone(), extra));
        let mut duplicate = owners.clone();
        duplicate[0] = duplicate[1].clone();
        assert!(attempt(originals.clone(), duplicate));
        let mut foreign = owners.clone();
        foreign[0] = KeyPair::from_seed(b"foreign retained owner".to_vec(), Algorithm::BlsNormal);
        assert!(attempt(originals.clone(), foreign));
        // Genesis transactions use the Genesis marker; the operator's chain label
        // is selected externally and does not alter the signed genesis or NetworkId.
        let selected_chain = ChainId::from("renamed-retained-chain");
        assert_ne!(admitted.genesis.manifest.chain_id(), &selected_chain);
        let mut manifest_value: norito::json::Value =
            norito::json::from_slice(&originals.manifest_json).unwrap();
        manifest_value.as_object_mut().unwrap().insert(
            "chain".to_owned(),
            norito::json::Value::String(selected_chain.to_string()),
        );
        let mut source = originals.clone();
        source.manifest_json = norito::json::to_vec(&manifest_value).unwrap();
        // A newly selected label cannot excuse changing the selected original bytes.
        assert!(attempt(source.clone(), owners.clone()));
        source.manifest_sha256 = sha256(&source.manifest_json);
        let renamed = RetainedNetworkGenesis::new(source, owners.clone())
            .expect("an independently selected chain label preserves the signed genesis");
        assert_eq!(renamed.genesis.manifest.chain_id(), &selected_chain);
        assert_eq!(renamed.genesis.profile().unwrap().chain_id, selected_chain);
        assert_eq!(renamed.genesis.originals.signed_wire, originals.signed_wire);
        assert_eq!(renamed.genesis.originals.block_hash, originals.block_hash);
        assert_eq!(
            iroha_data_model::NetworkId::from_genesis_hash(
                renamed.genesis.validated.block().hash()
            ),
            iroha_data_model::NetworkId::from_genesis_hash(
                admitted.genesis.validated.block().hash()
            )
        );
        assert_eq!(config::genesis_signing_count(), signs_before);
        // A validly encoded change to signed semantics still fails with a new digest.
        let mut changed_fingerprint = admitted
            .genesis
            .validated
            .consensus_metadata()
            .consensus_fingerprint;
        changed_fingerprint.0[0] ^= 1;
        let mut manifest_value: norito::json::Value =
            norito::json::from_slice(&originals.manifest_json).unwrap();
        manifest_value.as_object_mut().unwrap().insert(
            "consensus_fingerprint".to_owned(),
            norito::json::to_value(&changed_fingerprint).unwrap(),
        );
        let mut source = originals.clone();
        source.manifest_json = norito::json::to_vec(&manifest_value).unwrap();
        source.manifest_sha256 = sha256(&source.manifest_json);
        let changed_semantics: RawGenesisTransaction =
            norito::json::from_slice(&source.manifest_json)
                .expect("changed fingerprint remains a typed, valid manifest");
        assert_eq!(
            changed_semantics.consensus_fingerprint(),
            Some(changed_fingerprint)
        );
        assert!(attempt(source, owners.clone()));
        let mut changed_manifest =
            norito::json::from_slice::<RawGenesisTransaction>(&originals.manifest_json).unwrap();
        changed_manifest =
            changed_manifest.with_chain_discriminant(originals.chain_discriminant ^ 1);
        let mut source = originals.clone();
        source.manifest_json = norito::json::to_vec(&changed_manifest).unwrap();
        source.manifest_sha256 = sha256(&source.manifest_json);
        assert!(attempt(source, owners));
    }

    #[test]
    fn retained_recipe_refuses_generated_mutations_before_peer_allocation() {
        let (_generated, originals, owners) = retained_fixture();
        let input = RetainedNetworkGenesis::new(originals, owners).unwrap();
        let mutations: Vec<Box<dyn Fn(&mut NetworkBuilder)>> = vec![
            Box::new(|recipe| recipe.n_peers = 7),
            Box::new(|recipe| {
                recipe.genesis_isi.push(vec![
                    SetParameter::new(Parameter::SmartContract(SmartContractParameter::Fuel(
                        NonZero::new(1).unwrap(),
                    )))
                    .into(),
                ])
            }),
            Box::new(|recipe| recipe.block_cadence = Some(Duration::from_secs(37))),
            Box::new(|recipe| recipe.ivm_fuel = IvmFuelConfig::Auto),
            Box::new(|recipe| recipe.genesis_key_pair = ALICE_KEYPAIR.clone()),
            Box::new(|recipe| recipe.genesis_committee_keys_for_global_peers = true),
            Box::new(|recipe| recipe.auto_populate_trusted_peer_pops = false),
        ];
        for mutate in mutations {
            let mut recipe = NetworkBuilder::from_retained_genesis(input.clone());
            mutate(&mut recipe);
            assert!(recipe.validate_retained_recipe(&input).is_err());
        }
    }

    #[test]
    fn retained_runtime_refuses_changed_native_policy_without_rewriting_originals() -> Result<()> {
        let (generated, originals, owners) = retained_fixture();
        let input = RetainedNetworkGenesis::new(originals.clone(), owners)?;
        let retained = input.genesis.clone();
        let topology = generated
            .peers
            .iter()
            .map(NetworkPeer::id)
            .collect::<Vec<_>>();
        let layers = generated
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let mut actual = resolve_actual_config_result(&generated.peers[0], &layers)?;
        retained.validate_runtime(&actual, &topology)?;
        actual.nexus.fees.fee_sink_account_id =
            iroha_test_samples::BOB_ID.to_i105_for_discriminant(originals.chain_discriminant)?;
        let preexecutions = config::genesis_preexecution_count();
        let signatures = config::genesis_signing_count();
        assert!(retained.validate_runtime(&actual, &topology).is_err());
        assert!(
            config::genesis_preexecution_count() > preexecutions,
            "ordinary native validator was exercised"
        );
        assert_eq!(config::genesis_signing_count(), signatures);
        assert_eq!(retained.originals().signed_wire, originals.signed_wire);
        assert_eq!(retained.originals().manifest_json, originals.manifest_json);
        Ok(())
    }

    #[test]
    fn retained_resultless_proposal_admits_native_outputs_without_replacing_originals() -> Result<()>
    {
        let (generated, originals, owners) = retained_fixture();
        let retained = RetainedNetworkGenesis::new(originals.clone(), owners)?.genesis;
        let original = retained.block();
        assert!(original.0.is_resultless_proposal());
        let topology = generated
            .peers
            .iter()
            .map(NetworkPeer::id)
            .collect::<Vec<_>>();
        let layers = generated
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let actual = resolve_actual_config_result(&generated.peers[0], &layers)?;
        let signs_before = config::genesis_signing_count();
        let (executed, _) = config::validate_genesis_with_runtime_config(
            &original,
            &AccountId::new(originals.public_key.clone()),
            &topology,
            Some(&actual.pipeline),
            Some(&actual.nexus),
            Some(&actual.zk),
            Some(&actual),
        )?;
        assert!(
            executed.has_results(),
            "normal native validation actually executed"
        );
        assert_ne!(executed.encode_wire()?, originals.signed_wire);
        assert!(original.0.checked_resultless_proposal_eq(&executed)?);
        assert_eq!(
            executed.signatures().cloned().collect::<Vec<_>>(),
            original.0.signatures().cloned().collect::<Vec<_>>()
        );
        retained.validate_runtime(&actual, &topology)?;
        assert_eq!(retained.block().0.encode_wire()?, originals.signed_wire);
        assert_eq!(retained.originals().signed_wire, originals.signed_wire);
        assert_eq!(retained.originals().manifest_json, originals.manifest_json);
        assert_eq!(config::genesis_signing_count(), signs_before);
        Ok(())
    }

    #[test]
    fn retained_input_refuses_changed_proposal_and_foreign_signature() -> Result<()> {
        use iroha_data_model::block::{BlockSignature, BlockSignatures, SignedBlock};

        let (_generated, originals, owners) = retained_fixture();
        let retained = RetainedNetworkGenesis::new(originals.clone(), owners.clone())?.genesis;
        let original = retained.block().0;
        let mut payload = original.payload().clone();
        payload
            .header
            .set_view_change_index(original.header().view_change_index() + 1);
        let changed_proposal = SignedBlock::presigned_with_payload(
            original
                .signatures()
                .next()
                .expect("one genesis signature")
                .clone(),
            payload,
        );
        assert!(!original.checked_resultless_proposal_eq(&changed_proposal)?);
        let mut source = originals.clone();
        source.signed_wire = changed_proposal.encode_wire()?;
        // Move the supplied hash with the candidate so this is a genuine signature
        // refusal, not merely a stale expected-hash mismatch.
        source.block_hash = changed_proposal.hash();
        let refusal = RetainedNetworkGenesis::new(source, owners.clone())
            .err()
            .expect("changed signed proposal must be refused");
        assert!(
            refusal
                .to_string()
                .contains("verify genesis block signature")
        );

        assert_ne!(ALICE_KEYPAIR.public_key(), &originals.public_key);
        let foreign_signature = BlockSignature::new(
            0,
            iroha_crypto::SignatureOf::try_from_hash(ALICE_KEYPAIR.private_key(), original.hash())?,
        );
        let mut changed_signature = original.clone();
        changed_signature
            .replace_signatures(BlockSignatures::try_from_iter([foreign_signature])?)?;
        assert_eq!(changed_signature.hash(), original.hash());
        assert!(!original.checked_resultless_proposal_eq(&changed_signature)?);
        let mut source = originals.clone();
        source.signed_wire = changed_signature.encode_wire()?;
        let refusal = RetainedNetworkGenesis::new(source, owners)
            .err()
            .expect("foreign signature must be refused");
        assert!(
            refusal
                .to_string()
                .contains("verify genesis block signature")
        );
        assert_eq!(retained.originals().signed_wire, originals.signed_wire);
        assert_eq!(retained.originals().manifest_json, originals.manifest_json);
        Ok(())
    }

    #[test]
    fn retained_final_config_rejects_another_admitted_validator_owner() -> Result<()> {
        let (generated, originals, owners) = retained_fixture();
        let input = RetainedNetworkGenesis::new(originals, owners)?;
        let retained = input.genesis;
        let selected = &generated.peers[0];
        let other = &generated.peers[1];
        let mut layers = generated
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let actual = resolve_actual_config_result(selected, &layers)?;
        retained.validate_peer_owner(&actual, selected)?;
        // A different *admitted* key cannot be refused merely as foreign or lacking
        // a signed PoP. The final merged identity must match this precise owner.
        layers.push(
            Table::new()
                .write("public_key", other.key_pair.public_key().to_string())
                .write(
                    "private_key",
                    ExposedPrivateKey(other.key_pair.private_key().clone()).to_string(),
                ),
        );
        let overridden = resolve_actual_config_result(selected, &layers)?;
        assert_eq!(overridden.common.key_pair, other.key_pair);
        assert!(retained.validate_peer_owner(&overridden, selected).is_err());
        let mut observer = actual.clone();
        observer.sumeragi.role = iroha_config::parameters::actual::NodeRole::Observer;
        assert!(retained.validate_peer_owner(&observer, selected).is_err());
        Ok(())
    }

    #[test]
    fn maintained_engineering_fixture_keys_match_the_fixture_roster() {
        let keys = iroha_core::sumeragi::test_chain::fixture_keys();
        let roster = iroha_core::sumeragi::test_chain::fixture_validators();
        assert_eq!(keys.len(), 4);
        for (key, (peer, pop)) in keys.iter().zip(roster) {
            assert_eq!(key.public_key(), peer.public_key());
            assert_eq!(
                iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
                pop
            );
        }
    }
}
