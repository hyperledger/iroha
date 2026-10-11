//! Optional complete native AMX bootstrap sources for the ordinary genesis signing owner.

use std::path::{Path, PathBuf};

use color_eyre::eyre::{WrapErr, eyre};
use iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES;
use iroha_genesis::{RawGenesisTransaction, SIGNED_GENESIS_MAX_BYTES_V1};
use iroha_model_base::chain::ChainId;

#[derive(Default, clap::Args)]
#[group(id = "NativeAmxBootstrapArgs")]
pub(super) struct Args {
    /// Full global chain label selected for the private root's native AMX participant.
    #[clap(long, value_name = "CHAIN_ID", requires_all = ["amx_global_genesis", "amx_global_successor"])]
    amx_global_chain_id: Option<ChainId>,
    /// Complete original signed global genesis in canonical `SignedBlockWire` format.
    #[clap(long, value_name = "PATH", requires_all = ["amx_global_chain_id", "amx_global_successor"])]
    amx_global_genesis: Option<PathBuf>,
    /// Genuine global H2 whose exact quorum authenticates that original genesis result.
    #[clap(long, value_name = "PATH", requires_all = ["amx_global_chain_id", "amx_global_genesis"])]
    amx_global_successor: Option<PathBuf>,
}

impl Args {
    pub(super) fn source_paths(&self) -> impl Iterator<Item = &Path> {
        [
            self.amx_global_genesis.as_deref(),
            self.amx_global_successor.as_deref(),
        ]
        .into_iter()
        .flatten()
    }

    pub(super) fn append_to(
        self,
        genesis: RawGenesisTransaction,
    ) -> color_eyre::Result<RawGenesisTransaction> {
        match (
            self.amx_global_chain_id,
            self.amx_global_genesis,
            self.amx_global_successor,
        ) {
            (None, None, None) => Ok(genesis),
            (Some(chain), Some(g1), Some(h2)) => {
                let mut g1 = iroha_fs::read_regular(&g1, SIGNED_GENESIS_MAX_BYTES_V1)
                    .wrap_err("read stable bounded original AMX global genesis")?;
                let mut h2 = iroha_fs::read_regular(&h2, MAX_FINALITY_BLOCK_BYTES)
                    .wrap_err("read stable bounded original AMX global H2")?;
                iroha_deploy::genesis::amx::append_amx_participant(
                    genesis,
                    chain,
                    std::mem::take(&mut *g1),
                    std::mem::take(&mut *h2),
                )
            }
            _ => Err(eyre!(
                "explicit AMX bootstrap requires the full global chain label and both original G1/H2 frames"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use iroha_data_model::block::consensus::SumeragiGenesisContextParameters;
    use iroha_genesis::GenesisBuilder;

    fn manifest() -> RawGenesisTransaction {
        GenesisBuilder::new_without_executor(ChainId::from("ordinary-signing"), PathBuf::from("."))
            .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
            .build_raw()
            .unwrap()
    }

    #[test]
    fn ordinary_signing_without_amx_sources_preserves_the_exact_manifest() {
        let original = manifest();
        let before = norito::json::to_vec(&original).unwrap();
        let after = Args::default().append_to(original).unwrap();
        assert_eq!(norito::json::to_vec(&after).unwrap(), before);
        assert_eq!(Args::default().source_paths().count(), 0);
    }

    #[test]
    fn explicit_amx_bootstrap_arguments_require_exact_complete_source_pair() {
        let original = manifest();
        for selected in 1_u8..7 {
            let args = Args {
                amx_global_chain_id: (selected & 1 != 0).then(|| ChainId::from("global")),
                amx_global_genesis: (selected & 2 != 0).then(|| PathBuf::from("never-open-g1")),
                amx_global_successor: (selected & 4 != 0).then(|| PathBuf::from("never-open-h2")),
            };
            let error = args.append_to(original.clone()).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("requires the full global chain label")
            );
        }
        for missing in [
            "--amx-global-chain-id",
            "--amx-global-genesis",
            "--amx-global-successor",
        ] {
            let mut arguments = vec!["sign", "genesis.json", "--private-key-file", "private.key"];
            for (flag, value) in [
                ("--amx-global-chain-id", "global"),
                ("--amx-global-genesis", "global-g1.nrt"),
                ("--amx-global-successor", "global-h2.nrt"),
            ] {
                if flag != missing {
                    arguments.extend([flag, value]);
                }
            }
            assert!(super::super::Args::try_parse_from(arguments).is_err());
        }
        assert!(
            super::super::Args::try_parse_from([
                "sign",
                "genesis.json",
                "--private-key-file",
                "private.key",
                "--amx-global-chain-id",
                "global",
                "--amx-global-genesis",
                "global-g1.nrt",
                "--amx-global-successor",
                "global-h2.nrt",
            ])
            .is_ok()
        );
    }

    #[test]
    fn explicit_amx_bootstrap_refuses_to_overwrite_an_original_source_artifact() {
        use crate::RunArgs as _;
        use std::io::BufWriter;
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("private-genesis.json");
        let g1 = directory.path().join("global-g1.nrt");
        let h2 = directory.path().join("global-h2.nrt");
        let key = directory.path().join("must-not-read.key");
        std::fs::write(&key, b"inert source-alias rejection fixture").unwrap();
        std::fs::write(&manifest, b"{}").unwrap();
        std::fs::write(&g1, b"original G1 source stays untouched").unwrap();
        std::fs::write(&h2, b"original H2 source stays untouched").unwrap();
        let args = super::super::Args::try_parse_from([
            "sign",
            manifest.to_str().unwrap(),
            "--private-key-file",
            key.to_str().unwrap(),
            "--out-file",
            g1.to_str().unwrap(),
            "--amx-global-chain-id",
            "global",
            "--amx-global-genesis",
            g1.to_str().unwrap(),
            "--amx-global-successor",
            h2.to_str().unwrap(),
        ])
        .unwrap();
        let error = args.run(&mut BufWriter::new(Vec::new())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("AMX global source and signed genesis output must use different paths")
        );
        assert_eq!(
            std::fs::read(&g1).unwrap(),
            b"original G1 source stays untouched"
        );
        assert_eq!(
            std::fs::read(&h2).unwrap(),
            b"original H2 source stays untouched"
        );
    }

    #[test]
    fn explicit_amx_bootstrap_does_not_substitute_missing_or_malformed_sources() {
        let directory = tempfile::tempdir().unwrap();
        let g1 = directory.path().join("g1.nrt");
        let h2 = directory.path().join("h2.nrt");
        let args = || Args {
            amx_global_chain_id: Some(ChainId::from("global")),
            amx_global_genesis: Some(g1.clone()),
            amx_global_successor: Some(h2.clone()),
        };
        assert!(args().append_to(manifest()).is_err());
        std::fs::write(&g1, b"not canonical signed genesis").unwrap();
        assert!(args().append_to(manifest()).is_err());
        std::fs::write(&h2, b"not canonical H2").unwrap();
        let mut context = SumeragiGenesisContextParameters::recommended();
        context.root_scope = iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
            parent_network_id: iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"selected parent",
                )),
            ),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(741),
        };
        let error = args()
            .append_to(manifest().with_sumeragi_context_parameters(context))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("decode canonical AMX global source")
        );
    }

    // Original source frames come from actual global execution and a nonempty native H2.
    // This fixture launches neither validators nor a remote network.
    struct ExecutedGlobalSources {
        chain_id: ChainId,
        network_id: iroha_data_model::NetworkId,
        genesis: Vec<u8>,
        successor: Vec<u8>,
    }

    impl ExecutedGlobalSources {
        fn new() -> Self {
            use iroha_core::{
                state::World,
                sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
            };
            use iroha_data_model::{isi::Log, level::Level};
            let config = TestChainConfig::new(World::new(), 1_000);
            let chain_id = config.chain_id.clone();
            let signer = config.genesis_key.clone();
            let mut chain = CertifiedTestChain::start(config).unwrap();
            let transaction = chain.sign(
                &signer,
                [Log::new(Level::INFO, "genuine CLI AMX bootstrap H2".into()).into()],
                1_499,
            );
            assert_eq!(chain.commit_at(1_500, vec![transaction]), vec![true]);
            assert!(chain.committed(1).block().has_results());
            assert!(chain.committed(2).block().has_results());
            Self {
                chain_id,
                network_id: chain.network_id(),
                genesis: chain.committed(1).block().encode_wire().unwrap(),
                successor: chain.committed(2).block().encode_wire().unwrap(),
            }
        }
    }

    fn assert_original_signed_and_bound_outputs(
        bound_path: &Path,
        signed_path: &Path,
        identity_path: &Path,
        global: &ExecutedGlobalSources,
        spec: &iroha_deploy::localnet::PrivateRootSpec,
        public_key: &iroha_crypto::PublicKey,
        original_private_network: &str,
    ) {
        use iroha_data_model::{NetworkId, isi::sumeragi_amx::RegisterAmxParticipantV1};
        let bound = RawGenesisTransaction::from_path(bound_path).unwrap();
        let signed_wire = std::fs::read(signed_path).unwrap();
        let signed = iroha_genesis::decode_signed_genesis(&signed_wire).unwrap();
        assert_eq!(signed.encode_wire().unwrap(), signed_wire);
        assert_eq!(bound.sumeragi_context_parameters().root_scope, spec.scope());
        assert_eq!(
            iroha_genesis::signed_genesis_consensus_metadata(&signed)
                .unwrap()
                .sumeragi_context
                .root_scope,
            spec.scope()
        );
        let bound_registrations = bound
            .instructions()
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterAmxParticipantV1>()
            })
            .collect::<Vec<_>>();
        let signed_registrations = signed
            .external_transactions()
            .flat_map(|transaction| transaction.instructions().explicit_instructions())
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterAmxParticipantV1>()
            })
            .collect::<Vec<_>>();
        for registrations in [&bound_registrations, &signed_registrations] {
            assert_eq!(registrations.len(), 1);
            assert_eq!(registrations[0].dataspace, spec.dataspace_id);
            assert_eq!(registrations[0].global_chain_id, global.chain_id);
            assert_eq!(registrations[0].global_genesis, global.genesis);
            assert_eq!(registrations[0].global_successor, global.successor);
        }
        assert!(signed.has_results());
        assert!(signed.output_results().count() > 0);
        assert!(
            signed
                .output_results()
                .all(|result| result.as_ref().is_ok())
        );
        signed.validate_output_merkle_cache().unwrap();
        assert_eq!(signed.signatures().count(), 1);
        for signature in signed.signatures() {
            signature
                .signature()
                .verify_hash(public_key, signed.hash())
                .unwrap();
        }
        for transaction in signed.external_transactions() {
            transaction.verify_signature().unwrap();
        }
        let identity = NetworkId::from_genesis_hash(signed.hash());
        assert_eq!(
            std::fs::read_to_string(identity_path).unwrap(),
            format!("{identity}\n")
        );
        assert_ne!(identity.to_string(), original_private_network);
    }

    fn assert_actual_node_admits_original_cli_bundle(
        config_path: &Path,
        original_config: &[u8],
        bound_path: &Path,
        signed_path: &Path,
    ) {
        // Run only after Args::run: this is the actual generated validator's policy,
        // not policy adaptation supplied to the CLI before its normalization/signing.
        let mut node = super::super::load_peer_config_bytes(config_path, original_config).unwrap();
        let table = crate::secret_toml::Table::new(
            crate::secret_toml::parse_table(
                std::str::from_utf8(original_config).unwrap(),
                "original private node policy after CLI signing",
            )
            .unwrap(),
        );
        iroha_config::sora_profile::SoraProfileSelection::from_table(&table).apply(&mut node);
        let bound = RawGenesisTransaction::from_path(bound_path).unwrap();
        let wire = std::fs::read(signed_path).unwrap();
        let signed = iroha_genesis::decode_signed_genesis(&wire).unwrap();
        // A newly published bundle supplies its exact new identity; every other configured
        // validator policy and source field remains from the original generated configuration.
        node.genesis.expected_hash = signed.hash();
        let admitted = iroha_deploy::genesis::staging::staged_signed_native_genesis(
            &bound, &wire, &node,
        )
        .expect(
            "the actual generated Sora/private validator must admit and execute the CLI bundle",
        );
        assert_eq!(admitted.genesis().hash(), signed.hash());
        assert_eq!(admitted.genesis().encode_wire().unwrap(), wire);
        assert!(admitted.genesis().has_results());
        assert!(admitted.genesis().output_results().count() > 0);
        assert!(
            admitted
                .genesis()
                .output_results()
                .all(|result| result.as_ref().is_ok())
        );
    }

    #[test]
    fn explicit_amx_bootstrap_cli_signs_and_binds_original_sources_with_generated_private_config() {
        use crate::RunArgs as _;
        use iroha_data_model::sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1};
        use std::io::BufWriter;
        let global = ExecutedGlobalSources::new();
        let temporary = tempfile::tempdir().unwrap();
        let private = temporary.path().join("private");
        let alias = "amxcli";
        let name = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias).unwrap();
        let spec = iroha_deploy::localnet::PrivateRootSpec {
            parent_network_id: global.network_id,
            dataspace_id: iroha_model_base::topology::DataSpaceId::from_hash(&name.name_hash()),
            dataspace_alias: alias.into(),
        };
        let ports = iroha_deploy::managed::LocalnetPorts::reserve().unwrap();
        let prepared =
            iroha_deploy::localnet::prepare_private_root("amx-cli", &private, &ports, &spec)
                .expect(
                    "generate actual private fee/SNS/topology policy and canonical signer custody",
                );
        let client = prepared.context.load_client_config().unwrap();
        let manifest = private.join("genesis.json");
        let key = private.join(iroha_deploy::localnet::GENESIS_PRIVATE_KEY_FILE);
        let config = &prepared.peers[0].config_path;
        let original_manifest = std::fs::read(&manifest).unwrap();
        let original_config = iroha_fs::read_private(config, 1024 * 1024).unwrap();
        let original_key = iroha_fs::read_private(&key, 4096).unwrap();
        let g1 = temporary.path().join("global-g1.nrt");
        let h2 = temporary.path().join("global-h2.nrt");
        std::fs::write(&g1, &global.genesis).unwrap();
        std::fs::write(&h2, &global.successor).unwrap();
        let signed_path = temporary.path().join("amx-signed.nrt");
        let bound_path = temporary.path().join("amx-bound.json");
        let identity_path = temporary.path().join("amx-network-id");
        let chain_label = global.chain_id.to_string();
        let public_key = client.key_pair.public_key().to_string();
        let args = super::super::Args::try_parse_from([
            "sign",
            manifest.to_str().unwrap(),
            "--private-key-file",
            key.to_str().unwrap(),
            "--expected-public-key",
            &public_key,
            "--config",
            config.to_str().unwrap(),
            "--creation-time-ms",
            "1700000000000",
            "--out-file",
            signed_path.to_str().unwrap(),
            "--bound-manifest-out",
            bound_path.to_str().unwrap(),
            "--expected-hash-out",
            identity_path.to_str().unwrap(),
            "--amx-global-chain-id",
            &chain_label,
            "--amx-global-genesis",
            g1.to_str().unwrap(),
            "--amx-global-successor",
            h2.to_str().unwrap(),
        ])
        .unwrap();
        args.run(&mut BufWriter::new(Vec::new()))
            .expect("actual CLI normalization/config binding must preserve and execute native AMX bootstrap");
        assert_original_signed_and_bound_outputs(
            &bound_path,
            &signed_path,
            &identity_path,
            &global,
            &spec,
            client.key_pair.public_key(),
            &prepared.context.network_id,
        );
        assert_actual_node_admits_original_cli_bundle(
            config,
            &original_config,
            &bound_path,
            &signed_path,
        );
        assert_eq!(std::fs::read(&g1).unwrap(), global.genesis);
        assert_eq!(std::fs::read(&h2).unwrap(), global.successor);
        assert_eq!(std::fs::read(&manifest).unwrap(), original_manifest);
        assert!(
            iroha_fs::read_private(config, 1024 * 1024)
                .unwrap()
                .as_slice()
                == original_config.as_slice()
        );
        assert!(iroha_fs::read_private(&key, 4096).unwrap().as_slice() == original_key.as_slice());
    }
}
