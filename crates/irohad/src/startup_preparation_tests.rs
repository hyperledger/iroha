mod startup_preparation_tests {
    //! Actual prepared-state custody across provider refusal, replay and emergency admission.

    use super::*;
    use std::{
        cell::Cell,
        net::TcpListener,
        sync::{Weak, mpsc},
    };

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn unsupported_consensus_pairing_refuses_startup_before_any_reservation() {
        use crate::startup_preparation::refuse_unsupported_consensus_pairing;
        let linked = iroha_core::sumeragi::crypto::BlsCrypto::check_pairing_geometry();
        assert!(refuse_unsupported_consensus_pairing(linked).is_ok());
        let refusal = iroha_crypto::bls::consensus::UnsupportedPairingGeometry {
            context_bytes: 5496,
            stack_bytes: 4096,
        };
        let report = refuse_unsupported_consensus_pairing(Err(refusal)).unwrap_err();
        assert!(matches!(
            report.current_context(),
            StartError::ConsensusPairing
        ));
        let rendered = format!("{report:?}");
        assert!(rendered.contains("reports 5496 bytes"), "{rendered}");
        // Checked before the process-wide NTS reservation and every later owner.
        let preparation = include_str!("startup_preparation.rs");
        let check = preparation
            .find("refuse_unsupported_consensus_pairing(pairing)?;")
            .expect("startup pairing refusal");
        let reservation = preparation
            .find("let nts_reservation = iroha_core::time::reserve(")
            .expect("NTS reservation");
        assert!(check < reservation);
    }

    #[test]
    fn startup_logger_runs_on_owned_runtime_without_leaking_entry() {
        // The production logger is process-global. Isolate its real constructor from the
        // test suite's shared logger rather than borrowing an already initialized actor.
        let module = module_path!().split_once("::").unwrap().1;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                format!("{module}::startup_logger_process"),
                "--exact".into(),
                "--ignored".into(),
                "--nocapture".into(),
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "isolated startup logger failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "isolated child of startup_logger_runs_on_owned_runtime_without_leaking_entry"]
    fn startup_logger_process() {
        let runtime = runtime();
        assert!(tokio::runtime::Handle::try_current().is_err());
        let logger = init_startup_logger(
            &runtime,
            iroha_logger::Config {
                level: iroha_logger::Level::INFO,
                filter: None,
                format: iroha_logger::Format::Compact,
                terminal_colors: false,
            },
        )
        .unwrap();
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "provider resolution must remain outside Tokio"
        );
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                logger
                    .reload_level(iroha_logger::Level::WARN.into())
                    .await
                    .unwrap();
                logger
                    .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Regular)
                    .await
                    .unwrap();
            })
            .await
            .expect("the logger actor must run on the original runtime");
        });
        assert!(tokio::runtime::Handle::try_current().is_err());
    }

    /// Retain the selected storage and every passive trusted-peer endpoint until shutdown closes.
    struct FixtureResources {
        _directory: tempfile::TempDir,
        _peer_endpoints: Vec<TcpListener>,
    }

    fn fixture(
        instructions: impl IntoIterator<Item = InstructionBox>,
    ) -> (FixtureResources, LocalSemanticGenesisFixture) {
        fixture_with_source_account(instructions, None)
    }

    fn fixture_with_source_account(
        instructions: impl IntoIterator<Item = InstructionBox>,
        source_only_account: Option<&AccountId>,
    ) -> (FixtureResources, LocalSemanticGenesisFixture) {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = offline_semantic_genesis_fixture(instructions);
        fixture.config.kura.store_dir = WithOrigin::inline(directory.path().join("kura"));
        fixture.config.snapshot.store_dir = WithOrigin::inline(directory.path().join("snapshots"));
        fixture.config.snapshot.mode = SnapshotMode::Disabled;
        fixture.config.genesis.file = None;
        fixture.config.genesis.manifest_json = None;
        fixture.config.streaming.session_store_dir = directory.path().join("streaming");
        // Reserve distinct OS-selected fixture endpoints, then release them before startup.
        let network = TcpListener::bind("127.0.0.1:0").unwrap();
        let torii = TcpListener::bind("127.0.0.1:0").unwrap();
        fixture.config.network.address =
            WithOrigin::inline(network.local_addr().unwrap().to_string().parse().unwrap());
        fixture.config.network.public_address = fixture.config.network.address.clone();
        fixture.config.torii.address =
            WithOrigin::inline(torii.local_addr().unwrap().to_string().parse().unwrap());

        // Match the actual signed roster, not sample_config's unrelated local validator.
        // Passive neighbor listeners remain fixture-owned throughout activation and cleanup;
        // no default neighbor address or external validator can enter this fixture.
        let validator_keys: Vec<_> = (0_u8..4)
            .map(|index| {
                iroha_crypto::KeyPair::try_from_seed(vec![0x50 + index; 32], Algorithm::BlsNormal)
                    .expect("the same deterministic validator used by signed genesis")
            })
            .collect();
        let peer_endpoints: Vec<_> = (0..3)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let myself = iroha_data_model::peer::Peer::new(
            fixture.config.network.address.value().clone(),
            validator_keys[0].public_key().clone(),
        );
        let others = peer_endpoints
            .iter()
            .zip(validator_keys.iter().skip(1))
            .map(|(endpoint, key)| {
                iroha_data_model::peer::Peer::new(
                    endpoint.local_addr().unwrap().into(),
                    key.public_key().clone(),
                )
            })
            .collect();
        let pops = validator_keys
            .iter()
            .map(|key| {
                (
                    key.public_key().clone(),
                    iroha_crypto::bls_normal_pop_prove(key.private_key())
                        .expect("the same proof of possession used by signed genesis"),
                )
            })
            .collect();
        fixture.config.common.key_pair = validator_keys[0].clone();
        fixture.config.common.peer = myself.clone();
        fixture.config.common.trusted_peers =
            WithOrigin::inline(iroha_config::parameters::actual::TrustedPeers {
                myself,
                others,
                pops,
            });
        seal_startup_genesis(&mut fixture, source_only_account);
        // The host requires authentic successful execution outputs before the prepared owner.
        // The negative fixture was genuinely executed in a different source World; only its
        // replay in the ordinary fresh target World is intentionally invalid.
        validate_available_genesis_inputs(&fixture.config, &fixture.genesis)
            .expect("prepared-startup fixture must pass actual supplied-genesis input admission");
        (
            FixtureResources {
                _directory: directory,
                _peer_endpoints: peer_endpoints,
            },
            fixture,
        )
    }

    /// Execute the signing proposal without publishing, then sign its actual sealed outputs.
    /// The common offline helper deliberately keeps proposals resultless and stays unchanged.
    fn seal_startup_genesis(
        fixture: &mut LocalSemanticGenesisFixture,
        source_only_account: Option<&AccountId>,
    ) {
        use iroha_core::state::WorldReadOnly as _;

        let signer = KeyPair::try_from_seed(
            b"offline-genesis-validation-authority".to_vec(),
            Algorithm::Ed25519,
        )
        .expect("the proposal's original deterministic genesis authority");
        assert_eq!(signer.public_key(), &fixture.config.genesis.public_key);
        let config = &fixture.config;
        let root = DisposableValidationRoot::create().expect("temporary genesis sealing storage");
        let kura = open_disposable_validation_kura(config, &root).expect("genesis sealing Kura");
        let budget =
            iroha_allocation::AllocationBudget::new(config.pipeline.ivm_execution_max_bytes);
        let mut accounts = vec![genesis_account(signer.public_key().clone())];
        if let Some(account) = source_only_account {
            // This is the exact fresh target account set in PreparedStartup. The extra account
            // exists only in the signing source, so Unregister succeeds there but not on replay.
            assert!(accounts.iter().all(|existing| existing.id() != account));
            accounts.push(Account::new(account.clone()).build(&fixture.authority));
        }
        let mut world = World::try_with_execution_budget(
            [genesis_domain(signer.public_key().clone())],
            accounts,
            [],
            &budget,
        )
        .expect("genesis sealing World");
        iroha_core::sns::seed_genesis_alias_bootstrap(
            &mut world,
            &fixture.genesis.0,
            &config.nexus.dataspace_catalog,
        )
        .expect("authenticated genesis SNS bootstrap");
        let mut state = State::try_new_with_chain_and_network_id(
            budget,
            world,
            kura,
            LiveQueryStore::start_test(),
            config.common.chain.clone(),
            NetworkId::from_genesis_hash(fixture.genesis.0.hash()),
            #[cfg(feature = "telemetry")]
            StateTelemetry::default(),
        )
        .expect("genesis sealing State");
        install_zk_config_before_kura_replay(&mut state, config).expect("genesis ZK policy");
        apply_state_runtime_config_before_snapshot_auth(&mut state, config)
            .expect("fixture runtime policy configuration");
        let baseline = freeze_lane_manifests_for_startup_replay(&config.nexus)
            .expect("genesis lane manifests");
        let policies =
            install_lane_policies_for_startup_replay(&mut state, config.nexus.clone(), &baseline)
                .expect("genesis lane policy");
        apply_state_geometry_config_before_kura_replay(&mut state, &policies)
            .expect("genesis geometry");
        if let Some(account) = source_only_account {
            assert!(state.world_view().accounts().get(account).is_some());
        }
        let voters = iroha_core::sumeragi::schedule::genesis_validators(&fixture.genesis)
            .expect("signed genesis voters");
        let topology = Topology::new(voters.into_keys());
        let (mode, context) = signed_genesis_context_metadata(&fixture.genesis.0)
            .expect("signed startup genesis consensus context");
        assert_eq!(mode, fixture.mode);
        let (valid, staged) = ValidBlock::validate_signed_genesis(
            fixture.genesis.0.clone(),
            &topology,
            &fixture.authority,
            &TimeSource::new_system(),
            &state,
            mode,
            context.root_scope,
        )
        .unpack(|_| {})
        .unwrap_or_else(|(_, error)| {
            panic!("fixture must genuinely execute before sealing: {error}")
        });
        if let Some(account) = source_only_account {
            assert!(staged.world().accounts().get(account).is_none());
        }
        drop(staged);
        let mut executed: iroha_data_model::block::SignedBlock = valid.into();
        let signature = iroha_data_model::block::BlockSignature::new(
            0,
            iroha_crypto::SignatureOf::try_from_hash(signer.private_key(), executed.hash())
                .expect("sign the native sealed genesis hash"),
        );
        executed
            .replace_signatures(
                iroha_data_model::block::BlockSignatures::try_from_iter([signature])
                    .expect("one canonical genesis signature"),
            )
            .expect("replace proposal signature after native sealing");
        iroha_core::validate_genesis_block(&executed, &fixture.authority)
            .expect("sealed genesis carries genuine successful execution outputs");
        fixture.config.genesis.expected_hash = executed.hash();
        fixture.genesis = GenesisBlock(executed);
    }

    fn reopen(config: &Config) -> (Arc<Kura>, iroha_core::kura::BlockCount) {
        Kura::new_with_configured_lane_catalog(
            &config.kura,
            &config.nexus.lane_config,
            &config.nexus.configured_lane_catalog,
        )
        .expect("original storage custody was released")
    }

    fn assert_nts_released(config: &Config) {
        let reservation = iroha_core::time::reserve(iroha_core::time::Params::from(&config.nts));
        assert!(
            reservation.is_some(),
            "the failed generation must release its original NTS owner"
        );
        drop(reservation);
    }

    type CustodyProbe = (Weak<State>, Weak<Kura>, mpsc::Receiver<(bool, bool, bool)>);

    /// Add a real supervised child that observes custody only after original shutdown admission.
    fn custody_probe(
        runtime: &tokio::runtime::Runtime,
        prepared: &mut PreparedStartup,
    ) -> CustodyProbe {
        let state = Arc::downgrade(&prepared.native.state);
        let kura = Arc::downgrade(&prepared.native.kura);
        let child_state = state.clone();
        let child_kura = kura.clone();
        let config = prepared.config().clone();
        let shutdown = prepared.native.supervisor.shutdown_signal();
        let (sent, received) = mpsc::sync_channel(1);
        prepared.native.supervisor.monitor(Child::new(
            runtime.spawn(async move {
                shutdown.receive().await;
                let nts_held =
                    iroha_core::time::reserve(iroha_core::time::Params::from(&config.nts))
                        .is_none();
                let store_held = Kura::new_with_configured_lane_catalog(
                    &config.kura,
                    &config.nexus.lane_config,
                    &config.nexus.configured_lane_catalog,
                )
                .is_err();
                sent.send((
                    child_state.upgrade().is_some() && child_kura.upgrade().is_some(),
                    nts_held,
                    store_held,
                ))
                .unwrap();
            }),
            OnShutdown::Wait(Duration::from_secs(5)),
        ));
        (state, kura, received)
    }

    #[test]
    #[serial_test::serial]
    fn original_prepared_state_survives_provider_boundary_and_joins_before_release() {
        let _registry = instruction_registry_test_guard();
        iroha_genesis::init_instruction_registry();
        let (_resources, fixture) = fixture([]);
        let config = fixture.config.clone();
        let expected = fixture.genesis.0.hash();
        let runtime = runtime();
        let calls = Cell::new(0);
        let (mut prepared, _) =
            prepare_with_runtime_deps(&runtime, fixture.config, Some(fixture.genesis), |config| {
                calls.set(calls.get() + 1);
                assert!(
                    tokio::runtime::Handle::try_current().is_err(),
                    "synchronous providers stay outside Tokio"
                );
                assert!(
                    iroha_core::time::reserve(iroha_core::time::Params::from(&config.nts))
                        .is_none()
                );
                assert!(
                    TcpListener::bind(config.network.address.value().to_string()).is_ok(),
                    "P2P is not active yet"
                );
                assert!(
                    TcpListener::bind(config.torii.address.value().to_string()).is_ok(),
                    "Torii is not active yet"
                );
                Ok(IrohaRuntimeDeps::default())
            })
            .expect("real original preparation");
        assert_eq!(calls.get(), 1);
        assert_eq!(prepared.native.state.committed_height(), 1);
        assert_eq!(
            prepared.native.kura.exact_durable_blocks_count().unwrap(),
            1
        );
        assert_eq!(
            prepared.native.state.network_id,
            NetworkId::from_genesis_hash(expected)
        );
        let (state, kura, received) = custody_probe(&runtime, &mut prepared);
        runtime
            .block_on(prepared.close())
            .expect("all original children join");
        assert_eq!(received.try_recv().unwrap(), (true, true, true));
        assert!(state.upgrade().is_none());
        assert!(kura.upgrade().is_none());
        assert_nts_released(&config);
        let (replayed, _) = prepare_with_runtime_deps(&runtime, config.clone(), None, |_| {
            Ok(IrohaRuntimeDeps::default())
        })
        .expect("Strict retry re-executes the retained exact genesis, with no local file");
        assert_eq!(replayed.native.state.committed_height(), 1);
        let stored = replayed.native.stored_genesis_block.as_ref().unwrap();
        assert_eq!(stored.hash(), expected);
        assert_eq!(
            replayed.native.kura.exact_durable_blocks_count().unwrap(),
            1
        );
        runtime.block_on(replayed.close()).unwrap();
        assert_nts_released(&config);
    }

    #[test]
    #[serial_test::serial]
    fn provider_refusal_retains_valid_genesis_but_releases_native_owners() {
        let _registry = instruction_registry_test_guard();
        iroha_genesis::init_instruction_registry();
        let (_resources, fixture) = fixture([]);
        let config = fixture.config.clone();
        let expected = fixture.genesis.0.hash();
        let runtime = runtime();
        let error =
            prepare_with_runtime_deps(&runtime, fixture.config, Some(fixture.genesis), |_| {
                assert!(tokio::runtime::Handle::try_current().is_err());
                Err(Report::new(MainError::Config).attach("fixture provider refusal"))
            })
            .err()
            .expect("provider refusal is returned");
        assert!(format!("{error:?}").contains("fixture provider refusal"));
        assert_nts_released(&config);
        let (kura, count) = reopen(&config);
        assert_eq!(count.0, 1, "valid genesis remains durably retained");
        let budget =
            iroha_allocation::AllocationBudget::new(config.pipeline.ivm_execution_max_bytes);
        assert_eq!(
            read_stored_genesis_block(&kura, count, &budget)
                .unwrap()
                .unwrap()
                .hash(),
            expected
        );
    }

    #[test]
    #[serial_test::serial]
    fn invalid_native_genesis_never_resolves_a_provider_or_publishes_h1() {
        let _registry = instruction_registry_test_guard();
        iroha_genesis::init_instruction_registry();
        let absent = AccountId::new(
            KeyPair::from_seed(vec![0xEF; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let (_resources, fixture) = fixture_with_source_account(
            [Unregister::account(absent.clone()).into()],
            Some(&absent),
        );
        let config = fixture.config.clone();
        let runtime = runtime();
        let calls = Cell::new(0);
        let error =
            prepare_with_runtime_deps(&runtime, fixture.config, Some(fixture.genesis), |_| {
                calls.set(calls.get() + 1);
                Ok(IrohaRuntimeDeps::default())
            })
            .err()
            .expect("semantically invalid signed genesis must fail native execution");
        assert!(
            format!("{error:?}").contains("Sumeragi could not rebuild the state"),
            "{error:?}"
        );
        assert_eq!(calls.get(), 0);
        assert_nts_released(&config);
        let (_kura, count) = reopen(&config);
        assert_eq!(count.0, 0);
    }

    #[test]
    #[serial_test::serial]
    fn late_prepare_refusal_joins_before_native_storage_can_be_reopened() {
        let _registry = instruction_registry_test_guard();
        iroha_genesis::init_instruction_registry();
        let (_resources, mut fixture) = fixture([]);
        fixture.config.sumeragi.keys.allowed_algorithms.clear();
        let config = fixture.config.clone();
        let runtime = runtime();
        let error =
            prepare_with_runtime_deps(&runtime, fixture.config, Some(fixture.genesis), |_| {
                panic!("key-policy admission precedes provider resolution")
            })
            .err()
            .expect("a different local key policy must refuse after original H1 execution");
        assert!(
            format!("{error:?}").contains("configured Sumeragi key policy differs"),
            "{error:?}"
        );
        assert_nts_released(&config);
        let (_kura, count) = reopen(&config);
        assert_eq!(
            count.0, 1,
            "valid genesis remains; failed runtime admission creates no second block"
        );
    }

    #[test]
    #[serial_test::serial]
    fn activation_provider_preflight_keeps_original_custody_until_children_exit() {
        let _registry = instruction_registry_test_guard();
        iroha_genesis::init_instruction_registry();
        let (_resources, mut fixture) = fixture([]);
        fixture
            .config
            .torii
            .sorafs_storage
            .governance_dag_service
            .enabled = true;
        let config = fixture.config.clone();
        let runtime = runtime();
        let mut prepared = runtime
            .block_on(PreparedStartup::prepare(
                fixture.config,
                Some(fixture.genesis),
            ))
            .expect("original native preparation");
        let (state, kura, received) = custody_probe(&runtime, &mut prepared);
        let logger = {
            let _entered = runtime.enter();
            iroha_logger::test_logger()
        };
        let error = runtime
            .block_on(Iroha::activate_with_runtime_deps(
                test_build_metadata(),
                prepared,
                logger,
                ShutdownSignal::new(),
                IrohaRuntimeDeps::default(),
                None,
            ))
            .err()
            .expect("enabled Governance DAG rejects missing deployment providers");
        assert!(
            format!("{error:?}")
                .contains("failed to qualify Governance DAG service runtime providers"),
            "{error:?}"
        );
        assert_eq!(received.try_recv().unwrap(), (true, true, true));
        assert!(state.upgrade().is_none());
        assert!(kura.upgrade().is_none());
        assert_nts_released(&config);
        let (_kura, count) = reopen(&config);
        assert_eq!(count.0, 1);
        assert!(TcpListener::bind(config.network.address.value().to_string()).is_ok());
        assert!(TcpListener::bind(config.torii.address.value().to_string()).is_ok());
    }

    #[derive(Debug)]
    struct UnexpectedRetentionAuthority;

    impl iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionAuthorityV1
        for UnexpectedRetentionAuthority
    {
        fn handle(&self) -> &str {
            panic!("disabled reputation rejects the owner before consulting its handle")
        }

        fn qualification(&self) -> Result<
            iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionAuthorityQualificationV1,
            iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
        >{
            panic!("disabled reputation must not qualify an unrequested provider")
        }

        fn load_latest(&self, _: &NetworkId) -> Result<
            Option<iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionApprovalRecordV1>,
            iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
        >{
            panic!("disabled reputation must not read an unrequested provider")
        }

        fn compare_and_swap_latest(
            &self, _: &NetworkId, _: Option<[u8; 32]>,
            _: &iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionApprovalRecordV1,
        ) -> Result<(), iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1>{
            panic!("disabled reputation must not write an unrequested provider")
        }
    }

    #[test]
    #[serial_test::serial]
    fn late_activation_refusal_joins_manifest_watchers_before_release() {
        let _registry = instruction_registry_test_guard();
        iroha_genesis::init_instruction_registry();
        let (_resources, mut fixture) = fixture([]);
        // The direct injected path rejects this unrequested owner after creating the real
        // manifest watcher and P2P, but before consensus or Torii. No provider method runs.
        assert!(
            fixture
                .config
                .torii
                .sorafs_storage
                .reputation_runtime
                .is_none()
        );
        fixture.config.nexus.registry.poll_interval = Duration::from_secs(3_600);
        let config = fixture.config.clone();
        let runtime = runtime();
        let mut prepared = runtime
            .block_on(PreparedStartup::prepare(
                fixture.config,
                Some(fixture.genesis),
            ))
            .expect("original native preparation");
        let (state, kura, received) = custody_probe(&runtime, &mut prepared);
        let logger = {
            let _entered = runtime.enter();
            iroha_logger::test_logger()
        };
        let error = runtime
            .block_on(Iroha::activate_with_runtime_deps(
                test_build_metadata(),
                prepared,
                logger,
                ShutdownSignal::new(),
                IrohaRuntimeDeps::default().with_sorafs_reputation_retention_authority(Arc::new(
                    UnexpectedRetentionAuthority,
                )),
                None,
            ))
            .err()
            .expect("the later runtime dependency admission must refuse");
        let message = format!("{error:?}");
        assert!(message.contains("disabled SoraFS reputation runtime rejects an unexpected finalized-archive retention authority"), "{message}");
        // The late error proves execution reached the selected feature variant's real watcher creation.
        // An old detached watcher keeps this exact State/Kura alive after supervisor shutdown.
        assert_eq!(received.try_recv().unwrap(), (true, true, true));
        assert!(
            state.upgrade().is_none(),
            "the real manifest watcher must have exited"
        );
        assert!(kura.upgrade().is_none());
        assert_nts_released(&config);
        let (_kura, count) = reopen(&config);
        assert_eq!(count.0, 1);
        assert!(TcpListener::bind(config.network.address.value().to_string()).is_ok());
        assert!(TcpListener::bind(config.torii.address.value().to_string()).is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn emergency_fast_requires_its_exact_snapshot_without_replay_or_provider_resolution() {
        let _registry = instruction_registry_test_guard();
        iroha_genesis::init_instruction_registry();
        let (_resources, fixture) = fixture([]);
        let mut config = fixture.config.clone();
        let runtime = runtime();
        let prepared = runtime
            .block_on(PreparedStartup::prepare(
                fixture.config,
                Some(fixture.genesis),
            ))
            .unwrap();
        runtime.block_on(prepared.close()).unwrap();
        let root = Kura::canonical_storage_path(&config.kura.store_dir.resolve_relative_path());
        let files = [
            "blocks.data",
            "blocks.index",
            "blocks.hashes",
            "blocks.count.norito",
        ];
        let before: Vec<_> = files
            .iter()
            .map(|file| fs::read(root.join(file)).unwrap())
            .collect();
        config.kura.init_mode = InitMode::Fast;
        let error = prepare_with_runtime_deps(&runtime, config.clone(), None, |_| {
            panic!("Fast without its exact signed snapshot cannot resolve providers")
        })
        .err()
        .expect("Fast must not use Strict replay as a snapshot fallback");
        assert!(
            format!("{error:?}")
                .contains("emergency Fast startup requires one valid signed snapshot"),
            "{error:?}"
        );
        let after: Vec<_> = files
            .iter()
            .map(|file| fs::read(root.join(file)).unwrap())
            .collect();
        assert_eq!(before, after, "emergency admission is read-only");
        assert_nts_released(&config);
        config.kura.init_mode = InitMode::Strict;
        let (_kura, count) = reopen(&config);
        assert_eq!(count.0, 1);
    }
}
