//! Own the original prepared State until providers are admitted or cleanup has joined.

use super::*;

/// Actual native startup owners; no scalar verdict can substitute for this handoff.
pub struct PreparedNative {
    pub(super) config: Config,
    pub(super) supervisor: Supervisor,
    pub(super) kura: Arc<Kura>,
    pub(super) state: Arc<State>,
    pub(super) live_query_store: iroha_core::query::store::LiveQueryStoreHandle,
    pub(super) genesis: Option<GenesisBlock>,
    pub(super) stored_genesis_block: Option<iroha_data_model::block::SharedSignedBlock>,
    pub(super) block_count: iroha_core::kura::BlockCount,
    pub(super) prepared_sumeragi: Option<iroha_core::sumeragi::node::Prepared>,
    pub(super) signed_consensus_mode: iroha_data_model::block::consensus::ConsensusMode,
    pub(super) frozen_startup_lane_manifests: LaneManifestRegistryHandle,
    pub(super) frozen_startup_lane_compliance: Option<Arc<LaneComplianceEngine>>,
    pub(super) expected_network_id: NetworkId,
    pub(super) snapshot_writer_key: Option<KeyPair>,
    pub(super) snapshot_read_buffer_budget: iroha_allocation::AllocationBudget,
    pub(super) events_sender: broadcast::Sender<iroha_data_model::events::EventBox>,
    pub(super) startup_trace_started_at: Instant,
    pub(super) telemetry_profile: iroha_config::parameters::actual::TelemetryProfile,
    #[cfg(feature = "telemetry")]
    pub(super) metrics: Arc<iroha_telemetry::metrics::Metrics>,
    #[cfg(feature = "telemetry")]
    pub(super) state_telemetry: StateTelemetry,
    #[cfg(feature = "telemetry")]
    pub(super) streaming_telemetry: Option<StreamingTelemetry>,
}

/// Resource custody that outlives every fallible phase and its original child drain.
pub struct StartupLifetime {
    pub(super) nts_reservation: iroha_core::time::SamplerReservation,
    pub(super) kura: Option<Arc<Kura>>,
    pub(super) state: Option<Arc<State>>,
}

/// Own the actual prepared node and its cleanup lifetime through provider resolution.
pub struct PreparedStartup {
    // Keep the original large configuration/native owner off the Result and async handoff
    // stacks. Preparation still creates it once; activation or joined cleanup consumes it.
    pub(super) native: Box<PreparedNative>,
    pub(super) lifetime: StartupLifetime,
}

impl PreparedStartup {
    pub(super) fn config(&self) -> &Config {
        &self.native.config
    }

    pub(super) async fn prepare(
        config: Config,
        genesis: Option<GenesisBlock>,
    ) -> ReportResult<Self, StartError> {
        let nts_reservation = iroha_core::time::reserve(iroha_core::time::Params::from(
            &config.nts,
        ))
        .ok_or_else(|| {
            Report::new(StartError::StartP2p)
                .attach("network time service already has a process owner")
        })?;
        let mut lifetime = StartupLifetime {
            nts_reservation,
            kura: None,
            state: None,
        };
        let mut supervisor = Supervisor::new();
        match Self::prepare_inner(config, genesis, &mut supervisor, &mut lifetime) {
            Ok(native) => Ok(Self { native, lifetime }),
            Err(error) => {
                supervisor.shutdown_signal().send();
                let cleanup = supervisor.start().await;
                // Even an early inner error cannot make NTS or original storage available
                // to a second startup while this generation still owns a child.
                drop(lifetime);
                match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup) => {
                        Err(error.attach(format!("prepared startup cleanup failed: {cleanup:?}")))
                    }
                }
            }
        }
    }

    // Native preparation itself is synchronous. Its query-pruner child stays in this exact
    // owner until activation or joined shutdown; no Kura writer or network listener starts.
    #[allow(clippy::too_many_lines)]
    fn prepare_inner(
        config: Config,
        genesis: Option<GenesisBlock>,
        supervisor: &mut Supervisor,
        lifetime: &mut StartupLifetime,
    ) -> ReportResult<Box<PreparedNative>, StartError> {
        // Compile and validate immutable privacy profiles before any public
        // service begins accepting requests. In particular, the ZK-X.509
        // profile validates six fixed algebraic schedules; doing that work in
        // a Torii handler would make the first capability request CPU-bound.
        let privacy_catalog_started = Instant::now();
        let privacy_catalog =
            iroha_core_privacy::privacy_profiles::compiled_privacy_profile_catalog_v1().map_err(
                |error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to initialize compiled privacy profile catalog: {error}"
                    ))
                },
            )?;
        iroha_logger::info!(
            protocol_count = privacy_catalog.protocols.len(),
            elapsed_ms = privacy_catalog_started.elapsed().as_millis(),
            "compiled privacy profile catalog initialized before Torii startup"
        );
        let emergency_fast = config.kura.init_mode == InitMode::Fast;
        let snapshot_writer_key =
            if !emergency_fast && matches!(config.snapshot.mode, SnapshotMode::ReadWrite) {
                Some(
                    snapshot_signing_key(&config)
                        .map_err(|error| Report::new(StartError::InitKura).attach(error))?,
                )
            } else {
                None
            };
        let startup_trace_started_at = Instant::now();
        log_startup_trace("irohad.start.enter", startup_trace_started_at);
        let (kura, mut block_count) = Kura::new_with_configured_lane_catalog(
            &config.kura,
            &config.nexus.lane_config,
            &config.nexus.configured_lane_catalog,
        )
        .map_err(|err| {
            let resolved = config.kura.store_dir.resolve_relative_path();
            Report::new(err).attach(format!(
                "failed to initialize Kura for store_dir {} (raw {})",
                resolved.display(),
                config.kura.store_dir.value().display(),
            ))
        })
        .change_context(StartError::InitKura)?;
        lifetime.kura = Some(Arc::clone(&kura));
        kura.configure_fastpq_proof_sidecar_limits(&config.zk.fastpq);
        let live_query_store =
            LiveQueryStore::from_config(config.live_query_store, supervisor.shutdown_signal());
        let live_query_store = if emergency_fast {
            live_query_store.into_inert_handle()
        } else {
            let (handle, child) = live_query_store.start();
            supervisor.monitor(child);
            handle
        };
        let telemetry_profile = if emergency_fast {
            iroha_config::parameters::actual::TelemetryProfile::Disabled
        } else {
            config.telemetry_profile
        };
        #[cfg(feature = "telemetry")]
        let (metrics, state_telemetry, streaming_telemetry) = {
            let metrics =
                init_global_metrics_handle(config.dev_telemetry.panic_on_duplicate_metrics);
            let state = StateTelemetry::from_privacy_parameters(
                Arc::clone(&metrics),
                telemetry_profile.metrics_enabled(),
                &config.network.soranet_privacy,
            );
            let streaming = if telemetry_profile.metrics_enabled() {
                Some(StreamingTelemetry::new(
                    Arc::clone(&metrics),
                    telemetry_profile.metrics_enabled(),
                ))
            } else {
                None
            };
            (metrics, state, streaming)
        };
        let verification_key = config
            .snapshot
            .verification_public_key
            .as_ref()
            .unwrap_or_else(|| config.common.key_pair.public_key());
        let genesis = load_configured_startup_genesis(genesis, config.genesis.file.as_ref())?;
        // Resolve the trust source before reading a genesis body from Kura. The on-disk block may
        // satisfy an already resolved exact hash, but it can never choose its own trust anchor.
        let startup_trust_root = ResolvedGenesisTrustAnchor::resolve(
            &config.genesis.public_key,
            config.genesis.expected_hash,
            genesis.as_ref(),
        )?;
        let state_execution_budget =
            iroha_allocation::AllocationBudget::new(config.pipeline.ivm_execution_max_bytes);
        let stored_genesis_block =
            read_stored_genesis_block(kura.as_ref(), block_count, &state_execution_budget)?;
        let effective_genesis = stored_genesis_block
            .as_ref()
            .map(AsRef::as_ref)
            .or_else(|| genesis.as_ref().map(|genesis| &genesis.0));
        let genesis_to_verify = effective_genesis.ok_or_else(|| {
            Report::new(StartError::InitKura).attach(
                "startup has an exact genesis trust anchor but no local or stored signed genesis body; peer genesis retrieval is not supported",
            )
        })?;
        startup_trust_root.verify(genesis_to_verify)?;
        let signed_genesis_context = Some(
            signed_genesis_context_metadata(genesis_to_verify)
                .map_err(|error| Report::new(StartError::InitKura).attach(error))?,
        );
        let effective_genesis_public_key = config.genesis.public_key.clone();
        // Freeze configured sources before deserialization creates its first State
        // view, then retain the same baseline through replay and runtime handoff.
        let configured_lane_manifests = if emergency_fast {
            Arc::new(LaneManifestRegistry::provisional_empty_for_emergency_fast_startup())
        } else {
            freeze_lane_manifests_for_startup_replay(&config.nexus)
                .map_err(|error| Report::new(error).change_context(StartError::InitKura))
                .map_err(|report| {
                    report.attach("lane manifest registry is not ready before snapshot restoration")
                })?
        };
        let mut loaded_state_from_snapshot = false;
        let snapshot_read_buffer_budget =
            iroha_allocation::AllocationBudget::new(config.snapshot.max_read_buffer_bytes.get());
        let snapshot_result = if snapshot_mode_allows_restore(config.snapshot.mode) {
            try_read_snapshot_with_limits(
                &state_execution_budget,
                config.snapshot.store_dir.resolve_relative_path(),
                &kura,
                &configured_lane_manifests,
                &config.nexus,
                || live_query_store.clone(),
                block_count,
                config.snapshot.merkle_chunk_size_bytes,
                config.snapshot.max_payload_bytes,
                config.snapshot.resources,
                verification_key,
                &config.common.chain,
                &NetworkId::from_genesis_hash(config.genesis.expected_hash),
                &config.zk,
                #[cfg(feature = "telemetry")]
                state_telemetry.clone(),
                &snapshot_read_buffer_budget,
            )
        } else {
            iroha_logger::info!("Snapshot restore is disabled by configuration");
            Err(TryReadSnapshotError::NotFound)
        };
        let mut state = match snapshot_result {
            Ok(state) => {
                iroha_logger::info!(
                    at_height = state.committed_height(),
                    "Successfully loaded the state from a snapshot"
                );
                loaded_state_from_snapshot = true;
                refresh_block_count_after_snapshot_load(
                    &mut block_count,
                    state.committed_height(),
                    kura.as_ref(),
                )
                .map_err(|error| Report::new(StartError::InitKura).attach(error))?;
                state
            }
            Err(error) if snapshot_failure_allows_empty_state_fallback(&error, emergency_fast) => {
                if matches!(&error, TryReadSnapshotError::NotFound) {
                    iroha_logger::info!("Didn't find a state snapshot; creating an empty state");
                } else {
                    iroha_logger::warn!(
                        ?error,
                        "Failed to load state snapshot; checking whether Kura can rebuild from an empty state"
                    );
                }
                preflight_empty_state_snapshot_fallback(
                    kura.as_ref(),
                    &NetworkId::from_genesis_hash(config.genesis.expected_hash),
                    &config.nexus.configured_lane_catalog,
                )?;
                iroha_logger::warn!(
                    "Kura retains the configured-primary replay floor; rebuilding state from blocks"
                );
                let genesis_public_key = effective_genesis_public_key.clone();
                let mut world = World::try_with_execution_budget(
                    [genesis_domain(genesis_public_key.clone())],
                    [genesis_account(genesis_public_key)],
                    [],
                    &state_execution_budget,
                )
                .map_err(|error: iroha_core::state::WorldConstructionError| {
                    Report::new(error).change_context(StartError::InitKura)
                })?;
                if let Some(genesis_block) = effective_genesis {
                    iroha_core::sns::seed_genesis_alias_bootstrap(
                        &mut world,
                        genesis_block,
                        &config.nexus.dataspace_catalog,
                    )
                    .map_err(|error| Report::new(StartError::InitKura).attach(error))?;
                }
                Box::new(
                    State::try_new_with_chain_and_network_id(
                        state_execution_budget.clone(),
                        world,
                        Arc::clone(&kura),
                        live_query_store.clone(),
                        config.common.chain.clone(),
                        NetworkId::from_genesis_hash(config.genesis.expected_hash),
                        #[cfg(feature = "telemetry")]
                        state_telemetry.clone(),
                    )
                    .map_err(|error| Report::new(error).change_context(StartError::InitKura))?,
                )
            }
            Err(error) if emergency_fast => {
                return Err(Report::new(error)
                    .change_context(StartError::InitKura)
                    .attach(
                        "emergency Fast startup requires one valid signed snapshot at the exact durable Kura tip; restart in Strict mode to rebuild or repair state",
                    ));
            }
            Err(error) => {
                return Err(Report::new(error).change_context(StartError::InitKura));
            }
        };
        #[cfg(feature = "telemetry")]
        {
            kura.attach_telemetry(state.telemetry.clone());
        }
        let expected_network_id = NetworkId::from_genesis_hash(config.genesis.expected_hash);
        if state.network_id != expected_network_id {
            return Err(Report::new(StartError::InitKura).attach(format!(
                "restored state network id {} differs from genesis.expected_hash-derived id {}",
                state.network_id, expected_network_id
            )));
        }
        if state.chain_id != config.common.chain {
            return Err(Report::new(StartError::InitKura).attach(
                "restored native chain identity differs from configured consensus instance",
            ));
        }
        if !loaded_state_from_snapshot {
            // Snapshot candidates install this at their post-decode,
            // pre-reconciliation boundary. Fresh and Kura-rebuilt state has no
            // snapshot boundary, so install it exactly once here before replay.
            install_zk_config_before_kura_replay(&mut state, &config)?;
        }
        if emergency_fast {
            state
                .validate_restored_governance(&config.gov)
                .map_err(|error| {
                    Report::new(StartError::InitKura).attach(format!(
                        "emergency Fast restored governance is incompatible with configured governance: {error}"
                    ))
                })?;
        } else {
            apply_state_runtime_config_before_snapshot_auth(&mut state, &config)
                .map_err(|error| Report::new(error).change_context(StartError::InitKura))?;
        }
        let startup_lane_policies = if emergency_fast {
            None
        } else {
            Some(install_lane_policies_for_startup_replay(
                &mut state,
                config.nexus.clone(),
                &configured_lane_manifests,
            )?)
        };
        if let Some(policies) = startup_lane_policies.as_ref() {
            apply_state_geometry_config_before_kura_replay(&mut state, policies)?;
        }
        // Reuse the policy snapshot installed before geometry; emergency Fast never scans local
        // policy sources.
        let (frozen_startup_lane_manifests, frozen_startup_lane_compliance) =
            startup_lane_policies.as_ref().map_or_else(
                || {
                    iroha_logger::warn!(
                        "emergency Fast startup deferred lane-manifest and compliance directory loading until a Strict restart"
                    );
                    (
                        Arc::new(LaneManifestRegistry::provisional_empty_for_emergency_fast_startup()),
                        None,
                    )
                },
                |policies| (Arc::clone(&policies.manifests), policies.compliance.clone()),
            );
        if emergency_fast {
            state
                .install_provisional_empty_lane_manifests_for_emergency_fast_pre_auth()
                .map_err(|error| Report::new(error).change_context(StartError::InitKura))?;
            state.install_lane_compliance_engine(None);
        }
        let (signed_consensus_mode, signed_context) = match signed_genesis_context {
            Some(context) => context,
            None => {
                return Err(Report::new(StartError::InitKura)
                    .attach("startup has no signed genesis metadata"));
            }
        };
        // The original genesis signature and exact configured trust anchor were verified above.
        // A private root owns one independent lane zero; its non-universal dataspace is not a
        // public multi-lane topology and does not change the signed consensus mode.
        startup_root_topology::validate(
            &config.nexus,
            signed_consensus_mode,
            signed_context.root_scope,
        )
        .map_err(|reason| Report::new(StartError::InitKura).attach(reason))?;
        // Thread the remaining runtime preferences from config into state before Sumeragi
        // rebuilds it, so replayed and live blocks execute under the same configuration. ZK
        // configuration was installed once above.
        if emergency_fast {
            iroha_logger::warn!(
                "emergency Fast startup left the tiered-state backend disabled and skipped lane-directory preflight and reconciliation until a Strict restart"
            );
        } else {
            state
                .set_tiered_backend(&config.tiered_state)
                .map_err(|err| Report::new(err).change_context(StartError::InitKura))
                .map_err(|report| {
                    report.attach("failed to restore effective Nexus tiered lane geometry")
                })?;
            install_node_pipeline_config(&mut state, &config)
                .map_err(|error| Report::new(error).change_context(StartError::InitKura))?;
            state.set_oracle(config.oracle.clone());
            state.install_node_fraud_monitoring(config.fraud_monitoring.clone());
            state.set_gov(config.gov.clone());
            log_startup_trace(
                "irohad.state.runtime_config_applied",
                startup_trace_started_at,
            );
        }
        // Delay Arc wrapping until after we tweak state with config
        let events_buffer_capacity = if emergency_fast {
            1
        } else {
            config.torii.events_buffer_capacity.get()
        };
        let (events_sender, _) = broadcast::channel(events_buffer_capacity);
        let state: Arc<State> = Arc::from(state);
        lifetime.state = Some(Arc::clone(&state));
        // Sumeragi rebuilds the state: it applies (fresh chain) or re-executes (restart) the
        // signed genesis and replays every block Kura holds against its commit certificate.
        let prepared_sumeragi = if emergency_fast {
            None
        } else {
            log_startup_trace("irohad.sumeragi.prepare", startup_trace_started_at);
            let prepared =
                iroha_core::sumeragi::node::prepare(iroha_core::sumeragi::node::PrepareInputs {
                    state: Arc::clone(&state),
                    events: events_sender.clone(),
                    genesis: genesis.as_ref().map(|genesis| genesis.0.clone()),
                    genesis_account: AccountId::new(effective_genesis_public_key.clone()),
                    consensus_mode: signed_consensus_mode,
                })
                .map_err(|error| {
                    Report::new(StartError::InitKura)
                        .attach(format!("Sumeragi could not rebuild the state: {error}"))
                })?;
            iroha_logger::info!(
                height = state.committed_height(),
                instance = ?prepared.instance(),
                "Sumeragi rebuilt the state from genesis and Kura"
            );
            Some(prepared)
        };
        // Key admission and rotation read canonical WSV parameters. Local configuration must
        // match that authority rather than overwriting it without a block.
        state
            .validate_sumeragi_key_policy(&config.sumeragi)
            .map_err(|field| {
                Report::new(StartError::InitKura).attach(format!(
                    "configured Sumeragi key policy differs from canonical state: {field}"
                ))
            })?;
        Ok(Box::new(PreparedNative {
            config,
            supervisor: std::mem::take(supervisor),
            kura,
            state,
            live_query_store,
            genesis,
            stored_genesis_block,
            block_count,
            prepared_sumeragi,
            signed_consensus_mode,
            frozen_startup_lane_manifests,
            frozen_startup_lane_compliance,
            expected_network_id,
            snapshot_writer_key,
            snapshot_read_buffer_budget,
            events_sender,
            startup_trace_started_at,
            telemetry_profile,
            #[cfg(feature = "telemetry")]
            metrics,
            #[cfg(feature = "telemetry")]
            state_telemetry,
            #[cfg(feature = "telemetry")]
            streaming_telemetry,
        }))
    }

    /// Stop and join before releasing the configured State, storage and NTS owners.
    pub(super) async fn close(self) -> iroha_futures::supervisor::Result<()> {
        let Self {
            mut native,
            lifetime,
        } = self;
        // StateExecutor's Drop closes admission and joins its original native thread.
        drop(native.prepared_sumeragi.take());
        let supervisor = std::mem::take(&mut native.supervisor);
        supervisor.shutdown_signal().send();
        let result = supervisor.start().await;
        drop(native);
        drop(lifetime);
        result
    }
}
