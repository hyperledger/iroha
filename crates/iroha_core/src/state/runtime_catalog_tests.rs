use crate::query::store::LiveQueryStore;
use iroha_data_model::nexus::{
    DataSpaceMetadata, LaneConfig as RuntimeLaneConfig, LaneLifecycleParameterV1,
    NexusCatalogTransitionV1, NexusRuntimeCatalogV1, RuntimeDataSpaceAdditionV1,
    RuntimeLaneManifestV1,
};

fn run_catalog_test(test: impl FnOnce() + Send + 'static) {
    let result = std::thread::Builder::new()
        .name("runtime-catalog-test".to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(test)
        .expect("spawn bounded-stack catalog test")
        .join();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[test]
fn lifecycle_rebind_requires_materialized_manifest_source() {
    let nexus = iroha_config::parameters::actual::Nexus::default();
    let registry =
        LaneManifestRegistry::from_config(&nexus.lane_catalog, &nexus.governance, &nexus.registry);
    rebind_lane_manifests_for_lifecycle(&registry, &nexus.lane_catalog, &nexus.governance)
        .expect("materialized source rebinds to its exact catalog");
    let status_only = LaneManifestRegistry::from_statuses(BTreeMap::new());
    let error =
        rebind_lane_manifests_for_lifecycle(&status_only, &nexus.lane_catalog, &nexus.governance)
            .expect_err("status-only scaffolding cannot authorize a lifecycle transition");
    assert!(
        error.to_string().contains("materialized frozen source"),
        "unexpected lifecycle diagnostic: {error}"
    );
}

#[test]
fn materialized_manifest_install_rejects_status_only_without_publication() {
    run_catalog_test(|| {
        // Match production's unbound constructor before the first policy installation.
        let state = State::try_new(
            AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            #[cfg(feature = "telemetry")]
            Default::default(),
        )
        .unwrap();
        let nexus = state.nexus_snapshot();
        let original_manifests = state.lane_manifests.read().clone();
        let original_privacy = state.lane_privacy_registry.read().clone();
        let generation = state.state_view_generation();
        let status_only = Arc::new(LaneManifestRegistry::from_statuses(BTreeMap::new()));
        let error = state
            .install_materialized_lane_manifests_for_catalog(
                &status_only,
                &nexus.lane_catalog,
                &nexus.governance,
            )
            .expect_err("status-only registry cannot publish");
        assert!(error.to_string().contains("materialized frozen source"));
        assert_eq!(state.state_view_generation(), generation);
        assert!(Arc::ptr_eq(
            &state.lane_manifests.read(),
            &original_manifests
        ));
        assert!(Arc::ptr_eq(
            &state.lane_privacy_registry.read(),
            &original_privacy
        ));

        let materialized = Arc::new(LaneManifestRegistry::from_config(
            &nexus.lane_catalog,
            &nexus.governance,
            &nexus.registry,
        ));
        state
            .install_materialized_lane_manifests_for_catalog(
                &materialized,
                &nexus.lane_catalog,
                &nexus.governance,
            )
            .expect("matching frozen source publishes");
        assert!(Arc::ptr_eq(&state.lane_manifests.read(), &materialized));
        assert_eq!(state.state_view_generation(), generation + 2);
        let installed_privacy = state.lane_privacy_registry.read().clone();
        let equivalent = Arc::new(materialized.rebind(&nexus.lane_catalog, &nexus.governance));
        state
            .install_materialized_lane_manifests_for_catalog(
                &equivalent,
                &nexus.lane_catalog,
                &nexus.governance,
            )
            .unwrap();
        assert_eq!(state.state_view_generation(), generation + 2);
        assert!(Arc::ptr_eq(&state.lane_manifests.read(), &materialized));
        assert!(Arc::ptr_eq(
            &state.lane_privacy_registry.read(),
            &installed_privacy
        ));

        // A genuinely different, valid initial source still uses an actual publication.
        let directory = tempfile::tempdir().unwrap();
        let alias = &nexus.lane_catalog.lanes()[0].alias;
        std::fs::write(
            directory.path().join(format!("{alias}.manifest.json")),
            norito::json::to_vec(&norito::json!({ "lane": alias })).unwrap(),
        )
        .unwrap();
        let changed = Arc::new(LaneManifestRegistry::from_config(
            &nexus.lane_catalog,
            &nexus.governance,
            &iroha_config::parameters::actual::LaneRegistry {
                manifest_directory: Some(directory.path().to_path_buf()),
                ..Default::default()
            },
        ));
        state
            .install_materialized_lane_manifests_for_catalog(
                &changed,
                &nexus.lane_catalog,
                &nexus.governance,
            )
            .unwrap();
        assert_eq!(state.state_view_generation(), generation + 4);
        assert!(Arc::ptr_eq(&state.lane_manifests.read(), &changed));
        assert!(!Arc::ptr_eq(
            &state.lane_privacy_registry.read(),
            &installed_privacy
        ));
    });
}

#[test]
fn provisional_emergency_manifest_install_is_empty_and_one_shot() {
    run_catalog_test(|| {
        let mut strict_state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        assert!(
            strict_state
                .install_provisional_empty_lane_manifests_for_emergency_fast_pre_auth()
                .is_err(),
            "Strict startup must refuse the emergency pre-authentication installer"
        );
        let mut state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing_in_emergency_fast_mode(),
            LiveQueryStore::start_test(),
        );
        state
            .install_provisional_empty_lane_manifests_for_emergency_fast_pre_auth()
            .expect("unshared pre-authentication State admits one empty provisional install");
        let provisional = state.lane_manifests.read().clone();
        assert!(provisional.statuses().is_empty());
        assert!(
            provisional
                .validate_materialized_source_projection()
                .is_err()
        );
        let privacy = state.lane_privacy_registry.read().clone();
        let error = state
            .install_provisional_empty_lane_manifests_for_emergency_fast_pre_auth()
            .expect_err("emergency pre-authentication install must be one-shot");
        assert!(
            error
                .to_string()
                .contains("one-shot pre-authentication phase")
        );
        assert!(Arc::ptr_eq(&*state.lane_manifests.read(), &provisional));
        assert!(Arc::ptr_eq(&*state.lane_privacy_registry.read(), &privacy));
    });
}

#[derive(Clone, Copy)]
enum InvalidMember {
    None,
    MissingAccount,
    MissingPeer,
    MissingKey,
    MissingPop,
    InvalidPop,
    WrongRole,
    Disabled,
    NotYetActive,
    Expired,
    ExpiresAtNativeActivation,
}

fn catalog_fixture(invalid: InvalidMember) -> (State, Vec<iroha_crypto::KeyPair>) {
    let keys: Vec<_> = (1_u8..=4)
        .map(|seed| {
            iroha_crypto::KeyPair::try_from_seed(vec![seed; 32], iroha_crypto::Algorithm::BlsNormal)
                .expect("deterministic synthetic validator key")
        })
        .collect();
    let accounts: Vec<_> = keys
        .iter()
        .enumerate()
        .filter_map(|(index, key)| {
            if index == 0 && matches!(invalid, InvalidMember::MissingAccount) {
                return None;
            }
            let id = AccountId::new(key.public_key().clone());
            Some(iroha_data_model::account::Account::new(id.clone()).build(&id))
        })
        .collect();
    let lanes = LaneCatalog::new(
        NonZeroU32::new(5).unwrap(),
        (0..5)
            .map(|id| RuntimeLaneConfig {
                id: LaneId::new(id),
                alias: format!("existing-{id}"),
                dataspace_id: DataSpaceId::new(match id {
                    3 => 10,
                    4 => 12,
                    _ => 0,
                }),
                ..RuntimeLaneConfig::default()
            })
            .collect(),
    )
    .expect("five retained fixture lanes");
    let dataspaces = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: DataSpaceId::new(10),
            alias: "dpn".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: DataSpaceId::new(12),
            alias: "existing-private".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("retained fixture dataspaces");
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.configured_lane_catalog = lanes.clone();
    nexus.lane_catalog = lanes;
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.configured_dataspace_catalog = dataspaces.clone();
    nexus.dataspace_catalog = dataspaces;
    nexus.staking.public_validator_mode =
        iroha_config::parameters::actual::LaneValidatorMode::AdminManaged;
    // These component transitions need the actual retained global schedule.
    // Structural handshake metadata alone never supplies proposal-height authority.
    let mut config =
        crate::sumeragi::test_chain::TestChainConfig::new(World::with([], accounts, []), 0);
    config.nexus = Some(nexus.clone());
    config.lane_manifests = Some(Arc::new(LaneManifestRegistry::from_config(
        &nexus.lane_catalog,
        &nexus.governance,
        &nexus.registry,
    )));
    let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
    let mode = config.consensus_mode;
    let prepared = crate::sumeragi::test_chain::CertifiedTestChain::prepare(config)
        .expect("prepare catalog fixture's original signed global genesis");
    let genesis = prepared.genesis.block().clone();
    // Acquire the unshared owner before any worker can retain it.
    let state = Arc::try_unwrap(prepared.state)
        .unwrap_or_else(|_| panic!("catalog fixture owns its unique unapplied State"));
    crate::sumeragi::startup::apply_genesis(
        &state,
        genesis.clone(),
        &genesis_account,
        mode.into(),
        None,
    )
    .expect("apply the original signed genesis and retain its exact schedule");
    assert_eq!(state.latest_block_hash_fast(), Some(genesis.hash()));
    assert_eq!(
        state.network_id,
        iroha_data_model::NetworkId::from_genesis_hash(genesis.hash())
    );
    let mut world = state.world.block();
    {
        let mut peers = world.peers_mut_for_testing().transaction();
        for (index, key) in keys.iter().enumerate() {
            if index != 0 || !matches!(invalid, InvalidMember::MissingPeer) {
                peers.push(PeerId::new(key.public_key().clone()));
            }
        }
        peers.apply();
    }
    for (index, key) in keys.iter().enumerate() {
        if index == 0 && matches!(invalid, InvalidMember::MissingKey) {
            continue;
        }
        // Runtime catalog additions activate a participant lane, whose peers
        // must carry live Committee keys rather than global Validator keys.
        let mut id = derive_committee_key_id(key.public_key());
        if index == 0 && matches!(invalid, InvalidMember::WrongRole) {
            id.role = ConsensusKeyRole::Endorsement;
        }
        let mut pop =
            Some(iroha_crypto::bls_normal_pop_prove(key.private_key()).expect("synthetic BLS PoP"));
        if index == 0 {
            match invalid {
                InvalidMember::MissingPop => pop = None,
                InvalidMember::InvalidPop => pop.as_mut().unwrap()[0] ^= 1,
                _ => {}
            }
        }
        let record = ConsensusKeyRecord {
            id: id.clone(),
            public_key: key.public_key().clone(),
            pop,
            activation_height: if index == 0 && matches!(invalid, InvalidMember::NotYetActive) {
                4
            } else {
                0
            },
            expiry_height: if index == 0 {
                match invalid {
                    InvalidMember::Expired => Some(3),
                    InvalidMember::ExpiresAtNativeActivation => Some(4),
                    _ => None,
                }
            } else {
                None
            },
            replaces: None,
            status: if index == 0 && matches!(invalid, InvalidMember::Disabled) {
                ConsensusKeyStatus::Disabled
            } else {
                ConsensusKeyStatus::Active
            },
        };
        world.consensus_keys.insert(id.clone(), record);
        world
            .consensus_keys_by_pk
            .insert(key.public_key().to_string(), vec![id]);
    }
    world.commit();
    if matches!(invalid, InvalidMember::None) {
        for key in &keys {
            let peer = PeerId::new(key.public_key().clone());
            assert!(state.world.view().peers().iter().any(|p| p == &peer));
            assert!(peer_has_live_consensus_key_for_lane(
                &state.world.view(),
                &peer,
                3,
                LaneId::new(5),
            ));
        }
    }
    (state, keys)
}

fn catalog_payload(state: &State, keys: &[iroha_crypto::KeyPair]) -> NexusCatalogTransitionV1 {
    let hash = [0x67; 32];
    catalog_transition_for_testing(
        state,
        DataSpaceMetadata {
            id: DataSpaceId::from_hash(&hash),
            alias: "new-catalog-ds".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        hash,
        RuntimeLaneConfig {
            id: LaneId::new(5),
            alias: "new-catalog-lane".to_owned(),
            dataspace_id: DataSpaceId::from_hash(&hash),
            ..RuntimeLaneConfig::default()
        },
        &keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>(),
    )
}

/// Build an additive request from the current retained catalog and original committee peers.
/// The caller still submits this through normal accepted execution and certified publication.
pub(crate) fn catalog_transition_for_testing(
    state: &State,
    descriptor: DataSpaceMetadata,
    manifest_hash: [u8; 32],
    lane: RuntimeLaneConfig,
    peers: &[PeerId],
) -> NexusCatalogTransitionV1 {
    let nexus = state.nexus_snapshot();
    NexusCatalogTransitionV1 {
        version: NexusCatalogTransitionV1::VERSION,
        expected_catalog_hash: LaneLifecycleParameterV1::catalog_hash(&nexus.lane_catalog),
        expected_incarnation_root: lane_lifecycle_incarnation_root(
            &nexus.lane_catalog,
            &state.lane_incarnations_snapshot(),
        )
        .unwrap(),
        expected_runtime_catalog_hash: state.view().runtime_catalog_hash().unwrap(),
        dataspace_additions: vec![RuntimeDataSpaceAdditionV1 {
            descriptor,
            manifest_hash,
        }],
        manifest_additions: vec![catalog_manifest_for_peers(lane.id, &lane.alias, peers)],
        lane_additions: vec![lane],
    }
}

fn catalog_manifest(
    lane_id: LaneId,
    alias: &str,
    keys: &[iroha_crypto::KeyPair],
) -> RuntimeLaneManifestV1 {
    catalog_manifest_for_peers(
        lane_id,
        alias,
        &keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>(),
    )
}

fn catalog_manifest_for_peers(
    lane_id: LaneId,
    alias: &str,
    peers: &[PeerId],
) -> RuntimeLaneManifestV1 {
    let validators: Vec<_> = peers
        .iter()
        .map(|peer| {
            let validator = AccountId::new(peer.public_key().clone()).to_string();
            let peer_id = peer.to_string();
            norito::json!({ "validator": validator, "peer_id": peer_id })
        })
        .collect();
    RuntimeLaneManifestV1 {
        lane_id,
        manifest: iroha_primitives::json::Json::new(norito::json!({
            "lane": alias, "version": 1, "validators": validators, "quorum": 3,
            "privacy_commitments": [{
                "id": 1, "scheme": "merkle",
                "merkle": {
                    "root": "1212121212121212121212121212121212121212121212121212121212121212",
                    "max_depth": 16,
                },
            }],
        })),
    }
}

#[test]
fn runtime_catalog_fixture_retains_original_schedule_and_cannot_authorize_by_header() {
    run_catalog_test(|| {
        let (state, _) = catalog_fixture(InvalidMember::None);
        let original = state
            .kura_handle()
            .get_block(
                std::num::NonZeroUsize::new(1).unwrap(),
                &state.ivm_execution_budget(),
            )
            .expect("completed original State read")
            .expect("actual retained signed genesis");
        let header = catalog_test_header(&state);
        assert_eq!(header.prev_block_hash(), Some(original.hash()));
        assert!(header.creation_time() > original.header().creation_time());
        assert_eq!(
            crate::sumeragi::schedule::scheduled_committee(&state.world.view(), 2)
                .expect("original genesis owns H2 authority")
                .len(),
            4
        );
        assert_eq!(
            state.nexus_snapshot().lane_catalog.lanes().len(),
            5,
            "the complete configured physical baseline is retained"
        );
        let (missing, missing_keys) = catalog_fixture(InvalidMember::None);
        let payload = catalog_payload(&missing, &missing_keys);
        // Retain the actual signed parent and all four live participant keys,
        // but corrupt only the schedule being tested. A header cannot replace it.
        let mut world = missing.world.block();
        *world.consensus_schedule.get_mut() = Default::default();
        world.commit();
        let before = norito::json::to_json(&missing.world).unwrap();
        let mut block = missing.block(catalog_test_header(&missing));
        let mut tx = block.transaction();
        let error = tx
            .stage_consensus_catalog_transition(&payload)
            .expect_err("an H2 header cannot supply an original consensus schedule");
        assert!(matches!(
            error,
            LaneLifecycleError::RuntimeCatalog(message)
                if message == "the stored consensus schedule is malformed"
        ));
        assert!(runtime_catalog_from_world(&tx.world).unwrap().is_none());
        assert!(tx.pending_lane_lifecycle.is_none());
        drop(tx);
        drop(block);
        assert_eq!(norito::json::to_json(&missing.world).unwrap(), before);
        assert_eq!(state.latest_block_hash_fast(), Some(original.hash()));
    });
}

#[test]
fn runtime_catalog_preflight_preserves_prior_additions_and_rejects_replacement() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let payload = catalog_payload(&state, &keys);
        let mut nexus = state.nexus_snapshot();
        let baseline_registry = state.lane_manifests.read().clone();
        let first = NexusRuntimeCatalogV1 {
            version: 1,
            baseline_dataspaces_hash: iroha_data_model::nexus::dataspace_catalog_hash(
                &nexus.configured_dataspace_catalog,
            ),
            baseline_manifests_hash: Hash::prehashed(
                baseline_registry.baseline_consensus_policy_digest(),
            ),
            dataspaces: payload.dataspace_additions,
            manifests: payload.manifest_additions,
        };
        let first_plan = iroha_data_model::nexus::LaneLifecyclePlan {
            additions: payload.lane_additions,
            retire: Vec::new(),
        };
        nexus.dataspace_catalog = runtime_catalog_transition_dataspaces(
            &nexus,
            &baseline_registry,
            &state.world.view(),
            &first,
            &first_plan,
        )
        .expect("first additive transition");
        nexus.lane_catalog = nexus.lane_catalog.apply_lifecycle(&first_plan).unwrap();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        let registry = baseline_registry
            .with_runtime_additions(
                &first.manifests,
                &nexus.lane_catalog,
                &nexus.dataspace_catalog,
                &nexus.governance,
            )
            .expect("accepted first native manifest");
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                first.clone().into_custom_parameter().unwrap(),
            ));
        world.commit();
        let second_plan = iroha_data_model::nexus::LaneLifecyclePlan {
            additions: vec![RuntimeLaneConfig {
                id: LaneId::new(6),
                alias: "second-catalog-lane".to_owned(),
                dataspace_id: first.dataspaces[0].descriptor.id,
                ..RuntimeLaneConfig::default()
            }],
            retire: Vec::new(),
        };
        let mut second = first.clone();
        second.manifests.push(catalog_manifest(
            LaneId::new(6),
            "second-catalog-lane",
            &keys,
        ));
        assert_eq!(
            runtime_catalog_transition_dataspaces(
                &nexus,
                &registry,
                &state.world.view(),
                &second,
                &second_plan,
            )
            .unwrap(),
            nexus.dataspace_catalog,
            "adding another lane preserves physical dataspaces"
        );
        for case in 0..7 {
            let mut changed = second.clone();
            let mut changed_plan = second_plan.clone();
            match case {
                0 => changed.dataspaces.clear(),
                1 => changed.dataspaces[0].descriptor.description = Some("changed".to_owned()),
                2 => {
                    changed.manifests.remove(0);
                }
                3 => changed.manifests[0] = catalog_manifest(LaneId::new(5), "changed", &keys),
                4 => changed.baseline_manifests_hash = Hash::new(b"foreign manifest baseline"),
                5 => changed_plan.retire.push(LaneId::new(4)),
                _ => changed_plan.additions[0].alias = "existing-4".to_owned(),
            }
            assert!(
                runtime_catalog_transition_dataspaces(
                    &nexus,
                    &registry,
                    &state.world.view(),
                    &changed,
                    &changed_plan,
                )
                .is_err(),
                "catalog replacement case {case}"
            );
        }
        assert_eq!(
            runtime_catalog_from_world(&state.world.view()).unwrap(),
            Some(first)
        );
    });
}

#[test]
fn runtime_catalog_stages_dataspace_lane_manifest_atomically_with_four_live_pops() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let before = state.nexus_snapshot();
        let original_native_policy = crate::sumeragi::lanes::lane_policy(&state.world.view())
            .expect("completed original routing metadata read");
        let payload = catalog_payload(&state, &keys);
        let mut block = state.block(catalog_test_header(&state));
        let mut transaction = block.transaction();
        transaction
            .stage_consensus_catalog_transition(&payload)
            .expect("complete atomic catalog transition");
        let runtime = runtime_catalog_from_world(&transaction.world)
            .unwrap()
            .expect("protected cumulative catalog");
        assert_eq!(runtime.dataspaces, payload.dataspace_additions);
        assert_eq!(runtime.manifests, payload.manifest_additions);
        assert_eq!(
            transaction.nexus.configured_dataspace_catalog,
            before.configured_dataspace_catalog
        );
        assert_eq!(
            &transaction.nexus.lane_catalog.lanes()[..5],
            before.lane_catalog.lanes()
        );
        assert_eq!(
            transaction.nexus.lane_catalog.lanes()[3].dataspace_id,
            DataSpaceId::new(10)
        );
        assert_eq!(
            transaction.nexus.lane_catalog.lanes()[4].dataspace_id,
            DataSpaceId::new(12)
        );
        assert!(transaction.lane_manifests.has_manifest(LaneId::new(5)));
        let native = crate::sumeragi::lanes::lane_policy(&transaction.world)
            .expect("completed original routing metadata read")
            .expect("physical registration also stages its native lane policy");
        let fixed = native.fixed_lane(LaneId::new(5)).unwrap();
        assert_eq!(
            fixed.dataspace,
            payload.dataspace_additions[0].descriptor.id
        );
        assert_eq!(fixed.committee.len(), 4);
        crate::sumeragi::lanes::step::validate_policy(&native).unwrap();
        assert!(
            transaction
                .lane_manifests
                .status(LaneId::new(5))
                .unwrap()
                .manifest_path
                .is_none()
        );
        assert_eq!(
            runtime_catalog_root_from_world(&transaction.world).unwrap(),
            Some(runtime.canonical_hash().unwrap())
        );
        assert!(
            transaction
                .pending_lane_lifecycle
                .as_ref()
                .unwrap()
                .runtime_catalog
                .is_some()
        );
        assert!(matches!(
            transaction.stage_consensus_catalog_transition(&payload),
            Err(LaneLifecycleError::LifecycleAlreadyStaged)
        ));
        drop(transaction);
        assert_eq!(
            block.nexus.lane_catalog, before.lane_catalog,
            "aborted transaction cannot publish topology"
        );
        assert!(runtime_catalog_from_world(&block.world).unwrap().is_none());
        assert_eq!(
            crate::sumeragi::lanes::lane_policy(&block.world)
                .expect("completed original routing metadata read"),
            original_native_policy,
            "aborting the catalog transaction preserves the exact original native policy"
        );
    });
}

#[test]
fn runtime_catalog_activates_native_private_lane_and_routes_exact_dataspace() {
    run_catalog_test(|| {
        use crate::sumeragi::lanes::{
            lane_policy, merge::LaneStepInput, routing::RoutingInputs, step,
        };
        use iroha_data_model::{
            nexus::LaneVisibility,
            smart_contract::ContractAddress,
            transaction::{Executable, TransactionBuilder, executable::ContractInvocation},
        };
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let mut payload = catalog_payload(&state, &keys);
        payload.lane_additions[0].visibility = LaneVisibility::Restricted;
        let lane = payload.lane_additions[0].id;
        let dataspace = payload.lane_additions[0].dataspace_id;
        let mut block = state.block(catalog_test_header(&state));
        let params = block.world.parameters().sumeragi.clone();
        let mut transaction = block.transaction();
        transaction
            .stage_consensus_catalog_transition(&payload)
            .unwrap();
        transaction.apply();
        step::advance(&mut block, &LaneStepInput::default()).unwrap();
        let mut policy = lane_policy(&block.world)
            .expect("completed original routing metadata read")
            .unwrap();
        assert_eq!(policy.lane_params, params);
        let record = block
            .world
            .sumeragi_lanes()
            .lane(lane)
            .expect("ordinary lane step creates instance");
        assert_eq!((record.created_at, record.active_from), (2, 4));
        assert_eq!(record.dataspace, dataspace);
        assert_eq!(record.committee, policy.fixed_lane(lane).unwrap().committee);
        assert!(record.closing.is_none());
        crate::sumeragi::lanes::lane_height_config(record).unwrap();
        assert_eq!(
            block
                .nexus
                .lane_catalog
                .lanes()
                .iter()
                .find(|entry| entry.id == lane)
                .unwrap()
                .visibility,
            LaneVisibility::Restricted
        );
        let authority = AccountId::new(keys[0].public_key().clone());
        let make_tx = |target| {
            let call = ContractInvocation {
                contract_address: ContractAddress::derive(&state.network_id, &authority, 0, target)
                    .unwrap(),
                expected_code_hash: Hash::new(b"catalog-routing-contract"),
                entrypoint: "call".to_owned(),
                arguments: None,
            };
            crate::tx::AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(
                TransactionBuilder::new(
                    state.network_id,
                    authority.clone(),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .with_executable(Executable::ContractCall(call))
                .sign(keys[0].private_key()),
            ))
        };
        // Even an explicit owner-wide route cannot capture registry/control-plane work
        // or change a concrete universal application target into private execution.
        policy
            .routes
            .push(iroha_data_model::sumeragi_lanes::SumeragiLaneRoute {
                lane,
                account: Some(authority.to_string()),
                instruction: None,
            });
        let inputs = RoutingInputs {
            root_scope: crate::sumeragi::lanes::routing::committed_root_scope(&block.world),
            policy: Some(&policy),
            lanes: block.world.sumeragi_lanes(),
            dataspaces: &block.nexus.dataspace_catalog,
            world: &block.world,
            ledger_time_ms: 0,
        };
        let private = make_tx(dataspace);
        assert_eq!(
            inputs
                .execution_route(&private, 4)
                .expect("completed original routing read"),
            None,
            "private work cannot escape to universal before activation is applied"
        );
        assert_eq!(
            inputs
                .execution_route(&private, 5)
                .expect("completed original routing read"),
            Some(crate::queue::RoutingDecision::new(lane, dataspace))
        );
        assert_eq!(
            inputs
                .execution_route(&make_tx(DataSpaceId::new(777)), 5)
                .expect("completed original routing read"),
            None
        );
        assert_eq!(
            inputs
                .execution_route(&make_tx(DataSpaceId::UNIVERSAL), 5)
                .expect("completed original routing read"),
            Some(crate::queue::RoutingDecision::new(
                LaneId::SINGLE,
                DataSpaceId::UNIVERSAL
            )),
            "the same owner still routes its universal work to universal"
        );
        use iroha_data_model::{
            alias_setup::{
                AliasDataSpaceIntentV1, AliasDataspaceBootstrapGrantV1, AliasIntentV1,
                AliasLeaseAcquisitionV1, AliasQuoteGuardV1, ResolvedDataSpaceV1,
            },
            isi::{InstructionBox, SetParameter, alias_setup::EnsureAlias},
            parameter::Parameter,
        };
        let bootstrap =
            AliasDataspaceBootstrapGrantV1::try_new("new-catalog-ds", authority.clone()).unwrap();
        let controls: [InstructionBox; 3] = [
            SetParameter::new(Parameter::Custom(
                payload.clone().into_custom_parameter().unwrap(),
            ))
            .into(),
            SetParameter::new(Parameter::Custom(
                bootstrap.into_custom_parameter().unwrap(),
            ))
            .into(),
            EnsureAlias::new(
                AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
                    dataspace: ResolvedDataSpaceV1::new(
                        "new-catalog-ds".parse().unwrap(),
                        dataspace,
                    ),
                    owner: authority.clone(),
                }),
                AliasLeaseAcquisitionV1::new(1, None),
                AliasQuoteGuardV1 {
                    expected_policy_version: 1,
                    expected_payment_asset:
                        iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                            .parse()
                            .unwrap(),
                    max_amount: 1_u32.into(),
                    valid_until_ms: u64::MAX,
                },
            )
            .into(),
        ];
        for instruction in controls {
            let control = crate::tx::AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(
                TransactionBuilder::new(
                    state.network_id,
                    authority.clone(),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .with_instructions([instruction])
                .sign(keys[0].private_key()),
            ));
            for height in 2..=5 {
                assert_eq!(
                    inputs
                        .execution_route(&control, height)
                        .expect("completed original routing read"),
                    Some(crate::queue::RoutingDecision::new(
                        LaneId::SINGLE,
                        DataSpaceId::UNIVERSAL,
                    )),
                    "all deployment phases stay global before and after native activation"
                );
            }
        }
        assert!(
            state.view().world().sumeragi_lanes().lane(lane).is_none(),
            "uncommitted block must not publish its native lane"
        );
    });
}

#[test]
fn runtime_catalog_rejects_native_lane_conflict_without_partial_state() {
    run_catalog_test(|| {
        use iroha_data_model::sumeragi_lanes::{
            SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy,
        };
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let payload = catalog_payload(&state, &keys);
        let mut block = state.block(catalog_test_header(&state));
        let mut policy = SumeragiLanePolicy::for_chain(
            block.world.parameters().sumeragi.clone(),
            iroha_sumeragi::availability::recommended_data_availability_layout(),
        );
        policy.fixed.push(SumeragiFixedLane {
            lane: LaneId::new(5),
            dataspace: DataSpaceId::new(99),
            committee: keys
                .iter()
                .map(|key| SumeragiLaneMember {
                    peer: PeerId::new(key.public_key().clone()),
                    pop: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
                })
                .collect(),
        });
        block.world.parameters.get_mut().set_parameter(
            iroha_data_model::parameter::Parameter::Custom(policy.clone().into_custom_parameter()),
        );
        let before = block.world.parameters().clone();
        let mut transaction = block.transaction();
        transaction
            .stage_consensus_catalog_transition(&payload)
            .expect_err("conflicting native policy cannot be overwritten");
        assert_eq!(transaction.world.parameters(), &before);
        assert!(transaction.pending_lane_lifecycle.is_none());
        assert!(
            runtime_catalog_from_world(&transaction.world)
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn runtime_catalog_rejects_ineligible_committee_without_partial_state() {
    run_catalog_test(|| {
        for invalid in [
            InvalidMember::MissingAccount,
            InvalidMember::MissingPeer,
            InvalidMember::MissingKey,
            InvalidMember::MissingPop,
            InvalidMember::InvalidPop,
            InvalidMember::WrongRole,
            InvalidMember::Disabled,
            InvalidMember::NotYetActive,
            InvalidMember::Expired,
            InvalidMember::ExpiresAtNativeActivation,
        ] {
            let (state, keys) = catalog_fixture(invalid);
            let before = state.nexus_snapshot();
            let payload = catalog_payload(&state, &keys);
            let mut block = state.block(BlockHeader::new(
                NonZeroU64::new(2).unwrap(),
                None,
                None,
                0,
                0,
            ));
            let mut transaction = block.transaction();
            transaction
                .stage_consensus_catalog_transition(&payload)
                .expect_err("invalid authority cannot activate");
            assert_eq!(transaction.nexus.lane_catalog, before.lane_catalog);
            assert_eq!(
                transaction.nexus.dataspace_catalog,
                before.dataspace_catalog
            );
            assert!(
                runtime_catalog_from_world(&transaction.world)
                    .unwrap()
                    .is_none()
            );
            assert!(transaction.pending_lane_lifecycle.is_none());
            assert!(!transaction.lane_manifests.has_manifest(LaneId::new(5)));
        }
    });
}

#[test]
fn runtime_catalog_rejects_stale_roots_and_genesis_without_partial_state() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let original = catalog_payload(&state, &keys);
        for case in 0..4 {
            let mut payload = original.clone();
            match case {
                0 => payload.expected_catalog_hash = Hash::new(b"stale catalog"),
                1 => payload.expected_incarnation_root = Hash::new(b"stale incarnation"),
                2 => payload.expected_runtime_catalog_hash = Some(Hash::new(b"stale runtime")),
                _ => {}
            }
            let height = if case == 3 { 1 } else { 2 };
            let mut block = state.block(BlockHeader::new(
                NonZeroU64::new(height).unwrap(),
                None,
                None,
                0,
                0,
            ));
            let mut transaction = block.transaction();
            transaction
                .stage_consensus_catalog_transition(&payload)
                .expect_err("stale or pre-genesis catalog request");
            assert!(
                runtime_catalog_from_world(&transaction.world)
                    .unwrap()
                    .is_none()
            );
            assert!(transaction.pending_lane_lifecycle.is_none());
        }
    });
}

#[test]
fn runtime_catalog_accessor_rejects_malformed_protected_state_and_baseline_drift() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        assert!(
            runtime_catalog_from_world(&state.world.view())
                .unwrap()
                .is_none()
        );
        let baseline = state.nexus_snapshot().configured_dataspace_catalog;
        let payload = catalog_payload(&state, &keys);
        let runtime = NexusRuntimeCatalogV1 {
            version: 1,
            baseline_dataspaces_hash: iroha_data_model::nexus::dataspace_catalog_hash(&baseline),
            baseline_manifests_hash: Hash::prehashed(
                state
                    .lane_manifests
                    .read()
                    .baseline_consensus_policy_digest(),
            ),
            dataspaces: payload.dataspace_additions,
            manifests: payload.manifest_additions,
        };
        let effective = runtime_catalog_dataspaces(&baseline, Some(&runtime)).unwrap();
        assert!(effective.by_id(DataSpaceId::new(10)).is_some());
        assert!(effective.by_id(DataSpaceId::new(12)).is_some());
        let mut wrong = runtime;
        wrong.baseline_dataspaces_hash = Hash::new(b"foreign baseline");
        assert!(runtime_catalog_dataspaces(&baseline, Some(&wrong)).is_err());
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                iroha_data_model::parameter::CustomParameter::new(
                    NexusRuntimeCatalogV1::parameter_id(),
                    iroha_primitives::json::Json::new(norito::json!({"version": 255})),
                ),
            ));
        world.commit();
        assert!(runtime_catalog_from_world(&state.world.view()).is_err());
        assert!(runtime_catalog_root_from_world(&state.world.view()).is_err());
    });
}

include!("runtime_catalog_commit_tests.rs");
