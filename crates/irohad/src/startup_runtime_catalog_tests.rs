//! Startup must derive additive catalog authority from protected World state and frozen baseline.

use super::*;
use iroha_data_model::nexus::{
    DataSpaceCatalog, DataSpaceMetadata, LaneConfig, LaneLifecyclePlan, NexusRuntimeCatalogV1,
    RuntimeDataSpaceAdditionV1, RuntimeLaneManifestV1, dataspace_catalog_hash,
};
use iroha_model_base::topology::{DataSpaceId, LaneId};
use iroha_primitives::json::Json;

fn run_startup_catalog_test(test: impl FnOnce() + Send + 'static) {
    // Debug State construction uses a large stack; keep the fixture independent of harness defaults.
    let result = std::thread::Builder::new()
        .name("startup-runtime-catalog".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(test)
        .expect("bounded-stack startup fixture")
        .join();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

fn public_manifest(lane: u32, alias: &str) -> RuntimeLaneManifestV1 {
    let validators: Vec<_> = (1_u8..=4)
        .map(|seed| {
            let key = iroha_crypto::KeyPair::try_from_seed(
                vec![seed; 32],
                iroha_crypto::Algorithm::BlsNormal,
            )
            .expect("synthetic manifest public key");
            let validator =
                iroha_data_model::account::AccountId::new(key.public_key().clone()).to_string();
            let peer_id = iroha_model_base::peer::PeerId::new(key.public_key().clone()).to_string();
            norito::json!({
                "validator": validator,
                "peer_id": peer_id,
            })
        })
        .collect();
    RuntimeLaneManifestV1 {
        lane_id: LaneId::new(lane),
        manifest: Json::new(norito::json!({
            "lane": alias, "version": 1, "validators": validators, "quorum": 3,
        })),
    }
}

fn effective_catalog(
    configured: &iroha_config::parameters::actual::Nexus,
    baseline: &LaneManifestRegistryHandle,
) -> (
    iroha_config::parameters::actual::Nexus,
    NexusRuntimeCatalogV1,
) {
    let manifest_hash = [0x67; 32];
    let dataspace = DataSpaceMetadata {
        id: DataSpaceId::from_hash(&manifest_hash),
        alias: "runtime-dataspace".to_owned(),
        description: None,
        fault_tolerance: 1,
    };
    let mut effective = configured.clone();
    effective.lane_catalog = configured
        .lane_catalog
        .apply_lifecycle(&LaneLifecyclePlan {
            additions: vec![LaneConfig {
                id: LaneId::new(5),
                alias: "runtime-lane".to_owned(),
                dataspace_id: dataspace.id,
                ..LaneConfig::default()
            }],
            retire: vec![],
        })
        .expect("restored runtime lane");
    effective.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&effective.lane_catalog);
    let mut dataspaces = configured.configured_dataspace_catalog.entries().to_vec();
    dataspaces.push(dataspace.clone());
    effective.dataspace_catalog = DataSpaceCatalog::new(dataspaces).expect("restored runtime DS");
    let runtime = NexusRuntimeCatalogV1 {
        version: NexusRuntimeCatalogV1::VERSION,
        baseline_dataspaces_hash: dataspace_catalog_hash(&configured.configured_dataspace_catalog),
        baseline_manifests_hash: iroha_crypto::Hash::prehashed(
            baseline.baseline_consensus_policy_digest(),
        ),
        dataspaces: vec![RuntimeDataSpaceAdditionV1 {
            descriptor: dataspace,
            manifest_hash,
        }],
        manifests: vec![public_manifest(5, "runtime-lane")],
    };
    (effective, runtime)
}

fn seed_committed_catalog(state: &mut State, runtime: NexusRuntimeCatalogV1) {
    let mut world = state.world.block();
    world
        .parameters
        .get_mut()
        .set_parameter(iroha_data_model::parameter::Parameter::Custom(
            runtime
                .into_custom_parameter()
                .expect("structurally valid protected test state"),
        ))
        .expect("install the committed runtime catalog fixture");
    world.commit();
}

#[test]
fn startup_catalog_freezes_only_baseline_files_and_reconstructs_world_manifest() {
    run_startup_catalog_test(|| {
        let directory = tempfile::tempdir().expect("public fixture directory");
        let mut configured = iroha_config::parameters::actual::Nexus::default();
        configured.registry.manifest_directory = Some(directory.path().to_path_buf());
        let baseline = freeze_lane_manifests_for_startup_replay(&configured).expect("baseline");
        let (effective, runtime) = effective_catalog(&configured, &baseline);
        std::fs::write(
            directory.path().join("runtime-lane.manifest.json"),
            b"{\"unexpected\":true}",
        )
        .expect("untrusted local file named for a runtime alias");
        let frozen = freeze_lane_manifests_for_startup_replay(&effective)
            .expect("only configured aliases enter the source scan");
        assert_eq!(
            frozen.consensus_policy_digest(),
            baseline.consensus_policy_digest()
        );
        assert!(!frozen.has_manifest_source_alias("runtime-lane"));
        assert!(frozen.status(LaneId::new(5)).is_none());

        let mut state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        seed_committed_catalog(&mut state, runtime);
        let projected = state
            .nexus_with_committed_catalog(effective.clone())
            .expect("protected DS projection");
        assert_eq!(projected.dataspace_catalog, effective.dataspace_catalog);
        assert_eq!(
            projected.configured_dataspace_catalog,
            configured.configured_dataspace_catalog
        );
        let installed = state
            .lane_manifests_with_committed_catalog(&frozen, &projected)
            .expect("exact public World source reconstructs runtime manifest");
        assert!(installed.has_manifest(LaneId::new(5)));
        assert!(
            installed
                .status(LaneId::new(5))
                .unwrap()
                .manifest_path
                .is_none()
        );
        assert_eq!(
            installed.baseline_consensus_policy_digest(),
            baseline.consensus_policy_digest()
        );
    });
}

#[test]
fn startup_catalog_handoff_includes_additions_committed_during_replay() {
    run_startup_catalog_test(|| {
        let configured = iroha_config::parameters::actual::Nexus::default();
        let baseline = freeze_lane_manifests_for_startup_replay(&configured).expect("baseline");
        let (mut effective, mut runtime) = effective_catalog(&configured, &baseline);
        let mut state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        seed_committed_catalog(&mut state, runtime.clone());
        let initial = state
            .lane_manifests_with_committed_catalog(&baseline, &effective)
            .expect("initial restored manifest");
        state.install_lane_manifests_for_testing(&initial);

        effective.lane_catalog = effective
            .lane_catalog
            .apply_lifecycle(&LaneLifecyclePlan {
                additions: vec![LaneConfig {
                    id: LaneId::new(6),
                    alias: "replayed-lane".to_owned(),
                    dataspace_id: runtime.dataspaces[0].descriptor.id,
                    ..LaneConfig::default()
                }],
                retire: vec![],
            })
            .expect("catalog committed during replay");
        effective.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&effective.lane_catalog);
        runtime.manifests.push(public_manifest(6, "replayed-lane"));
        seed_committed_catalog(&mut state, runtime.clone());
        let handoff = rebind_frozen_lane_manifests_after_startup_replay(&state, &effective)
            .expect("handoff derives the full current World overlay");
        assert!(handoff.has_manifest(LaneId::new(5)) && handoff.has_manifest(LaneId::new(6)));
        assert_eq!(
            handoff.baseline_consensus_policy_digest(),
            baseline.consensus_policy_digest()
        );
        assert_ne!(
            handoff.consensus_policy_digest(),
            initial.consensus_policy_digest()
        );

        runtime.baseline_manifests_hash = iroha_crypto::Hash::prehashed([0x42; 32]);
        seed_committed_catalog(&mut state, runtime);
        assert!(rebind_frozen_lane_manifests_after_startup_replay(&state, &effective).is_err());
        assert_eq!(
            state.lane_manifests.read().consensus_policy_digest(),
            initial.consensus_policy_digest(),
            "a failed reconstruction cannot mutate the installed registry"
        );
    });
}
