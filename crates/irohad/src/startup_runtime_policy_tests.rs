//! Startup policy loading must precede replay and remain frozen through runtime handoff.
use super::*;
use iroha_data_model::nexus::{
    AuditControls, JurisdictionSet, LaneCatalog, LaneCompliancePolicy, LaneCompliancePolicyId,
    LaneConfig,
};
use iroha_model_base::{
    metadata::Metadata,
    topology::{DataSpaceId, LaneId},
};

fn policy_startup_state(
    nexus: &iroha_config::parameters::actual::Nexus,
) -> (DisposableValidationRoot, State) {
    let mut config: Config = ConfigReader::new()
        .with_toml_source(iroha_config::base::toml::TomlSource::inline(
            crate::config_tests::minimal_config_table(),
        ))
        .read_and_complete::<UserConfig>()
        .expect("complete daemon fixture configuration")
        .parse()
        .expect("valid daemon fixture configuration");
    config.nexus = nexus.clone();
    // The parser fixture uses a tiny byte-unit example; actual startup needs a bounded
    // budget large enough for its authenticated baseline and publication temporaries.
    config.kura.max_disk_usage_bytes = iroha_config_base::util::Bytes(64 * 1024 * 1024);
    let root = DisposableValidationRoot::create().expect("isolated startup storage");
    let kura = open_disposable_validation_kura(&config, &root)
        .expect("authenticate configured Kura baseline before State geometry");
    // Use the production constructor: the generic testing constructor publishes default
    // geometry, whose incarnation is different from this governed configured baseline.
    let execution_budget = iroha_core::state::AllocationBudget::new(
        iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
    );
    let world = World::try_with_execution_budget([], [], [], &execution_budget)
        .expect("startup fixture World retains the original execution pool");
    let state = State::try_new_with_chain_and_network_id(
        execution_budget,
        world,
        kura,
        LiveQueryStore::start_test(),
        config.common.chain.clone(),
        NetworkId::from_genesis_hash(config.genesis.expected_hash),
        #[cfg(feature = "telemetry")]
        StateTelemetry::default(),
    )
    .expect("fresh State preserves the authenticated configured geometry boundary");
    (root, state)
}

fn policy() -> LaneCompliancePolicy {
    LaneCompliancePolicy {
        id: LaneCompliancePolicyId::new(iroha_crypto::Hash::prehashed([0x51; 32])),
        version: 1,
        lane_id: LaneId::SINGLE,
        dataspace_id: DataSpaceId::UNIVERSAL,
        jurisdiction: JurisdictionSet::default(),
        deny: Vec::new(),
        allow: Vec::new(),
        transfer_limits: Vec::new(),
        audit_controls: AuditControls::default(),
        metadata: Metadata::default(),
    }
}

#[test]
fn startup_compliance_is_installed_before_execution_policy_derivation_and_reused() {
    let directory = tempfile::tempdir().expect("policy directory");
    let path = directory.path().join("default.norito");
    std::fs::write(&path, policy().encode()).expect("write canonical policy");
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.compliance.enabled = true;
    nexus.compliance.policy_dir = Some(directory.path().to_path_buf());
    let baseline = freeze_lane_manifests_for_startup_replay(&nexus)
        .expect("freeze configured manifest baseline before State policy installation");
    let (_storage, mut state) = policy_startup_state(&nexus);
    let policies = install_lane_policies_for_startup_replay(&mut state, nexus.clone(), &baseline)
        .expect("validate and install all policies before geometry");
    let manifests = &policies.manifests;
    let engine = policies.compliance.as_ref().expect("enabled engine");
    apply_state_geometry_config_before_kura_replay(&mut state, &policies)
        .expect("geometry publication has complete policy coverage");
    let digest = state
        .execution_policy_digest_v1()
        .expect("policy is ready before replay");
    let candidate = state
        .execution_policy_digest_with_runtime_policies_v1(
            &nexus,
            manifests.as_ref(),
            Some(engine.as_ref()),
        )
        .expect("explicit frozen candidate");
    assert_eq!(candidate, digest);
    let mut changed = policy();
    changed.version = 2;
    std::fs::write(&path, changed.encode()).expect("replace directory after freeze");
    engine
        .validate_active_catalog(&nexus.lane_catalog)
        .expect("post-replay coverage uses frozen source");
    let retained = state.lane_compliance_engine().expect("same State engine");
    assert!(Arc::ptr_eq(engine, &retained));
    assert_eq!(
        state.execution_policy_digest_v1().expect("retained policy"),
        digest
    );
    let rescanned = freeze_lane_compliance_for_startup_replay(&nexus)
        .expect("changed policy is independently valid")
        .expect("enabled engine");
    assert_ne!(
        rescanned.consensus_policy_digest(),
        engine.consensus_policy_digest(),
        "a forbidden second directory load would change the frozen policy"
    );
}

#[test]
fn startup_compliance_rejects_missing_and_wrong_lane_policy_before_replay() {
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.compliance.enabled = true;
    nexus.compliance.policy_dir = None;
    assert!(freeze_lane_compliance_for_startup_replay(&nexus).is_err());
    let directory = tempfile::tempdir().expect("policy directory");
    let mut wrong = policy();
    wrong.lane_id = LaneId::new(9);
    std::fs::write(directory.path().join("wrong.norito"), wrong.encode())
        .expect("write other-lane policy");
    nexus.compliance.policy_dir = Some(directory.path().to_path_buf());
    assert!(freeze_lane_compliance_for_startup_replay(&nexus).is_err());
    nexus.compliance.enabled = false;
    std::fs::remove_dir_all(directory.path()).expect("remove disabled directory");
    assert!(
        freeze_lane_compliance_for_startup_replay(&nexus)
            .expect("disabled compliance never reads directory")
            .is_none()
    );
}

fn governed_nexus(directory: &std::path::Path) -> iroha_config::parameters::actual::Nexus {
    let catalog = LaneCatalog::new(
        std::num::NonZeroU32::new(1).expect("nonzero lane namespace"),
        vec![LaneConfig {
            governance: Some("parliament".to_owned()),
            ..LaneConfig::default()
        }],
    )
    .expect("governed primary lane");
    let mut nexus = iroha_config::parameters::actual::Nexus {
        lane_catalog: catalog.clone(),
        configured_lane_catalog: catalog.clone(),
        lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&catalog),
        ..Default::default()
    };
    nexus.governance.modules.insert(
        "parliament".to_owned(),
        iroha_config::parameters::actual::GovernanceModule::default(),
    );
    nexus.registry.manifest_directory = Some(directory.to_path_buf());
    nexus
}

#[test]
fn governed_startup_publishes_geometry_only_after_installing_frozen_policies() {
    let directory = tempfile::tempdir().expect("manifest directory");
    let path = directory.path().join("default.manifest.json");
    std::fs::write(&path, br#"{"lane":"default","governance":"parliament"}"#)
        .expect("write configured governance manifest");
    let nexus = governed_nexus(directory.path());
    let baseline = freeze_lane_manifests_for_startup_replay(&nexus)
        .expect("freeze the actual governed manifest source");
    let (_storage, mut state) = policy_startup_state(&nexus);
    let original_catalog = state.nexus_snapshot().lane_catalog;
    let policies = install_lane_policies_for_startup_replay(&mut state, nexus.clone(), &baseline)
        .expect("complete governed policy snapshot");
    assert_eq!(
        state.nexus_snapshot().lane_catalog,
        original_catalog,
        "process-local policy installation cannot authorize snapshot geometry mutation"
    );
    let digest = policies.manifests.consensus_policy_digest();
    std::fs::write(&path, b"invalid replacement after freeze").expect("replace manifest source");
    assert!(
        freeze_lane_manifests_for_startup_replay(&nexus).is_err(),
        "a forbidden rescan would fail"
    );
    apply_state_geometry_config_before_kura_replay(&mut state, &policies)
        .expect("the first governed State view must already have its manifest");
    assert_eq!(state.nexus_snapshot().lane_catalog, nexus.lane_catalog);
    state.view();
    state
        .execution_policy_digest_v1()
        .expect("governed execution policy is complete");
    let handoff = rebind_frozen_lane_manifests_after_startup_replay(&state, &policies.nexus)
        .expect("runtime handoff never reopens the changed manifest file");
    assert_eq!(handoff.consensus_policy_digest(), digest);
}

#[test]
fn startup_policy_failure_preserves_prior_policies_and_geometry() {
    let directory = tempfile::tempdir().expect("manifest directory");
    let mut nexus = governed_nexus(directory.path());
    let mut state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let original_catalog = state.nexus_snapshot().lane_catalog;
    let original_manifests = state.lane_manifests.read().clone();
    let original_baseline = freeze_lane_manifests_for_startup_replay(&state.nexus_snapshot())
        .expect("freeze the original ungoverned configured baseline");
    assert!(
        freeze_lane_manifests_for_startup_replay(&nexus).is_err(),
        "missing governed manifest fails at the actual source-freezing boundary"
    );
    assert!(
        install_lane_policies_for_startup_replay(&mut state, nexus.clone(), &original_baseline)
            .is_err(),
        "the original ungoverned baseline cannot authorize a missing governed manifest"
    );
    assert!(Arc::ptr_eq(
        &original_manifests,
        &state.lane_manifests.read()
    ));
    assert_eq!(state.nexus_snapshot().lane_catalog, original_catalog);
    std::fs::write(
        directory.path().join("default.manifest.json"),
        br#"{"lane":"default","governance":"parliament"}"#,
    )
    .expect("valid manifest before invalid compliance source");
    let baseline = freeze_lane_manifests_for_startup_replay(&nexus)
        .expect("freeze the actual newly supplied governed manifest");
    nexus.compliance.enabled = true;
    nexus.compliance.policy_dir = None;
    assert!(
        install_lane_policies_for_startup_replay(&mut state, nexus, &baseline).is_err(),
        "invalid compliance must not partially replace an otherwise valid manifest snapshot"
    );
    assert!(Arc::ptr_eq(
        &original_manifests,
        &state.lane_manifests.read()
    ));
    assert!(state.lane_compliance_engine().is_none());
    assert_eq!(state.nexus_snapshot().lane_catalog, original_catalog);
    state.view();
}
