use super::*;
fn state_for_lifecycle_test() -> Arc<CoreState> {
    let nexus = iroha_config::parameters::actual::Nexus::default();
    let state = CoreState::new_with_pre_genesis_nexus_for_testing(
        iroha_core::state::World::default(),
        nexus,
        iroha_core::query::store::LiveQueryStore::start_test(),
    );
    Arc::new(state)
}
#[test]
fn lane_lifecycle_status_binds_exact_current_catalog() {
    let state = state_for_lifecycle_test();
    let status = handle_get_nexus_lane_lifecycle(&state).expect("lifecycle status");
    let view = state.view();
    assert_eq!(
        status.validate().expect("validate lifecycle status"),
        view.nexus.lane_catalog
    );
    let expected_incarnations =
        iroha_data_model::nexus::LaneLifecycleParameterV1::canonical_incarnations(
            &view.nexus.lane_catalog,
            &view.lane_incarnations,
        )
        .expect("canonical committed incarnations");
    assert_eq!(status.incarnations, expected_incarnations);
    assert_eq!(status.runtime_catalog_hash, None);
}

#[test]
fn lane_lifecycle_status_exposes_native_runtime_root_and_propagates_invalid_state() {
    use iroha_data_model::{
        nexus::NexusRuntimeCatalogV1,
        parameter::{CustomParameter, Parameter},
    };
    let state = state_for_lifecycle_test();
    let before = handle_get_nexus_lane_lifecycle(&state).unwrap();
    let runtime = NexusRuntimeCatalogV1 {
        version: NexusRuntimeCatalogV1::VERSION,
        baseline_dataspaces_hash: iroha_data_model::nexus::dataspace_catalog_hash(
            &state.nexus_snapshot().configured_dataspace_catalog,
        ),
        baseline_manifests_hash: Hash::prehashed(
            state
                .lane_manifests
                .read()
                .baseline_consensus_policy_digest(),
        ),
        dataspaces: Vec::new(),
        manifests: Vec::new(),
    };
    let expected = runtime.canonical_hash().unwrap();
    let mut world = state.world.block();
    world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(runtime.into_custom_parameter().unwrap()))
        .expect("install the committed runtime catalog fixture");
    world.commit();
    let status = handle_get_nexus_lane_lifecycle(&state).unwrap();
    assert_eq!(status.runtime_catalog_hash, Some(expected));
    assert_eq!(status.catalog_hash, before.catalog_hash);
    assert_eq!(status.incarnation_root, before.incarnation_root);
    let mut world = state.world.block();
    world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(CustomParameter::new(
            NexusRuntimeCatalogV1::parameter_id(),
            iroha_primitives::json::Json::new(norito::json!({"version": 255})),
        )))
        .expect("store the malformed catalog fixture for native decoder rejection");
    world.commit();
    let error = handle_get_nexus_lane_lifecycle(&state)
        .expect_err("malformed protected state must never become an absent runtime root");
    let native_error = state
        .try_view()
        .err()
        .expect("the committed malformed parameter must fail native projection");
    // Torii's outer Query display omits the cause; inspect its typed conversion payload.
    match error {
        Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => assert_eq!(
            message,
            format!("invalid committed runtime catalog: {native_error}"),
        ),
        other => panic!("expected the native runtime catalog conversion error, got {other:?}"),
    }
}
