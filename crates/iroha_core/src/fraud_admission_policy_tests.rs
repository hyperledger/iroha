//! Committed fraud admission uses one parameter owner and a frozen predecessor.

use super::*;
use crate::{
    kura::Kura,
    pipeline_gas_policy::StateParameters,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World},
    tx::{LaneAssignment, enforce_fraud_policy},
};
use iroha_data_model::{
    block::BlockHeader,
    executor::ExecutorDataModel,
    isi::SetParameter,
    parameter::{CustomParameter, Parameter, Parameters},
};
use iroha_model_base::{
    metadata::Metadata,
    topology::{DataSpaceId, LaneId},
};
use iroha_primitives::json::Json;
use iroha_test_samples::ALICE_ID;
use std::{num::NonZeroU64, time::Duration};

fn policy(missing_assessment_permitted: bool) -> FraudAdmissionPolicyV1 {
    FraudAdmissionPolicyV1 {
        enabled: true,
        required_minimum_band: Some(FraudRiskBandV1::Low),
        missing_assessment_permitted,
        ..FraudAdmissionPolicyV1::protocol_default()
    }
}
fn state_with(policy: &FraudAdmissionPolicyV1) -> State {
    let world = World::new();
    let mut staged = world.block();
    staged
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(policy.clone().into_custom_parameter()))
        .unwrap();
    staged.commit();
    State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
fn header(height: u64) -> BlockHeader {
    BlockHeader::new(NonZeroU64::new(height).unwrap(), None, None, 0, 0)
}
fn accepts_missing(settings: &FraudMonitoring) -> bool {
    let catalog = iroha_data_model::nexus::DataSpaceCatalog::default();
    enforce_fraud_policy(
        settings,
        &Metadata::default(),
        None,
        &LaneAssignment {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            dataspace_catalog: &catalog,
        },
    )
    .is_ok()
}

#[test]
fn committed_fraud_projection_ignores_node_semantics_and_preserves_transport() {
    for missing in [false, true] {
        let committed = policy(missing);
        let mut state = state_with(&committed);
        let mut node = FraudMonitoring::default();
        node.policy.enabled = !committed.enabled;
        node.policy.missing_assessment_permitted = !missing;
        node.policy.required_minimum_band = Some(FraudRiskBandV1::Critical);
        node.service_endpoints = vec!["https://unavailable.invalid/assessment".parse().unwrap()];
        node.connect_timeout = Duration::from_millis(1);
        node.request_timeout = Duration::from_millis(2);
        state.install_node_fraud_monitoring(node.clone());
        let effective = state.fraud_monitoring_snapshot();
        assert_eq!(policy_of(&effective), committed);
        assert_eq!(effective.service_endpoints, node.service_endpoints);
        assert_eq!(effective.connect_timeout, node.connect_timeout);
        assert_eq!(effective.request_timeout, node.request_timeout);
        assert_eq!(accepts_missing(&effective), missing);
        assert_eq!(policy_of(&state.view().fraud_monitoring), committed);
        let mut block = state.block(header(2));
        assert_eq!(policy_of(&block.fraud_monitoring), committed);
        assert_eq!(policy_of(&block.transaction().fraud_monitoring), committed);
    }
}

#[test]
fn malformed_fraud_updates_and_restore_never_replace_original_parameter_owner() {
    let mut owner = StateParameters::default();
    owner
        .set_parameter(Parameter::Custom(policy(true).into_custom_parameter()))
        .unwrap();
    let original = owner.clone();
    let mut unsupported = policy(false);
    unsupported.version = 2;
    let malformed = [
        CustomParameter::new(FraudAdmissionPolicyV1::parameter_id(), Json::new("invalid")),
        unsupported.into_custom_parameter(),
    ];
    for custom in malformed {
        assert!(
            owner
                .set_parameter(Parameter::Custom(custom.clone()))
                .is_err()
        );
        assert_eq!(
            owner, original,
            "invalid replacement changes neither original nor projection"
        );
        let mut raw = Parameters::default();
        raw.set_parameter(Parameter::Custom(custom));
        let snapshot = norito::json::to_json(&raw).unwrap();
        assert!(norito::json::from_str::<StateParameters>(&snapshot).is_err());
    }
    let replacement = Parameter::Custom(policy(false).into_custom_parameter());
    let zero = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    norito::with_decode_limits_scope(zero, || {
        let error = owner.set_parameter(replacement).unwrap_err();
        assert!(norito::core::decode_error_matches_active_limits(&error));
        assert_eq!(
            owner, original,
            "local decode refusal preserves the same original"
        );
    });
    norito::with_decode_limits_scope(zero, || {
        let effective = effective_fraud(FraudMonitoring::default(), &owner);
        assert_eq!(
            policy_of(&effective),
            policy(true),
            "reads perform no decoding"
        );
    });
    let snapshot = norito::json::to_json(&owner).unwrap();
    let restored: StateParameters = norito::json::from_str(&snapshot).unwrap();
    assert_eq!(restored, original);
}

#[test]
fn fraud_policy_change_applies_only_after_its_original_block() {
    let state = state_with(&policy(true));
    let mut block = state.block(header(2));
    let mut transaction = block.transaction();
    assert!(accepts_missing(&transaction.fraud_monitoring));
    SetParameter::new(Parameter::Custom(policy(false).into_custom_parameter()))
        .execute(&ALICE_ID, &mut transaction)
        .unwrap();
    assert_eq!(
        transaction.world.parameters.get().fraud_policy(),
        &policy(false)
    );
    assert_eq!(policy_of(&transaction.fraud_monitoring), policy(true));
    assert!(
        accepts_missing(&transaction.fraud_monitoring),
        "same transaction retains predecessor"
    );
    transaction.apply();
    assert!(
        accepts_missing(&block.transaction().fraud_monitoring),
        "later transaction in the same block retains predecessor"
    );
    block.commit_world_overlay_for_testing().unwrap();
    let successor = state.block(header(3));
    assert_eq!(policy_of(&successor.fraud_monitoring), policy(false));
    assert!(!accepts_missing(&successor.fraud_monitoring));
}

#[test]
fn set_parameter_refuses_malformed_fraud_before_any_publication() {
    let state = state_with(&policy(true));
    let mut block = state.block(header(2));
    let mut transaction = block.transaction();
    let before = transaction.world.parameters.get().clone();
    let malformed = CustomParameter::new(FraudAdmissionPolicyV1::parameter_id(), Json::new(false));
    assert!(
        SetParameter::new(Parameter::Custom(malformed))
            .execute(&ALICE_ID, &mut transaction)
            .is_err()
    );
    assert_eq!(transaction.world.parameters.get(), &before);
    assert_eq!(policy_of(&transaction.fraud_monitoring), policy(true));
}

#[test]
fn executor_reconciliation_cannot_replace_or_remove_fraud_policy() {
    let state = state_with(&policy(true));
    let mut block = state.block(header(2));
    let mut transaction = block.transaction();
    let mut declared = ExecutorDataModel::default();
    declared
        .parameters
        .insert(policy(false).into_custom_parameter());
    transaction.world.apply_executor_data_model(declared);
    assert_eq!(
        transaction.world.parameters.get().fraud_policy(),
        &policy(true)
    );
    transaction
        .world
        .apply_executor_data_model(ExecutorDataModel::default());
    assert_eq!(
        transaction.world.parameters.get().fraud_policy(),
        &policy(true)
    );
}

#[test]
fn effective_policy_bytes_exclude_transport_and_invalid_application_is_atomic() {
    let original = policy(true);
    let mut settings = FraudMonitoring::default();
    apply_policy(&original, &mut settings).unwrap();
    let canonical = norito::encode_canonical(&policy_of(&settings)).unwrap();
    settings
        .service_endpoints
        .push("https://different.invalid/assessment".parse().unwrap());
    settings.connect_timeout += Duration::from_secs(1);
    settings.request_timeout += Duration::from_secs(1);
    assert_eq!(
        norito::encode_canonical(&policy_of(&settings)).unwrap(),
        canonical
    );
    let endpoints = settings.service_endpoints.clone();
    let connect_timeout = settings.connect_timeout;
    let mut invalid = policy(false);
    invalid.version = 2;
    assert_eq!(
        apply_policy(&invalid, &mut settings),
        Err(FraudAdmissionPolicyError::UnsupportedVersion(2))
    );
    assert_eq!(policy_of(&settings), original);
    assert_eq!(settings.service_endpoints, endpoints);
    assert_eq!(settings.connect_timeout, connect_timeout);
}
