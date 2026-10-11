//! Real generated-custody boundaries for the borrowed original-intent policy projection.

use super::*;
use crate::managed::service_policies::GeneratedServicePolicies;
use iroha_fs::PublishMode;

fn fixture() -> (tempfile::TempDir, ServiceAuthority) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = super::super::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "original-policy-view",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    (temporary, authority)
}

fn policy_bytes(authority: &ServiceAuthority) -> Vec<u8> {
    super::super::native_operation::encode(
        &GeneratedServicePolicies::select(authority).unwrap(),
        384 * 1024,
    )
    .unwrap()
}

#[test]
fn policy_projection_checks_actual_original_source_at_entry_and_successful_exit() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, authority) = fixture();
    let (original, checks) = profile_validation_test_support::count(|| policy_bytes(&authority));
    assert_eq!(checks, 2);
    let generation =
        PrivateDirectory::open_exact(authority.prepared.context.client_config.parent().unwrap())
            .unwrap();
    let retained = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = retained.to_vec();
    changed.extend_from_slice(b"\n# different original image despite identical parsed settings\n");

    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    assert!(authority.original_intent().is_err());
    assert!(GeneratedServicePolicies::select(&authority).is_err());
    generation
        .write_atomic("peer3.toml", &retained, PublishMode::Replace)
        .unwrap();
    assert_eq!(policy_bytes(&authority), original);

    let intent = authority.original_intent().unwrap();
    assert_eq!(intent.network_id(), authority.config.network_id);
    assert_eq!(
        intent.genesis_hash(),
        *authority.genesis.genesis.hash().as_ref()
    );
    assert_eq!(intent.provider_plans().unwrap().len(), 3);
    // Fault injection is confined to this test. Production view projections perform no I/O.
    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    assert!(intent.finish().is_err());
    generation
        .write_atomic("peer3.toml", &retained, PublishMode::Replace)
        .unwrap();
    assert_eq!(policy_bytes(&authority), original);
    assert_eq!(authority.directory.entries(8).unwrap(), ["operation.lock"]);
}

#[test]
fn original_policy_view_retains_network_scope_and_original_provider_refusals() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let original = policy_bytes(&parent);
    let provider = parent.manifest.providers[0].provider_id;
    let child =
        ServiceAuthority::open_provider(&parent.prepared, provider, ProviderPurpose::Custody)
            .unwrap();
    let error = GeneratedServicePolicies::select(&child).err().unwrap();
    assert!(matches!(
        error,
        super::super::Error::Invalid(message)
            if message == "provider service cannot select all network plans"
    ));
    assert!(child.provider_plans().is_err());
    let intent = parent.original_intent().unwrap();
    assert!(
        intent
            .gateway_compliance_plan(ProviderId::new([0x99; 32]))
            .is_err()
    );
    intent.finish().unwrap();
    assert_eq!(policy_bytes(&parent), original);
    assert_eq!(child.directory.entries(8).unwrap(), ["operation.lock"]);
}

#[test]
fn original_policy_view_preserves_fresh_compliance_decode_admission_and_same_source_retry() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, authority) = fixture();
    let original = policy_bytes(&authority);
    let provider = authority.manifest.providers[0].provider_id;
    let limits = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    let expected = norito::with_decode_limits_scope(limits, || {
        authority.gateway_compliance_plan(provider).err().unwrap()
    });
    let error = norito::with_decode_limits_scope(limits, || {
        GeneratedServicePolicies::select(&authority).err().unwrap()
    });
    assert_eq!(error.to_string(), expected.to_string());
    assert!(matches!(
        error,
        super::super::Error::Invalid(message)
            if message == "retained generated compliance plan differs"
    ));
    assert_eq!(policy_bytes(&authority), original);
    assert_eq!(authority.directory.entries(8).unwrap(), ["operation.lock"]);
}

#[test]
fn publication_intent_projection_preserves_network_scope_and_decode_admission() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, authority) = fixture();
    let expected = authority.publication_plan().unwrap();
    let intent = authority.original_intent().unwrap();
    let selected = intent.publication_plan().unwrap();
    assert_eq!(
        selected.configuration_table().unwrap(),
        expected.configuration_table().unwrap()
    );
    intent.finish().unwrap();

    let provider = authority.manifest.providers[0].provider_id;
    let child =
        ServiceAuthority::open_provider(&authority.prepared, provider, ProviderPurpose::Custody)
            .unwrap();
    let expected_error = child.publication_plan().err().unwrap().to_string();
    let intent = child.original_intent().unwrap();
    assert_eq!(
        intent.publication_plan().err().unwrap().to_string(),
        expected_error
    );
    intent.finish().unwrap();

    let limits = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    let expected_error = norito::with_decode_limits_scope(limits, || {
        authority.publication_plan().err().unwrap().to_string()
    });
    let intent = authority.original_intent().unwrap();
    let actual_error = norito::with_decode_limits_scope(limits, || {
        intent.publication_plan().err().unwrap().to_string()
    });
    assert_eq!(actual_error, expected_error);
    intent.finish().unwrap();
    assert_eq!(
        authority
            .publication_plan()
            .unwrap()
            .configuration_table()
            .unwrap(),
        expected.configuration_table().unwrap()
    );
}
