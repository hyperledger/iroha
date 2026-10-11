//! Native-certificate registry transitions, quotas and hostile restored state.

use super::*;
use crate::sumeragi_finality::{authenticated_genesis, test_fixtures::NativeFinalityFixture};
use iroha_crypto::{Hash, HashOf, KeyPair};

fn owner(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn fixture(id: u64) -> (NativeFinalityFixture, PrivateDataspaceRegistration) {
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"registry-parent",
        ))),
        dataspace_id: DataSpaceId::new(id),
    };
    let fixture = NativeFinalityFixture::start_with_scope(&format!("private-root-{id}"), scope);
    let result = fixture
        .verifier()
        .verify_retained_decision(fixture.genesis_proof())
        .unwrap()
        .result()
        .0;
    let registration = PrivateDataspaceRegistration::new(
        scope,
        fixture.chain_id().parse().unwrap(),
        fixture.network_id(),
        result,
        authenticated_genesis(fixture.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap(),
    )
    .unwrap();
    (fixture, registration)
}

fn next(
    fixture: &mut NativeFinalityFixture,
    registration: &PrivateDataspaceRegistration,
) -> PrivateDataspaceAnchor {
    let block = fixture.block_with_submitted_work(fixture.next_header());
    let proof = fixture.certify(block);
    let verified = fixture.verifier().verify_retained_decision(&proof).unwrap();
    PrivateDataspaceAnchor::from_certificate(
        registration,
        verified.block().commit_certificate().unwrap(),
    )
    .unwrap()
}

fn policy() -> PrivateDataspaceAdmissionPolicy {
    PrivateDataspaceAdmissionPolicy {
        max_registered_roots: 2,
        max_roots_per_owner: 1,
    }
}

#[test]
fn policy_is_explicit_bounded_and_roundtrips_without_defaulting_malformed_input() {
    assert!(
        PrivateDataspaceAdmissionPolicy::default()
            .validate()
            .is_ok()
    );
    assert_eq!(
        PrivateDataspaceAdmissionPolicy::from_custom_parameter(
            &policy().into_custom_parameter().unwrap()
        )
        .unwrap(),
        policy()
    );
    for invalid in [
        PrivateDataspaceAdmissionPolicy {
            max_registered_roots: 1,
            max_roots_per_owner: 0,
        },
        PrivateDataspaceAdmissionPolicy {
            max_registered_roots: 1,
            max_roots_per_owner: 2,
        },
        PrivateDataspaceAdmissionPolicy {
            max_registered_roots: MAX_PRIVATE_DATASPACE_ROOTS + 1,
            max_roots_per_owner: 1,
        },
    ] {
        assert!(invalid.validate().is_err());
        assert!(invalid.into_custom_parameter().is_err());
    }
    let malformed = CustomParameter::new(
        PrivateDataspaceAdmissionPolicy::parameter_id(),
        "{\"max_registered_roots\":2}"
            .parse::<iroha_primitives::json::Json>()
            .unwrap(),
    );
    assert!(PrivateDataspaceAdmissionPolicy::from_custom_parameter(&malformed).is_err());
    let foreign = CustomParameter::new(
        "unrelated".parse().unwrap(),
        "{}".parse::<iroha_primitives::json::Json>().unwrap(),
    );
    assert!(PrivateDataspaceAdmissionPolicy::from_custom_parameter(&foreign).is_err());
}

#[test]
fn registration_retry_preserves_advanced_cursor_and_cannot_reset_authority() {
    let (mut fixture, registration) = fixture(u64::MAX);
    let mut registry = PrivateDataspaceRegistry::default();
    registry
        .register_authorized(policy(), "acme".into(), owner(1), 7, registration.clone())
        .unwrap();
    let anchor = next(&mut fixture, &registration);
    assert_eq!(
        registry
            .apply_authorized(DataSpaceId::new(u64::MAX), &owner(1), 7, &anchor)
            .unwrap(),
        PrivateDataspaceAnchorOutcome::Advanced
    );
    assert_eq!(
        registry
            .apply_authorized(DataSpaceId::new(u64::MAX), &owner(1), 7, &anchor)
            .unwrap(),
        PrivateDataspaceAnchorOutcome::AlreadyAnchored
    );
    let retained = registry.clone();
    registry
        .register_authorized(
            PrivateDataspaceAdmissionPolicy::default(),
            "acme".into(),
            owner(1),
            7,
            registration.clone(),
        )
        .unwrap();
    assert_eq!(registry, retained);
    for (alias, who, generation) in [
        ("elsewhere", owner(1), 7),
        ("acme", owner(2), 7),
        ("acme", owner(1), 8),
    ] {
        assert!(
            registry
                .register_authorized(
                    policy(),
                    alias.into(),
                    who,
                    generation,
                    registration.clone()
                )
                .is_err()
        );
        assert_eq!(registry, retained);
    }
    assert_eq!(registry.records()[0].anchor.cursor().height, 2);
    assert_eq!(registry.records()[0].witness_key().last(), Some(&255));
    registry.validate().unwrap();
}

#[test]
fn new_admission_enforces_owner_total_alias_and_parent_bounds_atomically() {
    let (_, first) = fixture(u64::MAX);
    let (_, second) = fixture(u64::MAX - 1);
    let mut registry = PrivateDataspaceRegistry::default();
    assert!(
        registry
            .register_authorized(
                PrivateDataspaceAdmissionPolicy::default(),
                "acme".into(),
                owner(1),
                1,
                first.clone()
            )
            .is_err()
    );
    assert!(registry.records().is_empty());
    assert!(
        registry
            .register_authorized(policy(), "acme".into(), owner(1), 0, first.clone())
            .is_err()
    );
    registry
        .register_authorized(policy(), "acme".into(), owner(1), 1, first)
        .unwrap();
    let retained = registry.clone();
    assert!(
        registry
            .register_authorized(policy(), "other".into(), owner(1), 1, second.clone())
            .is_err()
    );
    assert!(
        registry
            .register_authorized(policy(), "acme".into(), owner(2), 1, second.clone())
            .is_err()
    );
    assert_eq!(registry, retained);
    registry
        .register_authorized(policy(), "other".into(), owner(2), 1, second)
        .unwrap();
    assert_eq!(
        registry.records()[0].dataspace_id(),
        DataSpaceId::new(u64::MAX - 1)
    );
    let (_, third) = fixture(3);
    assert!(
        registry
            .register_authorized(policy(), "third".into(), owner(3), 1, third)
            .is_err()
    );
    registry.validate().unwrap();
}

#[test]
fn anchor_rechecks_owner_generation_and_child_without_partial_mutation() {
    let (mut fixture, registration) = fixture(u64::MAX);
    let mut registry = PrivateDataspaceRegistry::default();
    registry
        .register_authorized(policy(), "acme".into(), owner(1), 1, registration.clone())
        .unwrap();
    let anchor = next(&mut fixture, &registration);
    let retained = registry.clone();
    for (id, who, generation) in [
        (u64::MAX, owner(2), 1),
        (u64::MAX, owner(1), 2),
        (2, owner(1), 1),
    ] {
        assert!(
            registry
                .apply_authorized(DataSpaceId::new(id), &who, generation, &anchor)
                .is_err()
        );
        assert_eq!(registry, retained);
    }
    let (mut foreign, other) = self::fixture(2);
    let foreign_anchor = next(&mut foreign, &other);
    assert!(
        registry
            .apply_authorized(DataSpaceId::new(u64::MAX), &owner(1), 1, &foreign_anchor)
            .is_err()
    );
    assert_eq!(registry, retained);
}

#[test]
fn restored_registry_requires_exact_keys_unique_names_and_valid_native_state() {
    let (_, registration) = fixture(u64::MAX);
    let mut registry = PrivateDataspaceRegistry::default();
    registry
        .register_authorized(policy(), "acme".into(), owner(1), 1, registration)
        .unwrap();
    let bytes = norito::encode_canonical(&registry).unwrap();
    assert_eq!(
        norito::decode_canonical::<PrivateDataspaceRegistry>(&bytes).unwrap(),
        registry
    );
    let json = norito::json::to_json(&registry).unwrap();
    let restored: PrivateDataspaceRegistry = norito::json::from_str(&json).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored, registry);
    let mut invalid = registry.clone();
    invalid.records[0].dataspace_id = DataSpaceId::new(2);
    assert!(invalid.validate().is_err());
    invalid = registry.clone();
    invalid.records.push(invalid.records[0].clone());
    assert!(invalid.validate().is_err());
    invalid = registry;
    invalid.records[0].ownership_generation = 0;
    assert!(invalid.validate().is_err());
}
