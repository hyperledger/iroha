//! Template DATA roundtrips preserve exact selected controls and concrete asset bindings.
use super::*;
use crate::kagemusha::kagemusha_wallet_v1::{
    enrollment_policy::enrollment_policy_tests::policy_fixture,
    identity::identity_tests::test_asset,
};

#[test]
fn template_binds_each_exact_asset_without_changing_selected_policy() {
    for apple in [false, true] {
        let (app, original) = policy_fixture(apple);
        let template = original.template();
        template.validate_for_app(&app).unwrap();
        let a = test_asset();
        let mut b = a.clone();
        b.asset_incarnation = *iroha_crypto::Hash::new(b"another registered incarnation").as_ref();
        b.scale += 1;
        let first = template.for_asset(&a).unwrap();
        let second = template.for_asset(&b).unwrap();
        assert_eq!(first.template(), template);
        assert_eq!(second.template(), template);
        assert_eq!(first.asset_digest, a.asset_digest());
        assert_eq!(second.asset_digest, b.asset_digest());
        assert_ne!(
            first.policy_digest().unwrap(),
            second.policy_digest().unwrap()
        );
        assert_eq!(first.regulatory_policy, original.regulatory_policy);
        assert_eq!(
            first.attestation_lease_lifetime_ms,
            original.attestation_lease_lifetime_ms
        );
        first.validate_for_app(&app).unwrap();
        second.validate_for_app(&app).unwrap();
    }
}

#[test]
fn template_original_is_bounded_canonical_and_distinct_from_concrete_policy() {
    let (_, policy) = policy_fixture(false);
    let template = policy.template();
    let raw = template.encode_canonical().unwrap();
    assert!(raw.len() <= KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletEnrollmentPolicyTemplateV1::decode_canonical(&raw, &policy.scheme_id)
            .unwrap(),
        template
    );
    assert!(KagemushaWalletEnrollmentPolicyTemplateV1::decode_canonical(&raw, &[7; 32]).is_err());
    assert!(KagemushaWalletEnrollmentPolicyV1::decode_canonical(&raw, &policy.scheme_id).is_err());
    assert!(
        KagemushaWalletEnrollmentPolicyTemplateV1::decode_canonical(
            &policy.encode_canonical().unwrap(),
            &policy.scheme_id
        )
        .is_err()
    );
    let mut trailing = raw;
    trailing.push(0);
    assert!(
        KagemushaWalletEnrollmentPolicyTemplateV1::decode_canonical(&trailing, &policy.scheme_id)
            .is_err()
    );
    assert!(
        KagemushaWalletEnrollmentPolicyTemplateV1::decode_canonical(
            &vec![0; KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1 + 1],
            &policy.scheme_id
        )
        .is_err()
    );
}

#[test]
fn template_does_not_relax_platform_asset_clock_or_regulatory_validation() {
    let (app, policy) = policy_fixture(false);
    let template = policy.template();
    let mut invalid = template.clone();
    invalid.version = 2;
    assert!(invalid.for_asset(&test_asset()).is_err());
    invalid = template.clone();
    invalid.challenge_lifetime_ms = 0;
    assert!(invalid.validate().is_err());
    invalid = template.clone();
    invalid.app_policy = [9; 32];
    assert!(invalid.validate_for_app(&app).is_err());
    invalid = template.clone();
    invalid.attestation_lease_lifetime_ms = 1;
    assert!(invalid.validate().is_err());
    let mut bad_asset = test_asset();
    bad_asset.asset_incarnation = [0; 32];
    assert!(template.for_asset(&bad_asset).is_err());
    bad_asset = test_asset();
    bad_asset.scale = u32::MAX;
    assert!(template.for_asset(&bad_asset).is_err());
    assert!(template.validate_for_app(&policy_fixture(true).0).is_err());
}
