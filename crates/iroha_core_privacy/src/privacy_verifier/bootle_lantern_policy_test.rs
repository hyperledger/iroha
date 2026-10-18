#[test]
fn bootle_lantern_trusted_policy_is_mandatory_valid_active_and_exact() {
    let fixture = bootle_lantern_fixture();
    let mut missing = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
    missing.bootle_lantern_policy = None;
    assert!(matches!(
        verify_privacy_envelope_v1(&fixture.envelope, &missing),
        Err(PrivacyVerificationErrorV1::BootleLanternState(detail))
            if detail.code == PrivacyBootleLanternStateFailureCodeV1::MissingTrustedPolicy
    ));
    let mut corrupt = fixture.policy.clone();
    corrupt.record_digest.0[0] ^= 1;
    let mut corrupt_context = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
    corrupt_context.bootle_lantern_policy = Some(&corrupt);
    assert!(matches!(
        verify_privacy_envelope_v1(&fixture.envelope, &corrupt_context),
        Err(PrivacyVerificationErrorV1::BootleLanternState(detail))
            if detail.code == PrivacyBootleLanternStateFailureCodeV1::InvalidTrustedPolicy
    ));
    let mut revoked = fixture.policy.clone();
    revoked.epoch += 1;
    revoked.lifecycle = BootleLanternIssuerPolicyLifecycleV1::Revoked;
    redigest_bootle_lantern_policy(&mut revoked);
    revoked
        .validate_revocation_successor(&fixture.policy)
        .expect("canonical terminal successor");
    let mut revoked_context = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
    revoked_context.bootle_lantern_policy = Some(&revoked);
    assert!(matches!(
        verify_privacy_envelope_v1(&fixture.envelope, &revoked_context),
        Err(PrivacyVerificationErrorV1::BootleLanternState(detail))
            if detail.code == PrivacyBootleLanternStateFailureCodeV1::PolicyRevoked
    ));
    let mut rotated = fixture.policy.clone();
    rotated.epoch += 1;
    rotated.required_disclosure_bitmap |= 1;
    redigest_bootle_lantern_policy(&mut rotated);
    rotated
        .validate_rotation_successor(&fixture.policy)
        .expect("canonical active successor");
    let mut rotated_context = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
    rotated_context.bootle_lantern_policy = Some(&rotated);
    assert!(matches!(
        verify_privacy_envelope_v1(&fixture.envelope, &rotated_context),
        Err(PrivacyVerificationErrorV1::NativeBootleLantern(_))
    ));
}
