// Cross-suite replay coverage for anonymous PGC proof envelopes.
#[test]
fn pgc_rejects_cross_suite_proof_replay() {
    let fixture = PgcFixture::new();
    let (verange_envelope, _, _) = valid_envelope();
    let mut replayed = fixture.envelope.clone();
    replayed.proof = verange_envelope.proof;
    assert!(matches!(
        verify_privacy_envelope_v1(&replayed, &fixture.verification_context()),
        Err(PrivacyVerificationErrorV1::Envelope(_))
    ));
}
