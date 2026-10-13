// SoraFS discovery rejects a valid signature from a key outside its admission envelope.
#[test]
fn disk_fixtures_detect_advert_key_mismatch() {
    let fixtures = [("advert_v1.to", "envelope_v1.to")];
    for (advert_path, envelope_path) in fixtures {
        let fixture = fixture_from_disk(advert_path, envelope_path);
        let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
        let mut cache = ProviderAdvertCache::new(
            [
                CapabilityType::ToriiGateway,
                CapabilityType::ChunkRangeFetch,
            ],
            registry,
        );
        let now = fixture
            .advert
            .issued_at
            .saturating_add(30)
            .min(fixture.advert.expires_at.saturating_sub(1))
            .max(fixture.advert.issued_at);
        assert_eq!(
            fixture.advert.signature.public_key.as_slice(),
            fixture.envelope.proposal.advert_key.as_slice(),
            "the checked-in advert and governance envelope are the valid control"
        );
        assert!(matches!(
            cache
                .ingest(fixture.advert.clone(), now)
                .expect("the original governed disk fixture must be admitted")
                .outcome,
            AdvertIngest::Stored { .. }
        ));
        let current_fingerprint = *cache
            .record_by_provider(&fixture.advert.body.provider_id)
            .expect("original fixture cached")
            .fingerprint();
        let replacement_key = SigningKey::from_bytes(&[0xE7; 32]);
        let mut mismatched = fixture.advert.clone();
        resign_advert(&mut mismatched, &replacement_key);
        assert_ne!(
            mismatched.signature.public_key, fixture.advert.signature.public_key,
            "the adversary must actually replace the governed key"
        );
        assert_eq!(
            mismatched.body, fixture.envelope.advert_body,
            "the signed advert body must still match governance"
        );
        mismatched
            .verify_signature()
            .expect("the mismatched key signs the complete canonical envelope correctly");
        let err = cache
            .ingest(mismatched, now)
            .expect_err("correctly re-signed replacement must fail due to advert key mismatch");
        match err {
            AdvertError::AdmissionFailed { error, .. } => {
                assert!(
                    matches!(*error, ProviderAdmissionAdvertError::AdvertKeyMismatch),
                    "expected advert key mismatch, got {error:?}"
                );
            }
            other => panic!("expected admission failure, got {other:?}"),
        }
        let current = cache
            .record_by_provider(&fixture.advert.body.provider_id)
            .expect("unauthorized key replacement must preserve the admitted advert");
        assert_eq!(current.fingerprint(), &current_fingerprint);
        assert_eq!(current.advert(), &fixture.advert);
    }
}
