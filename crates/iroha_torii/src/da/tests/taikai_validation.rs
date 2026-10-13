//! Taikai envelope validation and bounded payload-processing tests.

use super::*;

#[test]
fn take_ssm_entry_returns_payload_and_strips_metadata() {
    let mut metadata = taikai_metadata();
    metadata.items.push(MetadataEntry::new(
        taikai::META_TAIKAI_SSM,
        vec![1, 2, 3],
        MetadataVisibility::Public,
    ));
    let payload = taikai_ingest::take_ssm_entry(&mut metadata)
        .expect("extract ssm")
        .expect("payload present");
    assert_eq!(payload, vec![1, 2, 3]);
    assert!(
        metadata
            .items
            .iter()
            .all(|entry| entry.key != taikai::META_TAIKAI_SSM)
    );
}
#[test]
fn take_ssm_entry_rejects_duplicate_payloads_without_mutating_metadata() {
    let mut metadata = taikai_metadata();
    metadata.items.extend([
        MetadataEntry::new(
            taikai::META_TAIKAI_SSM,
            vec![1, 2, 3],
            MetadataVisibility::Public,
        ),
        MetadataEntry::new(
            taikai::META_TAIKAI_SSM,
            vec![4, 5, 6],
            MetadataVisibility::Public,
        ),
    ]);
    let err = taikai_ingest::take_ssm_entry(&mut metadata)
        .expect_err("duplicate signing manifests must reject");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("metadata entry must appear at most once"));
    assert_eq!(
        metadata
            .items
            .iter()
            .filter(|entry| entry.key == taikai::META_TAIKAI_SSM)
            .count(),
        2,
        "rejected extraction must leave the signed request unchanged"
    );
}
#[test]
fn take_trm_entry_returns_payload_and_strips_metadata() {
    let mut metadata = taikai_metadata();
    metadata.items.push(MetadataEntry::new(
        taikai::META_TAIKAI_TRM,
        vec![9, 8, 7],
        MetadataVisibility::Public,
    ));
    let payload = taikai_ingest::take_trm_entry(&mut metadata)
        .expect("extract trm")
        .expect("payload present");
    assert_eq!(payload, vec![9, 8, 7]);
    assert!(
        metadata
            .items
            .iter()
            .all(|entry| entry.key != taikai::META_TAIKAI_TRM)
    );
}
#[test]
fn take_trm_entry_rejects_duplicate_payloads_without_mutating_metadata() {
    let mut metadata = taikai_metadata();
    metadata.items.extend([
        MetadataEntry::new(
            taikai::META_TAIKAI_TRM,
            vec![9, 8, 7],
            MetadataVisibility::Public,
        ),
        MetadataEntry::new(
            taikai::META_TAIKAI_TRM,
            vec![6, 5, 4],
            MetadataVisibility::Public,
        ),
    ]);
    let err = taikai_ingest::take_trm_entry(&mut metadata)
        .expect_err("duplicate routing manifests must reject");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("metadata entry must appear at most once"));
    assert_eq!(
        metadata
            .items
            .iter()
            .filter(|entry| entry.key == taikai::META_TAIKAI_TRM)
            .count(),
        2,
        "rejected extraction must leave the signed request unchanged"
    );
}
pub(super) fn taikai_ssm_validation_fixture()
-> (ManifestArtifacts, taikai_ingest::EnvelopeArtifacts) {
    let mut request = sample_request();
    request.metadata = taikai_metadata();
    let canonical = normalize_payload(&request).expect("normalize payload");
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let metadata =
        encrypt_governance_metadata(&request.metadata, None, None).expect("metadata encrypt");
    let rent_policy = DaRentPolicyV1::default();
    let manifest = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &metadata,
        &request.retention_policy,
        1,
        &rent_policy,
    )
    .expect("manifest");
    let envelope =
        taikai_ingest::build_envelope(&manifest, &chunk_store, canonical.as_slice(), None)
            .expect("envelope");
    (manifest, envelope)
}
fn taikai_alias_cache_policy() -> crate::sorafs::AliasCachePolicy {
    crate::sorafs::AliasCachePolicy::new(
        Duration::from_secs(600),
        Duration::from_secs(60),
        Duration::from_secs(1_200),
        Duration::from_secs(60),
        Duration::from_secs(120),
        Duration::from_secs(10_000),
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
}

#[test]
fn validate_taikai_ssm_rejects_malformed_norito() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let (_, telemetry) = telemetry_handle_for_tests();
    let err = taikai::validate_taikai_ssm(
        b"not-a-norito-signing-manifest",
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &taikai_alias_cache_policy(),
        Some(&alias_council_policy(&[[0x33; 32]], 1)),
        &telemetry,
    )
    .expect_err("malformed Norito SSM must fail admission");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("failed to decode signing manifest"),
        "unexpected malformed SSM error: {}",
        err.1
    );
}

#[test]
fn validate_taikai_ssm_accepts_matching_payload() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let ssm_bytes = build_ssm_bytes(
        manifest.manifest_hash,
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
    );
    let alias_policy = taikai_alias_cache_policy();
    let (_, telemetry) = telemetry_handle_for_tests();
    let outcome = taikai::validate_taikai_ssm(
        &ssm_bytes,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &alias_policy,
        Some(&alias_council_policy(&[[0x33; 32]], 1)),
        &telemetry,
    )
    .expect("ssm valid");
    assert_eq!(outcome.alias_label, "sora/docs");
}

#[test]
fn validate_taikai_publisher_owner_binds_outer_principal() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let ssm_bytes = build_ssm_bytes(
        manifest.manifest_hash,
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
    );
    let signing_manifest: TaikaiSegmentSigningManifestV1 =
        norito::decode_from_bytes(&ssm_bytes).expect("decode signing manifest");
    let telemetry = crate::routing::MaybeTelemetry::disabled();
    let outcome = taikai::validate_taikai_ssm(
        &ssm_bytes,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &taikai_alias_cache_policy(),
        Some(&alias_council_policy(&[[0x33; 32]], 1)),
        &telemetry,
    )
    .expect("ssm valid");
    assert_eq!(
        outcome.publisher_account,
        signing_manifest.body.publisher_account
    );
    taikai::validate_taikai_publisher_owner(&outcome, &signing_manifest.body.publisher_account)
        .expect("the authenticated publisher may submit its own segment");
    let relayer = if signing_manifest.body.publisher_account != *ALICE_ID {
        ALICE_ID.clone()
    } else {
        BOB_ID.clone()
    };
    let err = taikai::validate_taikai_publisher_owner(&outcome, &relayer)
        .expect_err("an unrelated DA owner must not submit another publisher's SSM");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("does not match the SSM publisher"));
}

#[test]
fn validate_taikai_ssm_rejects_unsupported_body_version() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let ssm_bytes = build_ssm_bytes_with_alias_council_and_body_mutation(
        manifest.manifest_hash,
        manifest.manifest_hash,
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
        Algorithm::Ed25519,
        &[[0x33; 32]],
        |body| body.version = TaikaiSegmentSigningBodyV1::VERSION + 1,
    );
    let (_, telemetry) = telemetry_handle_for_tests();
    let err = taikai::validate_taikai_ssm(
        &ssm_bytes,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &taikai_alias_cache_policy(),
        Some(&alias_council_policy(&[[0x33; 32]], 1)),
        &telemetry,
    )
    .expect_err("unknown SSM body version must fail admission");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("unsupported signing manifest version"));
}

#[test]
fn validate_taikai_ssm_rejects_zero_signed_timestamp() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let ssm_bytes = build_ssm_bytes_with_alias_council_and_body_mutation(
        manifest.manifest_hash,
        manifest.manifest_hash,
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
        Algorithm::Ed25519,
        &[[0x33; 32]],
        |body| body.signed_unix_ms = 0,
    );
    let (_, telemetry) = telemetry_handle_for_tests();
    let err = taikai::validate_taikai_ssm(
        &ssm_bytes,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &taikai_alias_cache_policy(),
        Some(&alias_council_policy(&[[0x33; 32]], 1)),
        &telemetry,
    )
    .expect_err("zero SSM production timestamp must fail admission");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1
            .contains("signed_unix_ms must be a non-zero production timestamp"),
        "unexpected zero timestamp error: {}",
        err.1
    );
}

#[test]
fn validate_taikai_ssm_rejects_publisher_account_key_mismatch() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let ssm_bytes = build_ssm_bytes_with_alias_council_and_body_mutation(
        manifest.manifest_hash,
        manifest.manifest_hash,
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
        Algorithm::Ed25519,
        &[[0x33; 32]],
        |body| {
            body.publisher_account = if AccountId::new(body.publisher_key.clone()) != *ALICE_ID {
                ALICE_ID.clone()
            } else {
                BOB_ID.clone()
            };
        },
    );
    let (_, telemetry) = telemetry_handle_for_tests();
    let err = taikai::validate_taikai_ssm(
        &ssm_bytes,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &taikai_alias_cache_policy(),
        Some(&alias_council_policy(&[[0x33; 32]], 1)),
        &telemetry,
    )
    .expect_err("a valid signature must not authenticate another publisher account");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("publisher account does not match"));
}
#[test]
fn validate_taikai_ssm_rejects_self_asserted_alias_council() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let attacker_ssm = build_ssm_bytes(
        manifest.manifest_hash,
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
    );
    let trusted_policy = alias_council_policy(&[[0x44; 32]], 1);
    let (_, telemetry) = telemetry_handle_for_tests();
    let err = taikai::validate_taikai_ssm(
        &attacker_ssm,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &taikai_alias_cache_policy(),
        Some(&trusted_policy),
        &telemetry,
    )
    .expect_err("self-asserted alias council must fail Taikai admission");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("not trusted"), "unexpected error: {}", err.1);
}
#[test]
fn validate_taikai_ssm_accepts_trusted_alias_council_threshold() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let council_seeds = [[0x33; 32], [0x44; 32], [0x55; 32]];
    let ssm = build_ssm_bytes_with_alias_council(
        manifest.manifest_hash,
        manifest.manifest_hash,
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
        Algorithm::Ed25519,
        &council_seeds[..2],
    );
    let trusted_policy = alias_council_policy(&council_seeds, 2);
    let (_, telemetry) = telemetry_handle_for_tests();
    let outcome = taikai::validate_taikai_ssm(
        &ssm,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &taikai_alias_cache_policy(),
        Some(&trusted_policy),
        &telemetry,
    )
    .expect("trusted 2-of-3 alias council must authorize Taikai admission");
    assert_eq!(outcome.alias_label, "sora/docs");
}
#[test]
fn validate_taikai_ssm_rejects_alias_manifest_binding_mismatch() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let council_seeds = [[0x33; 32]];
    let ssm = build_ssm_bytes_with_alias_council(
        manifest.manifest_hash,
        BlobDigest::from_hash(blake3_hash(b"different DA manifest")),
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
        Algorithm::Ed25519,
        &council_seeds,
    );
    let trusted_policy = alias_council_policy(&council_seeds, 1);
    let (_, telemetry) = telemetry_handle_for_tests();
    let err = taikai::validate_taikai_ssm(
        &ssm,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &taikai_alias_cache_policy(),
        Some(&trusted_policy),
        &telemetry,
    )
    .expect_err("alias proof for another manifest must fail Taikai admission");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1
            .contains("does not commit to the canonical DA manifest"),
        "unexpected error: {}",
        err.1
    );
}
#[test]
fn validate_taikai_ssm_fails_closed_without_alias_council_policy() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let ssm = build_ssm_bytes(
        manifest.manifest_hash,
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
    );
    let (_, telemetry) = telemetry_handle_for_tests();
    let err = taikai::validate_taikai_ssm(
        &ssm,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &taikai_alias_cache_policy(),
        None,
        &telemetry,
    )
    .expect_err("Taikai admission without a trust policy must fail closed");
    assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        err.1
            .contains("requires a configured SoraFS council trust policy"),
        "unexpected error: {}",
        err.1
    );
}
#[test]
fn validate_taikai_ssm_rejects_manifest_mismatch() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let bad_ssm = build_ssm_bytes(
        BlobDigest::from_hash(blake3_hash(b"other-manifest")),
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
    );
    let alias_policy = taikai_alias_cache_policy();
    let (_, telemetry) = telemetry_handle_for_tests();
    let err = taikai::validate_taikai_ssm(
        &bad_ssm,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &alias_policy,
        Some(&alias_council_policy(&[[0x33; 32]], 1)),
        &telemetry,
    )
    .expect_err("manifest mismatch must fail");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
#[test]
fn validate_taikai_ssm_rejects_tampered_signature() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let mut ssm_bytes = build_ssm_bytes(
        manifest.manifest_hash,
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
    );
    // Flip a byte in the signature payload to break verification.
    if let Some(last) = ssm_bytes.last_mut() {
        *last ^= 0xFF;
    }
    let alias_policy = taikai_alias_cache_policy();
    let (_, telemetry) = telemetry_handle_for_tests();
    let err = taikai::validate_taikai_ssm(
        &ssm_bytes,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &alias_policy,
        Some(&alias_council_policy(&[[0x33; 32]], 1)),
        &telemetry,
    )
    .expect_err("tampered signature must fail");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
#[test]
fn validate_taikai_ssm_rejects_malformed_ed25519_signature_r() {
    const NONCANONICAL_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let ssm_bytes = build_ssm_bytes(
        manifest.manifest_hash,
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
    );
    let signing_manifest: TaikaiSegmentSigningManifestV1 =
        norito::decode_from_bytes(&ssm_bytes).expect("decode signing manifest");
    let alias_policy = taikai_alias_cache_policy();
    let (_, telemetry) = telemetry_handle_for_tests();
    taikai::validate_taikai_ssm(
        &ssm_bytes,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &alias_policy,
        Some(&alias_council_policy(&[[0x33; 32]], 1)),
        &telemetry,
    )
    .expect("valid SSM should verify before mutation");
    let mut small_order_r = [0_u8; 32];
    small_order_r[0] = 1;
    for (label, replacement_r) in [
        ("small-order", small_order_r),
        ("noncanonical", NONCANONICAL_R),
    ] {
        let mut malformed = signing_manifest.clone();
        let mut signature_payload = malformed.signature.payload().to_vec();
        signature_payload[..replacement_r.len()].copy_from_slice(&replacement_r);
        malformed.signature =
            SignatureOf::from_signature(Signature::from_bytes(&signature_payload));
        let malformed_ssm = to_bytes(&malformed).expect("encode malformed signing manifest");
        let err = taikai::validate_taikai_ssm(
            &malformed_ssm,
            (&manifest.manifest_hash, &taikai.car_digest),
            &taikai.envelope_bytes,
            taikai.telemetry.segment_sequence,
            &alias_policy,
            Some(&alias_council_policy(&[[0x33; 32]], 1)),
            &telemetry,
        )
        .expect_err("malformed Taikai SSM signature R must fail");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let message = &err.1;
        assert!(
            message.contains("publisher signature material malformed"),
            "{label} malformed SSM signature R should fail admission: {message}"
        );
    }
}
#[test]
fn validate_taikai_ssm_rejects_malformed_mldsa_signature_lengths() {
    let (manifest, taikai) = taikai_ssm_validation_fixture();
    let now_secs = crate::sorafs::unix_now_secs();
    let ssm_bytes = build_ssm_bytes_with_publisher_algorithm(
        manifest.manifest_hash,
        taikai.car_digest,
        BlobDigest::from_hash(blake3_hash(&taikai.envelope_bytes)),
        taikai.telemetry.segment_sequence,
        now_secs,
        now_secs + 600,
        Algorithm::MlDsa,
    );
    let signing_manifest: TaikaiSegmentSigningManifestV1 =
        norito::decode_from_bytes(&ssm_bytes).expect("decode ML-DSA signing manifest");
    let alias_policy = taikai_alias_cache_policy();
    let (_, telemetry) = telemetry_handle_for_tests();
    taikai::validate_taikai_ssm(
        &ssm_bytes,
        (&manifest.manifest_hash, &taikai.car_digest),
        &taikai.envelope_bytes,
        taikai.telemetry.segment_sequence,
        &alias_policy,
        Some(&alias_council_policy(&[[0x33; 32]], 1)),
        &telemetry,
    )
    .expect("valid ML-DSA SSM should verify before mutation");
    let mut extended = signing_manifest.signature.payload().to_vec();
    extended.push(0);
    for (label, signature_payload) in [
        (
            "truncated",
            signing_manifest.signature.payload()[..signing_manifest.signature.payload().len() - 1]
                .to_vec(),
        ),
        ("extended", extended),
    ] {
        let mut malformed = signing_manifest.clone();
        malformed.signature =
            SignatureOf::from_signature(Signature::from_bytes(&signature_payload));
        let malformed_ssm = to_bytes(&malformed).expect("encode malformed ML-DSA signing manifest");
        let err = taikai::validate_taikai_ssm(
            &malformed_ssm,
            (&manifest.manifest_hash, &taikai.car_digest),
            &taikai.envelope_bytes,
            taikai.telemetry.segment_sequence,
            &alias_policy,
            Some(&alias_council_policy(&[[0x33; 32]], 1)),
            &telemetry,
        )
        .expect_err("malformed Taikai SSM ML-DSA signature length must fail");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let message = &err.1;
        assert!(
            message.contains("publisher signature material malformed"),
            "{label} malformed SSM ML-DSA signature length should fail admission: {message}"
        );
    }
}
#[test]
fn validate_taikai_trm_accepts_matching_manifest() {
    let (_, taikai) = taikai_ssm_validation_fixture();
    let manifest = sample_trm_manifest_for_envelope(&taikai);
    let trm_bytes = to_bytes(&manifest).expect("encode trm");
    let routing_manifest =
        taikai::validate_taikai_trm(&trm_bytes, &taikai, &manifest.alias_binding)
            .expect("trm valid");
    assert_eq!(
        routing_manifest.alias_binding.name.as_str(),
        "docs",
        "alias binding should match the stream metadata"
    );
    assert_eq!(
        routing_manifest.segment_window.start_sequence, 0,
        "validated manifest should expose the expected window"
    );
}
#[test]
fn validate_taikai_trm_rejects_mismatched_event() {
    let (_, taikai) = taikai_ssm_validation_fixture();
    let mut trm = sample_trm_manifest_for_envelope(&taikai);
    trm.event_id = TaikaiEventId::new(Name::from_str("other-event").unwrap());
    let trm_bytes = to_bytes(&trm).expect("encode trm");
    let err = taikai::validate_taikai_trm(&trm_bytes, &taikai, &trm.alias_binding)
        .expect_err("validation must fail");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
#[test]
fn validate_taikai_trm_rejects_invalid_version() {
    let taikai = taikai_envelope_fixture();
    let mut trm = sample_trm_manifest_for_envelope(&taikai);
    trm.version = TaikaiRoutingManifestV1::VERSION + 1;
    let trm_bytes = to_bytes(&trm).expect("encode trm");
    let err = taikai::validate_taikai_trm(&trm_bytes, &taikai, &trm.alias_binding)
        .expect_err("validation must fail");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("unsupported manifest version"),
        "unexpected error message: {}",
        err.1
    );
}
#[test]
fn validate_taikai_trm_rejects_invalid_window() {
    let taikai = taikai_envelope_fixture();
    let mut trm = sample_trm_manifest_for_envelope(&taikai);
    trm.segment_window = TaikaiSegmentWindow::new(50, 40);
    let trm_bytes = to_bytes(&trm).expect("encode trm");
    let err = taikai::validate_taikai_trm(&trm_bytes, &taikai, &trm.alias_binding)
        .expect_err("validation must fail");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("invalid routing manifest"),
        "unexpected error message: {}",
        err.1
    );
}

#[test]
fn validate_taikai_trm_rejects_terminal_window_before_lineage_mutation() {
    let taikai = taikai_envelope_fixture();
    let mut trm = sample_trm_manifest_for_envelope(&taikai);
    trm.segment_window = TaikaiSegmentWindow::new(40, u64::MAX);
    let trm_bytes = to_bytes(&trm).expect("encode terminal-window trm");

    let err = taikai::validate_taikai_trm(&trm_bytes, &taikai, &trm.alias_binding)
        .expect_err("terminal TRM window must fail before a lineage guard is created");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1
            .contains("segment window end must be less than u64::MAX"),
        "unexpected terminal-window error: {}",
        err.1
    );
}

#[test]
fn validate_taikai_trm_rejects_oversized_window_before_lineage_mutation() {
    let taikai = taikai_envelope_fixture();
    let mut trm = sample_trm_manifest_for_envelope(&taikai);
    trm.segment_window = TaikaiSegmentWindow::new(40, 160);
    let trm_bytes = to_bytes(&trm).expect("encode oversized-window trm");

    let err = taikai::validate_taikai_trm(&trm_bytes, &taikai, &trm.alias_binding)
        .expect_err("121-segment TRM window must fail before a lineage guard is created");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1
            .contains("segment window covers 121 sequences; maximum is 120"),
        "unexpected oversized-window error: {}",
        err.1
    );
}

#[test]
fn validate_taikai_trm_rejects_rendition_window_that_misses_segment() {
    let taikai = taikai_envelope_fixture();
    let mut trm = sample_trm_manifest_for_envelope(&taikai);
    trm.renditions[0].ssm_range = TaikaiSegmentWindow::new(50, 64);
    let trm_bytes = to_bytes(&trm).expect("encode trm");
    let err = taikai::validate_taikai_trm(&trm_bytes, &taikai, &trm.alias_binding)
        .expect_err("rendition signing window must cover the admitted segment");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("rendition `1080p` signing window"),
        "unexpected error message: {}",
        err.1
    );
}
#[test]
fn validate_taikai_trm_rejects_head_manifest_mismatch() {
    let taikai = taikai_envelope_fixture();
    let mut trm = sample_trm_manifest_for_envelope(&taikai);
    trm.renditions[0].latest_manifest_hash = BlobDigest::from_hash(blake3_hash(b"other-manifest"));
    let trm_bytes = to_bytes(&trm).expect("encode trm");
    let err = taikai::validate_taikai_trm(&trm_bytes, &taikai, &trm.alias_binding)
        .expect_err("TRM head manifest must bind the admitted segment");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("latest_manifest_hash"));
}
#[test]
fn validate_taikai_trm_rejects_head_car_mismatch() {
    let taikai = taikai_envelope_fixture();
    let mut trm = sample_trm_manifest_for_envelope(&taikai);
    trm.renditions[0].latest_car.car_digest = BlobDigest::from_hash(blake3_hash(b"other-car"));
    let trm_bytes = to_bytes(&trm).expect("encode trm");
    let err = taikai::validate_taikai_trm(&trm_bytes, &taikai, &trm.alias_binding)
        .expect_err("TRM head CAR must bind the admitted segment");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("latest_car"));
}
#[test]
fn validate_taikai_trm_rejects_ssm_alias_mismatch() {
    let taikai = taikai_envelope_fixture();
    let trm = sample_trm_manifest_for_envelope(&taikai);
    let trm_bytes = to_bytes(&trm).expect("encode trm");
    let mut ssm_alias = trm.alias_binding.clone();
    ssm_alias.name = "other-alias".to_owned();
    let err = taikai::validate_taikai_trm(&trm_bytes, &taikai, &ssm_alias)
        .expect_err("TRM alias must bind the authenticated SSM alias");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("authenticated SSM alias binding"));
}
#[test]
fn validate_taikai_trm_rejects_ssm_alias_proof_mismatch() {
    let taikai = taikai_envelope_fixture();
    let trm = sample_trm_manifest_for_envelope(&taikai);
    let trm_bytes = to_bytes(&trm).expect("encode trm");
    let mut ssm_alias = trm.alias_binding.clone();
    ssm_alias.proof.push(0xff);
    let err = taikai::validate_taikai_trm(&trm_bytes, &taikai, &ssm_alias)
        .expect_err("TRM alias proof must be the proof authenticated by the SSM");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("authenticated SSM alias binding"));
}
#[test]
fn normalize_payload_handles_gzip() {
    let mut request = sample_request();
    let canonical = request.payload.clone();
    let mut encoder = GzEncoder::new(Vec::new(), FlateCompression::default());
    encoder.write_all(&canonical).expect("write gzip payload");
    let compressed = encoder.finish().expect("finish gzip payload");
    request.payload = compressed;
    request.compression = Compression::Gzip;
    request.total_size = canonical.len() as u64;
    let normalized = normalize_payload(&request).expect("normalize gzip payload");
    assert_eq!(normalized.as_slice(), canonical.as_slice());
}
#[test]
fn normalize_payload_rejects_size_mismatch() {
    let mut request = sample_request();
    let canonical = request.payload.clone();
    let mut encoder = GzEncoder::new(Vec::new(), FlateCompression::default());
    encoder.write_all(&canonical).expect("write gzip payload");
    let compressed = encoder.finish().expect("finish gzip payload");
    request.payload = compressed;
    request.compression = Compression::Gzip;
    request.total_size = (canonical.len() as u64) + 1;
    let err = match normalize_payload(&request) {
        Ok(_) => panic!("expected normalization to reject mismatched size"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
struct CountingReader {
    remaining: usize,
    emitted: usize,
}
impl CountingReader {
    fn new(remaining: usize) -> Self {
        Self {
            remaining,
            emitted: 0,
        }
    }
}
impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let n = self.remaining.min(buf.len());
        buf[..n].fill(0xA5);
        self.remaining -= n;
        self.emitted += n;
        Ok(n)
    }
}
#[test]
fn decompress_reader_stops_after_advertised_len_plus_one() {
    let mut reader = CountingReader::new(64);
    let err = decompress_reader(&mut reader, 8, "test")
        .expect_err("overlong decompressed stream should reject");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        reader.emitted, 9,
        "decompressor should read only one byte beyond advertised length"
    );
    assert!(
        err.1
            .contains("test payload decompressed to 9 bytes but total_size advertises 8 bytes"),
        "unexpected error message: {}",
        err.1
    );
}
#[test]
fn decompress_reader_rejects_unbounded_expected_len_without_reading() {
    let mut reader = CountingReader::new(1);
    let err = decompress_reader(&mut reader, usize::MAX, "test")
        .expect_err("unbounded expected length should reject");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert_eq!(reader.emitted, 0);
    assert!(
        err.1.contains("supported decompression boundary"),
        "unexpected error message: {}",
        err.1
    );
}
#[test]
fn build_receipt_includes_pdp_commitment() {
    let request = sample_request();
    let signer = checked_random_keypair();
    let pdp_commitment = sample_pdp_commitment_for_tests();
    let encoded = encode_pdp_commitment_bytes(&pdp_commitment).expect("encode commitment");
    let rent_quote = DaRentQuote {
        base_rent: XorQuantity::try_from_micro(111)
            .expect("legacy micro-XOR value is representable"),
        protocol_reserve: XorQuantity::try_from_micro(222)
            .expect("legacy micro-XOR value is representable"),
        provider_reward: XorQuantity::try_from_micro(333)
            .expect("legacy micro-XOR value is representable"),
        pdp_bonus: XorQuantity::try_from_micro(444)
            .expect("legacy micro-XOR value is representable"),
        potr_bonus: XorQuantity::try_from_micro(555)
            .expect("legacy micro-XOR value is representable"),
        egress_credit_per_gib: XorQuantity::try_from_micro(666)
            .expect("legacy micro-XOR value is representable"),
    };
    let receipt = build_receipt(
        &signer,
        &request,
        123,
        BlobDigest::from_hash(blake3_hash(b"blob-hash")),
        BlobDigest::from_hash(blake3_hash(b"chunk-root")),
        BlobDigest::from_hash(blake3_hash(b"manifest-hash")),
        StorageTicketId::new([0x44; 32]),
        encoded.clone(),
        rent_quote.clone(),
        DaStripeLayout::default(),
    )
    .expect("build receipt");
    assert_eq!(receipt.pdp_commitment, Some(encoded));
    assert_eq!(receipt.rent_quote, rent_quote);
}
#[test]
fn build_receipt_signs_with_operator_key() {
    let request = sample_request();
    let signer = checked_random_keypair();
    let receipt = build_receipt(
        &signer,
        &request,
        999,
        BlobDigest::from_hash(blake3_hash(b"blob-hash")),
        BlobDigest::from_hash(blake3_hash(b"chunk-root")),
        BlobDigest::from_hash(blake3_hash(b"manifest-hash")),
        StorageTicketId::new([0xAA; 32]),
        Vec::new(),
        DaRentQuote::default(),
        DaStripeLayout::default(),
    )
    .expect("build receipt");
    let unsigned_bytes =
        persistence::unsigned_receipt_bytes(&receipt, request.sequence).expect("unsigned receipt");
    receipt
        .operator_signature
        .verify(signer.public_key(), &unsigned_bytes)
        .expect("signature verifies");
    let wrong_sequence_bytes = persistence::unsigned_receipt_bytes(&receipt, request.sequence + 1)
        .expect("wrong-sequence unsigned receipt");
    assert!(
        receipt
            .operator_signature
            .verify(signer.public_key(), &wrong_sequence_bytes)
            .is_err(),
        "operator signature must bind the request sequence"
    );
}
#[test]
fn build_receipt_computes_chunk_root_from_payload() {
    let request = sample_request();
    let canonical = normalize_payload(&request).expect("normalize payload");
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let metadata =
        encrypt_governance_metadata(&request.metadata, None, None).expect("metadata encryption");
    let rent_policy = DaRentPolicyV1::default();
    let manifest = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &metadata,
        &request.retention_policy,
        1_701_000_000,
        &rent_policy,
    )
    .expect("resolve manifest");
    let pdp_commitment = compute_pdp_commitment(
        &manifest.manifest_hash,
        &manifest.manifest,
        &chunk_store,
        canonical.as_slice(),
        1_701_000_000,
    )
    .expect("pdp commitment");
    let pdp_tree =
        PdpMerkleTreeV1::from_bytes(canonical.as_slice()).expect("canonical PDP fixture tree");
    assert_eq!(pdp_commitment.payload_len, pdp_tree.payload_len());
    assert_eq!(pdp_commitment.hot_leaf_count, pdp_tree.hot_leaf_count());
    assert_eq!(pdp_commitment.segment_count, pdp_tree.segment_count());
    assert_eq!(pdp_commitment.commitment_root_hot, pdp_tree.hot_root());
    assert_eq!(
        pdp_commitment.commitment_root_segment,
        pdp_tree.segment_root()
    );
    let encoded_commitment =
        encode_pdp_commitment_bytes(&pdp_commitment).expect("encode commitment");
    let stripe_layout = stripe_layout_from_manifest(&manifest.manifest);
    let signer = checked_random_keypair();
    let receipt = build_receipt(
        &signer,
        &request,
        1_701_000_000,
        manifest.blob_hash,
        manifest.chunk_root,
        manifest.manifest_hash,
        manifest.storage_ticket,
        encoded_commitment,
        manifest.manifest.rent_quote,
        stripe_layout,
    )
    .expect("build receipt");
    assert_eq!(receipt.chunk_root, manifest.chunk_root);
    assert_eq!(
        manifest.chunk_root,
        BlobDigest::new(*chunk_store.por_tree().root())
    );
}
#[test]
fn build_receipt_prefers_chunk_root_from_manifest() {
    let mut request = sample_request();
    // Seed Taikai metadata so manifest validation passes gateway checks.
    request.metadata = taikai_metadata();
    let canonical = normalize_payload(&request).expect("normalize payload");
    let canonical_bytes = canonical.as_slice().to_vec();
    drop(canonical);
    let payload_hash = BlobDigest::from_hash(blake3_hash(&canonical_bytes));
    let chunk_store = build_chunk_store(&request, canonical_bytes.as_slice());
    taikai::apply_taikai_ingest_tags(
        &mut request.metadata,
        None,
        &request.retention_policy,
        request.total_size,
    );
    let manifest_chunk_root = BlobDigest::new(*chunk_store.por_tree().root());
    let chunk_commitments =
        build_chunk_commitments(&request, &chunk_store, canonical_bytes.as_slice())
            .expect("expected chunk commitments");
    let ipa_commitment =
        ipa_commitment_from_chunks(&chunk_commitments).expect("ipa commitment from chunks");
    let (total_stripes_full, shards_per_stripe) =
        manifest_stripe_layout_fields(chunk_store.chunks().len(), &request.erasure_profile)
            .expect("manifest stripe layout");
    let rent_policy = DaRentPolicyV1::default();
    let (rent_gib, rent_months) =
        rent_usage_from_request(request.total_size, &request.retention_policy)
            .expect("rent usage should fit test inputs");
    let rent_quote = rent_policy
        .quote(rent_gib, rent_months)
        .expect("compute rent quote for manifest");
    let manifest = DaManifestV1 {
        version: DaManifestV1::VERSION,
        client_blob_id: request.client_blob_id.clone(),
        lane_id: request.lane_id,
        epoch: request.epoch,
        blob_class: request.blob_class,
        codec: request.codec.clone(),
        blob_hash: payload_hash,
        chunk_root: manifest_chunk_root.clone(),
        storage_ticket: StorageTicketId::new([0x55; 32]),
        total_size: request.total_size,
        chunk_size: request.chunk_size,
        total_stripes: total_stripes_full,
        shards_per_stripe,
        erasure_profile: request.erasure_profile,
        retention_policy: request.retention_policy.clone(),
        rent_quote,
        chunks: chunk_commitments,
        ipa_commitment,
        metadata: request.metadata.clone(),
        issued_at_unix: 42,
    };
    request.norito_manifest = Some(to_bytes(&manifest).expect("encode manifest"));
    let canonical = normalize_payload(&request).expect("normalize payload with manifest");
    let metadata =
        encrypt_governance_metadata(&request.metadata, None, None).expect("metadata encryption");
    let rent_policy = DaRentPolicyV1::default();
    let manifest = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &metadata,
        &request.retention_policy,
        1_701_000_123,
        &rent_policy,
    )
    .expect("resolve provided manifest");
    let pdp_commitment = compute_pdp_commitment(
        &manifest.manifest_hash,
        &manifest.manifest,
        &chunk_store,
        canonical.as_slice(),
        1_701_000_123,
    )
    .expect("pdp commitment");
    let encoded_commitment =
        encode_pdp_commitment_bytes(&pdp_commitment).expect("encode commitment");
    let stripe_layout = stripe_layout_from_manifest(&manifest.manifest);
    let signer = checked_random_keypair();
    let receipt = build_receipt(
        &signer,
        &request,
        1_701_000_123,
        manifest.blob_hash,
        manifest.chunk_root,
        manifest.manifest_hash,
        manifest.storage_ticket,
        encoded_commitment,
        manifest.manifest.rent_quote,
        stripe_layout,
    )
    .expect("build receipt");
    assert_eq!(receipt.chunk_root, manifest_chunk_root);
}
#[test]
fn build_chunk_commitments_rejects_oversized_chunk_length() {
    let mut request = sample_request();
    request.chunk_size = MIN_CHUNK_SIZE_BYTES;
    let oversized_chunk_size = MIN_CHUNK_SIZE_BYTES * 2;
    request.payload = vec![
        0xA5;
        usize::try_from(oversized_chunk_size)
            .expect("test chunk size fits the host address space")
    ];
    request.total_size = request.payload.len() as u64;
    let canonical = normalize_payload(&request).expect("normalize payload");
    let oversized_profile = chunk_profile_for_request(oversized_chunk_size);
    let mut chunk_store = ChunkStore::with_profile(oversized_profile);
    chunk_store
        .ingest_bytes(canonical.as_slice())
        .expect("ingest canonical payload");
    let err = build_chunk_commitments(&request, &chunk_store, canonical.as_slice())
        .expect_err("oversized chunk length should be rejected");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("exceeds configured chunk_size"),
        "unexpected error message: {}",
        err.1
    );
}
#[test]
fn manifest_stripe_layout_fields_rejects_zero_data_shards() {
    let mut profile = sample_request().erasure_profile;
    profile.data_shards = 0;
    let err = manifest_stripe_layout_fields(1, &profile)
        .expect_err("zero data shards should be rejected before stripe math");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("at least one data shard"),
        "unexpected error message: {}",
        err.1
    );
}
#[test]
fn manifest_stripe_layout_fields_rejects_total_stripe_overflow() {
    let mut profile = sample_request().erasure_profile;
    profile.data_shards = 1;
    profile.parity_shards = 0;
    profile.row_parity_stripes = 1;
    let err = manifest_stripe_layout_fields(u32::MAX as usize, &profile)
        .expect_err("row parity must not overflow total stripe count");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1
            .contains("total stripes exceeds supported manifest stripe space"),
        "unexpected error message: {}",
        err.1
    );
}
#[test]
fn ipa_params_len_for_commitment_count_rounds_up_without_overflow() {
    assert_eq!(ipa_params_len_for_commitment_count(0).unwrap(), 1);
    assert_eq!(ipa_params_len_for_commitment_count(1).unwrap(), 1);
    assert_eq!(ipa_params_len_for_commitment_count(8).unwrap(), 8);
    assert_eq!(ipa_params_len_for_commitment_count(9).unwrap(), 16);
}
#[test]
fn ipa_params_len_for_commitment_count_rejects_power_of_two_overflow() {
    let overflow_count = (usize::MAX / 2).saturating_add(2);
    let err = ipa_params_len_for_commitment_count(overflow_count)
        .expect_err("overflowing IPA parameter length must reject");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("IPA commitment parameter size"),
        "unexpected error message: {}",
        err.1
    );
}
#[test]
fn build_chunk_commitments_rejects_row_parity_base_offset_overflow() {
    let mut request = sample_request();
    request.chunk_size = MIN_CHUNK_SIZE_BYTES;
    request.payload = vec![0xA5, 0x5A];
    request.total_size = u64::MAX - 1;
    request.erasure_profile = ErasureProfile {
        data_shards: 1,
        parity_shards: 1,
        row_parity_stripes: 1,
        chunk_alignment: 2,
        fec_scheme: FecScheme::Rs12_10,
    };
    let chunk_store = build_chunk_store(&request, request.payload.as_slice());
    let err = build_chunk_commitments(&request, &chunk_store, request.payload.as_slice())
        .expect_err("row parity base offset overflow should be rejected");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1
            .contains("stripe parity base offset exceeded supported size"),
        "unexpected error message: {}",
        err.1
    );
}
#[test]
fn build_chunk_commitments_rejects_row_parity_chunk_offset_overflow() {
    let mut request = sample_request();
    request.chunk_size = MIN_CHUNK_SIZE_BYTES;
    request.payload = vec![0xA5, 0x5A];
    request.total_size = u64::MAX - 1;
    request.erasure_profile = ErasureProfile {
        data_shards: 2,
        parity_shards: 0,
        row_parity_stripes: 1,
        chunk_alignment: 2,
        fec_scheme: FecScheme::Rs12_10,
    };
    let chunk_store = build_chunk_store(&request, request.payload.as_slice());
    let err = build_chunk_commitments(&request, &chunk_store, request.payload.as_slice())
        .expect_err("row parity chunk offset overflow should be rejected");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1
            .contains("stripe parity chunk offset exceeded supported size"),
        "unexpected error message: {}",
        err.1
    );
}
