// Private HTTP service test body included from the parent module.
#[test]
fn backend_errors_are_closed_standard_errors_without_diagnostic_sources() {
    for (error, expected) in [
        (
            MusubiPublicationServiceBackendErrorV1::Retryable,
            "Musubi publication backend is temporarily unavailable",
        ),
        (
            MusubiPublicationServiceBackendErrorV1::Permanent,
            "Musubi publication backend requires configuration or state changes",
        ),
    ] {
        let standard: &(dyn std::error::Error + Send + Sync) = &error;
        assert_eq!(standard.to_string(), expected);
        assert!(standard.source().is_none());
    }
}

#[test]
fn authorization_is_domain_bound_and_verifiable() {
    let (client, _) = client();
    let runtime = AuthenticatedMusubiPublicationRuntimeClientV1::from_iroha_client(
        &client,
        Duration::from_secs(5),
    )
    .expect("runtime client");
    let operation_id = [0x44; 32];
    let digest = [0x55; 32];
    let authorization = runtime
        .authorization_at(
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            operation_id,
            digest,
            1_000,
        )
        .expect("authorization");
    authorization
        .verify(
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            operation_id,
            digest,
            1_001,
        )
        .expect("verify exact authorization");
    assert!(
        authorization
            .verify(
                MusubiPublicationRuntimeOperationV1::ProviderReadback,
                operation_id,
                digest,
                1_001,
            )
            .is_err()
    );
    let mut substituted = authorization.clone();
    substituted.payload.domain = [0x99; 32];
    assert!(substituted.payload.validate().is_err());
    assert!(
        substituted.approvals[0]
            .signature
            .verify_hash(
                &substituted.approvals[0].public_key,
                HashOf::new(&substituted.payload),
            )
            .is_err()
    );
}
#[test]
fn authorization_verifier_enforces_fixed_clock_skew_bound() {
    let (client, _) = client();
    let runtime = AuthenticatedMusubiPublicationRuntimeClientV1::from_iroha_client(
        &client,
        Duration::from_secs(5),
    )
    .expect("runtime client");
    let operation = MusubiPublicationRuntimeOperationV1::StorageCoordination;
    let operation_id = [0x46; 32];
    let digest = [0x57; 32];
    let current_time_ms = 1_000;
    let issued_at_ms = current_time_ms + MUSUBI_PUBLICATION_SERVICE_MAX_CLOCK_SKEW_MS_V1;
    let authorization = runtime
        .authorization_at(operation, operation_id, digest, issued_at_ms)
        .expect("future-skew authorization");
    authorization
        .verify_with_clock_skew(
            operation,
            operation_id,
            digest,
            current_time_ms,
            MUSUBI_PUBLICATION_SERVICE_MAX_CLOCK_SKEW_MS_V1,
        )
        .expect("the exact protocol skew boundary is accepted");
    for (verification_time_ms, skew_ms) in [
        (
            current_time_ms,
            MUSUBI_PUBLICATION_SERVICE_MAX_CLOCK_SKEW_MS_V1 + 1,
        ),
        (0, 0),
    ] {
        let error = authorization
            .verify_with_clock_skew(
                operation,
                operation_id,
                digest,
                verification_time_ms,
                skew_ms,
            )
            .expect_err("an invalid verifier clock policy must fail closed");
        assert_eq!(error.code(), "MUSUBI_RUNTIME_CLOCK_INVALID");
        assert_eq!(
            error.class(),
            MusubiPublicationRuntimeTransportFailureClassV1::Permanent
        );
    }
}
#[test]
fn publisher_authorization_resamples_clock_after_signing() {
    let operation = MusubiPublicationRuntimeOperationV1::StorageCoordination;
    let operation_id = [0x48; 32];
    let digest = [0x59; 32];
    let (slow_client, _) = client();
    let slow_runtime = AuthenticatedMusubiPublicationRuntimeClientV1::from_iroha_client(
        &slow_client,
        Duration::from_secs(5),
    )
    .expect("runtime client");
    let mut slow_samples = [1_000, 31_001].into_iter();
    let error = slow_runtime
        .authorization_with_clock(operation, operation_id, digest, || {
            Ok(slow_samples.next().expect("two clock samples"))
        })
        .expect_err("authorization expired during signing");
    assert_eq!(
        error.code(),
        "MUSUBI_RUNTIME_AUTHORIZATION_SIGNER_UNAVAILABLE"
    );
    assert_eq!(
        error.class(),
        MusubiPublicationRuntimeTransportFailureClassV1::Retryable
    );
    let (regressing_client, _) = client();
    let regressing_runtime = AuthenticatedMusubiPublicationRuntimeClientV1::from_iroha_client(
        &regressing_client,
        Duration::from_secs(5),
    )
    .expect("runtime client");
    let mut regressing_samples = [2_000, 1_999].into_iter();
    let error = regressing_runtime
        .authorization_with_clock(operation, operation_id, digest, || {
            Ok(regressing_samples.next().expect("two clock samples"))
        })
        .expect_err("authorization clock regression");
    assert_eq!(
        error.code(),
        "MUSUBI_RUNTIME_AUTHORIZATION_CLOCK_UNAVAILABLE"
    );
    assert_eq!(
        error.class(),
        MusubiPublicationRuntimeTransportFailureClassV1::Retryable
    );
}
#[test]
fn publisher_authorization_accepts_exact_multisig_quorum_and_rejects_bad_sets() {
    let operation = MusubiPublicationRuntimeOperationV1::StorageCoordination;
    let operation_id = [0x45; 32];
    let digest = [0x56; 32];
    let runtime = threshold_authorization_runtime(ThresholdAuthorizationSigningBehavior::Correct);
    let authorization = runtime
        .authorization_at(operation, operation_id, digest, 1_000)
        .expect("2-of-3 publisher authorization");
    assert_eq!(authorization.approvals.len(), 2);
    authorization
        .verify(operation, operation_id, digest, 1_001)
        .expect("verify multisig publisher authorization");
    for (behavior, code, class) in [
        (
            ThresholdAuthorizationSigningBehavior::BelowThreshold,
            "MUSUBI_RUNTIME_AUTHORIZATION_THRESHOLD_UNMET",
            MusubiPublicationRuntimeTransportFailureClassV1::Permanent,
        ),
        (
            ThresholdAuthorizationSigningBehavior::Duplicate,
            "MUSUBI_RUNTIME_AUTHORIZATION_APPROVALS_INVALID",
            MusubiPublicationRuntimeTransportFailureClassV1::Permanent,
        ),
        (
            ThresholdAuthorizationSigningBehavior::Unsorted,
            "MUSUBI_RUNTIME_AUTHORIZATION_APPROVALS_INVALID",
            MusubiPublicationRuntimeTransportFailureClassV1::Permanent,
        ),
        (
            ThresholdAuthorizationSigningBehavior::OverApprovalBound,
            "MUSUBI_RUNTIME_AUTHORIZATION_APPROVALS_INVALID",
            MusubiPublicationRuntimeTransportFailureClassV1::Permanent,
        ),
        (
            ThresholdAuthorizationSigningBehavior::WrongPayload,
            "MUSUBI_RUNTIME_AUTHORIZATION_SIGNATURE_INVALID",
            MusubiPublicationRuntimeTransportFailureClassV1::Permanent,
        ),
        (
            ThresholdAuthorizationSigningBehavior::RetryableFailure,
            "MUSUBI_RUNTIME_AUTHORIZATION_SIGNER_UNAVAILABLE",
            MusubiPublicationRuntimeTransportFailureClassV1::Retryable,
        ),
        (
            ThresholdAuthorizationSigningBehavior::PermanentFailure,
            "MUSUBI_RUNTIME_AUTHORIZATION_SIGNING_FAILED",
            MusubiPublicationRuntimeTransportFailureClassV1::Permanent,
        ),
    ] {
        let error = threshold_authorization_runtime(behavior)
            .authorization_at(operation, operation_id, digest, 1_000)
            .expect_err("invalid approval set must fail before transport");
        assert_eq!(error.code(), code);
        assert_eq!(error.class(), class);
    }
}
#[test]
fn publisher_authorization_counts_weight_and_rejects_invalid_policy() {
    let operation = MusubiPublicationRuntimeOperationV1::StorageCoordination;
    let operation_id = [0x47; 32];
    let digest = [0x58; 32];
    let key_pairs: Vec<_> = (0_u8..3)
        .map(|index| {
            KeyPair::try_from_seed(vec![0x70 + index; 32], Algorithm::Ed25519)
                .expect("derive weighted publisher key")
        })
        .collect();
    let members = key_pairs
        .iter()
        .zip([3_u16, 1, 1])
        .map(|(key_pair, weight)| {
            MultisigMember::new(key_pair.public_key().clone(), weight)
                .expect("weighted publisher member")
        })
        .collect();
    let publisher = AccountId::new_multisig(
        MultisigPolicy::new(3, members).expect("weighted publisher policy"),
    );
    let payload = MusubiPublicationRuntimeAuthorizationPayloadV1 {
        domain: AUTH_DOMAIN_V1,
        version: 1,
        operation,
        operation_id,
        network_id: test_network_id(0x21),
        publisher,
        request_digest: digest,
        issued_at_ms: 1_000,
        expires_at_ms: 2_000,
    };
    let authorization_for = |indices: &[usize]| {
        let mut approvals: Vec<_> = indices
            .iter()
            .map(|index| MusubiPublicationRuntimeAuthorizationApprovalV1 {
                public_key: key_pairs[*index].public_key().clone(),
                signature: SignatureOf::try_new(key_pairs[*index].private_key(), &payload)
                    .expect("weighted publisher signature"),
            })
            .collect();
        approvals.sort_by(|left, right| left.public_key.cmp(&right.public_key));
        MusubiPublicationRuntimeAuthorizationV1 {
            payload: payload.clone(),
            approvals,
        }
    };
    authorization_for(&[0])
        .verify(operation, operation_id, digest, 1_001)
        .expect("one weight-three member meets threshold three");
    let error = authorization_for(&[1, 2])
        .verify(operation, operation_id, digest, 1_001)
        .expect_err("two weight-one members remain below threshold three");
    assert_eq!(error.code(), "MUSUBI_RUNTIME_AUTHORIZATION_THRESHOLD_UNMET");
    let valid_policy = MultisigPolicy::new(
        1,
        vec![MultisigMember::new(key_pairs[0].public_key().clone(), 1).expect("publisher member")],
    )
    .expect("valid policy fixture");
    let mut unchecked_json =
        norito::json::to_value(&valid_policy).expect("serialize policy fixture");
    *unchecked_json
        .as_object_mut()
        .and_then(|object| object.get_mut("threshold"))
        .expect("policy threshold field") = norito::json::Value::from(0_u64);
    assert!(
        norito::json::from_value::<MultisigPolicy>(unchecked_json).is_err(),
        "invalid controller policy must fail at the canonical decode boundary"
    );
}
#[test]
fn software_publisher_authorizer_requires_one_matching_controller_key() {
    let keys: Vec<_> = (0_u8..2)
        .map(|index| {
            KeyPair::try_from_seed(vec![0xe0_u8 + index; 32], Algorithm::Ed25519)
                .expect("derive publisher key")
        })
        .collect();
    let members = keys
        .iter()
        .map(|key_pair| {
            MultisigMember::new(key_pair.public_key().clone(), 1).expect("publisher member")
        })
        .collect();
    let publisher =
        AccountId::new_multisig(MultisigPolicy::new(2, members).expect("publisher policy"));
    let error =
        SoftwareMusubiPublicationRuntimeAuthorizationSignerV1::new(publisher, keys[0].clone())
            .expect_err("software adapter must not pretend to collect a threshold");
    assert_eq!(
        error.code(),
        "MUSUBI_RUNTIME_MULTISIG_AUTH_PROVIDER_REQUIRED"
    );
}
#[test]
fn private_service_urls_reject_credentials_redirect_primitives_and_retired_upload() {
    for valid in [
        "https://seed.example/",
        "https://seed.example/private/",
        "https://127.0.0.1:8443/",
    ] {
        validate_publication_service_base_url(&Url::parse(valid).expect("valid URL"))
            .expect("accepted private HTTPS base");
    }
    for invalid in [
        "http://seed.example/",
        "https://user:secret@seed.example/",
        "https://seed.example/path",
        "https://seed.example/?token=secret",
        "https://seed.example/#fragment",
        "https://seed.example/v1/sorafs/upload/",
    ] {
        assert!(
            validate_publication_service_base_url(
                &Url::parse(invalid).expect("syntactically valid URL")
            )
            .is_err(),
            "accepted {invalid}"
        );
    }
}
#[test]
fn request_digest_binds_operation_length_and_body() {
    let body = b"canonical request";
    let digest = request_digest(
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        body,
    )
    .expect("bounded digest input");
    assert_ne!(
        digest,
        request_digest(MusubiPublicationRuntimeOperationV1::ProviderReadback, body)
            .expect("bounded digest input")
    );
    assert_ne!(
        digest,
        request_digest(
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            b"canonical request!"
        )
        .expect("bounded digest input")
    );
}
#[test]
fn remote_error_retryability_uses_canonical_service_response() {
    for (retryable, expected_class) in [
        (
            true,
            MusubiPublicationRuntimeTransportFailureClassV1::Retryable,
        ),
        (
            false,
            MusubiPublicationRuntimeTransportFailureClassV1::Permanent,
        ),
    ] {
        let body = norito::encode_canonical(&MusubiPublicationServiceErrorResponseV1 {
            version: 1,
            code: MusubiPublicationServiceErrorCodeV1::AuthorizationExpired,
            retryable,
        })
        .expect("canonical service error");
        let error = remote_transport_error(StatusCode::UNAUTHORIZED, &body);
        assert_eq!(error.class(), expected_class);
        assert_eq!(
            error.code(),
            MusubiPublicationServiceErrorCodeV1::AuthorizationExpired.as_str()
        );
    }
    let fallback = remote_transport_error(StatusCode::SERVICE_UNAVAILABLE, b"not-norito");
    assert_eq!(
        fallback.class(),
        MusubiPublicationRuntimeTransportFailureClassV1::Retryable
    );
    assert_eq!(fallback.code(), "MUSUBI_RUNTIME_REMOTE_RETRYABLE");
}
#[test]
fn receipt_verification_accepts_only_bounded_service_clock_lead() {
    let fixture = control_service_fixture(false, false);
    let broker_key = KeyPair::try_from_seed(
        b"musubi-publication-control-broker".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("broker key");
    let current_time_ms = 1;
    let mut at_limit = fixture.storage_request.staging_receipt.clone();
    at_limit.payload.issued_at_ms =
        current_time_ms + MUSUBI_PUBLICATION_SERVICE_MAX_CLOCK_SKEW_MS_V1;
    at_limit.payload.expires_at_ms = at_limit.payload.issued_at_ms + 60_000;
    at_limit.approvals[0].signature =
        SignatureOf::try_from_hash(broker_key.private_key(), at_limit.payload.signing_hash())
            .expect("bounded-lead receipt signature");
    verify_seed_ingress_receipt(&at_limit, &at_limit.payload.binding, current_time_ms)
        .expect("bounded service clock lead");
    let mut too_far_ahead = at_limit;
    too_far_ahead.payload.issued_at_ms += 1;
    too_far_ahead.payload.expires_at_ms += 1;
    too_far_ahead.approvals[0].signature = SignatureOf::try_from_hash(
        broker_key.private_key(),
        too_far_ahead.payload.signing_hash(),
    )
    .expect("excessive-lead receipt signature");
    let error = verify_seed_ingress_receipt(
        &too_far_ahead,
        &too_far_ahead.payload.binding,
        current_time_ms,
    )
    .expect_err("service clock lead exceeds the fixed bound");
    assert_eq!(error.code(), "MUSUBI_SEED_INGRESS_RECEIPT_INVALID");
}
#[test]
fn seed_ingress_carries_exact_metadata_and_authorization_with_framed_plan_body() {
    let (client, _) = client();
    let mut builder = client.to_builder();
    builder.headers.insert(
        "Authorization".to_owned(),
        "Basic must-not-cross-boundary".to_owned(),
    );
    builder.headers.insert(
        "x-platform-secret".to_owned(),
        "must-not-cross-boundary".to_owned(),
    );
    let client = builder.build().expect("valid isolated Torii headers");
    let runtime = AuthenticatedMusubiPublicationRuntimeClientV1::from_iroha_client(
        &client,
        Duration::from_secs(5),
    )
    .expect("runtime client");
    let fixture = private_service_fixture(false);
    let car = fixture.car;
    let stage_request = fixture.request;
    let operation_id = stage_request.operation_id;
    stage_request.validate().expect("valid stage metadata");
    let metadata = norito::encode_canonical(&stage_request).expect("encode stage metadata");
    let digest = request_digest(MusubiPublicationRuntimeOperationV1::SeedIngress, &metadata)
        .expect("bounded metadata digest");
    let authorization = runtime
        .authorization_at(
            MusubiPublicationRuntimeOperationV1::SeedIngress,
            operation_id,
            digest,
            1_000,
        )
        .expect("authorize exact metadata");
    let endpoint = publication_route(
        &Url::parse("https://seed.example/private/").expect("base URL"),
        SEED_INGRESS_ROUTE,
    )
    .expect("stage endpoint");
    let prepared = runtime
        .prepare_request(
            endpoint,
            APPLICATION_MUSUBI_SEED_ENVELOPE,
            &authorization,
            Some(&metadata),
            car.clone(),
        )
        .expect("prepare seed-ingress request");
    assert_eq!(
        prepared.body().and_then(reqwest::blocking::Body::as_bytes),
        Some(car.as_slice())
    );
    assert!(prepared.headers().get("Authorization").is_none());
    assert!(prepared.headers().get("x-platform-secret").is_none());
    assert_eq!(
        prepared.url().path(),
        "/private/v1/musubi/publication/seed-ingress"
    );
    let encoded_metadata = prepared
        .headers()
        .get(SEED_INGRESS_METADATA_HEADER)
        .expect("typed metadata header")
        .to_str()
        .expect("ASCII metadata header");
    assert!(
        prepared
            .headers()
            .get(SEED_INGRESS_METADATA_HEADER)
            .expect("typed metadata header")
            .is_sensitive()
    );
    assert_eq!(
        encoded_metadata,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&metadata)
    );
    let decoded_metadata = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_metadata)
        .expect("decode metadata header");
    let decoded_request: MusubiSeedIngressStageRequestV1 =
        norito::decode_canonical(&decoded_metadata).expect("decode canonical metadata");
    assert_eq!(decoded_request, stage_request);
    let encoded_authorization = prepared
        .headers()
        .get(AUTHORIZATION_HEADER)
        .expect("authorization header")
        .to_str()
        .expect("ASCII authorization header");
    assert!(
        prepared
            .headers()
            .get(AUTHORIZATION_HEADER)
            .expect("authorization header")
            .is_sensitive()
    );
    let authorization_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_authorization)
        .expect("decode authorization header");
    let decoded_authorization: MusubiPublicationRuntimeAuthorizationV1 =
        norito::decode_canonical(&authorization_bytes).expect("decode authorization");
    decoded_authorization
        .verify(
            MusubiPublicationRuntimeOperationV1::SeedIngress,
            operation_id,
            digest,
            1_001,
        )
        .expect("authorization binds exact metadata");
}
#[test]
fn seed_ingress_plan_witness_round_trips_only_the_exact_commitment_chunker() {
    let fixture = private_service_fixture(false);
    let witness =
        MusubiSeedIngressCarPlanV1::from_car_build_plan(&fixture.plan, &fixture.request.commitment)
            .expect("wire plan");
    let canonical = witness.canonical_bytes().expect("canonical wire plan");
    let decoded: MusubiSeedIngressCarPlanV1 =
        norito::decode_canonical_with_limits(&canonical, SEED_INGRESS_PLAN_DECODE_LIMITS)
            .expect("decode canonical wire plan");
    assert_eq!(decoded, witness);
    assert_eq!(
        decoded
            .to_car_build_plan(&fixture.request.commitment)
            .expect("reconstruct exact plan"),
        fixture.plan
    );
    let mut substituted = fixture.request.commitment;
    substituted.chunker.name = "sf2".to_owned();
    assert!(decoded.to_car_build_plan(&substituted).is_err());
}
#[test]
fn seed_ingress_plan_witness_reports_portable_path_failures_as_source_tree() {
    let fixture = private_service_fixture(false);
    let mut witness =
        MusubiSeedIngressCarPlanV1::from_car_build_plan(&fixture.plan, &fixture.request.commitment)
            .expect("wire plan");
    let source = witness
        .files
        .iter_mut()
        .find(|file| !file.path.join("/").starts_with(".musubi/"))
        .expect("fixture source file");
    source.path = vec!["bad?.ko".to_owned()];
    let canonical = norito::encode_canonical(&witness).expect("invalid-path wire plan");
    let error = decode_seed_ingress_plan_witness(&canonical)
        .expect_err("nonportable source path must fail before archive verification");
    assert_eq!(
        error.code,
        MusubiPublicationServiceErrorCodeV1::CarBodyMismatch
    );
    assert!(!error.retryable);
    assert_eq!(
        error.telemetry,
        Some(MusubiPublicationServiceTelemetryEventV1::IntegrityFailure(
            MusubiIntegritySurfaceV1::SourceTree,
        ))
    );
}
#[test]
fn seed_ingress_and_provider_bundle_verifier_have_evidence_and_error_parity() {
    let fixture = private_service_fixture(false);
    let seed_evidence = verify_seed_ingress_body(&fixture.request, &fixture.car)
        .expect("seed ingress accepts the complete fixture bundle");
    assert_eq!(&seed_evidence.plan, &fixture.plan);
    assert_eq!(seed_evidence.car, fixture.raw_car.as_slice());
    let provider_evidence = MusubiBundleVerifierV1::verify(
        &fixture.plan,
        &fixture.raw_car,
        &fixture.request.commitment,
    )
    .expect("provider-grade verifier accepts the same fixture");
    assert_eq!(
        provider_evidence.semantic_release().semantic_digest(),
        fixture.request.binding.semantic_release_manifest_digest
    );
    assert_eq!(
        provider_evidence.descriptor().verification_lock_digest,
        provider_evidence.verification_lock().digest()
    );
    for (shared, service) in [
        (
            MusubiBundleIntegritySurfaceV1::ArchiveCommitment,
            MusubiIntegritySurfaceV1::ArchiveCommitment,
        ),
        (
            MusubiBundleIntegritySurfaceV1::Bundle,
            MusubiIntegritySurfaceV1::Bundle,
        ),
        (
            MusubiBundleIntegritySurfaceV1::Descriptor,
            MusubiIntegritySurfaceV1::Descriptor,
        ),
        (
            MusubiBundleIntegritySurfaceV1::SourceTree,
            MusubiIntegritySurfaceV1::SourceTree,
        ),
        (
            MusubiBundleIntegritySurfaceV1::VerificationLock,
            MusubiIntegritySurfaceV1::VerificationLock,
        ),
    ] {
        let mapped = seed_ingress_bundle_integrity_failure(shared);
        assert_eq!(
            mapped.code,
            MusubiPublicationServiceErrorCodeV1::CarBodyMismatch
        );
        assert!(!mapped.retryable);
        assert_eq!(
            mapped.telemetry,
            Some(MusubiPublicationServiceTelemetryEventV1::IntegrityFailure(
                service
            ))
        );
    }
}
#[test]
fn seed_ingress_wire_accepts_valid_high_path_heap_geometry() {
    let fixture = private_service_fixture(false);
    let source_file_count =
        usize::try_from(MUSUBI_MAX_FILES_V1).expect("public file bound fits usize");
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(source_file_count + 3)
        .expect("bounded high-geometry fixture allocation");
    for file_index in 0..source_file_count {
        let path = (0..64)
            .map(|component_index| {
                format!("f{file_index:04}c{component_index:02}{}", "x".repeat(55))
            })
            .collect();
        entries.push(FileEntry {
            path,
            data: vec![u8::try_from(file_index % 251).expect("fixture byte")],
        });
    }
    for (path, byte) in [
        (BUNDLE_RELEASE_PATH_V1, 0xa1),
        (BUNDLE_DESCRIPTOR_PATH_V1, 0xa2),
        (BUNDLE_VERIFICATION_LOCK_PATH_V1, 0xa3),
    ] {
        entries.push(FileEntry {
            path: path.split('/').map(str::to_owned).collect(),
            data: vec![byte],
        });
    }
    let (plan, _) = CarBuildPlan::from_files(entries).expect("high-path canonical plan");
    let validation = plan.validate().expect("high-path geometry validates");
    assert!(
        validation.estimated_ingest_heap_bytes() > 24 * 1024 * 1024,
        "fixture must exercise geometry above the retired 24 MiB heap cap"
    );
    assert!(
        validation.estimated_ingest_heap_bytes() <= DEFAULT_CHUNK_STORE_MAX_ESTIMATED_HEAP_BYTES
    );
    let mut commitment = fixture.request.commitment;
    commitment.content_length = plan.content_length;
    commitment.chunk_plan_digest =
        MusubiContentDigestV1::new(compute_chunk_plan_digest_sha3(&plan.chunks));
    commitment.file_count = u32::try_from(source_file_count).expect("public file bound fits u32");
    commitment.chunk_count = u32::try_from(plan.chunks.len()).expect("chunk count fits u32");
    commitment.validate().expect("high-path commitment shape");
    let witness = MusubiSeedIngressCarPlanV1::from_car_build_plan(&plan, &commitment)
        .expect("public-max path geometry is admitted");
    assert!(
        witness.canonical_bytes().expect("bounded wire").len()
            <= MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1
    );
    assert_eq!(
        witness
            .to_car_build_plan(&commitment)
            .expect("high-path witness round-trip"),
        plan
    );
}
#[test]
fn seed_ingress_rejects_portable_unicode_aliases_before_backend() {
    for (collision_path, case) in [
        (
            vec![".muſubi".to_owned(), "semantic-release.norito".to_owned()],
            "whole-path collision",
        ),
        (
            vec![".muſubi".to_owned()],
            "file/directory prefix collision",
        ),
    ] {
        let mut fixture = private_service_fixture(false);
        let source_index = fixture
            .plan
            .files
            .iter()
            .position(|file| !file.path.join("/").starts_with(".musubi/"))
            .expect("fixture source file");
        let mut forged_plan = fixture.plan.clone();
        forged_plan.files[source_index].path = collision_path.clone();
        forged_plan
            .validate()
            .expect("the lower-level SoraFS plan permits the portable Unicode alias");
        assert!(
            validate_musubi_portable_path_set_v1(
                forged_plan.files.iter().map(|file| file.path.as_slice())
            )
            .is_err(),
            "the long-s spelling must reject the mandatory .musubi {case}"
        );
        let mut witness = MusubiSeedIngressCarPlanV1::from_car_build_plan(
            &fixture.plan,
            &fixture.request.commitment,
        )
        .expect("valid fixture witness");
        witness.files[source_index].path = collision_path;
        assert!(
            witness
                .to_car_build_plan(&fixture.request.commitment)
                .is_err(),
            "the public wire conversion must reject the {case}"
        );
        assert!(witness.canonical_bytes().is_err(), "{case}");
        assert!(witness.canonical_digest().is_err(), "{case}");
        assert!(witness.canonical_len().is_err(), "{case}");
        let canonical_plan =
            norito::encode_canonical(&witness).expect("test-only forged canonical wire witness");
        let mut request = fixture.request.clone();
        request.plan_digest =
            seed_ingress_plan_digest(&canonical_plan).expect("forged plan digest");
        request.plan_length = u64::try_from(canonical_plan.len()).expect("forged plan length");
        let metadata = norito::encode_canonical(&request).expect("forged plan metadata");
        let authorization = authorization_header(&fixture.runtime, &request, &metadata, 8_300);
        let body = encode_seed_ingress_body(&canonical_plan, &fixture.raw_car)
            .expect("framed forged plan witness");
        let response = seed_http_response(&mut fixture, &authorization, &metadata, &body, 8_301);
        assert_eq!(response.status, 422, "{case}");
        assert_eq!(
            decode_service_error(&response).code,
            MusubiPublicationServiceErrorCodeV1::CarBodyMismatch,
            "{case}"
        );
        assert_eq!(*fixture.calls.lock().expect("seed calls"), 0, "{case}");
    }
}
#[test]
fn seed_ingress_source_transcript_uses_joined_path_byte_order() {
    let a_dash_digest = *blake3::hash(b"dash").as_bytes();
    let a_slash_z_digest = *blake3::hash(b"slash-z").as_bytes();
    // Structural component ordering places ["a", "z"] before ["a-"], but package
    // commitment semantics compare the joined strings and therefore require `a-` first.
    let structural_order = vec![
        ("a/z".to_owned(), 7, a_slash_z_digest),
        ("a-".to_owned(), 4, a_dash_digest),
    ];
    let mut expected = Vec::new();
    seed_ingress_append_frame(&mut expected, SOURCE_TREE_DOMAIN_V1).expect("source domain frame");
    expected.extend_from_slice(&2_u32.to_be_bytes());
    for (path, size, digest) in [
        ("a-", 4_u64, a_dash_digest),
        ("a/z", 7_u64, a_slash_z_digest),
    ] {
        seed_ingress_append_frame(&mut expected, path.as_bytes()).expect("source path frame");
        expected.extend_from_slice(&size.to_be_bytes());
        expected.extend_from_slice(&digest);
    }
    assert_eq!(
        seed_ingress_source_material(structural_order, expected.len())
            .expect("joined-path source material"),
        expected
    );
}
#[test]
fn private_service_accepts_plan_witness_larger_than_metadata_header() {
    let mut fixture = private_service_fixture(false);
    let retained =
        CarVerifier::verify_canonical_car_with_plan_retained(&fixture.plan, &fixture.raw_car)
            .expect("verify compact fixture CAR");
    let mut payload = Vec::new();
    retained
        .payload_reader()
        .read_to_end(&mut payload)
        .expect("read authenticated fixture payload");
    let mut source_entries = Vec::new();
    let mut source_transcript = Vec::new();
    let mut semantic_release_bytes = None;
    let mut verification_lock_bytes = None;
    let mut payload_offset = 0_usize;
    for file in &fixture.plan.files {
        let file_size = usize::try_from(file.size).expect("fixture file size fits usize");
        let file_end = payload_offset + file_size;
        let bytes = payload[payload_offset..file_end].to_vec();
        let path = file.path.join("/");
        match path.as_str() {
            BUNDLE_RELEASE_PATH_V1 => semantic_release_bytes = Some(bytes),
            BUNDLE_DESCRIPTOR_PATH_V1 => {}
            BUNDLE_VERIFICATION_LOCK_PATH_V1 => verification_lock_bytes = Some(bytes),
            _ => {
                source_transcript.push((path, file.size, *blake3::hash(&bytes).as_bytes()));
                source_entries.push(FileEntry {
                    path: file.path.clone(),
                    data: bytes,
                });
            }
        }
        payload_offset = file_end;
    }
    assert_eq!(payload_offset, payload.len());
    // Empty files need no undersized chunks, yet each contributes a bounded portable file
    // witness. This grows the canonical plan beyond the 64 KiB metadata-header ceiling while
    // retaining the exact registered SF1 profile and all package bundle commitments.
    for index in 0..2_048_u16 {
        let path = vec!["generated".to_owned(), format!("empty-{index:04}.ko")];
        source_transcript.push((path.join("/"), 0, *blake3::hash(&[]).as_bytes()));
        source_entries.push(FileEntry {
            path,
            data: Vec::new(),
        });
    }
    let source_file_count = u32::try_from(source_entries.len()).expect("source file count");
    let source_bytes = source_entries
        .iter()
        .try_fold(0_u64, |total, entry| {
            total.checked_add(u64::try_from(entry.data.len()).ok()?)
        })
        .expect("bounded source byte count");
    let source_material_length = source_transcript.iter().fold(
        8 + SOURCE_TREE_DOMAIN_V1.len() + 4,
        |total, (path, _, _)| total + 8 + path.len() + 8 + 32,
    );
    let source_material = seed_ingress_source_material(source_transcript, source_material_length)
        .expect("large fixture source transcript");
    let source_tree_digest = seed_ingress_domain_digest(SOURCE_TREE_DOMAIN_V1, &source_material)
        .expect("large fixture source-tree digest");
    let semantic_release_bytes = semantic_release_bytes.expect("fixture semantic release");
    let verification_lock_bytes = verification_lock_bytes.expect("fixture verification lock");
    let verification_lock =
        MusubiVerificationLockV1::decode_canonical_bundle_file(&verification_lock_bytes)
            .expect("fixture verification lock");
    let descriptor = MusubiArtifactDescriptorV1::new(
        fixture.request.binding.semantic_release_manifest_digest,
        source_tree_digest,
        verification_lock.digest(),
        source_bytes,
        source_file_count,
    )
    .expect("large fixture descriptor");
    let descriptor_bytes = descriptor.encode();
    let mut descriptor_material = Vec::new();
    seed_ingress_append_frame(&mut descriptor_material, ARTIFACT_DESCRIPTOR_DOMAIN_V1)
        .expect("large fixture descriptor domain");
    seed_ingress_append_frame(&mut descriptor_material, &descriptor_bytes)
        .expect("large fixture descriptor");
    let descriptor_digest =
        seed_ingress_domain_digest(ARTIFACT_DESCRIPTOR_DOMAIN_V1, &descriptor_material)
            .expect("large fixture descriptor digest");
    let mut bundle_material = Vec::new();
    for bytes in [
        BUNDLE_DOMAIN_V1,
        semantic_release_bytes.as_slice(),
        descriptor_material.as_slice(),
        source_material.as_slice(),
        verification_lock_bytes.as_slice(),
    ] {
        seed_ingress_append_frame(&mut bundle_material, bytes)
            .expect("large fixture bundle material");
    }
    let bundle_digest = seed_ingress_domain_digest(BUNDLE_DOMAIN_V1, &bundle_material)
        .expect("large fixture bundle digest");
    source_entries.extend([
        FileEntry {
            path: BUNDLE_RELEASE_PATH_V1
                .split('/')
                .map(str::to_owned)
                .collect(),
            data: semantic_release_bytes,
        },
        FileEntry {
            path: BUNDLE_DESCRIPTOR_PATH_V1
                .split('/')
                .map(str::to_owned)
                .collect(),
            data: descriptor_bytes,
        },
        FileEntry {
            path: BUNDLE_VERIFICATION_LOCK_PATH_V1
                .split('/')
                .map(str::to_owned)
                .collect(),
            data: verification_lock_bytes,
        },
    ]);
    let (large_plan, payload) =
        CarBuildPlan::from_files(source_entries).expect("large canonical file plan");
    large_plan.validate().expect("profile-valid large plan");
    let mut raw_car = Vec::new();
    let stats = CarWriter::new(&large_plan, &payload)
        .expect("large-plan CAR writer")
        .write_to(&mut raw_car)
        .expect("large-plan canonical CAR");
    let mut commitment = fixture.request.commitment.clone();
    commitment.root_cid =
        ManifestRootCid::try_from(stats.root_cids[0].clone()).expect("large-plan canonical root");
    commitment.chunk_plan_digest =
        MusubiContentDigestV1::new(compute_chunk_plan_digest_sha3(&large_plan.chunks));
    commitment.por_root = MusubiContentDigestV1::new(
        compute_por_root(&payload, &large_plan).expect("large-plan PoR"),
    );
    commitment.content_length = large_plan.content_length;
    commitment.car_digest = MusubiContentDigestV1::new(*stats.car_archive_digest.as_bytes());
    commitment.car_size = stats.car_size;
    commitment.bundle_digest = bundle_digest;
    commitment.source_tree_digest = source_tree_digest;
    commitment.descriptor_digest = descriptor_digest;
    commitment.file_count = source_file_count;
    commitment.chunk_count =
        u32::try_from(large_plan.chunks.len()).expect("large plan chunk count fits u32");
    commitment.validate().expect("large-plan commitment");
    let witness = MusubiSeedIngressCarPlanV1::from_car_build_plan(&large_plan, &commitment)
        .expect("large wire plan");
    let canonical_plan = witness
        .canonical_bytes()
        .expect("large canonical wire plan");
    assert!(
        canonical_plan.len() > MAX_SEED_INGRESS_METADATA_BYTES,
        "plan witness must prove it cannot fit in the authenticated metadata header"
    );
    let mut request = fixture.request.clone();
    request.commitment = commitment;
    request.binding.archive_id = request.commitment.archive_id();
    request.binding.car_body_digest = request.commitment.car_digest;
    request.binding.car_body_length = request.commitment.car_size;
    request.plan_digest = witness.canonical_digest().expect("large plan digest");
    request.plan_length = witness.canonical_len().expect("large plan length");
    let metadata = norito::encode_canonical(&request).expect("large-plan metadata");
    assert!(metadata.len() <= MAX_SEED_INGRESS_METADATA_BYTES);
    let authorization = authorization_header(&fixture.runtime, &request, &metadata, 7_000);
    let body = encode_seed_ingress_body(&canonical_plan, &raw_car).expect("large-plan envelope");
    let response = seed_http_response(&mut fixture, &authorization, &metadata, &body, 7_001);
    assert_eq!(response.status, 200);
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 1);
}
#[test]
fn private_service_rejects_frame_plan_and_commitment_substitution_before_backend() {
    {
        let mut fixture = private_service_fixture(false);
        let metadata = fixture.metadata.clone();
        let authorization =
            authorization_header(&fixture.runtime, &fixture.request, &metadata, 8_000);
        let mut malformed = fixture.car.clone();
        malformed[0] ^= 0x01;
        let response =
            seed_http_response(&mut fixture, &authorization, &metadata, &malformed, 8_001);
        assert_eq!(response.status, 422);
        assert_eq!(
            decode_service_error(&response).code,
            MusubiPublicationServiceErrorCodeV1::CarBodyMismatch
        );
        assert_eq!(*fixture.calls.lock().expect("seed calls"), 0);
    }
    {
        let mut fixture = private_service_fixture(false);
        let mut request = fixture.request.clone();
        request.plan_digest = MusubiContentDigestV1::new([0xa1; 32]);
        let metadata = norito::encode_canonical(&request).expect("substituted plan metadata");
        let authorization = authorization_header(&fixture.runtime, &request, &metadata, 8_100);
        let body = fixture.car.clone();
        let response = seed_http_response(&mut fixture, &authorization, &metadata, &body, 8_101);
        assert_eq!(response.status, 422);
        assert_eq!(
            decode_service_error(&response).code,
            MusubiPublicationServiceErrorCodeV1::CarBodyMismatch
        );
        assert_eq!(*fixture.calls.lock().expect("seed calls"), 0);
    }
    {
        let mut fixture = private_service_fixture(false);
        let mut request = fixture.request.clone();
        request.commitment.por_root = MusubiContentDigestV1::new([0xa2; 32]);
        request.binding.archive_id = request.commitment.archive_id();
        let metadata = norito::encode_canonical(&request).expect("substituted commitment metadata");
        let authorization = authorization_header(&fixture.runtime, &request, &metadata, 8_200);
        let body = fixture.car.clone();
        let response = seed_http_response(&mut fixture, &authorization, &metadata, &body, 8_201);
        assert_eq!(response.status, 422);
        assert_eq!(
            decode_service_error(&response).code,
            MusubiPublicationServiceErrorCodeV1::CarBodyMismatch
        );
        assert_eq!(*fixture.calls.lock().expect("seed calls"), 0);
    }
}
#[test]
fn private_service_constructs_and_verifies_exact_external_signer_payload() {
    let mut fixture = private_service_fixture(false);
    let broker_key = KeyPair::try_from_seed(
        b"musubi-publication-runtime-broker-test".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("derive broker key");
    let (provider, observed) = TestReceiptSigningProvider::new(
        fixture.request.binding.ingress_broker.clone(),
        broker_key,
        TestSigningBehavior::Correct,
    );
    fixture.service.receipt_signer = Box::new(provider);
    fixture.service.seed_ingress = Box::new(RecordingSeedIngress {
        provider: fixture.request.binding.seed_provider,
        calls: Arc::clone(&fixture.calls),
        fail_first: false,
        clock_after_stage: Some((Arc::clone(&fixture.clock), 1_901)),
    });
    let metadata = fixture.metadata.clone();
    let car = fixture.car.clone();
    let authorization = authorization_header(&fixture.runtime, &fixture.request, &metadata, 900);
    let response = seed_http_response(&mut fixture, &authorization, &metadata, &car, 901);
    assert_eq!(response.status, 200);
    let receipt: MusubiSeedIngressReceiptV1 =
        norito::decode_canonical_with_limits(&response.body, RESPONSE_DECODE_LIMITS)
            .expect("externally signed receipt");
    receipt
        .verify(&fixture.request.binding, 1_901)
        .expect("service verifies exact external approval");
    let observed = observed.lock().expect("observed signing payloads");
    assert_eq!(observed.as_slice(), std::slice::from_ref(&receipt.payload));
    assert_eq!(receipt.payload.binding, fixture.request.binding);
    assert_eq!(receipt.payload.issued_at_ms, 1_901);
    assert_eq!(receipt.payload.expires_at_ms, 61_901);
}
#[test]
fn private_service_rejects_invalid_or_unavailable_external_signer_and_retries_exactly() {
    for (behavior, expected_status, expected_retryable) in [
        (TestSigningBehavior::WrongPayload, 422, false),
        (TestSigningBehavior::WrongController, 422, false),
        (TestSigningBehavior::DuplicateApproval, 422, false),
        (TestSigningBehavior::RetryableFailure, 503, true),
    ] {
        let mut fixture = private_service_fixture(false);
        let broker_key = KeyPair::try_from_seed(
            b"musubi-publication-runtime-broker-test".to_vec(),
            Algorithm::Ed25519,
        )
        .expect("derive broker key");
        let (provider, _) = TestReceiptSigningProvider::new(
            fixture.request.binding.ingress_broker.clone(),
            broker_key.clone(),
            behavior,
        );
        fixture.service.receipt_signer = Box::new(provider);
        let metadata = fixture.metadata.clone();
        let car = fixture.car.clone();
        let authorization =
            authorization_header(&fixture.runtime, &fixture.request, &metadata, 10_000);
        let failed = seed_http_response(&mut fixture, &authorization, &metadata, &car, 10_001);
        let failure = decode_service_error(&failed);
        assert_eq!(failed.status, expected_status);
        assert_eq!(
            failure.code,
            MusubiPublicationServiceErrorCodeV1::ReceiptSigningUnavailable
        );
        assert_eq!(failure.retryable, expected_retryable);
        assert_eq!(*fixture.calls.lock().expect("seed calls"), 1);
        let (correct, _) = TestReceiptSigningProvider::new(
            fixture.request.binding.ingress_broker.clone(),
            broker_key,
            TestSigningBehavior::Correct,
        );
        fixture.service.receipt_signer = Box::new(correct);
        let fresh = authorization_header(&fixture.runtime, &fixture.request, &metadata, 10_002);
        let retried = seed_http_response(&mut fixture, &fresh, &metadata, &car, 10_003);
        assert_eq!(
            retried.status, 200,
            "exact signer retry must leave its tombstone usable"
        );
        assert_eq!(*fixture.calls.lock().expect("seed calls"), 2);
    }
    let mut fixture = private_service_fixture(false);
    let broker_key = KeyPair::try_from_seed(
        b"musubi-publication-runtime-broker-test".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("derive broker key");
    let (slow_provider, _) = TestReceiptSigningProvider::new(
        fixture.request.binding.ingress_broker.clone(),
        broker_key.clone(),
        TestSigningBehavior::Correct,
    );
    fixture.service.receipt_signer =
        Box::new(slow_provider.with_clock_after_signing(Arc::clone(&fixture.clock), 70_001));
    let metadata = fixture.metadata.clone();
    let car = fixture.car.clone();
    let authorization = authorization_header(&fixture.runtime, &fixture.request, &metadata, 10_000);
    let expired = seed_http_response(&mut fixture, &authorization, &metadata, &car, 10_001);
    let expired_error = decode_service_error(&expired);
    assert_eq!(expired.status, 503);
    assert_eq!(
        expired_error.code,
        MusubiPublicationServiceErrorCodeV1::ReceiptSigningUnavailable
    );
    assert!(expired_error.retryable);
    let (correct, _) = TestReceiptSigningProvider::new(
        fixture.request.binding.ingress_broker.clone(),
        broker_key,
        TestSigningBehavior::Correct,
    );
    fixture.service.receipt_signer = Box::new(correct);
    let fresh = authorization_header(&fixture.runtime, &fixture.request, &metadata, 70_002);
    let retried = seed_http_response(&mut fixture, &fresh, &metadata, &car, 70_003);
    assert_eq!(retried.status, 200);
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 2);
}
#[test]
fn private_service_constructor_binds_signer_and_seed_backend_identities() {
    let broker_key = KeyPair::try_from_seed(
        b"musubi-publication-constructor-broker".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("derive broker key");
    let broker = AccountId::new(broker_key.public_key().clone());
    let provider = ProviderId::new([0xa1; 32]);
    let config = MusubiPublicationServiceConfigurationV1 {
        network_id: test_network_id(0xa2),
        ingress_broker: broker.clone(),
        seed_provider: provider,
        max_future_clock_skew_ms: 1_000,
        receipt_lifetime_ms: 60_000,
    };
    let journal_binding = MusubiPublicationServiceJournalBindingV1::from_configuration(&config);
    let wrong_broker_key = KeyPair::try_from_seed(
        b"musubi-publication-constructor-wrong-broker".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("derive wrong broker key");
    let wrong_broker = AccountId::new(wrong_broker_key.public_key().clone());
    let wrong_signer =
        SoftwareMusubiSeedIngressReceiptSignerV1::new(wrong_broker, wrong_broker_key)
            .expect("internally consistent wrong signer");
    let (signer_mismatch_clock, _) = TestPublicationClock::new(1_000);
    let signer_mismatch = MusubiPublicationPrivateServiceV1::new(
        config.clone(),
        Box::new(signer_mismatch_clock),
        Box::new(wrong_signer),
        Box::new(
            InMemoryMusubiPublicationServiceJournalV1::new(journal_binding.clone(), 2, 4)
                .expect("journal"),
        ),
        Box::new(RecordingSeedIngress {
            provider,
            calls: Arc::new(Mutex::new(0)),
            fail_first: false,
            clock_after_stage: None,
        }),
        Box::new(UnusedStorage),
        Box::new(UnusedReadback),
    );
    assert!(matches!(
        signer_mismatch,
        Err(MusubiPublicationServiceErrorCodeV1::IdentityMismatch)
    ));
    let signer = SoftwareMusubiSeedIngressReceiptSignerV1::new(broker, broker_key)
        .expect("matching software signer");
    let signer_debug = format!("{signer:?}");
    assert!(!signer_debug.contains("key_pair"));
    assert!(!signer_debug.contains("private"));
    let (provider_mismatch_clock, _) = TestPublicationClock::new(1_000);
    let provider_mismatch = MusubiPublicationPrivateServiceV1::new(
        config,
        Box::new(provider_mismatch_clock),
        Box::new(signer),
        Box::new(
            InMemoryMusubiPublicationServiceJournalV1::new(journal_binding, 2, 4).expect("journal"),
        ),
        Box::new(RecordingSeedIngress {
            provider: ProviderId::new([0xa3; 32]),
            calls: Arc::new(Mutex::new(0)),
            fail_first: false,
            clock_after_stage: None,
        }),
        Box::new(UnusedStorage),
        Box::new(UnusedReadback),
    );
    assert!(matches!(
        provider_mismatch,
        Err(MusubiPublicationServiceErrorCodeV1::IdentityMismatch)
    ));
}
#[test]
fn private_service_verifies_bounded_threshold_signing_provider() {
    let mut fixture = threshold_private_service_fixture(ThresholdSigningBehavior::Correct);
    let metadata = fixture.metadata.clone();
    let car = fixture.car.clone();
    let authorization = authorization_header(&fixture.runtime, &fixture.request, &metadata, 1_000);
    let response = seed_http_response(&mut fixture, &authorization, &metadata, &car, 1_001);
    assert_eq!(response.status, 200);
    let receipt: MusubiSeedIngressReceiptV1 =
        norito::decode_canonical_with_limits(&response.body, RESPONSE_DECODE_LIMITS)
            .expect("threshold receipt");
    receipt
        .verify(&fixture.request.binding, 1_001)
        .expect("2-of-3 broker receipt");
    assert_eq!(receipt.approvals.len(), 2);
    for behavior in [
        ThresholdSigningBehavior::BelowThreshold,
        ThresholdSigningBehavior::Empty,
        ThresholdSigningBehavior::Unsorted,
        ThresholdSigningBehavior::OverApprovalBound,
    ] {
        let mut fixture = threshold_private_service_fixture(behavior);
        let metadata = fixture.metadata.clone();
        let car = fixture.car.clone();
        let authorization =
            authorization_header(&fixture.runtime, &fixture.request, &metadata, 2_000);
        let response = seed_http_response(&mut fixture, &authorization, &metadata, &car, 2_001);
        let error = decode_service_error(&response);
        assert_eq!(response.status, 422);
        assert_eq!(
            error.code,
            MusubiPublicationServiceErrorCodeV1::ReceiptSigningUnavailable
        );
        assert!(!error.retryable);
    }
}
#[test]
fn private_service_rejects_broker_quorum_larger_than_receipt_bound() {
    let key_pairs: Vec<_> =
        (0_u8..u8::try_from(MUSUBI_MAX_PUBLICATION_ATTESTATION_APPROVALS_V1 + 1)
            .expect("approval bound fits u8"))
            .map(|index| {
                KeyPair::try_from_seed(vec![index.saturating_add(1); 32], Algorithm::Ed25519)
                    .expect("derive impossible broker key")
            })
            .collect();
    let members = key_pairs
        .iter()
        .map(|key_pair| {
            MultisigMember::new(key_pair.public_key().clone(), 1).expect("impossible broker member")
        })
        .collect();
    let broker = AccountId::new_multisig(
        MultisigPolicy::new(
            u16::try_from(MUSUBI_MAX_PUBLICATION_ATTESTATION_APPROVALS_V1 + 1)
                .expect("approval bound fits u16"),
            members,
        )
        .expect("65-of-65 account policy is structurally valid"),
    );
    let provider = ProviderId::new([0xb5; 32]);
    let config = MusubiPublicationServiceConfigurationV1 {
        network_id: test_network_id(0xb6),
        ingress_broker: broker.clone(),
        seed_provider: provider,
        max_future_clock_skew_ms: 1_000,
        receipt_lifetime_ms: 60_000,
    };
    let journal_binding = MusubiPublicationServiceJournalBindingV1::from_configuration(&config);
    let signer = ThresholdReceiptSigningProvider {
        broker,
        key_pairs,
        behavior: ThresholdSigningBehavior::Correct,
    };
    let (clock, _) = TestPublicationClock::new(1_000);
    let service = MusubiPublicationPrivateServiceV1::new(
        config,
        Box::new(clock),
        Box::new(signer),
        Box::new(ConflictJournal {
            binding: journal_binding,
        }),
        Box::new(RecordingSeedIngress {
            provider,
            calls: Arc::new(Mutex::new(0)),
            fail_first: false,
            clock_after_stage: None,
        }),
        Box::new(UnusedStorage),
        Box::new(UnusedReadback),
    );
    assert!(matches!(
        service,
        Err(MusubiPublicationServiceErrorCodeV1::IdentityMismatch)
    ));
}
#[test]
fn private_service_rejects_trusted_clock_regression() {
    let mut fixture = private_service_fixture(false);
    let metadata = fixture.metadata.clone();
    let car = fixture.car.clone();
    let authorization = authorization_header(&fixture.runtime, &fixture.request, &metadata, 3_000);
    let first = seed_http_response(&mut fixture, &authorization, &metadata, &car, 3_001);
    assert_eq!(first.status, 200);
    let regressed_authorization =
        authorization_header(&fixture.runtime, &fixture.request, &metadata, 2_999);
    let regressed = seed_http_response(
        &mut fixture,
        &regressed_authorization,
        &metadata,
        &car,
        3_000,
    );
    let error = decode_service_error(&regressed);
    assert_eq!(regressed.status, 503);
    assert_eq!(
        error.code,
        MusubiPublicationServiceErrorCodeV1::TrustedClockUnavailable
    );
    assert!(error.retryable);
    let recovered_authorization =
        authorization_header(&fixture.runtime, &fixture.request, &metadata, 3_002);
    let recovered = seed_http_response(
        &mut fixture,
        &recovered_authorization,
        &metadata,
        &car,
        3_003,
    );
    assert_eq!(recovered.status, 200);
    assert_eq!(recovered.body, first.body);
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 1);
}
#[test]
fn private_service_classifies_receipt_expiry_overflow_as_clock_failure() {
    let mut fixture = private_service_fixture(false);
    fixture.service.seed_ingress = Box::new(RecordingSeedIngress {
        provider: fixture.request.binding.seed_provider,
        calls: Arc::clone(&fixture.calls),
        fail_first: false,
        clock_after_stage: Some((Arc::clone(&fixture.clock), u64::MAX.saturating_sub(59_999))),
    });
    let metadata = fixture.metadata.clone();
    let car = fixture.car.clone();
    let authorization = authorization_header(&fixture.runtime, &fixture.request, &metadata, 4_000);
    let response = seed_http_response(&mut fixture, &authorization, &metadata, &car, 4_001);
    let error = decode_service_error(&response);
    assert_eq!(response.status, 503);
    assert_eq!(
        error.code,
        MusubiPublicationServiceErrorCodeV1::TrustedClockUnavailable
    );
    assert!(!error.retryable);
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 1);
}
#[test]
fn private_service_returns_one_broker_receipt_and_reuses_exact_completed_operation() {
    let mut fixture = private_service_fixture(false);
    let metadata = fixture.metadata.clone();
    let car = fixture.car.clone();
    let first_authorization =
        authorization_header(&fixture.runtime, &fixture.request, &metadata, 1_000);
    let first = seed_http_response(&mut fixture, &first_authorization, &metadata, &car, 1_001);
    assert_eq!(first.status, 200);
    let receipt: MusubiSeedIngressReceiptV1 =
        norito::decode_canonical_with_limits(&first.body, RESPONSE_DECODE_LIMITS)
            .expect("signed receipt");
    receipt
        .verify(&fixture.request.binding, 1_001)
        .expect("receipt binds the exact staged CAR");
    let retry_authorization =
        authorization_header(&fixture.runtime, &fixture.request, &metadata, 1_002);
    let retry = seed_http_response(&mut fixture, &retry_authorization, &metadata, &car, 1_003);
    assert_eq!(retry.status, 200);
    assert_eq!(retry.body, first.body);
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 1);
    let mut substituted = fixture.request.clone();
    substituted.binding.nonce = [0x7b; 32];
    let substituted_metadata =
        norito::encode_canonical(&substituted).expect("substituted metadata");
    let substituted_authorization =
        authorization_header(&fixture.runtime, &substituted, &substituted_metadata, 1_004);
    let conflict = seed_http_response(
        &mut fixture,
        &substituted_authorization,
        &substituted_metadata,
        &car,
        1_005,
    );
    assert_eq!(conflict.status, 422);
    assert_eq!(
        decode_service_error(&conflict).code,
        MusubiPublicationServiceErrorCodeV1::OperationConflict
    );
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 1);
    let refresh_authorization =
        authorization_header(&fixture.runtime, &fixture.request, &metadata, 62_000);
    let refreshed = seed_http_response(
        &mut fixture,
        &refresh_authorization,
        &metadata,
        &car,
        62_001,
    );
    assert_eq!(refreshed.status, 200);
    assert_ne!(refreshed.body, first.body);
    let refreshed_receipt: MusubiSeedIngressReceiptV1 =
        norito::decode_canonical_with_limits(&refreshed.body, RESPONSE_DECODE_LIMITS)
            .expect("refreshed receipt");
    refreshed_receipt
        .verify(&fixture.request.binding, 62_001)
        .expect("refreshed receipt is live and exact");
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 2);
}
#[test]
fn private_service_cached_seed_receipt_requires_retained_seed_custody() {
    let mut fixture = private_service_fixture(false);
    let metadata = fixture.metadata.clone();
    let car = fixture.car.clone();
    let first_authorization =
        authorization_header(&fixture.runtime, &fixture.request, &metadata, 1_000);
    let first = seed_http_response(&mut fixture, &first_authorization, &metadata, &car, 1_001);
    assert_eq!(first.status, 200);
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 1);

    let retained_calls = Arc::clone(&fixture.calls);
    fixture.service.seed_ingress = Box::new(RecordingSeedIngress {
        provider: fixture.request.binding.seed_provider,
        calls: Arc::new(Mutex::new(0)),
        fail_first: false,
        clock_after_stage: None,
    });
    let retry_authorization =
        authorization_header(&fixture.runtime, &fixture.request, &metadata, 1_002);
    let lost = seed_http_response(&mut fixture, &retry_authorization, &metadata, &car, 1_003);
    assert_eq!(lost.status, 422);
    assert_eq!(
        decode_service_error(&lost).code,
        MusubiPublicationServiceErrorCodeV1::SeedIngressUnavailable,
    );
    assert_eq!(*retained_calls.lock().expect("seed calls"), 1);

    fixture.service.seed_ingress = Box::new(RecordingSeedIngress {
        provider: fixture.request.binding.seed_provider,
        calls: retained_calls,
        fail_first: false,
        clock_after_stage: None,
    });
    let restored_authorization =
        authorization_header(&fixture.runtime, &fixture.request, &metadata, 1_004);
    let restored = seed_http_response(
        &mut fixture,
        &restored_authorization,
        &metadata,
        &car,
        1_005,
    );
    assert_eq!(restored.status, 200);
    assert_eq!(restored.body, first.body);
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 1);
}
#[test]
fn private_service_rejects_consumed_authorization_but_accepts_fresh_retry() {
    let mut fixture = private_service_fixture(true);
    let metadata = fixture.metadata.clone();
    let car = fixture.car.clone();
    let authorization = authorization_header(&fixture.runtime, &fixture.request, &metadata, 2_000);
    let failed = seed_http_response(&mut fixture, &authorization, &metadata, &car, 2_001);
    let failed_error = decode_service_error(&failed);
    assert_eq!(failed.status, 503);
    assert_eq!(
        failed_error.code,
        MusubiPublicationServiceErrorCodeV1::SeedIngressUnavailable
    );
    assert!(failed_error.retryable);
    let replay = seed_http_response(&mut fixture, &authorization, &metadata, &car, 2_002);
    assert_eq!(replay.status, 401);
    let replay_error = decode_service_error(&replay);
    assert_eq!(
        replay_error.code,
        MusubiPublicationServiceErrorCodeV1::AuthorizationReplay
    );
    assert!(replay_error.retryable);
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 1);
    let mut substituted = fixture.request.clone();
    substituted.binding.nonce = [0x7c; 32];
    let substituted_metadata =
        norito::encode_canonical(&substituted).expect("substituted metadata");
    let substituted_authorization =
        authorization_header(&fixture.runtime, &substituted, &substituted_metadata, 2_003);
    let conflict = seed_http_response(
        &mut fixture,
        &substituted_authorization,
        &substituted_metadata,
        &car,
        2_004,
    );
    assert_eq!(conflict.status, 422);
    assert_eq!(
        decode_service_error(&conflict).code,
        MusubiPublicationServiceErrorCodeV1::OperationConflict
    );
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 1);
    let fresh = authorization_header(&fixture.runtime, &fixture.request, &metadata, 2_005);
    let success = seed_http_response(&mut fixture, &fresh, &metadata, &car, 2_006);
    assert_eq!(success.status, 200);
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 2);
}
#[test]
fn private_service_rejects_expiry_signer_metadata_and_car_substitution() {
    let mut fixture = private_service_fixture(false);
    let metadata = fixture.metadata.clone();
    let car = fixture.car.clone();
    let expired_authorization =
        authorization_header(&fixture.runtime, &fixture.request, &metadata, 3_000);
    let expired = seed_http_response(
        &mut fixture,
        &expired_authorization,
        &metadata,
        &car,
        33_001,
    );
    let expired_error = decode_service_error(&expired);
    assert_eq!(
        expired_error.code,
        MusubiPublicationServiceErrorCodeV1::AuthorizationExpired
    );
    assert!(expired_error.retryable);
    let future_authorization =
        authorization_header(&fixture.runtime, &fixture.request, &metadata, 50_000);
    let future = seed_http_response(&mut fixture, &future_authorization, &metadata, &car, 33_002);
    let future_error = decode_service_error(&future);
    assert_eq!(
        future_error.code,
        MusubiPublicationServiceErrorCodeV1::AuthorizationExpired
    );
    assert!(future_error.retryable);
    let valid_authorization =
        authorization_header(&fixture.runtime, &fixture.request, &metadata, 33_003);
    let mut substituted_request = fixture.request.clone();
    substituted_request.binding.nonce = [0x77; 32];
    let substituted_metadata =
        norito::encode_canonical(&substituted_request).expect("substituted metadata");
    let substituted = seed_http_response(
        &mut fixture,
        &valid_authorization,
        &substituted_metadata,
        &car,
        33_004,
    );
    assert_eq!(
        decode_service_error(&substituted).code,
        MusubiPublicationServiceErrorCodeV1::AuthorizationInvalid
    );
    let mut wrong_body = car.clone();
    wrong_body[0] ^= 0x01;
    let wrong_body_response = seed_http_response(
        &mut fixture,
        &valid_authorization,
        &metadata,
        &wrong_body,
        33_004,
    );
    assert_eq!(
        decode_service_error(&wrong_body_response).code,
        MusubiPublicationServiceErrorCodeV1::CarBodyMismatch
    );
    let authorization_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&valid_authorization)
        .expect("decode authorization");
    let mut wrong_signer: MusubiPublicationRuntimeAuthorizationV1 =
        norito::decode_canonical(&authorization_bytes).expect("authorization");
    let attacker = KeyPair::try_from_seed(
        b"musubi-publication-runtime-attacker".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("attacker key");
    wrong_signer.approvals[0] = MusubiPublicationRuntimeAuthorizationApprovalV1 {
        public_key: attacker.public_key().clone(),
        signature: SignatureOf::try_new(attacker.private_key(), &wrong_signer.payload)
            .expect("attacker signature"),
    };
    let wrong_signer = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(norito::encode_canonical(&wrong_signer).expect("wrong-signer authorization"));
    let wrong_signer_response =
        seed_http_response(&mut fixture, &wrong_signer, &metadata, &car, 33_004);
    assert_eq!(
        decode_service_error(&wrong_signer_response).code,
        MusubiPublicationServiceErrorCodeV1::AuthorizationInvalid
    );
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 0);
}
#[test]
fn private_service_rejects_noncanonical_headers_and_nonexact_routes() {
    let mut fixture = private_service_fixture(false);
    let metadata = fixture.metadata.clone();
    let car = fixture.car.clone();
    let authorization = authorization_header(&fixture.runtime, &fixture.request, &metadata, 6_000);
    let encoded_metadata = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&metadata);
    fixture.clock.store(6_001, Ordering::SeqCst);
    let route = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: "/v1/musubi/publication/seed-ingress/extra",
            content_type: APPLICATION_MUSUBI_SEED_ENVELOPE,
            authorization: Some(&authorization),
            seed_ingress_metadata: Some(&encoded_metadata),
            body: &car,
        });
    assert_eq!(route.status, 404);
    assert_eq!(
        decode_service_error(&route).code,
        MusubiPublicationServiceErrorCodeV1::RouteNotFound
    );
    let method = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "GET",
            path: MUSUBI_PUBLICATION_SEED_INGRESS_PATH_V1,
            content_type: APPLICATION_MUSUBI_SEED_ENVELOPE,
            authorization: Some(&authorization),
            seed_ingress_metadata: Some(&encoded_metadata),
            body: &car,
        });
    assert_eq!(method.status, 405);
    assert_eq!(
        decode_service_error(&method).code,
        MusubiPublicationServiceErrorCodeV1::MethodInvalid
    );
    let legacy_raw_car = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_SEED_INGRESS_PATH_V1,
            content_type: "application/vnd.sorafs.car",
            authorization: Some(&authorization),
            seed_ingress_metadata: Some(&encoded_metadata),
            body: &fixture.raw_car,
        });
    assert_eq!(legacy_raw_car.status, 415);
    assert_eq!(
        decode_service_error(&legacy_raw_car).code,
        MusubiPublicationServiceErrorCodeV1::MediaTypeInvalid
    );
    assert_eq!(*fixture.calls.lock().expect("seed calls"), 0);
    let padded_authorization = format!("{authorization}=");
    let noncanonical = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_SEED_INGRESS_PATH_V1,
            content_type: APPLICATION_MUSUBI_SEED_ENVELOPE,
            authorization: Some(&padded_authorization),
            seed_ingress_metadata: Some(&encoded_metadata),
            body: &car,
        });
    assert_eq!(noncanonical.status, 401);
    assert_eq!(
        decode_service_error(&noncanonical).code,
        MusubiPublicationServiceErrorCodeV1::AuthorizationInvalid
    );
    let malformed_control = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: Some(&authorization),
            seed_ingress_metadata: None,
            body: b"not norito",
        });
    assert_eq!(malformed_control.status, 422);
    assert_eq!(
        decode_service_error(&malformed_control).code,
        MusubiPublicationServiceErrorCodeV1::RequestInvalid
    );
}
#[test]
fn private_service_authenticates_control_requests_before_embedded_evidence() {
    let mut fixture = control_service_fixture(false, false);
    let attacker = KeyPair::try_from_seed(
        b"musubi-publication-control-signature-attacker".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("attacker key");
    let mut storage_request = fixture.storage_request.clone();
    let receipt_hash = storage_request.staging_receipt.payload.signing_hash();
    storage_request.staging_receipt.approvals[0].signature =
        SignatureOf::try_from_hash(attacker.private_key(), receipt_hash)
            .expect("mismatched receipt signature");
    let storage_body = norito::encode_canonical(&storage_request).expect("storage request bytes");
    fixture.clock.store(2_001, Ordering::SeqCst);
    let anonymous_storage = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: None,
            seed_ingress_metadata: None,
            body: &storage_body,
        });
    assert_eq!(anonymous_storage.status, 401);
    assert_eq!(
        decode_service_error(&anonymous_storage).code,
        MusubiPublicationServiceErrorCodeV1::AuthorizationInvalid
    );
    let storage_authorization = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        storage_request.operation_id,
        &storage_body,
        2_000,
    );
    let authenticated_storage = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: Some(&storage_authorization),
            seed_ingress_metadata: None,
            body: &storage_body,
        });
    assert_eq!(authenticated_storage.status, 422);
    assert_eq!(
        decode_service_error(&authenticated_storage).code,
        MusubiPublicationServiceErrorCodeV1::RequestInvalid
    );
    let valid_storage_body =
        norito::encode_canonical(&fixture.storage_request).expect("valid storage request bytes");
    let valid_storage_authorization = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        fixture.storage_request.operation_id,
        &valid_storage_body,
        2_002,
    );
    fixture.clock.store(2_003, Ordering::SeqCst);
    let valid_storage = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: Some(&valid_storage_authorization),
            seed_ingress_metadata: None,
            body: &valid_storage_body,
        });
    assert_eq!(valid_storage.status, 200);
    let mut readback_request = fixture.readback_request.clone();
    readback_request.location.archive_id = ArchiveId::new([0xee; 32]);
    let readback_body =
        norito::encode_canonical(&readback_request).expect("readback request bytes");
    fixture.clock.store(3_001, Ordering::SeqCst);
    let anonymous_readback = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_PROVIDER_READBACK_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: None,
            seed_ingress_metadata: None,
            body: &readback_body,
        });
    assert_eq!(anonymous_readback.status, 401);
    assert_eq!(
        decode_service_error(&anonymous_readback).code,
        MusubiPublicationServiceErrorCodeV1::AuthorizationInvalid
    );
    let readback_authorization = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::ProviderReadback,
        readback_request.operation_id,
        &readback_body,
        3_000,
    );
    let authenticated_readback = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_PROVIDER_READBACK_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: Some(&readback_authorization),
            seed_ingress_metadata: None,
            body: &readback_body,
        });
    assert_eq!(authenticated_readback.status, 422);
    assert_eq!(
        decode_service_error(&authenticated_readback).code,
        MusubiPublicationServiceErrorCodeV1::RequestInvalid
    );
}
#[test]
fn authenticated_staging_receipt_failures_have_exact_deadletter_reasons() {
    let mut invalid_fixture = control_service_fixture(false, false);
    let attacker = KeyPair::try_from_seed(
        b"musubi-publication-invalid-receipt-observer".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("attacker key");
    let mut invalid_request = invalid_fixture.storage_request.clone();
    let receipt_hash = invalid_request.staging_receipt.payload.signing_hash();
    invalid_request.staging_receipt.approvals[0].signature =
        SignatureOf::try_from_hash(attacker.private_key(), receipt_hash)
            .expect("mismatched receipt signature");
    let invalid_body =
        norito::encode_canonical(&invalid_request).expect("invalid receipt request bytes");
    let invalid_authorization = control_authorization_header(
        &invalid_fixture.runtime,
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        invalid_request.operation_id,
        &invalid_body,
        2_000,
    );
    let invalid_error = invalid_fixture
        .service
        .handle_storage_coordination(
            MusubiPublicationPrivateHttpRequestV1 {
                method: "POST",
                path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
                content_type: APPLICATION_NORITO,
                authorization: Some(&invalid_authorization),
                seed_ingress_metadata: None,
                body: &invalid_body,
            },
            2_001,
            std::time::Instant::now(),
        )
        .expect_err("authenticated invalid staging receipt");
    assert_eq!(
        invalid_error.telemetry,
        Some(MusubiPublicationServiceTelemetryEventV1::IngestDeadletter(
            MusubiIngestDeadletterReasonV1::ReceiptInvalid,
        ))
    );
    let mut future_fixture = control_service_fixture(false, false);
    future_fixture.service.config.max_future_clock_skew_ms = 1;
    let future_body = norito::encode_canonical(&future_fixture.storage_request)
        .expect("future receipt request bytes");
    let future_authorization = control_authorization_header(
        &future_fixture.runtime,
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        future_fixture.storage_request.operation_id,
        &future_body,
        2,
    );
    let future_error = future_fixture
        .service
        .handle_storage_coordination(
            MusubiPublicationPrivateHttpRequestV1 {
                method: "POST",
                path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
                content_type: APPLICATION_NORITO,
                authorization: Some(&future_authorization),
                seed_ingress_metadata: None,
                body: &future_body,
            },
            2,
            std::time::Instant::now(),
        )
        .expect_err("authenticated future-skewed staging receipt");
    assert_eq!(
        future_error.telemetry,
        Some(MusubiPublicationServiceTelemetryEventV1::IngestDeadletter(
            MusubiIngestDeadletterReasonV1::ReceiptInvalid,
        ))
    );
}
#[test]
fn storage_coordination_accepts_an_expired_receipt_for_the_exact_finalized_archive() {
    let mut fixture = control_service_fixture(false, false);
    let body = norito::encode_canonical(&fixture.storage_request)
        .expect("expired finalized archive request bytes");
    let authorization = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        fixture.storage_request.operation_id,
        &body,
        120_000,
    );
    let response = fixture
        .service
        .handle_storage_coordination(
            MusubiPublicationPrivateHttpRequestV1 {
                method: "POST",
                path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
                content_type: APPLICATION_NORITO,
                authorization: Some(&authorization),
                seed_ingress_metadata: None,
                body: &body,
            },
            120_001,
            std::time::Instant::now(),
        )
        .expect("finalized archive outlives its registration receipt");
    let decoded: MusubiStorageCoordinationResponseV1 =
        norito::decode_canonical_with_limits(&response, RESPONSE_DECODE_LIMITS)
            .expect("storage response");
    assert_eq!(decoded, fixture.storage_response);
}
#[test]
fn private_service_accepts_exact_storage_and_provider_readback_evidence() {
    let mut fixture = control_service_fixture(false, false);
    let storage_body =
        norito::encode_canonical(&fixture.storage_request).expect("storage request bytes");
    let storage_authorization = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        fixture.storage_request.operation_id,
        &storage_body,
        2_000,
    );
    fixture.clock.store(2_001, Ordering::SeqCst);
    let storage = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: Some(&storage_authorization),
            seed_ingress_metadata: None,
            body: &storage_body,
        });
    assert_eq!(storage.status, 200);
    let storage_response: MusubiStorageCoordinationResponseV1 =
        norito::decode_canonical_with_limits(&storage.body, RESPONSE_DECODE_LIMITS)
            .expect("storage response");
    assert_eq!(storage_response, fixture.storage_response);
    let readback_body =
        norito::encode_canonical(&fixture.readback_request).expect("readback request bytes");
    let readback_authorization = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::ProviderReadback,
        fixture.readback_request.operation_id,
        &readback_body,
        3_000,
    );
    fixture.clock.store(3_001, Ordering::SeqCst);
    let readback = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_PROVIDER_READBACK_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: Some(&readback_authorization),
            seed_ingress_metadata: None,
            body: &readback_body,
        });
    assert_eq!(readback.status, 200);
    let readback_response: MusubiProviderReadbackResponseV1 =
        norito::decode_canonical_with_limits(&readback.body, RESPONSE_DECODE_LIMITS)
            .expect("readback response");
    assert_eq!(readback_response, fixture.readback_response);
}
#[test]
fn cached_storage_response_rechecks_finalized_registration_without_replaying_effects() {
    use std::sync::atomic::AtomicUsize;

    struct ClosedRegistration(Arc<AtomicUsize>, MusubiPublicationServiceBackendErrorV1);
    impl MusubiStorageCoordinationBackendV1 for ClosedRegistration {
        fn verify_current_registration(
            &self,
            _request: &MusubiStorageCoordinationRequestV1,
        ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(self.1)
        }

        fn coordinate_storage(
            &mut self,
            _request: &VerifiedStorageCoordinationRequestV1<'_>,
        ) -> Result<MusubiStorageCoordinationResponseV1, MusubiPublicationServiceBackendErrorV1>
        {
            panic!("cached replay must not repeat storage effects");
        }
    }

    let mut fixture = control_service_fixture(false, false);
    let request = fixture.storage_request.clone();
    let first = control_storage_response(&mut fixture, &request, 2_000);
    assert_eq!(first.status, 200);

    let checks = Arc::new(AtomicUsize::new(0));
    fixture.service.storage = Box::new(ClosedRegistration(
        Arc::clone(&checks),
        MusubiPublicationServiceBackendErrorV1::Retryable,
    ));
    let lagging = control_storage_response(&mut fixture, &request, 2_002);
    assert_eq!(lagging.status, 503);
    assert_eq!(
        decode_service_error(&lagging).code,
        MusubiPublicationServiceErrorCodeV1::StorageCoordinationUnavailable,
    );
    assert!(decode_service_error(&lagging).retryable);
    assert_eq!(checks.load(Ordering::SeqCst), 1);

    fixture.service.storage = Box::new(ClosedRegistration(
        Arc::clone(&checks),
        MusubiPublicationServiceBackendErrorV1::Permanent,
    ));
    let revoked = control_storage_response(&mut fixture, &request, 2_004);
    assert_eq!(revoked.status, 422);
    assert_eq!(
        decode_service_error(&revoked).code,
        MusubiPublicationServiceErrorCodeV1::StorageCoordinationUnavailable,
    );
    assert!(!decode_service_error(&revoked).retryable);
    assert_eq!(checks.load(Ordering::SeqCst), 2);

    fixture.service.storage = Box::new(FixedStorage {
        response: fixture.storage_response.clone(),
        substitute: false,
    });
    let restored = control_storage_response(&mut fixture, &request, 2_006);
    assert_eq!(restored.status, 200);
    assert_eq!(restored.body, first.body);
}

#[test]
fn cached_provider_readback_rechecks_current_target_before_replaying_response() {
    let mut fixture = control_service_fixture(false, false);
    let request = fixture.readback_request.clone();
    let first = control_readback_response(&mut fixture, &request, 3_000);
    assert_eq!(first.status, 200);

    fixture.service.readback = Box::new(UnusedReadback);
    let revoked = control_readback_response(&mut fixture, &request, 3_002);
    assert_eq!(revoked.status, 422);
    assert_eq!(
        decode_service_error(&revoked).code,
        MusubiPublicationServiceErrorCodeV1::ProviderReadbackUnavailable,
    );

    fixture.service.readback = Box::new(FixedReadback {
        response: fixture.readback_response.clone(),
        substitute: false,
    });
    let restored = control_readback_response(&mut fixture, &request, 3_004);
    assert_eq!(restored.status, 200);
    assert_eq!(restored.body, first.body);
}
/// Drop the service's durable journal, then reopen it from disk as a restarted service would.
#[cfg(unix)]
fn reopen_durable_journal(
    fixture: &mut ControlServiceFixture,
    root: &std::path::Path,
    binding: &MusubiPublicationServiceJournalBindingV1,
    limits: DurableMusubiPublicationServiceJournalLimitsV1,
) {
    let fallback = InMemoryMusubiPublicationServiceJournalV1::new(binding.clone(), 1, 1)
        .expect("temporary journal");
    let durable = std::mem::replace(&mut fixture.service.journal, Box::new(fallback));
    drop(durable);
    fixture.service.journal = Box::new(
        DurableMusubiPublicationServiceJournalV1::open(root, binding.clone(), limits)
            .expect("reopen durable readback journal"),
    );
}
#[cfg(unix)]
#[test]
fn durable_readback_journal_separates_replacement_and_renewal_targets() {
    let mut fixture = control_service_fixture(false, false);
    let root = tempfile::tempdir().expect("durable readback journal root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private journal root permissions");
    let binding =
        MusubiPublicationServiceJournalBindingV1::from_configuration(&fixture.service.config);
    // The journal must retain all three fixed-shape fixture responses while still reserving one
    // full protocol-sized terminal response before the next backend call.
    let retained_response_bytes = norito::encode_canonical(&fixture.readback_response)
        .expect("canonical readback response")
        .len()
        .checked_mul(3)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .expect("three retained readback responses fit u64");
    let response_budget = MAX_CONTROL_RESPONSE_BYTES_U64
        .checked_add(retained_response_bytes)
        .expect("readback response budget fits u64");
    let limits = DurableMusubiPublicationServiceJournalLimitsV1::new(
        16,
        64,
        response_budget,
        response_budget + 1024 * 1024,
    )
    .expect("durable journal limits");
    fixture.service.journal = Box::new(
        DurableMusubiPublicationServiceJournalV1::initialize(root.path(), binding.clone(), limits)
            .expect("initialize durable readback journal"),
    );
    let calls = Arc::new(Mutex::new(Vec::new()));
    fixture.service.readback = Box::new(RecordingExactReadback {
        calls: Arc::clone(&calls),
    });
    let initial = fixture.readback_request.clone();
    let initial_response = control_readback_response(&mut fixture, &initial, 3_000);
    assert_eq!(initial_response.status, 200);
    assert_eq!(calls.lock().expect("readback calls").len(), 1);
    reopen_durable_journal(&mut fixture, root.path(), &binding, limits);
    let cached = control_readback_response(&mut fixture, &initial, 3_100);
    assert_eq!(cached.status, 200);
    assert_eq!(cached.body, initial_response.body);
    assert_eq!(calls.lock().expect("cached readback calls").len(), 1);
    let mut replacement = initial.clone();
    replacement.location.location_id = MusubiArchiveLocationIdV1::new([0xe1; 32]);
    replacement.location.finalized_height += 1;
    assert_ne!(
        provider_readback_target(&initial.location, initial.provider),
        provider_readback_target(&replacement.location, replacement.provider)
    );
    let replacement_response = control_readback_response(&mut fixture, &replacement, 3_200);
    assert_eq!(replacement_response.status, 200);
    let mut renewal = replacement.clone();
    renewal.location.revision += 1;
    renewal.location.finalized_height += 1;
    renewal.location.renew_after_epoch += 1;
    renewal.location.expires_at_epoch += 1;
    assert_ne!(
        provider_readback_target(&replacement.location, replacement.provider),
        provider_readback_target(&renewal.location, renewal.provider)
    );
    let renewal_response = control_readback_response(&mut fixture, &renewal, 3_300);
    assert_eq!(renewal_response.status, 200);
    assert_eq!(calls.lock().expect("replacement readback calls").len(), 3);
    reopen_durable_journal(&mut fixture, root.path(), &binding, limits);
    let cached_replacement = control_readback_response(&mut fixture, &replacement, 3_400);
    assert_eq!(cached_replacement.status, 200);
    assert_eq!(cached_replacement.body, replacement_response.body);
    let cached_renewal = control_readback_response(&mut fixture, &renewal, 3_500);
    assert_eq!(cached_renewal.status, 200);
    assert_eq!(cached_renewal.body, renewal_response.body);
    assert_eq!(
        calls.lock().expect("durable cached readback calls").len(),
        3
    );
    let mut substituted_same_tuple = renewal.clone();
    substituted_same_tuple.location.renew_after_epoch += 1;
    assert_eq!(
        provider_readback_target(
            &substituted_same_tuple.location,
            substituted_same_tuple.provider
        ),
        provider_readback_target(&renewal.location, renewal.provider)
    );
    let conflict = control_readback_response(&mut fixture, &substituted_same_tuple, 3_600);
    assert_eq!(conflict.status, 422);
    assert_eq!(
        decode_service_error(&conflict).code,
        MusubiPublicationServiceErrorCodeV1::OperationConflict
    );
    assert_eq!(calls.lock().expect("conflicting readback calls").len(), 3);
}
#[test]
fn storage_response_rejects_a_refreshed_receipt_after_registration() {
    let fixture = control_service_fixture(false, false);
    let broker_key = KeyPair::try_from_seed(
        b"musubi-publication-control-broker".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("broker key");
    let mut request = fixture.storage_request.clone();
    let payload = MusubiSeedIngressReceiptPayloadV1 {
        version: 1,
        binding: request.staging_receipt.payload.binding.clone(),
        issued_at_ms: request.staging_receipt.payload.expires_at_ms + 1,
        expires_at_ms: request.staging_receipt.payload.expires_at_ms + 60_001,
    };
    request.staging_receipt = MusubiSeedIngressReceiptV1 {
        approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
            public_key: broker_key.public_key().clone(),
            signature: SignatureOf::try_from_hash(broker_key.private_key(), payload.signing_hash())
                .expect("refreshed receipt signature"),
        }],
        payload,
    };
    assert_ne!(
        fixture.storage_response.archive.staging_receipt,
        request.staging_receipt
    );
    assert!(fixture.storage_response.validate_for(&request).is_err());
    request.staging_receipt.payload.binding.nonce = [0xee; 32];
    request.staging_receipt.approvals[0].signature = SignatureOf::try_from_hash(
        broker_key.private_key(),
        request.staging_receipt.payload.signing_hash(),
    )
    .expect("different-operation receipt signature");
    assert!(fixture.storage_response.validate_for(&request).is_err());
}
#[test]
fn storage_response_requires_replication_quorum_and_exact_lock_digest() {
    let fixture = control_service_fixture(false, false);
    let mut below_quorum = fixture.storage_response.clone();
    let MusubiStorageLocationDispositionV1::NeedsRegistration {
        completed_providers,
        ..
    } = &mut below_quorum.disposition
    else {
        panic!("fixture requires location registration")
    };
    completed_providers.truncate(usize::from(MUSUBI_MIN_HEALTHY_REPLICAS_V1).saturating_sub(1));
    assert!(below_quorum.validate_for(&fixture.storage_request).is_err());
    let mut wrong_lock = fixture.storage_request.clone();
    wrong_lock.verification_lock_digest = MusubiVerificationLockDigestV1::new([0xee; 32]);
    assert!(fixture.storage_response.validate_for(&wrong_lock).is_err());
}
#[test]
fn storage_location_generations_have_distinct_bounded_journal_targets() {
    let first = storage_generation_target(1);
    let last = storage_generation_target(
        u8::try_from(MUSUBI_MAX_PUBLICATION_LOCATION_ATTEMPTS_V1)
            .expect("location generation bound fits u8"),
    );
    assert_ne!(first, last);
    assert!(valid_storage_generation_target(first));
    assert!(valid_storage_generation_target(last));
    assert!(!valid_storage_generation_target([0; 32]));
    assert!(!valid_storage_generation_target(storage_generation_target(
        u8::try_from(MUSUBI_MAX_PUBLICATION_LOCATION_ATTEMPTS_V1 + 1)
            .expect("one past the bound fits u8"),
    )));
    let mut malformed = first;
    malformed[31] = 1;
    assert!(!valid_storage_generation_target(malformed));
}
#[test]
fn storage_response_never_reuses_a_prior_location_generation() {
    let fixture = control_service_fixture(false, false);
    let retired_location_id = fixture.storage_response.location_id;
    let mut replacement_request = fixture.storage_request.clone();
    replacement_request.generation = 2;
    replacement_request.prior_location_ids = vec![retired_location_id];
    replacement_request
        .validate()
        .expect("a sorted second generation is structurally valid");
    assert!(
        fixture
            .storage_response
            .validate_for(&replacement_request)
            .is_err(),
        "the coordinator cannot return a retired stable identity"
    );
    let mut replacement = fixture.storage_response;
    replacement.location_id = MusubiArchiveLocationIdV1::new([0xee; 32]);
    assert!(
        replacement.validate_for(&replacement_request).is_err(),
        "a new location still requires the exact replacement request digest"
    );
    replacement.request_digest = replacement_request.canonical_request_digest().unwrap();
    replacement
        .validate_for(&replacement_request)
        .expect("a never-before-used replacement identity remains valid");
    let mut unsorted_third = replacement_request;
    unsorted_third.generation = 3;
    unsorted_third.prior_location_ids = vec![
        MusubiArchiveLocationIdV1::new([0xff; 32]),
        retired_location_id,
    ];
    assert!(unsorted_third.validate().is_err());
}
#[test]
fn storage_request_binds_immutable_registration_without_freezing_location_state() {
    let fixture = control_service_fixture(false, false);
    let mut wrong_height = fixture.storage_request.clone();
    wrong_height
        .finalized_registration
        .registration
        .registered_at_height += 1;
    wrong_height.validate().expect(
        "a different internally valid projection is digest-bound but must be authorized upstream",
    );
    let exact = norito::encode_canonical(&fixture.storage_request).expect("exact request");
    let substituted = norito::encode_canonical(&wrong_height).expect("substituted request");
    assert_ne!(
        request_digest(
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            &exact,
        )
        .expect("exact request digest"),
        request_digest(
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            &substituted,
        )
        .expect("substituted request digest")
    );
    assert!(
        fixture
            .storage_response
            .validate_for(&wrong_height)
            .is_err()
    );
    let mut wrong_registrant = fixture.storage_request.clone();
    let other = KeyPair::try_from_seed(
        b"musubi-storage-authoritative-record-substitution".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("other registrant key");
    wrong_registrant
        .finalized_registration
        .registration
        .registered_by = AccountId::new(other.public_key().clone());
    assert!(wrong_registrant.validate().is_err());
    let mut missing_transaction = fixture.storage_request.clone();
    missing_transaction.finalized_registration.transaction_hash = [0; 32];
    assert!(missing_transaction.validate().is_err());
    let mut wrong_lock = fixture.storage_request.clone();
    wrong_lock.verification_lock_digest = MusubiVerificationLockDigestV1::new([0xee; 32]);
    wrong_lock
        .validate()
        .expect("a nonzero lock digest remains structurally valid");
    assert!(fixture.storage_response.validate_for(&wrong_lock).is_err());
    wrong_lock.verification_lock_digest = MusubiVerificationLockDigestV1::new([0; 32]);
    assert!(wrong_lock.validate().is_err());
    let mut pre_registration_snapshot = fixture.storage_request.clone();
    pre_registration_snapshot
        .finalized_registration
        .snapshot
        .finalized_height = pre_registration_snapshot
        .finalized_registration
        .registration
        .registered_at_height
        .saturating_sub(1);
    assert!(pre_registration_snapshot.validate().is_err());
    let mut later_current_archive = fixture.storage_response;
    later_current_archive.archive.location_revision = 2;
    later_current_archive.archive.location_ids = vec![MusubiArchiveLocationIdV1::new([0xdd; 32])];
    let MusubiStorageLocationDispositionV1::NeedsRegistration {
        expected_location_revision,
        ..
    } = &mut later_current_archive.disposition
    else {
        panic!("fixture requires location registration")
    };
    *expected_location_revision = 2;
    later_current_archive
        .validate_for(&fixture.storage_request)
        .expect("a later finalized location directory preserves registration evidence");
}
#[test]
fn private_service_rejects_substituted_storage_and_readback_backend_evidence() {
    let mut fixture = control_service_fixture(true, true);
    let storage_body =
        norito::encode_canonical(&fixture.storage_request).expect("storage request bytes");
    let storage_authorization = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        fixture.storage_request.operation_id,
        &storage_body,
        4_000,
    );
    fixture.clock.store(4_001, Ordering::SeqCst);
    let storage = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: Some(&storage_authorization),
            seed_ingress_metadata: None,
            body: &storage_body,
        });
    assert_eq!(storage.status, 422);
    assert_eq!(
        decode_service_error(&storage).code,
        MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid
    );
    let readback_body =
        norito::encode_canonical(&fixture.readback_request).expect("readback request bytes");
    let readback_authorization = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::ProviderReadback,
        fixture.readback_request.operation_id,
        &readback_body,
        5_000,
    );
    fixture.clock.store(5_001, Ordering::SeqCst);
    let readback = fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_PROVIDER_READBACK_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: Some(&readback_authorization),
            seed_ingress_metadata: None,
            body: &readback_body,
        });
    assert_eq!(readback.status, 422);
    assert_eq!(
        decode_service_error(&readback).code,
        MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid
    );
}
#[test]
fn restored_journal_preserves_completed_idempotency_and_replay_state() {
    let (client, _) = client();
    let binding = MusubiPublicationOperationBindingV1 {
        operation_id: [0x81; 32],
        network_id: *client.network_id(),
        publisher: client.account().clone(),
        archive_id: ArchiveId::new([0x82; 32]),
        car_body_digest: MusubiContentDigestV1::new([0x83; 32]),
        car_body_length: 99,
    };
    let journal_binding = MusubiPublicationServiceJournalBindingV1 {
        network_id: binding.network_id,
        ingress_broker: binding.publisher.clone(),
        seed_provider: ProviderId::new([0x88; 32]),
    };
    let mut journal =
        InMemoryMusubiPublicationServiceJournalV1::new(journal_binding, 8, 8).expect("journal");
    let attempt = MusubiPublicationJournalAttemptV1 {
        key: MusubiPublicationIdempotencyKeyV1 {
            operation: MusubiPublicationRuntimeOperationV1::SeedIngress,
            operation_id: binding.operation_id,
            target: [0; 32],
        },
        binding: binding.clone(),
        request_digest: [0x84; 32],
        authorization_digest: [0x85; 32],
        authorization_expires_at_ms: 20_000,
    };
    assert_eq!(
        journal.begin(&attempt, 10_000).expect("reserve"),
        MusubiPublicationJournalBeginV1::Execute
    );
    journal
        .commit(attempt.key, attempt.request_digest, b"canonical response")
        .expect("commit");
    // Cloning models restoring the same durable records into a replacement service process.
    let mut restored = journal.clone();
    let mut retry = attempt.clone();
    retry.authorization_digest = [0x86; 32];
    assert_eq!(
        restored.begin(&retry, 10_001).expect("cached retry"),
        MusubiPublicationJournalBeginV1::Cached(b"canonical response".to_vec())
    );
    assert_eq!(
        restored.begin(&retry, 10_001).expect("cached replay"),
        MusubiPublicationJournalBeginV1::Cached(b"canonical response".to_vec())
    );
    let mut conflict = retry.clone();
    conflict.binding.archive_id = ArchiveId::new([0x87; 32]);
    assert_eq!(
        restored.begin(&conflict, 10_002),
        Err(MusubiPublicationServiceJournalErrorV1::Conflict)
    );
    let mut reset_conflict = retry.clone();
    reset_conflict.binding.network_id = test_network_id(0x8a);
    assert_eq!(
        restored.begin(&reset_conflict, 10_002),
        Err(MusubiPublicationServiceJournalErrorV1::Invalid)
    );
    let replay = MusubiPublicationJournalAttemptV1 {
        key: MusubiPublicationIdempotencyKeyV1 {
            operation: MusubiPublicationRuntimeOperationV1::ProviderReadback,
            operation_id: binding.operation_id,
            target: [0x88; 32],
        },
        binding,
        request_digest: [0x89; 32],
        authorization_digest: attempt.authorization_digest,
        authorization_expires_at_ms: attempt.authorization_expires_at_ms,
    };
    assert_eq!(
        restored.begin(&replay, 10_003),
        Err(MusubiPublicationServiceJournalErrorV1::Replay)
    );
}

#[test]
fn storage_request_digest_uses_exact_canonical_authorization_domain() {
    let fixture = control_service_fixture(false, false);
    let request = &fixture.storage_request;
    let canonical = norito::encode_canonical(request).unwrap();
    let digest = request.canonical_request_digest().unwrap();
    assert_eq!(
        digest,
        request_digest(
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            &canonical
        )
        .unwrap()
    );
    assert_eq!(fixture.storage_response.request_digest, digest);
    {
        let _ambient = norito::core::DecodeFlagsGuard::enter(
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN,
        );
        assert_eq!(request.canonical_request_digest().unwrap(), digest);
        fixture.storage_response.validate_for(request).unwrap();
    }
    let mut changed = request.clone();
    changed.verification_lock_digest = MusubiVerificationLockDigestV1::new([0xee; 32]);
    assert_ne!(changed.canonical_request_digest().unwrap(), digest);
    assert!(fixture.storage_response.validate_for(&changed).is_err());
    changed.operation_id = [0; 32];
    assert!(changed.canonical_request_digest().is_err());
    let mut changed_response = fixture.storage_response.clone();
    changed_response.request_digest = [0; 32];
    assert!(changed_response.validate_for(request).is_err());
    let mut duplicates = fixture.storage_response.clone();
    let MusubiStorageLocationDispositionV1::NeedsRegistration {
        completed_providers,
        ..
    } = &mut duplicates.disposition
    else {
        panic!("registration fixture");
    };
    completed_providers[1] = completed_providers[0];
    assert!(duplicates.validate_for(request).is_err());
}

#[test]
fn storage_request_digest_charges_one_exact_frame_without_renewal() {
    let fixture = control_service_fixture(false, false);
    let request = &fixture.storage_request;
    let expected = request.canonical_request_digest().unwrap();
    let length = norito::canonical_frame_len(request).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, length, 128);
    norito::with_decode_limits_scope(limits, || {
        assert_eq!(request.canonical_request_digest().unwrap(), expected);
        assert!(request.canonical_request_digest().is_err(),
            "a second request frame cannot renew the original allowance");
    });
}
