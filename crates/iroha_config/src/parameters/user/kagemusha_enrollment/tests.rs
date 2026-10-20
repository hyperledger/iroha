//! Configuration admission only: fixture certificates are not a deployed issuer or provider.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};

fn fixture() -> KagemushaEnrollmentIssuer {
    let vectors: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap();
    let objects = vectors["objects"].as_array().unwrap();
    let original = objects
        .iter()
        .find(|v| v["type"].as_str() == Some("KagemushaWalletSchemeV1"))
        .unwrap();
    let scheme_hex = original["canonical_hex"].as_str().unwrap().to_owned();
    let scheme: KagemushaWalletSchemeV1 =
        norito::decode_canonical(&hex::decode(&scheme_hex).unwrap()).unwrap();
    let original = vectors["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["variant"].as_str() == Some("Request"))
        .unwrap();
    let envelope: KagemushaWalletEnvelopeV1 = norito::decode_canonical(
        &hex::decode(original["canonical_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let KagemushaWalletMessageV1::Request { request } = envelope.message else {
        panic!("Request fixture")
    };
    let certificate = request
        .certificates
        .certificates
        .into_iter()
        .find(|c| c.body.role == KagemushaWalletSignerRoleV1::Enrollment)
        .unwrap();
    let app = KagemushaWalletAppPolicyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        identity: KagemushaWalletAppIdentityV1::Apple {
            app_id: "TEAM.org.example.wallet".into(),
        },
    };
    let enrollment = KagemushaWalletEnrollmentPolicyTemplateV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        app_policy: app.policy_digest().unwrap(),
        platform: KagemushaWalletEnrollmentPlatformV1::Apple {
            attestation_root_sha256: [9; 32],
        },
        regulatory_policy: KagemushaWalletRegulatoryPolicyV1::default(),
        challenge_lifetime_ms: 600_001,
        attestation_lease_lifetime_ms: 0,
    };
    let key = KeyPair::from_seed(vec![32; 32], Algorithm::Ed25519);
    let eligibility = KagemushaEligibilityPolicyTemplateV1 {
        version: 1,
        network_id: scheme.network_id,
        scheme_id: scheme.scheme_id(),
        revision: 1,

        authority: KagemushaEligibilityAuthorityV1::Bank {
            fi_digest: [10; 32],
        },
        public_key: key.public_key().to_bytes().1.try_into().unwrap(),
        maximum_response_ms: 5000,
    };
    KagemushaEnrollmentIssuer {
        revision: 1,
        scope_hex: "01".repeat(32),
        journal_dir: "/var/lib/iroha/enrollment".into(),
        request_timeout_ms: 5000,
        max_inflight: 16,
        providers: vec![KagemushaEnrollmentProvider {
            eligibility_template_hex: hex::encode(eligibility.encode_canonical().unwrap()),
            scheme_hex,
            app_hex: hex::encode(app.encode_canonical().unwrap()),
            enrollment_template_hex: hex::encode(enrollment.encode_canonical().unwrap()),
            certificate_hex: hex::encode(certificate.to_canonical_bytes().unwrap()),
            manifest_digest_hex: "11".repeat(32),
            release_digest_hex: "12".repeat(32),
            service_origin_digest_hex: "13".repeat(32),
            observation_endpoint: "https://provider.example/eligibility".into(),
            observation_credential: "/var/lib/iroha/private/provider-credential".into(),
            worker: KagemushaEnrollmentWorker {
                python_executable: "/opt/issuer/python".into(),
                python_sha256_hex: "41".repeat(32),
                verifier_archive: "/opt/issuer/verifier.pyz".into(),
                verifier_sha256_hex: "42".repeat(32),
                openssl_executable: "/opt/issuer/openssl".into(),
                openssl_sha256_hex: "43".repeat(32),
                attestation_root: Some("/opt/issuer/root.pem".into()),
                store_directory: "/var/lib/issuer/worker".into(),
                exchange_timeout_ms: 60_000,
            },
            signer_private_key: "/var/lib/iroha/private/enrollment-signer".into(),
        }],
    }
}

#[test]
fn canonical_boundaries_reject_aliases_and_excessive_input_before_decode() {
    assert_eq!(bounded_hex("00ff", 2).unwrap(), vec![0, 255]);
    for value in ["", "0", "FF", " 00", "0x00", "000000"] {
        assert!(bounded_hex(value, 2).is_err(), "{value}");
    }
    assert_eq!(digest(&"01".repeat(32)).unwrap(), [1; 32]);
    assert!(digest(&"00".repeat(32)).is_err());
    assert!(digest("01").is_err());
}

#[test]
fn paths_and_endpoints_do_not_accept_credentials_or_ambiguous_routing() {
    assert!(absolute_path(Path::new("/private/issuer")).is_ok());
    for value in ["relative", "/private/../issuer"] {
        assert!(absolute_path(Path::new(value)).is_err());
    }
    assert!(endpoint("https://provider.example/eligibility").is_ok());
    for value in [
        "http://provider.example/",
        "https://u:p@provider.example/",
        "https://provider.example/?token=a",
        "https://provider.example/#alias",
        "https://BANK.example/",
        "https://provider.example",
    ] {
        assert!(endpoint(value).is_err(), "{value}");
    }
}

#[test]
fn complete_bank_route_preserves_exact_originals_and_runtime_selection() {
    let input = fixture();
    let expected = input.providers[0].clone();
    let mut emitter = Emitter::new();
    let actual = input.parse(&mut emitter).unwrap();
    emitter.into_result().unwrap();
    let provider = &actual.providers[0];
    assert_eq!(
        hex::encode(provider.scheme.to_canonical_bytes().unwrap()),
        expected.scheme_hex
    );
    assert_eq!(
        hex::encode(provider.app.encode_canonical().unwrap()),
        expected.app_hex
    );
    assert_eq!(
        hex::encode(provider.enrollment.encode_canonical().unwrap()),
        expected.enrollment_template_hex
    );
    assert_eq!(
        hex::encode(provider.eligibility.encode_canonical().unwrap()),
        expected.eligibility_template_hex
    );
    assert_eq!(
        hex::encode(provider.certificate.to_canonical_bytes().unwrap()),
        expected.certificate_hex
    );
    assert_eq!(
        provider.worker.python_executable,
        expected.worker.python_executable
    );
    assert_eq!(provider.worker.python_sha256, [0x41; 32]);
    assert_eq!(actual.request_timeout, Duration::from_millis(5000));
}

#[test]
fn source_bindings_and_role_are_mandatory() {
    let base = fixture();
    for field in ["scheme", "app", "enrollment", "certificate", "eligibility"] {
        let mut bad = base.clone();
        let route = &mut bad.providers[0];
        match field {
            "scheme" => route.scheme_hex = "00".into(),
            "app" => route.app_hex = "00".into(),
            "enrollment" => route.enrollment_template_hex = "00".into(),
            "certificate" => route.certificate_hex = "00".into(),
            _ => route.eligibility_template_hex = "00".into(),
        }
        assert!(bad.checked().is_err(), "{field}");
    }
    let mut bad = base;
    let mut policy = KagemushaEligibilityPolicyTemplateV1::decode_canonical(
        &hex::decode(&bad.providers[0].eligibility_template_hex).unwrap(),
    )
    .unwrap();
    policy.network_id = [55; 32];
    bad.providers[0].eligibility_template_hex = hex::encode(policy.encode_canonical().unwrap());
    assert!(bad.checked().is_err());
}

#[test]
fn duplicate_routes_refuse_and_explicit_scheme_operator_routes_are_admitted() {
    let mut input = fixture();
    input.providers.push(input.providers[0].clone());
    assert!(input.checked().is_err());
    let mut input = fixture();
    let mut policy = KagemushaEligibilityPolicyTemplateV1::decode_canonical(
        &hex::decode(&input.providers[0].eligibility_template_hex).unwrap(),
    )
    .unwrap();
    policy.authority = KagemushaEligibilityAuthorityV1::SchemeOperator {
        operator_digest: [20; 32],
    };
    input.providers[0].eligibility_template_hex = hex::encode(policy.encode_canonical().unwrap());
    let selected = input.checked().unwrap();
    assert_eq!(
        selected.providers[0].eligibility.authority.scope_digest(),
        [20; 32]
    );
    assert_eq!(selected.providers[0].eligibility, policy);
}

#[test]
fn absent_trust_and_unbounded_limits_never_fall_back() {
    let base = fixture();
    let edits: [fn(&mut KagemushaEnrollmentIssuer); 9] = [
        |c| c.revision = 0,
        |c| c.providers.clear(),
        |c| c.request_timeout_ms = 0,
        |c| c.request_timeout_ms = 60_001,
        |c| c.max_inflight = 0,
        |c| c.max_inflight = 1025,
        |c| c.providers[0].worker.python_executable.clear(),
        |c| c.providers[0].signer_private_key.clear(),
        |c| c.scope_hex = "00".repeat(32),
    ];
    for edit in edits {
        let mut input = base.clone();
        edit(&mut input);
        let mut emitter = Emitter::new();
        assert!(input.parse(&mut emitter).is_none());
        assert!(emitter.into_result().is_err());
    }
}

#[test]
fn debug_omits_custody_paths_handles_and_endpoints() {
    let input = fixture();
    for text in [
        format!("{input:?}"),
        format!("{:?}", input.providers[0]),
        format!("{:?}", input.clone().checked().unwrap()),
        format!("{:?}", input.checked().unwrap().providers[0]),
    ] {
        for private in [
            "/var/lib/",
            "provider.example",
            "platform-worker",
            "enrollment-signer",
        ] {
            assert!(!text.contains(private));
        }
    }
}

#[test]
fn worker_original_paths_pins_timeouts_and_platform_are_required() {
    let base = fixture().providers.remove(0).worker;
    let apple = KagemushaWalletEnrollmentPlatformV1::Apple {
        attestation_root_sha256: [9; 32],
    };
    let android = KagemushaWalletEnrollmentPlatformV1::Android {
        root_set: vec![KagemushaWalletAndroidRootV1 {
            family: KagemushaWalletAndroidRootFamilyV1::GoogleCa1,
            spki_sha256: [9; 32],
            revocation_source: KagemushaWalletRevocationSourceV1::GoogleAttestationStatus,
        }],
        patch_floor_yyyymm: 202_608,
    };
    let edits: [fn(&mut KagemushaEnrollmentWorker); 11] = [
        |worker| worker.python_executable = "relative".into(),
        |worker| worker.verifier_archive = "/private/../archive".into(),
        |worker| worker.openssl_executable.clear(),
        |worker| worker.attestation_root = Some(PathBuf::new()),
        |worker| worker.attestation_root = None,
        |worker| worker.store_directory.clear(),
        |worker| worker.python_sha256_hex = "00".repeat(32),
        |worker| worker.verifier_sha256_hex = "FF".repeat(32),
        |worker| worker.openssl_sha256_hex = "01".into(),
        |worker| worker.exchange_timeout_ms = 0,
        |worker| worker.exchange_timeout_ms = 300_001,
    ];
    for edit in edits {
        let mut invalid = base.clone();
        edit(&mut invalid);
        assert!(invalid.checked(&apple).is_err());
    }
    // Android selects no root original: its KeyMint chain carries the root.
    assert!(base.clone().checked(&android).is_err());
    let mut rootless = base.clone();
    rootless.attestation_root = None;
    assert_eq!(rootless.checked(&android).unwrap().attestation_root, None);
    for millis in [1, 300_000] {
        let mut valid = base.clone();
        valid.exchange_timeout_ms = millis;
        assert_eq!(
            valid.checked(&apple).unwrap().exchange_timeout,
            Duration::from_millis(millis)
        );
    }
}
